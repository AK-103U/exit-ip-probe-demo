import { spawn, execFile } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { aesDecrypt, hmacSign } from '../shared/crypto.mjs';
import { isValidUuid } from '../shared/validate.mjs';
import { parseNodesInput } from './parser.mjs';
import {
  buildNodeResult,
  createLineBuffer,
  ipMatchesFamily,
  parseCfTrace,
  summarizeCodes,
} from './diagnostics.mjs';
import { geoLookup, prepareEch, resolveEntry, runnerHasIpv6 } from './netinfo.mjs';

const execFileAsync = promisify(execFile);

const SING_BOX_BIN = process.env.SING_BOX_BIN || 'sing-box';
const CONCURRENCY = Number(process.env.PROBE_CONCURRENCY || 5);

/**
 * Exit IP probes per address family. IP-literal endpoints force the node to egress over
 * that family; `dual` uses a dual-stack hostname to reveal which family the node prefers.
 */
const PROBES = {
  ipv4: {
    family: 4,
    primary: 'https://1.1.1.1/cdn-cgi/trace',
    fallback: 'https://api4.ipify.org?format=json',
    hosts: ['1.1.1.1', 'api4.ipify.org'],
  },
  ipv6: {
    family: 6,
    primary: 'https://[2606:4700:4700::1111]/cdn-cgi/trace',
    fallback: 'https://api6.ipify.org?format=json',
    hosts: ['2606:4700:4700::1111', 'api6.ipify.org'],
  },
  dual: {
    family: 0,
    primary: 'https://www.cloudflare.com/cdn-cgi/trace',
    fallback: 'https://api64.ipify.org?format=json',
    hosts: ['www.cloudflare.com', 'api64.ipify.org'],
  },
};

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForPort(host, port, timeoutMs = 5000, shouldAbort = () => false) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (shouldAbort()) return false;
    const open = await new Promise((resolve) => {
      const sock = net.createConnection({ host, port });
      sock.once('connect', () => {
        sock.destroy();
        resolve(true);
      });
      sock.once('error', () => {
        sock.destroy();
        resolve(false);
      });
    });
    if (open) return true;
    await sleep(50);
  }
  return false;
}

/** Never throws: returns { ok, body } or { ok: false, curlCode, message }. */
async function curlViaSocks(port, url, timeoutSec = 10) {
  try {
    const { stdout } = await execFileAsync(
      'curl',
      [
        '-sS',
        '-g',
        '--socks5-hostname',
        `127.0.0.1:${port}`,
        '--connect-timeout',
        String(Math.min(timeoutSec, 8)),
        '--max-time',
        String(timeoutSec),
        url,
      ],
      { timeout: (timeoutSec + 2) * 1000, maxBuffer: 256 * 1024 },
    );
    return { ok: true, body: stdout };
  } catch (err) {
    const stderr = String(err?.stderr || '').trim().split(/\r?\n/).pop() || '';
    return {
      ok: false,
      curlCode: typeof err?.code === 'number' ? err.code : null,
      message: (stderr || (err?.killed ? 'curl killed after timeout' : 'curl failed')).slice(0, 200),
    };
  }
}

async function probeFamily(port, spec) {
  const started = Date.now();
  const attempts = [];

  const trace = await curlViaSocks(port, spec.primary, 10);
  if (trace.ok) {
    const t = parseCfTrace(trace.body);
    if (ipMatchesFamily(t.ip, spec.family)) {
      return { ok: true, ip: t.ip, colo: t.colo, warp: t.warp, source: 'cf-trace', ms: Date.now() - started };
    }
    attempts.push({ ok: false, badResponse: true, message: 'unexpected cdn-cgi/trace response' });
  } else {
    attempts.push(trace);
  }

  const ipify = await curlViaSocks(port, spec.fallback, 8);
  if (ipify.ok) {
    let ip;
    try {
      ip = JSON.parse(ipify.body)?.ip;
    } catch {
      ip = undefined;
    }
    if (ipMatchesFamily(ip, spec.family)) {
      return { ok: true, ip, source: 'ipify', ms: Date.now() - started };
    }
    attempts.push({ ok: false, badResponse: true, message: 'unexpected ipify response' });
  } else {
    attempts.push(ipify);
  }

  return { ok: false, attempts, ms: Date.now() - started };
}

/** Runs one node through sing-box and collects raw observations (not yet redacted). */
async function probeSingleNode(node, index) {
  const socksPort = 21000 + index;
  const cfgPath = join(tmpdir(), `sb-probe-${process.pid}-${index}.json`);
  const config = {
    // Captured in memory only (never printed) so failures can be classified.
    log: { level: 'warn', timestamp: false },
    inbounds: [{ type: 'socks', tag: 'socks-in', listen: '127.0.0.1', listen_port: socksPort }],
    outbounds: [node.outbound],
  };
  writeFileSync(cfgPath, JSON.stringify(config), { mode: 0o600 });

  const base = { index, name: node.name, type: node.type, outbound: node.outbound, ech: node.ech };
  const entryPromise = resolveEntry(node.outbound.server);
  const logs = createLineBuffer(80);
  const startedAt = Date.now();
  let spawnErr = null;

  const child = spawn(SING_BOX_BIN, ['run', '-c', cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (d) => logs.push(d));
  child.stderr.on('data', (d) => logs.push(d));
  child.on('error', (err) => {
    spawnErr = err;
  });

  try {
    const ready = await waitForPort('127.0.0.1', socksPort, 5000, () => Boolean(spawnErr || child.exitCode !== null));
    const coreReadyMs = Date.now() - startedAt;

    if (spawnErr || !ready || child.exitCode !== null) {
      await sleep(100); // let the core flush its fatal message
      return {
        ...base,
        entry: await entryPromise,
        coreFailure: spawnErr ? 'core_spawn_failed' : 'core_start_failed',
        coreFailureDetail: spawnErr ? `spawn ${spawnErr.code || 'error'}` : undefined,
        coreLines: logs.lines(),
        latency_ms: Date.now() - startedAt,
        timings: { core_ready_ms: coreReadyMs },
      };
    }

    const [ipv4, ipv6, dual] = await Promise.all([
      probeFamily(socksPort, PROBES.ipv4),
      probeFamily(socksPort, PROBES.ipv6),
      probeFamily(socksPort, PROBES.dual),
    ]);
    await sleep(50);

    return {
      ...base,
      entry: await entryPromise,
      families: { ipv4, ipv6, dual },
      coreLines: logs.lines(),
      latency_ms: Date.now() - startedAt,
      timings: { core_ready_ms: coreReadyMs, ipv4_ms: ipv4.ms, ipv6_ms: ipv6.ms, dual_ms: dual.ms },
    };
  } finally {
    try {
      child.kill('SIGTERM');
    } catch {
      // ignore
    }
    try {
      rmSync(cfgPath, { force: true });
    } catch {
      // ignore
    }
  }
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;

  async function worker() {
    while (next < items.length) {
      const idx = next++;
      results[idx] = await fn(items[idx], idx);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

async function coreVersion() {
  try {
    const { stdout } = await execFileAsync(SING_BOX_BIN, ['version'], { timeout: 5000 });
    return /version\s+(\S+)/.exec(stdout)?.[1] || null;
  } catch {
    return null;
  }
}

/** Enriches raw probes with exact-IP geo data and turns them into redacted results. */
async function finalizeResults(probes) {
  const ips = [];
  for (const p of probes) {
    ips.push(...(p.entry?.ips || []));
    for (const f of Object.values(p.families || {})) if (f?.ok) ips.push(f.ip);
  }

  const needsIpv6Check = probes.some(
    (p) => !Object.values(p.families || {}).some((f) => f?.ok) && (p.entry?.ips || []).some((ip) => net.isIP(ip) === 6),
  );
  const [geoMap, runnerIpv6] = await Promise.all([
    geoLookup(ips),
    needsIpv6Check ? runnerHasIpv6() : Promise.resolve(undefined),
  ]);

  const hosts = { ipv4: PROBES.ipv4.hosts, ipv6: PROBES.ipv6.hosts };
  const results = probes.map((p) => buildNodeResult(p, geoMap, { runnerIpv6, hosts }));
  const geoSources = [...new Set([...geoMap.values()].map((g) => g.geo_source))];
  return { results, runnerIpv6, geoSources };
}

async function pullEncryptedPayload(workerUrl, taskId, pullToken, runId) {
  const url = `${workerUrl.replace(/\/$/, '')}/internal/pull?task_id=${encodeURIComponent(taskId)}`;
  const headers = { Authorization: `Bearer ${pullToken}` };
  if (runId) headers['X-Run-Id'] = runId;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await fetch(url, { headers });
    if (res.ok) {
      return res.json();
    }
    if (res.status !== 404 || attempt === 3) {
      throw new Error(`Pull failed with status ${res.status}`);
    }
    await sleep(1000 * attempt);
  }
  throw new Error('Pull exhausted retries');
}

async function sendCallback(workerUrl, callbackSecret, payload) {
  const body = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = await hmacSign(callbackSecret, timestamp, body);
  const url = `${workerUrl.replace(/\/$/, '')}/internal/callback`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Timestamp': timestamp,
      'X-Signature': signature,
    },
    body,
  });

  if (!res.ok) {
    throw new Error(`Callback failed with status ${res.status}`);
  }
}

async function main() {
  const taskId = process.env.TASK_ID || '';
  const workerUrl = process.env.WORKER_URL || '';
  const pullToken = process.env.PULL_TOKEN || '';
  const aesKey = process.env.AES_KEY || '';
  const callbackSecret = process.env.CALLBACK_SECRET || '';
  const runId = /^\d{1,20}$/.test(process.env.GITHUB_RUN_ID || '') ? process.env.GITHUB_RUN_ID : undefined;

  if (!isValidUuid(taskId)) {
    throw new Error('Invalid or missing TASK_ID');
  }
  if (!workerUrl || !pullToken || !aesKey || !callbackSecret) {
    throw new Error('Missing required runner environment variables');
  }

  const startedAt = Date.now();
  const meta = { core: 'sing-box', core_version: null, run_id: runId };
  let callbackPayload;

  try {
    const pulled = await pullEncryptedPayload(workerUrl, taskId, pullToken, runId);
    const decrypted = JSON.parse(await aesDecrypt(pulled.cipher, aesKey));
    const nodes = parseNodesInput(decrypted.raw_input);
    meta.core_version = await coreVersion();

    if (nodes.length === 0) {
      callbackPayload = {
        task_id: taskId,
        status: 'error',
        results: [],
        error: 'No valid proxy nodes parsed from input',
        duration_ms: Date.now() - startedAt,
      };
    } else {
      await prepareEch(nodes);
      const probes = await mapWithConcurrency(nodes, CONCURRENCY, probeSingleNode);
      const { results, runnerIpv6, geoSources } = await finalizeResults(probes);
      meta.runner_ipv6 = runnerIpv6;
      meta.geo_sources = geoSources;
      callbackPayload = {
        task_id: taskId,
        status: 'done',
        results,
        duration_ms: Date.now() - startedAt,
      };
    }
  } catch (err) {
    callbackPayload = {
      task_id: taskId,
      status: 'error',
      results: [],
      error: err?.message ? String(err.message).slice(0, 160) : 'Runner execution failed',
      duration_ms: Date.now() - startedAt,
    };
  }

  callbackPayload.meta = meta;
  await sendCallback(workerUrl, callbackSecret, callbackPayload);

  // Never print node details, credentials, or exit IPs in public CI logs: counts and codes only.
  const results = callbackPayload.results || [];
  const okCount = results.filter((r) => r.ok).length;
  const codes = summarizeCodes(results);
  console.log(
    `Task ${taskId} ${callbackPayload.status}: total=${results.length}, ok=${okCount}, duration_ms=${callbackPayload.duration_ms}` +
      (codes ? `, codes=${codes}` : ''),
  );
}

main().catch((err) => {
  console.error(`Runner fatal: ${err?.message || 'unknown error'}`);
  process.exit(1);
});
