import { spawn, execFile } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { aesDecrypt, hmacSign } from '../shared/crypto.mjs';
import { isValidUuid } from '../shared/validate.mjs';
import { buildProbeConfig, parseNodesInput } from './parser.mjs';
import { asnNumber, buildNodeResult, CDN_ASNS, createLineBuffer, isPublicIp, summarizeCodes } from './diagnostics.mjs';
import { buildFamilySpecs, IPPURE_HOST, probeFamily } from './exitprobe.mjs';
import {
  geoLookup,
  isCloudflareEdge,
  prepareEch,
  resolveEntry,
  resolveHostAddresses,
  runnerHasIpv6,
} from './netinfo.mjs';

const execFileAsync = promisify(execFile);

const SING_BOX_BIN = process.env.SING_BOX_BIN || 'sing-box';
const CONCURRENCY = Number(process.env.PROBE_CONCURRENCY || 5);

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

/**
 * Never throws: returns { ok, body } or { ok: false, curlCode, message }.
 * `connectTo` (host:port:addr:port) pins the connection to one address family while keeping
 * the URL's hostname for SNI / Host; with SOCKS5 the pinned address is what the node dials.
 */
async function curlViaSocks(port, url, { timeoutSec = 10, connectTo } = {}) {
  const args = ['-sS', '-g', '--socks5-hostname', `127.0.0.1:${port}`];
  if (connectTo) args.push('--connect-to', connectTo);
  args.push('--connect-timeout', String(Math.min(timeoutSec, 8)), '--max-time', String(timeoutSec), url);
  try {
    const { stdout } = await execFileAsync('curl', args, {
      timeout: (timeoutSec + 2) * 1000,
      maxBuffer: 256 * 1024,
    });
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

/** Runs one node through sing-box and collects raw observations (not yet redacted). */
async function probeSingleNode(node, index, specs) {
  const socksPort = 21000 + index;
  const base = {
    index,
    name: node.name,
    type: node.type,
    outbound: node.outbound,
    chain: node.chain,
    via: node.via,
    ech: node.ech,
  };

  if (node.chainError) {
    return {
      ...base,
      entry: await resolveEntry(node.outbound.server),
      coreFailure: 'chain_invalid',
      coreFailureDetail: node.chainError,
      coreLines: [],
      latency_ms: 0,
    };
  }

  const cfgPath = join(tmpdir(), `sb-probe-${process.pid}-${index}.json`);
  // Logs are captured in memory only (never printed) so failures can be classified.
  writeFileSync(cfgPath, JSON.stringify(buildProbeConfig(node, socksPort)), { mode: 0o600 });

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

    const curl = (url, opts) => curlViaSocks(socksPort, url, opts);
    const [ipv4, ipv6, dual] = await Promise.all([
      probeFamily(specs.ipv4, curl),
      probeFamily(specs.ipv6, curl),
      probeFamily(specs.dual, curl),
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
async function finalizeResults(probes, specs) {
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

  const hosts = { ipv4: specs.ipv4.hosts, ipv6: specs.ipv6.hosts };
  const cdnEdges = await detectCloudflareEdges(probes, geoMap);
  const results = probes.map((p) => buildNodeResult(p, geoMap, { runnerIpv6, hosts, cdnEdges }));
  const usedIppure = probes.some((p) => Object.values(p.families || {}).some((f) => f?.ok && f.geo));
  const geoSources = [...new Set([...(usedIppure ? ['ippure'] : []), ...[...geoMap.values()].map((g) => g.geo_source)])];
  return { results, runnerIpv6, geoSources };
}

/**
 * For nodes whose exit is unrelated to the entry and whose entry ASN is not a known CDN,
 * check whether the entry is actually a Cloudflare edge (BYOIP / "优选" IP). One check per IP.
 */
async function detectCloudflareEdges(probes, geoMap) {
  const candidates = new Set();
  for (const p of probes) {
    const entryIps = p.entry?.ips || [];
    const exits = Object.values(p.families || {}).filter((f) => f?.ok).map((f) => f.ip);
    if (entryIps.length === 0 || exits.length === 0 || exits.some((ip) => entryIps.includes(ip))) continue;
    if (entryIps.some((ip) => CDN_ASNS.has(asnNumber(geoMap.get(ip)?.asn)))) continue;
    const ip = entryIps.find(isPublicIp);
    if (ip) candidates.add(ip);
  }
  const checks = await Promise.all([...candidates].slice(0, 20).map(async (ip) => [ip, await isCloudflareEdge(ip)]));
  return new Set(checks.filter(([, edge]) => edge).map(([ip]) => ip));
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
      const [ippureAddrs] = await Promise.all([resolveHostAddresses(IPPURE_HOST), prepareEch(nodes)]);
      const specs = buildFamilySpecs(ippureAddrs);
      const probes = await mapWithConcurrency(nodes, CONCURRENCY, (node, i) => probeSingleNode(node, i, specs));
      const { results, runnerIpv6, geoSources } = await finalizeResults(probes, specs);
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
