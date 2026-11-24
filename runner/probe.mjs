import { spawn, execFile } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { aesDecrypt, hmacSign } from '../shared/crypto.mjs';
import { isValidUuid } from '../shared/validate.mjs';
import { parseNodesInput } from './parser.mjs';

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

async function curlViaSocks(port, url, timeoutSec = 10) {
  const { stdout } = await execFileAsync(
    'curl',
    [
      '-sS',
      '-L',
      '--socks5-hostname',
      `127.0.0.1:${port}`,
      '--connect-timeout',
      String(Math.min(timeoutSec, 8)),
      '--max-time',
      String(timeoutSec),
      url,
    ],
    { timeout: (timeoutSec + 2) * 1000 },
  );
  return stdout;
}

function parseCfTrace(text) {
  const map = {};
  for (const line of String(text).split(/\r?\n/)) {
    const eq = line.indexOf('=');
    if (eq > 0) {
      map[line.slice(0, eq)] = line.slice(eq + 1).trim();
    }
  }
  return map;
}

async function queryExitInfo(port) {
  let exitIp = '';
  let loc = '';

  // Primary: Cloudflare cdn-cgi/trace (fast, plain text, no bot challenge)
  try {
    const trace = parseCfTrace(await curlViaSocks(port, 'https://www.cloudflare.com/cdn-cgi/trace', 10));
    if (trace.ip) {
      exitIp = trace.ip;
      loc = trace.loc || '';
    }
  } catch {
    // fallback below
  }

  // Fallback: ipify
  if (!exitIp) {
    const ipifyRaw = await curlViaSocks(port, 'https://api64.ipify.org?format=json', 10);
    const parsed = JSON.parse(ipifyRaw);
    if (!parsed?.ip) throw new Error('Empty IP response');
    exitIp = parsed.ip;
  }

  // Best-effort Geo/ASN enrichment via proxy
  let geo = {};
  try {
    const geoRaw = await curlViaSocks(
      port,
      'http://ip-api.com/json?fields=status,country,countryCode,regionName,city,isp,org,as,query',
      6,
    );
    const parsed = JSON.parse(geoRaw);
    if (parsed?.status === 'success') {
      geo = parsed;
    }
  } catch {
    // ignore geo enrichment failures
  }

  return {
    exit_ip: exitIp,
    country: geo.countryCode || geo.country || loc || undefined,
    region: geo.regionName || undefined,
    city: geo.city || undefined,
    isp: geo.isp || geo.org || undefined,
    asn: geo.as || undefined,
  };
}

async function probeSingleNode(node, index) {
  const socksPort = 21000 + index;
  const cfgPath = join(tmpdir(), `sb-probe-${process.pid}-${index}.json`);
  const config = {
    log: { level: 'panic' },
    inbounds: [
      {
        type: 'socks',
        tag: 'socks-in',
        listen: '127.0.0.1',
        listen_port: socksPort,
      },
    ],
    outbounds: [node.outbound],
  };

  writeFileSync(cfgPath, JSON.stringify(config), { mode: 0o600 });

  const startedAt = Date.now();
  let spawnErr = null;
  const child = spawn(SING_BOX_BIN, ['run', '-c', cfgPath], {
    stdio: 'ignore',
  });
  child.on('error', (err) => {
    spawnErr = err;
  });

  try {
    const ready = await waitForPort(
      '127.0.0.1',
      socksPort,
      5000,
      () => Boolean(spawnErr || child.exitCode !== null),
    );
    if (spawnErr) {
      throw new Error(`sing-box spawn error: ${spawnErr.code || spawnErr.message}`);
    }
    if (!ready || child.exitCode !== null) {
      throw new Error('sing-box failed to start');
    }

    const info = await queryExitInfo(socksPort);
    return {
      index,
      name: node.name,
      type: node.type,
      ok: true,
      ...info,
      latency_ms: Date.now() - startedAt,
    };
  } catch (err) {
    return {
      index,
      name: node.name,
      type: node.type,
      ok: false,
      error: err?.message ? String(err.message).slice(0, 120) : 'Probe failed',
      latency_ms: Date.now() - startedAt,
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

async function pullEncryptedPayload(workerUrl, taskId, pullToken) {
  const url = `${workerUrl.replace(/\/$/, '')}/internal/pull?task_id=${encodeURIComponent(taskId)}`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${pullToken}` },
    });
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

  if (!isValidUuid(taskId)) {
    throw new Error('Invalid or missing TASK_ID');
  }
  if (!workerUrl || !pullToken || !aesKey || !callbackSecret) {
    throw new Error('Missing required runner environment variables');
  }

  const startedAt = Date.now();
  let callbackPayload;

  try {
    const pulled = await pullEncryptedPayload(workerUrl, taskId, pullToken);
    const decrypted = JSON.parse(await aesDecrypt(pulled.cipher, aesKey));
    const nodes = parseNodesInput(decrypted.raw_input);

    if (nodes.length === 0) {
      callbackPayload = {
        task_id: taskId,
        status: 'error',
        results: [],
        error: 'No valid proxy nodes parsed from input',
        duration_ms: Date.now() - startedAt,
      };
    } else {
      const results = await mapWithConcurrency(nodes, CONCURRENCY, probeSingleNode);
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

  await sendCallback(workerUrl, callbackSecret, callbackPayload);

  // Never print node details, credentials, or exit IPs in public CI logs.
  const okCount = (callbackPayload.results || []).filter((r) => r.ok).length;
  console.log(
    `Task ${taskId} ${callbackPayload.status}: total=${(callbackPayload.results || []).length}, ok=${okCount}, duration_ms=${callbackPayload.duration_ms}`,
  );
}

main().catch((err) => {
  console.error(`Runner fatal: ${err?.message || 'unknown error'}`);
  process.exit(1);
});
