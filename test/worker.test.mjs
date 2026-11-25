import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { aesDecrypt, hmacSign } from '../shared/crypto.mjs';

// Load worker module directly; mock .html import via loader-free inline test or read ui.html?
// Note: Node doesn't natively import .html without a loader, so we test via wrangler/miniflare OR check index.mjs logic.
// Let's provide a tiny ESM register hook in this test? Wait: Node 24 supports module.registerHooks!
import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.endsWith('.html')) {
      return { shortCircuit: true, url: new URL('../worker/ui.html', import.meta.url).href };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.endsWith('.html')) {
      const html = readFileSync(new URL(url), 'utf8');
      return {
        shortCircuit: true,
        format: 'module',
        source: `export default ${JSON.stringify(html)};`,
      };
    }
    return nextLoad(url, context);
  },
});

const { createWorker } = await import('../worker/index.mjs');

function createMockKv() {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, val) {
      store.set(key, String(val));
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

function makeEnv() {
  return {
    PROBE_KV: createMockKv(),
    API_TOKEN: 'api-secret-token',
    PULL_TOKEN: 'pull-secret-token',
    CALLBACK_SECRET: 'callback-hmac-secret',
    AES_KEY: randomBytes(32).toString('base64'),
    GITHUB_TOKEN: 'ghp_mocktoken',
    GITHUB_OWNER: 'demo-owner',
    GITHUB_REPO: 'demo-repo',
    GITHUB_WORKFLOW: 'probe.yml',
    GITHUB_REF: 'main',
  };
}

test('full Worker workflow: probe -> dispatch -> burn-after-read pull -> signed callback -> result', async () => {
  const env = makeEnv();
  const dispatchCalls = [];

  const worker = createWorker(async (url, init) => {
    dispatchCalls.push({ url, init, body: JSON.parse(init.body) });
    return new Response(null, { status: 204 });
  });

  // 1. UI serves HTML
  const uiRes = await worker.fetch(new Request('https://example.com/'), env);
  assert.equal(uiRes.status, 200);
  assert.match(await uiRes.text(), /Exit IP Probe/);

  // 2. Unauthorized /probe fails
  const unauthRes = await worker.fetch(
    new Request('https://example.com/probe', {
      method: 'POST',
      body: JSON.stringify({ input: 'test' }),
    }),
    env,
  );
  assert.equal(unauthRes.status, 401);

  // 3. Authorized /probe encrypts payload, stores in KV, dispatches ONLY task_id to GitHub
  const rawNode = '- { name: HK, server: 198.51.100.1, port: 20000, type: hysteria2, password: top-secret-pass }';
  const probeRes = await worker.fetch(
    new Request('https://example.com/probe', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: rawNode }),
    }),
    env,
  );
  assert.equal(probeRes.status, 202);
  const probeJson = await probeRes.json();
  assert.equal(probeJson.ok, true);
  assert.equal(probeJson.status, 'queued');

  assert.equal(dispatchCalls.length, 1);
  assert.deepEqual(dispatchCalls[0].body, {
    ref: 'main',
    inputs: { task_id: probeJson.task_id },
  });
  assert.equal(JSON.stringify(dispatchCalls[0].body).includes('top-secret-pass'), false);

  // 4. Polling /result shows queued
  const res1 = await worker.fetch(
    new Request(`https://example.com/result?task_id=${probeJson.task_id}`, {
      headers: { Authorization: `Bearer ${env.API_TOKEN}` },
    }),
    env,
  );
  assert.equal((await res1.json()).status, 'queued');

  // 5. Internal pull returns cipher once and burns it immediately
  const pullRes = await worker.fetch(
    new Request(`https://example.com/internal/pull?task_id=${probeJson.task_id}`, {
      headers: { Authorization: `Bearer ${env.PULL_TOKEN}`, 'X-Run-Id': '123456789' },
    }),
    env,
  );
  assert.equal(pullRes.status, 200);

  // Observability: once pulled, the task is "running" and links to the public Actions run.
  const running = await (
    await worker.fetch(
      new Request(`https://example.com/result?task_id=${probeJson.task_id}`, {
        headers: { Authorization: `Bearer ${env.API_TOKEN}` },
      }),
      env,
    )
  ).json();
  assert.equal(running.status, 'running');
  assert.equal(running.run_url, 'https://github.com/demo-owner/demo-repo/actions/runs/123456789');
  assert.equal(typeof running.started_at, 'number');
  assert.equal(typeof running.created_at, 'number');
  const pullJson = await pullRes.json();
  const decrypted = JSON.parse(await aesDecrypt(pullJson.cipher, env.AES_KEY));
  assert.equal(decrypted.raw_input, rawNode);

  // Second pull must return 404 (burn after read)
  const pullRes2 = await worker.fetch(
    new Request(`https://example.com/internal/pull?task_id=${probeJson.task_id}`, {
      headers: { Authorization: `Bearer ${env.PULL_TOKEN}` },
    }),
    env,
  );
  assert.equal(pullRes2.status, 404);

  // 6. Unsigned callback is rejected
  const cbBody = JSON.stringify({
    task_id: probeJson.task_id,
    status: 'done',
    results: [{ index: 0, name: 'HK', type: 'hysteria2', ok: true, exit_ip: '198.51.100.1', latency_ms: 420 }],
    duration_ms: 1500,
    meta: { core: 'sing-box', core_version: '1.13.13', run_id: '123456789', runner_ipv6: false },
  });
  const badCb = await worker.fetch(
    new Request('https://example.com/internal/callback', {
      method: 'POST',
      headers: { 'X-Timestamp': '1', 'X-Signature': 'deadbeef' },
      body: cbBody,
    }),
    env,
  );
  assert.equal(badCb.status, 401);

  // 7. Properly HMAC-signed callback updates result
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = await hmacSign(env.CALLBACK_SECRET, ts, cbBody);
  const goodCb = await worker.fetch(
    new Request('https://example.com/internal/callback', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Timestamp': ts,
        'X-Signature': sig,
      },
      body: cbBody,
    }),
    env,
  );
  assert.equal(goodCb.status, 200);

  // 8. Final /result returns done + exit_ip
  const res2 = await worker.fetch(
    new Request(`https://example.com/result?task_id=${probeJson.task_id}`, {
      headers: { Authorization: `Bearer ${env.API_TOKEN}` },
    }),
    env,
  );
  const finalJson = await res2.json();
  assert.equal(finalJson.status, 'done');
  assert.equal(finalJson.results[0].exit_ip, '198.51.100.1');
  assert.equal(finalJson.meta.core_version, '1.13.13');
  assert.equal(finalJson.run_url, running.run_url);
  assert.equal(finalJson.created_at, running.created_at);
  assert.equal(finalJson.started_at, running.started_at);
});

test('/probe keeps the indentation of pasted Clash YAML (no trim of the first line)', async () => {
  const env = makeEnv();
  const worker = createWorker(async () => new Response(null, { status: 204 }));
  const pasted = '\n    - { name: A, type: ss, server: 198.51.100.1, port: 8388, cipher: aes-128-gcm, password: p1 }\n    - { name: B, type: ss, server: 198.51.100.2, port: 8388, cipher: aes-128-gcm, password: p2 }\n   \n';
  const res = await worker.fetch(
    new Request('https://example.com/probe', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: pasted }),
    }),
    env,
  );
  const { task_id: taskId } = await res.json();
  const pull = await worker.fetch(
    new Request(`https://example.com/internal/pull?task_id=${taskId}`, {
      headers: { Authorization: `Bearer ${env.PULL_TOKEN}` },
    }),
    env,
  );
  const { raw_input: rawInput } = JSON.parse(await aesDecrypt((await pull.json()).cipher, env.AES_KEY));
  assert.equal(rawInput.startsWith('    - { name: A'), true);
  assert.equal(rawInput.endsWith('p2 }'), true);

  const rejected = await worker.fetch(
    new Request('https://example.com/probe', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: '  \n \t \n' }),
    }),
    env,
  );
  assert.equal(rejected.status, 400);
});
