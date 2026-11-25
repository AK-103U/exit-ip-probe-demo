import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { aesEncrypt, hmacVerify } from '../shared/crypto.mjs';

const execFileAsync = promisify(execFile);

test('runner/probe.mjs pulls encrypted task, masks stdout, and posts HMAC-signed callback', async () => {
  const aesKey = randomBytes(32).toString('base64');
  const pullToken = 'test-pull-token';
  const callbackSecret = 'test-callback-secret';
  const taskId = '22222222-2222-4222-8222-222222222222';
  const secretPass = 'SUPER_SECRET_PASSWORD_XYZ';

  const cipher = await aesEncrypt(
    JSON.stringify({
      task_id: taskId,
      raw_input: `- { name: TestHK, server: 127.0.0.1, port: 19999, type: hysteria2, password: ${secretPass} }`,
      created_at: Date.now(),
    }),
    aesKey,
  );

  let pulledOnce = false;
  let receivedCallback = null;
  let callbackSignatureValid = false;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/internal/pull') {
      assert.equal(req.headers.authorization, `Bearer ${pullToken}`);
      assert.equal(url.searchParams.get('task_id'), taskId);
      assert.equal(pulledOnce, false);
      pulledOnce = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, task_id: taskId, cipher }));
      return;
    }
    if (req.method === 'POST' && url.pathname === '/internal/callback') {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const rawBody = Buffer.concat(chunks).toString('utf8');
      const ts = req.headers['x-timestamp'];
      const sig = req.headers['x-signature'];
      callbackSignatureValid = await hmacVerify(callbackSecret, ts, rawBody, sig);
      receivedCallback = JSON.parse(rawBody);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['runner/probe.mjs'], {
      env: {
        ...process.env,
        TASK_ID: taskId,
        WORKER_URL: `http://127.0.0.1:${port}`,
        PULL_TOKEN: pullToken,
        AES_KEY: aesKey,
        CALLBACK_SECRET: callbackSecret,
        SING_BOX_BIN: 'nonexistent-sing-box-binary-for-test',
        GITHUB_RUN_ID: '987654321',
      },
    });

    assert.equal(pulledOnce, true);
    assert.equal(callbackSignatureValid, true);
    assert.equal(receivedCallback.task_id, taskId);
    assert.equal(receivedCallback.status, 'done');
    assert.equal(receivedCallback.results.length, 1);
    assert.equal(receivedCallback.results[0].name, 'TestHK');
    assert.equal(receivedCallback.results[0].ok, false);
    assert.equal(receivedCallback.results[0].error_code, 'core_spawn_failed');
    assert.match(receivedCallback.results[0].error, /sing-box/);
    assert.equal(receivedCallback.meta.core, 'sing-box');
    assert.equal(receivedCallback.meta.run_id, '987654321');

    // Ensure no sensitive data or node details leak to CI logs
    const combinedLogs = `${stdout}\n${stderr}`;
    assert.equal(combinedLogs.includes(secretPass), false);
    assert.equal(combinedLogs.includes('TestHK'), false);
    assert.match(stdout, new RegExp(`Task ${taskId} done: total=1, ok=0, duration_ms=\\d+, codes=core_spawn_failed:1`));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
