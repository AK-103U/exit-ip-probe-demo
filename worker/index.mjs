import uiHtml from './ui.html';
import { aesEncrypt, hmacVerify, timingSafeEqualStr } from '../shared/crypto.mjs';
import { isValidUuid, validateProbeInput } from '../shared/validate.mjs';

const PAYLOAD_TTL_SEC = 180;
const RESULT_TTL_SEC = 3600;

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

function extractBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  return (request.headers.get('X-Access-Token') || '').trim();
}

async function authorize(request, expectedToken) {
  if (!expectedToken) return false;
  const provided = extractBearerToken(request);
  if (!provided) return false;
  return timingSafeEqualStr(provided, expectedToken);
}

function getMissingConfig(env) {
  const required = [
    'PROBE_KV',
    'API_TOKEN',
    'PULL_TOKEN',
    'CALLBACK_SECRET',
    'AES_KEY',
    'GITHUB_TOKEN',
    'GITHUB_OWNER',
    'GITHUB_REPO',
  ];
  return required.filter((k) => !env[k]);
}

async function handleProbe(request, env, fetchFn) {
  if (!(await authorize(request, env.API_TOKEN))) {
    return jsonResponse({ ok: false, error: 'Unauthorized' }, 401);
  }

  const missing = getMissingConfig(env);
  if (missing.length > 0) {
    return jsonResponse({ ok: false, error: `Server misconfigured: missing ${missing.join(', ')}` }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ ok: false, error: 'Invalid JSON body' }, 400);
  }

  const check = validateProbeInput(body?.input);
  if (!check.ok) {
    return jsonResponse({ ok: false, error: check.error }, 400);
  }

  const taskId = crypto.randomUUID();
  const createdAt = Date.now();
  const plaintext = JSON.stringify({
    task_id: taskId,
    raw_input: check.value,
    created_at: createdAt,
  });

  let cipher;
  try {
    cipher = await aesEncrypt(plaintext, env.AES_KEY);
  } catch (err) {
    return jsonResponse({ ok: false, error: `Encryption failed: ${err.message}` }, 500);
  }

  const payloadKey = `payload:${taskId}`;
  const resultKey = `result:${taskId}`;

  await Promise.all([
    env.PROBE_KV.put(payloadKey, cipher, { expirationTtl: PAYLOAD_TTL_SEC }),
    env.PROBE_KV.put(
      resultKey,
      JSON.stringify({ task_id: taskId, status: 'queued', created_at: createdAt }),
      { expirationTtl: RESULT_TTL_SEC },
    ),
  ]);

  const workflow = env.GITHUB_WORKFLOW || 'probe.yml';
  const ref = env.GITHUB_REF || 'main';
  const dispatchUrl = `https://api.github.com/repos/${encodeURIComponent(env.GITHUB_OWNER)}/${encodeURIComponent(env.GITHUB_REPO)}/actions/workflows/${encodeURIComponent(workflow)}/dispatches`;

  const ghRes = await fetchFn(dispatchUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'cf-exit-ip-probe-demo',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: JSON.stringify({
      ref,
      inputs: { task_id: taskId },
    }),
  });

  if (!ghRes.ok) {
    const errText = await ghRes.text().catch(() => '');
    await Promise.all([
      env.PROBE_KV.delete(payloadKey),
      env.PROBE_KV.put(
        resultKey,
        JSON.stringify({
          task_id: taskId,
          status: 'error',
          error: `GitHub dispatch failed (${ghRes.status})`,
          created_at: createdAt,
        }),
        { expirationTtl: RESULT_TTL_SEC },
      ),
    ]);
    return jsonResponse(
      { ok: false, error: `GitHub dispatch failed (${ghRes.status}): ${errText.slice(0, 200)}` },
      502,
    );
  }

  return jsonResponse({ ok: true, task_id: taskId, status: 'queued' }, 202);
}

async function handleResult(request, env, url) {
  if (!(await authorize(request, env.API_TOKEN))) {
    return jsonResponse({ ok: false, error: 'Unauthorized' }, 401);
  }
  const taskId = url.searchParams.get('task_id') || '';
  if (!isValidUuid(taskId)) {
    return jsonResponse({ ok: false, error: 'Invalid task_id' }, 400);
  }
  const raw = await env.PROBE_KV.get(`result:${taskId}`);
  if (!raw) {
    return jsonResponse({ ok: false, error: 'Task not found or expired' }, 404);
  }
  return new Response(raw, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

async function handleInternalPull(request, env, url) {
  if (!(await authorize(request, env.PULL_TOKEN))) {
    return jsonResponse({ ok: false, error: 'Unauthorized' }, 401);
  }
  const taskId = url.searchParams.get('task_id') || '';
  if (!isValidUuid(taskId)) {
    return jsonResponse({ ok: false, error: 'Invalid task_id' }, 400);
  }

  const payloadKey = `payload:${taskId}`;
  const cipher = await env.PROBE_KV.get(payloadKey);
  if (!cipher) {
    return jsonResponse({ ok: false, error: 'Payload not found or already consumed' }, 404);
  }

  // Burn after read so each task_id can only be pulled once.
  await env.PROBE_KV.delete(payloadKey);
  return jsonResponse({ ok: true, task_id: taskId, cipher }, 200);
}

async function handleInternalCallback(request, env) {
  if (!env.CALLBACK_SECRET) {
    return jsonResponse({ ok: false, error: 'Server misconfigured' }, 500);
  }

  const timestamp = request.headers.get('X-Timestamp') || '';
  const signature = request.headers.get('X-Signature') || '';
  const rawBody = await request.text();

  const valid = await hmacVerify(env.CALLBACK_SECRET, timestamp, rawBody, signature);
  if (!valid) {
    return jsonResponse({ ok: false, error: 'Invalid callback signature' }, 401);
  }

  let data;
  try {
    data = JSON.parse(rawBody);
  } catch {
    return jsonResponse({ ok: false, error: 'Invalid JSON body' }, 400);
  }

  if (!isValidUuid(data?.task_id)) {
    return jsonResponse({ ok: false, error: 'Invalid task_id' }, 400);
  }

  const status = data.status === 'error' ? 'error' : 'done';
  const record = {
    task_id: data.task_id,
    status,
    results: Array.isArray(data.results) ? data.results : [],
    error: data.error || undefined,
    duration_ms: typeof data.duration_ms === 'number' ? data.duration_ms : undefined,
    finished_at: Date.now(),
  };

  await env.PROBE_KV.put(`result:${data.task_id}`, JSON.stringify(record), {
    expirationTtl: RESULT_TTL_SEC,
  });

  return jsonResponse({ ok: true }, 200);
}

export function createWorker(fetchFn = globalThis.fetch.bind(globalThis)) {
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      const { pathname } = url;

      if (request.method === 'GET' && pathname === '/') {
        const html = env.API_TOKEN ? uiHtml : uiHtml
          .replace('id="submitBtn"', 'id="submitBtn" disabled')
          .replace('<span id="status" class="status"></span>', '<span id="status" class="status warn">尚未配置：请在 Cloudflare 的 Worker 设置 → Variables and Secrets 中添加 API_TOKEN，保存部署后刷新。</span>');
        return new Response(html, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        });
      }
      if (request.method === 'GET' && pathname === '/health') {
        return jsonResponse({ ok: true });
      }
      if (request.method === 'POST' && pathname === '/probe') {
        return handleProbe(request, env, fetchFn);
      }
      if (request.method === 'GET' && pathname === '/result') {
        return handleResult(request, env, url);
      }
      if (request.method === 'GET' && pathname === '/internal/pull') {
        return handleInternalPull(request, env, url);
      }
      if (request.method === 'POST' && pathname === '/internal/callback') {
        return handleInternalCallback(request, env);
      }
      return jsonResponse({ ok: false, error: 'Not Found' }, 404);
    },
  };
}

export default createWorker();
