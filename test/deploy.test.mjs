import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { extractWorkerUrl, parseGitHubRemote, stripJsonComments } from '../scripts/deploy.mjs';

const execFileAsync = promisify(execFile);

test('parseGitHubRemote supports HTTPS and SSH GitHub URLs', () => {
  assert.deepEqual(parseGitHubRemote('https://github.com/AK-103U/exit-ip-probe-demo.git'), {
    owner: 'AK-103U',
    repo: 'exit-ip-probe-demo',
  });
  assert.deepEqual(parseGitHubRemote('https://github.com/AK-103U/exit-ip-probe-demo/'), {
    owner: 'AK-103U',
    repo: 'exit-ip-probe-demo',
  });
  assert.deepEqual(parseGitHubRemote('git@github.com:AK-103U/exit-ip-probe-demo.git'), {
    owner: 'AK-103U',
    repo: 'exit-ip-probe-demo',
  });
  assert.equal(parseGitHubRemote('https://example.com/foo/bar'), null);
});

test('extractWorkerUrl extracts deployed workers.dev URL', () => {
  const sample = `
Uploaded exit-ip-probe-demo (1.23 sec)
Published exit-ip-probe-demo (0.45 sec)
  https://exit-ip-probe-demo.my-subdomain.workers.dev
Current Deployment ID: abc
`;
  assert.equal(extractWorkerUrl(sample), 'https://exit-ip-probe-demo.my-subdomain.workers.dev');
  assert.equal(extractWorkerUrl('no url here'), null);
});

test('stripJsonComments preserves URLs inside strings while removing comments', () => {
  const raw = `{
    // line comment
    "url": "https://example.com//path",
    /* block comment */
    "ok": true
  }`;
  assert.deepEqual(JSON.parse(stripJsonComments(raw)), {
    url: 'https://example.com//path',
    ok: true,
  });
});

test('scripts/deploy.mjs --dry-run succeeds', async () => {
  const { stdout } = await execFileAsync(process.execPath, ['scripts/deploy.mjs', '--dry-run']);
  assert.match(stdout, /\[dry-run\] Passed/);
});
