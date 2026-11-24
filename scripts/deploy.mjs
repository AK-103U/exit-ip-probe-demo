import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

const ROOT_DIR = resolve(import.meta.dirname, '..');
const WRANGLER_BIN = resolve(ROOT_DIR, 'node_modules/wrangler/bin/wrangler.js');
const WRANGLER_CONFIG = resolve(ROOT_DIR, 'wrangler.jsonc');
const SECRETS_FILE = resolve(ROOT_DIR, '.deploy-secrets.json');
const DEV_VARS_FILE = resolve(ROOT_DIR, '.dev.vars');

export function parseGitHubRemote(remoteUrl) {
  if (typeof remoteUrl !== 'string') return null;
  const trimmed = remoteUrl.trim();
  const httpsMatch = trimmed.match(/^https?:\/\/github\.com\/([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i);
  if (httpsMatch) {
    return { owner: httpsMatch[1], repo: httpsMatch[2] };
  }
  const sshMatch = trimmed.match(/^(?:ssh:\/\/)?git@github\.com[:/]([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i);
  if (sshMatch) {
    return { owner: sshMatch[1], repo: sshMatch[2] };
  }
  return null;
}

export function extractWorkerUrl(output) {
  if (typeof output !== 'string') return null;
  const match = output.match(/https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.workers\.dev\b/i);
  return match ? match[0] : null;
}

export function stripJsonComments(input) {
  let out = '';
  let inString = false;
  let escaped = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const next = input[i + 1];

    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }

    if (ch === '/' && next === '/') {
      while (i < input.length && input[i] !== '\n') i++;
      if (i < input.length) out += '\n';
      continue;
    }

    if (ch === '/' && next === '*') {
      i += 2;
      while (i < input.length && !(input[i] === '*' && input[i + 1] === '/')) i++;
      i += 1;
      continue;
    }

    out += ch;
  }

  return out;
}

function runCommand(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    cwd: ROOT_DIR,
    encoding: 'utf8',
    stdio: opts.inherit ? 'inherit' : 'pipe',
    input: opts.input,
    env: opts.env || process.env,
  });
  return res;
}

function runWrangler(args, opts = {}) {
  if (existsSync(WRANGLER_BIN)) {
    return runCommand(process.execPath, [WRANGLER_BIN, ...args], opts);
  }
  const pnpmCmd = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
  return runCommand(pnpmCmd, ['exec', 'wrangler', ...args], opts);
}

function detectGitHubInfo() {
  const remoteRes = runCommand('git', ['remote', 'get-url', 'origin']);
  const branchRes = runCommand('git', ['branch', '--show-current']);
  const parsed = remoteRes.status === 0 ? parseGitHubRemote(remoteRes.stdout) : null;
  const branch = branchRes.status === 0 && branchRes.stdout.trim() ? branchRes.stdout.trim() : 'main';
  return {
    owner: parsed?.owner || null,
    repo: parsed?.repo || null,
    ref: branch,
  };
}

function syncWranglerVars(owner, repo, ref) {
  const raw = readFileSync(WRANGLER_CONFIG, 'utf8');
  const cfg = JSON.parse(stripJsonComments(raw));
  cfg.vars = cfg.vars || {};

  const nextOwner = owner || cfg.vars.GITHUB_OWNER;
  const nextRepo = repo || cfg.vars.GITHUB_REPO;
  const nextRef = ref || cfg.vars.GITHUB_REF || 'main';

  if (
    cfg.vars.GITHUB_OWNER === nextOwner &&
    cfg.vars.GITHUB_REPO === nextRepo &&
    cfg.vars.GITHUB_REF === nextRef
  ) {
    return { owner: nextOwner, repo: nextRepo, ref: nextRef };
  }

  cfg.vars.GITHUB_OWNER = nextOwner;
  cfg.vars.GITHUB_REPO = nextRepo;
  cfg.vars.GITHUB_REF = nextRef;
  writeFileSync(WRANGLER_CONFIG, `${JSON.stringify(cfg, null, 2)}\n`, 'utf8');
  return { owner: nextOwner, repo: nextRepo, ref: nextRef };
}

function loadOrCreateSecrets({ rotateSecrets }) {
  let existing = {};
  if (existsSync(SECRETS_FILE) && !rotateSecrets) {
    existing = JSON.parse(readFileSync(SECRETS_FILE, 'utf8'));
  }

  const secrets = {
    AES_KEY: existing.AES_KEY || randomBytes(32).toString('base64'),
    API_TOKEN: existing.API_TOKEN || randomBytes(24).toString('base64url'),
    PULL_TOKEN: existing.PULL_TOKEN || randomBytes(24).toString('base64url'),
    CALLBACK_SECRET: existing.CALLBACK_SECRET || randomBytes(32).toString('hex'),
    GITHUB_TOKEN: process.env.GITHUB_DISPATCH_TOKEN || existing.GITHUB_TOKEN || '',
  };

  return secrets;
}

function saveSecrets(secrets) {
  writeFileSync(SECRETS_FILE, `${JSON.stringify(secrets, null, 2)}\n`, { mode: 0o600 });
}

function writeDevVars(secrets) {
  const lines = [
    `API_TOKEN=${secrets.API_TOKEN}`,
    `PULL_TOKEN=${secrets.PULL_TOKEN}`,
    `CALLBACK_SECRET=${secrets.CALLBACK_SECRET}`,
    `AES_KEY=${secrets.AES_KEY}`,
    `GITHUB_TOKEN=${secrets.GITHUB_TOKEN}`,
  ];
  writeFileSync(DEV_VARS_FILE, `${lines.join('\n')}\n`, { mode: 0o600 });
}

async function promptText(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

function parseFlags(argv) {
  const flags = {
    dryRun: argv.includes('--dry-run'),
    rotateSecrets: argv.includes('--rotate-secrets'),
    writeDevVars: argv.includes('--write-dev-vars'),
    workerUrl: null,
  };
  const urlIdx = argv.indexOf('--worker-url');
  if (urlIdx !== -1 && argv[urlIdx + 1]) {
    flags.workerUrl = argv[urlIdx + 1].trim().replace(/\/$/, '');
  }
  return flags;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const gitInfo = detectGitHubInfo();
  const { owner, repo, ref } = syncWranglerVars(gitInfo.owner, gitInfo.repo, gitInfo.ref);

  if (!owner || !repo) {
    throw new Error('Could not detect GitHub owner/repo from git origin or wrangler.jsonc');
  }

  console.log(`[1/5] Target GitHub repo: ${owner}/${repo} (ref: ${ref})`);

  const secrets = loadOrCreateSecrets({ rotateSecrets: flags.rotateSecrets });

  if (flags.dryRun) {
    console.log('[dry-run] Validating Wrangler bundle...');
    const dryRes = runWrangler(['deploy', '--dry-run']);
    if (dryRes.status !== 0) {
      throw new Error(dryRes.stderr || dryRes.stdout || 'wrangler deploy --dry-run failed');
    }
    console.log('[dry-run] Passed. Would deploy Worker, bulk-upload 5 secrets, and sync 4 GitHub Secrets.');
    return;
  }

  console.log('[2/5] Checking Cloudflare & GitHub CLI auth...');
  let cfWhoami = runWrangler(['whoami']);
  if (cfWhoami.status !== 0) {
    console.log('Cloudflare not logged in. Launching `wrangler login`...');
    const loginRes = runWrangler(['login'], { inherit: true });
    if (loginRes.status !== 0) {
      throw new Error('Cloudflare login failed');
    }
    cfWhoami = runWrangler(['whoami']);
    if (cfWhoami.status !== 0) {
      throw new Error('Cloudflare authentication still unavailable after login');
    }
  }

  const ghAuth = runCommand('gh', ['auth', 'status']);
  if (ghAuth.status !== 0) {
    throw new Error('GitHub CLI not logged in. Run `gh auth login` first.');
  }

  if (!secrets.GITHUB_TOKEN) {
    console.log('');
    console.log(`Create a Fine-grained GitHub PAT for ${owner}/${repo} with permission: Actions (Read and write).`);
    console.log('URL: https://github.com/settings/personal-access-tokens/new');
    secrets.GITHUB_TOKEN = await promptText('Paste Fine-grained GITHUB_TOKEN (or set GITHUB_DISPATCH_TOKEN env): ');
    if (!secrets.GITHUB_TOKEN) {
      throw new Error('GITHUB_TOKEN is required to dispatch workflow_dispatch from Worker');
    }
  }

  saveSecrets(secrets);
  if (flags.writeDevVars) {
    writeDevVars(secrets);
  }

  console.log('[3/5] Deploying Worker & auto-provisioning PROBE_KV...');
  const deployRes = runWrangler(['deploy']);
  if (deployRes.stdout) process.stdout.write(deployRes.stdout);
  if (deployRes.stderr) process.stderr.write(deployRes.stderr);
  if (deployRes.status !== 0) {
    throw new Error('wrangler deploy failed');
  }

  let workerUrl = flags.workerUrl || extractWorkerUrl(`${deployRes.stdout || ''}\n${deployRes.stderr || ''}`);
  if (!workerUrl) {
    workerUrl = (await promptText('Enter deployed Worker URL (e.g. https://exit-ip-probe-demo.xxx.workers.dev): ')).replace(
      /\/$/,
      '',
    );
  }
  if (!workerUrl) {
    throw new Error('WORKER_URL is required for GitHub Runner callback');
  }

  console.log('[4/5] Uploading Worker secrets in one bulk request...');
  const bulkRes = runWrangler(['secret', 'bulk'], {
    input: JSON.stringify({
      API_TOKEN: secrets.API_TOKEN,
      PULL_TOKEN: secrets.PULL_TOKEN,
      CALLBACK_SECRET: secrets.CALLBACK_SECRET,
      AES_KEY: secrets.AES_KEY,
      GITHUB_TOKEN: secrets.GITHUB_TOKEN,
    }),
  });
  if (bulkRes.status !== 0) {
    throw new Error(bulkRes.stderr || bulkRes.stdout || 'wrangler secret bulk failed');
  }

  console.log(`[5/5] Syncing GitHub Actions secrets to ${owner}/${repo}...`);
  const ghSecrets = {
    AES_KEY: secrets.AES_KEY,
    PULL_TOKEN: secrets.PULL_TOKEN,
    CALLBACK_SECRET: secrets.CALLBACK_SECRET,
    WORKER_URL: workerUrl,
  };
  for (const [name, value] of Object.entries(ghSecrets)) {
    const setRes = runCommand('gh', ['secret', 'set', name, '-R', `${owner}/${repo}`], {
      input: value,
    });
    if (setRes.status !== 0) {
      throw new Error(`Failed to set GitHub secret ${name}: ${setRes.stderr || setRes.stdout}`);
    }
  }

  console.log('');
  console.log('Deployment complete!');
  console.log(`Worker URL : ${workerUrl}`);
  console.log(`API_TOKEN  : ${secrets.API_TOKEN}`);
  console.log(`Local copy : ${SECRETS_FILE} (gitignored)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`Deploy failed: ${err.message}`);
    process.exit(1);
  });
}
