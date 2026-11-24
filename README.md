# 节点落地 IP 探测 Demo（CF Worker + Public GitHub Actions）

## 目录结构

- `worker/`：Cloudflare Worker 控制面与单页前端 (`index.mjs`, `ui.html`)
- `runner/`：GitHub Actions 执行端解析与 `sing-box` 探测脚本 (`parser.mjs`, `probe.mjs`)
- `shared/`：两端共用的 Web Crypto（AES-256-GCM / HMAC-SHA256）与基础校验
- `.github/workflows/probe.yml`：仅支持 `workflow_dispatch(task_id)` 的公开仓库工作流
- `scripts/gen-secrets.mjs`：生成部署所需随机密钥

## 本地运行测试

```bash
pnpm install
pnpm test
pnpm run gen-secrets
```

## 部署步骤

### 1. 生成密钥

```bash
pnpm run gen-secrets
```

记下输出的 `AES_KEY`、`API_TOKEN`、`PULL_TOKEN`、`CALLBACK_SECRET`。

### 2. 创建并推送公开 GitHub 仓库

1. 在 GitHub 创建一个 **Public** 仓库（如 `exit-ip-probe`），将本目录代码推送到 `main` 分支。
2. 在仓库 **Settings → Secrets and variables → Actions** 中添加以下 4 个 Secrets（`WORKER_URL` 在部署完 Worker 后填入）：
   - `AES_KEY`
   - `PULL_TOKEN`
   - `CALLBACK_SECRET`
   - `WORKER_URL`（例如 `https://exit-ip-probe-demo.<subdomain>.workers.dev`）
3. 在 GitHub 申请一个 **Fine-grained Personal Access Token**：
   - Repository access：仅勾选该仓库
   - Permissions：`Actions` → **Read and write**

### 3. 部署 Cloudflare Worker

1. 登录 Wrangler 并创建 KV Namespace：
   ```bash
   pnpm exec wrangler login
   pnpm exec wrangler kv namespace create PROBE_KV
   ```
2. 将返回的 KV `id`、以及 `GITHUB_OWNER` / `GITHUB_REPO` 填入 `wrangler.toml`。
3. 写入 Worker Secrets 并部署：
   ```bash
   pnpm exec wrangler secret put API_TOKEN
   pnpm exec wrangler secret put PULL_TOKEN
   pnpm exec wrangler secret put CALLBACK_SECRET
   pnpm exec wrangler secret put AES_KEY
   pnpm exec wrangler secret put GITHUB_TOKEN
   pnpm run deploy
   ```
4. 部署完成后，将得到的 `https://*.workers.dev` 地址填入 GitHub 仓库 Secrets 的 `WORKER_URL`。
