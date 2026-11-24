# 节点落地 IP 探测 Demo（CF Worker + Public GitHub Actions）

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/AK-103U/exit-ip-probe-demo)

## 目录结构

- `worker/`：Cloudflare Worker 控制面与单页前端 (`index.mjs`, `ui.html`)
- `runner/`：GitHub Actions 执行端解析与 `sing-box` 探测脚本 (`parser.mjs`, `probe.mjs`)
- `shared/`：两端共用的 Web Crypto（AES-256-GCM / HMAC-SHA256）与基础校验
- `.github/workflows/probe.yml`：仅支持 `workflow_dispatch(task_id)` 的公开仓库探测工作流
- `.github/workflows/deploy-worker.yml`：可选 Worker CI/CD 自动部署工作流
- `scripts/deploy.mjs`：一条命令全自动闭环部署脚本（KV 自动编排 + 批量密钥 + 同步 GitHub Secrets）
- `scripts/gen-secrets.mjs`：生成随机密钥

---

## 一键部署方案（三选一）

### 方案 A：一条命令全自动闭环部署（最推荐，自动打通 Worker 与 GitHub Secrets）

脚本会自动完成：
1. 读取 Git `origin` 识别仓库并更新 [wrangler.jsonc](wrangler.jsonc)
2. 首次部署自动创建并绑定 `PROBE_KV`（无需手动 `kv namespace create`）
3. 自动生成密钥并通过 `wrangler secret bulk` 一次性上传 5 个 Worker Secrets
4. 自动提取部署后的 `WORKER_URL` 并通过 `gh secret set` 同步写入 GitHub Actions Secrets

运行前仅需在 GitHub 申请一个仅授权本仓库 `Actions: Read and write` 的 Fine-grained PAT，然后执行：

```bash
pnpm install
pnpm run deploy:all
```

> 重复运行 `pnpm run deploy:all` 会自动复用本地 `.deploy-secrets.json`（已加入 `.gitignore`），不会重置现有密钥；如需轮换密钥可加 `--rotate-secrets`。

---

### 方案 B：网页一键部署（Deploy to Cloudflare 按钮）

点击上方 **Deploy to Cloudflare** 按钮后，Cloudflare 会自动：
1. 克隆仓库到你的 GitHub 账号；
2. 依据 [wrangler.jsonc](wrangler.jsonc) 自动创建 `PROBE_KV`；
3. 依据 [.dev.vars.example](.dev.vars.example) 与 [package.json](package.json) 弹出网页表单让你填写 5 个 Secrets 并完成部署。

部署成功后，回到克隆出来的 GitHub 仓库 **Settings → Secrets and variables → Actions**，补充写入 4 个同名 Secrets 即可联通回调：
- `AES_KEY`（与 Worker 中相同）
- `PULL_TOKEN`（与 Worker 中相同）
- `CALLBACK_SECRET`（与 Worker 中相同）
- `WORKER_URL`（部署得到的 `https://*.workers.dev` 地址）

---

### 方案 C：GitHub Actions 自动持续部署 Worker

如果希望后续修改 `worker/` 或 `shared/` 后推送 `main` 自动更新线上 Worker，只需在仓库 Actions Secrets 额外配置 `CLOUDFLARE_API_TOKEN`（如账户下有多个 Account 再加 `CLOUDFLARE_ACCOUNT_ID`），[.github/workflows/deploy-worker.yml](.github/workflows/deploy-worker.yml) 会自动触发部署。

---

## 本地开发与测试

```bash
pnpm install
pnpm test
pnpm run dev
```
