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

点击 **Deploy to Cloudflare**，选择目标仓库和 Worker，确认 `GITHUB_OWNER` 与 `GITHUB_REPO` 指向自己的仓库即可部署。`PROBE_KV` 自动绑定，无需在部署表单里填写密钥。此时首页可预览，尚不能提交探测任务。

首次使用时，由仓库所有者完成配置：

1. 在本地执行 `pnpm run gen-secrets`，生成 `API_TOKEN`、`AES_KEY`、`PULL_TOKEN`、`CALLBACK_SECRET`。不要把生成的值提交到仓库。
2. 在 **Cloudflare → Workers & Pages → 该 Worker → Settings → Variables and Secrets** 中将这四项添加为 Secret，再添加 `GITHUB_TOKEN`（仅目标仓库的 Fine-grained PAT，权限为 Actions: Read and write），保存并部署。`API_TOKEN` 是探测页面使用的访问密码，不是 Cloudflare 账户令牌。
3. 在目标 GitHub 仓库 **Settings → Secrets and variables → Actions** 配置以下四项：
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

---

## 输入格式

- Clash YAML：完整配置（含 `proxies:`）、节点列表，或单行 `- { name: ..., type: ... }`。直接从 `proxies:` 下复制的带缩进内容可以原样粘贴。
- 分享链接：`hysteria2://` / `hy2://` / `vless://` / `vmess://` / `trojan://` / `ss://` / `tuic://`，每行一个；也支持 Base64 订阅正文。
- ECH：支持 Clash `ech-opts: { enable, config, query-server-name }` 和分享链接的 `ech=` 参数。未内置 `config` 时，Runner 会通过 DoH（Cloudflare，失败时改用 Google）查询 HTTPS 记录拿到 ECH 配置再交给 sing-box，不依赖 Runner 系统解析器。REALITY 节点会忽略 ECH。
- 前置节点（链式代理）：在节点上加 mihomo 的 `dialer-proxy: <前置节点名>`，前置节点也要写在同一次输入里，Runner 会把它映射为 sing-box 的 `detour`，最多支持 3 层。适用于 Runner 直连不通的入口，例如只有 IPv6 的入口（GitHub Runner 没有 IPv6）、只放行特定来源 IP 的入口。结果中的 `via` 字段是前置节点名；前置节点不存在或链路成环时，报 `chain_invalid`。

## 探测结果

每个节点会分别探测 **IPv4 出口**、**IPv6 出口**和**双栈默认出口**，三项都经节点隧道发出请求：

- 主力：[ippure](https://my.ippure.com/v1/info)。一次请求就能拿到落地 IP、归属地、ASN，以及风险分（`fraud_score`）、是否住宅 IP（`residential`）、是否广播 IP（`broadcast`）。ippure 是双栈域名，所以 Runner 会先解析出它的 A/AAAA 地址，再用 `curl --connect-to` 强制走 IPv4 或 IPv6。
- 备用：Cloudflare `cdn-cgi/trace`（`1.1.1.1` / `2606:4700:4700::1111` / `www.cloudflare.com`），然后是 ipify。
- 入口 IP 的归属，以及落地 IP 的机房/代理/移动网络标记，由 Runner 直接按确切 IP 查询：主源为 ip-api 批量接口，失败时改用 ipwho.is。归属信息总是对应显示的那个 IP，落地的位置和 ASN 以 ippure 为准。

| 字段 | 含义 |
| :--- | :--- |
| `ipv4` / `ipv6` | 各协议族的出口 IP、国家/城市、ISP、ASN；`fraud_score` / `residential` / `broadcast`（来自 ippure）；`hosting`（机房 IP）、`warp`（经 Cloudflare WARP 出口）、`same_as_entry`；`source` 表示 IP 来自哪个查询源 |
| `preferred` | 访问双栈网站时节点优先使用的协议族 |
| `entry.ips` / `relation` | 入口解析结果与出入口关系：`direct`（入口即落地）、`same_network`（同 ASN 不同 IP）、`relay`（中转/分离出口）、`cdn`（入口为 CDN 边缘，包括 ASN 不属于 Cloudflare、但由 Cloudflare 边缘应答的“优选 IP”，此时 `entry.cdn_edge` 为 `cloudflare`） |
| `error_code` / `error` / `detail` | 失败原因分类、中文说明，以及脱敏后的内核或 curl 报错（已去除服务器地址、SNI、密码、UUID 等） |
| `family_errors` | 节点可用但某一协议族失败时的原因（如没有 IPv6 出口） |
| `timings` | 内核就绪耗时，以及各协议族的探测耗时 |

常见 `error_code`：`handshake_timeout`（QUIC 无回应，常见于节点屏蔽境外机房 IP）、`auth_failed`、`tls_error` / `ech_rejected`、`reality_failed`、`connect_timeout`、`connection_refused`、`runner_no_ipv6`（GitHub Runner 没有 IPv6，无法连接仅 IPv6 入口的节点）、`core_start_failed`。

任务状态依次为 `queued` → `running`（Runner 已领取，附 `run_url`）→ `done` / `error`。公开的 Actions 日志只输出节点数量、成功数和错误码计数，不包含节点名、地址或 IP。
