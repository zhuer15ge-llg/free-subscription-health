# 自动筛选免费节点订阅

Cloudflare Workers 负责收集、转换和提供订阅。GitHub Actions 独立检测节点。
客户端直接连接免费节点；Cloudflare 和 GitHub 均不承载用户上网流量。

## 检测和发布

1. 十四个公开源每 30 分钟更新，严格解析、跨源去重和轮流取样，每轮最多 1000 个候选。
   七个日更网站每轮重新读取最新文章或复制按钮中的地址，合并同篇文章的所有 TXT 订阅。
   最新文章不可用时尝试上一篇；单站故障不影响其它站点。原有源最多取 80 个兼容节点，
   日更源合并后最多取 500 个，避免一个大型合集占满检测资源。
   Actions 同时从自身网络读取七个日更源，作为 Cloudflare 出口读取失败时的备用。
   备用只提交原生 URI，Worker 再解析、去重，仍须逐节点通过 HTTPS 检测后才发布。
   FreeV2 短暂故障时可复用最近两小时读取成功的源文件；缓存不续期，节点仍逐轮重测。
2. GitHub Actions 计划在每小时第 17、47 分钟运行，也可手动触发。
3. 使用固定版本且校验 SHA-256 的 Mihomo，每个节点独立绑定临时 loopback 监听器。
   不开 TUN，不修改系统代理，没有 DIRECT 回退。
4. 每个节点必须通过 `https://1.1.1.1/cdn-cgi/trace` 和
   `https://www.google.com/generate_204` 两项测试：TLS 证书有效，状态和内容符合预期。
   单纯 TCP 端口可连接不算通过。
5. 报告必须完整覆盖对应候选批次；Worker 只发布其中通过项，同时更新四种格式。
6. 结果有效期为检测结束后 2 小时。过期、未检测或零通过时，订阅返回 HTTP 503，
   不退回未检测节点。源刷新失败或检测器故障不会覆盖尚在有效期内的上一份结果。

检测代表 GitHub 网络当时的连通性，无法保证用户所在网络也能连接。
客户端仍会每五分钟测试自动选择组。需要更新订阅才能取得剔除后的列表；
Worker 无法远程删除客户端已缓存的配置。节点可能在两轮检测之间失效。

## 十四个公开源

- [Nodes Radar](https://github.com/nodesradar/nodesradar-en)
- [Au1rxx](https://github.com/Au1rxx/free-vpn-subscriptions)
- [Pawdroid](https://github.com/Pawdroid/Free-servers)
- [Epodonios](https://github.com/Epodonios/v2ray-configs)
- [Eternity](https://github.com/mahdibland/V2RayAggregator)
- [OpenProxyList](https://github.com/roosterkid/openproxylist)
- [Igareck](https://github.com/igareck/vpn-configs-for-russia)
- [米贝分享](https://www.mibei77.com/category/jiedian)：最新文章中的原生 TXT 订阅
- [HiddifyNext](https://hiddify-next-node.github.io/)：最新文章中的全部 TXT 链接
- [FreeClashNode](https://www.freeclashnode.com/free-node/)：最新文章中的全部 TXT 链接
- [大翻墙运动](https://end-gfw.com/#free)：首页公开的通用订阅
- [V2rayDog](https://v2raydog.com/)：最新每日文章中的 TXT 订阅
- [长风分享](https://www.cfmem.com/search/label/%E5%85%8D%E8%B4%B9%E8%8A%82%E7%82%B9)：当前免费节点分类的最新文章，提取 Nodebuf 原生 V2Ray 订阅
- [FreeV2](https://b.freev2.net/)：每日重新读取公开复制按钮，适配地址轮换

`source-loader.mjs` 只允许各站已确认的文章路径和订阅域名，最多读取 45 个响应。
每个来源整体限时 45 秒，每个响应最多 4 MiB。不执行页面脚本，不跟随任意重定向，
不抓取广告、赞助服务或上游路由规则。来源更换域名或页面结构时会显示失败并等待维护。

2026-10-27：暂停下发 Igareck 来源的 Trojan 节点，因用户本地实际代理连接反复重置或超时。
源仍保留，其它协议可参与筛选；其它来源的 Trojan 不受此规则影响。
Trojan WebSocket 未指定 Host 时显式补入 SNI/peer/服务器名，使 Mihomo、sing-box 和原生 URI 一致。

2026-10-30：按用户提供的本地不可用列表，屏蔽 258 个精确“协议＋主机＋端口”端点，
并记录 285 个节点 ID。该规则跨来源、名称和凭据变化生效，不封禁整个来源或网段。
当前缓存订阅在读取时同步过滤，保留原始检测时间；旧批次的迟到检测报告也不能重新
发布已屏蔽端点。`health.policyBlockedCount` 记录政策排除数量，包含在拒绝计数中。
名单位于 `src/block-policy.mjs`，只含端点和 ID，不含节点密码或完整 URI。

精确地址见 `src/free-sources.mjs`。仅提取公开 URI，不执行上游脚本，不导入其
DNS、路由或程序。支持 SS、VMess、VLESS、Trojan、Hysteria2；拒绝不支持的参数、
关闭证书验证的配置及非公网字面地址。国家名称显示中文，未知位置标为“未标注”。

## GitHub Actions 部署

将本目录的 `src/`、`test/`、`checker/`、`.github/`、`package.json` 和 README
放到专用仓库默认分支。不要上传部署凭据、原始源样本或本地生成的订阅。
添加 Actions Secrets：

| Secret | 内容 |
|---|---|
| `SUBSCRIPTION_ORIGIN` | Worker HTTPS 域名，不含路径、token 或查询参数 |
| `SUBSCRIPTION_ADMIN_TOKEN` | Worker 管理密钥；不是 Cloudflare API 令牌或登录密码 |

工作流使用标准 `ubuntu-24.04` runner，最大 18 分钟；并发组只允许一轮检测执行。
Mihomo v1.19.33 下载包摘要固定在 `checker/install-core.mjs`。
临时配置执行后删除，日志只输出计数，不打印节点凭据。
首次部署后手动运行 “Check subscription nodes” 并确认成功。

公开仓库使用标准托管 runner 免费；私有仓库受账户免费分钟额度限制，较大的 runner
收费。见 [GitHub 计费说明](https://docs.github.com/en/billing/concepts/product-billing/github-actions#free-use-of-github-actions)。
定时任务可能延迟或丢弃；公开仓库 60 天无仓库活动可能停用定时工作流，可在 Actions
页面重新启用。不能保证永久无人值守。见 [Schedule 官方说明](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)。

## Worker 接口与部署

原域名、登录密码和订阅 token 保留。Cloudflare Cron 只生成待检测候选。
Worker 不导入 socket 或代理转发模块；订阅请求只读取 KV。

| 接口 | 用途 |
|---|---|
| `/login`、`/`、`/logout` | 登录和带检测状态的管理页 |
| `/healthz` | 公开状态，`trafficRelay: false` |
| `/sub/mihomo.yaml` | 完整 Mihomo 配置 |
| `/sub/provider.yaml` | Mihomo 节点集合 |
| `/sub/karing.json` | 标准 sing-box outbounds |
| `/sub/v2rayn.txt` | 通用 Base64 URI |
| `/sub/v2rayn.yaml` | 兼容原有 Mihomo YAML 地址 |
| `/api/status` | 来源、检测时间和计数；过期也能查询 |
| `/api/nodes` | 当前有效节点无凭据元数据 |
| `POST /admin/refresh` | 生成候选批次 |
| `GET /admin/candidates` | 检测器读取候选连接配置 |
| `POST /admin/check-results` | 提交完整结果并发布通过项 |

订阅需要订阅 token；管理接口只接受管理 Bearer token。候选批次保留 4 小时。
报告最多距今 30 分钟，旧批次/旧报告不能覆盖更新结果。KV 最终一致，跨地区可能
短暂读到上一份结果；每次读取都检查有效期。不要额外启动并发结果写入器。

使用 `wrangler.jsonc` 或 Cloudflare API 部署，保留 `STORE` KV 绑定及
`SUB_TOKEN`、`ADMIN_TOKEN`、`LOGIN_PASSWORD` 三个 secrets。
HTML 必须保留 same-origin referrer，保证自定义域名表单登录正常。无需付费计划。

## 验证

Node.js 22，无 npm 运行时依赖：`node --test test/*.test.mjs`。
测试覆盖解析、密钥校验、完整报告校验、格式一致性、失败剔除、过期 503、认证及登录。
实际探测需要 Mihomo 和 curl。本地报告必须标为 `local-windows`，不冒充 GitHub 结果。
旧 `converter.mjs`、`karing.mjs` 仅保留历史测试；生产入口不再使用 VPN Gate/OpenVPN。
