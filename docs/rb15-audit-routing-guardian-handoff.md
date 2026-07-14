# codex2api rb15 审计、CYB 路由与 Guardian 交接基线

更新时间：2026-07-15 02:52 +08:00

用途：供新的 Codex 开发任务继续工作。本文是决策与验收基线，不替代生产实时核验。

开发分支：`feat/rb15-audit-routing-guardian`

独立工作树：`/root/codex2api-wt-rb15-audit-routing`

基线提交：`d7b44d90323fafa3144f877b873df35bcef09965`

## 一、权威位置与当前生产基线

- codex2api 正式生产源码仍为 s12 `/root/codex2api-src`，分支 `s12-production`。
- 本轮开发只能在独立工作树 `/root/codex2api-wt-rb15-audit-routing` 进行；验证完成后再按安全发版流程合入生产分支。
- 当前生产 tag：`s12-v2.5.4-rb14-controller1-20260714`。
- 当前生产容器镜像 ID：`sha256:032faaa1a970c3b5f8f8cdb00d68f6e9a2c03ae0268c14df563257c089b46ef6`；controller1 只更新控制器脚本，codex2api 镜像仍为 rb14。
- 2026-07-15 02:47 实时状态：`/health=ok`，容器 running、restart count 0；Relay group 3 配置/启用/正常可调度均为 4，effective slots 3998，suspect/open/quarantine/probation/degraded 均为 0。
- sub2 bridge 账号 7692 `codex2api-pro` 当前 `active + schedulable`；故障转移 timer active。
- 所有服务、DB、容器、账号和配置状态都易变化。新任务和每次发版前必须重新实时核验，不得把本文快照当现状。

## 二、已经确认且必须保留的架构决定

### 2.1 审核与路由边界

- sub2 的 Omni/审核已经由用户配置好，本项目不修改 sub2 配置，也不修改 sub2 源码。
- codex2api 旧版语义审核与二次审核保持下线/关闭：`CODEX_SEMANTIC_REVIEW_ENABLED=false`；不得为本轮修复恢复旧语义判官。
- codex2api 本地规则只做监控与 Relay 路由，不在 codex2api 本地拦截用户请求。
- 路由判断必须覆盖完整请求：system、instructions、skills、tools 与用户输入都不能整体排除，因为它们也可能让 OAuth 上游返回 `cyber_policy`。
- 同时必须防止超大 system/tools 信封挤占用户输入扫描预算。完整 payload 检查继续保留，并增加字段/角色感知的独立有界扫描，而不是简单降低全局阈值。
- 探针不再本地短路，探针请求统一进入 Relay 路由。审计页只保留顶部探针数值，不恢复旧探针行为列表。
- 当前系统无法判断“真实 CYB”本质，只能判断路由证据和上游实际结果。运营目标是避免受保护 OAuth 承受任何 `cyber_policy`，包括上游误判。

### 2.2 会话、缓存与归属

- 禁止恢复内容派生 pin、Bearer/API key 派生 scheduler pin 或 Idempotency-Key pin。
- scheduler affinity 仅允许明确身份：哈希后的 `X-Codex2API-Affinity-Key` 或现有明确 session/conversation 标识。
- `previous_response_id` 与有效 `encrypted_content` 属于不透明上游状态，必须保持原账号归属；不得复制、伪造或跨账号复用 encrypted content。
- 有效 encrypted content 必须字节级透传；无法安全恢复时删除整个无效顶层 item 或仅保留可恢复文本，绝不能留下缺少 `encrypted_content` 的空壳。
- close 1009 的 WS→同账号 HTTP fallback、单次 lease/permit 转移、累计延迟与 attempt 审计语义必须保留。
- 最终用户可见 canonical row 是业务权威；hidden attempt、重试和 `guardian_attempt_only` 只能作为尝试链路证据，不能成为独立业务请求。

### 2.3 Relay 调度与熔断

- Relay 前门账号 ID 和数量会变化，禁止把 50/51/53/55/156 等账号 ID 写死在业务逻辑。
- API KEY/Responses 账号默认并发为 100，可配置至 10000；OAuth 上限保持官方边界。不得再次把 API KEY 账号默认并发降成 50。
- 单个 502/504/Cloudflare/transport 错误只能使前门进入 `suspect`，不能一次摘除整个 Relay 前门。
- 状态链保持 `closed -> suspect -> open -> probation`；真正 open 要求独立确认；最后一个可用 Relay 路径必须通过 `last_resort` 保留有限容量。
- 同一逻辑请求不能重试已经失败的同一 Relay 前门；一旦下游开始输出，禁止跨账号重放。
- sub2 备用接管要依据 canonical 最终 `relay_route_unavailable`、稳定容量和用户可见失败，不得被 nominal half-open、Guardian 探针或已被重试吸收的失败误导。

### 2.4 sub2 codex-pro 安全边界

- 主 bridge 账号为当前运行配置指定的 7692 `codex2api-pro`，但账号 ID 必须是运行配置而不是源码默认常量；未来账号可能替换。
- 自动化和 Guardian 严禁主动关闭、暂停或切换 7692；7692 的健康状态由 sub2 自己管理。
- 只允许修改同组其他 `active`、未删除账号的 `schedulable`；严禁把 inactive/error/deleted 账号恢复成 active。
- 维护 codex2api 时，必须先打开并验证合格备用账号，再对 7692 执行维护 drain；服务恢复和 7692 健康后才能关闭备用。
- Relay 池无实际可用容量时，故障转移控制器应打开合格备用；Relay 与主 bridge 恢复后，才可将备用改回不可调度。
- 打开备用必须 fail-closed 验证 DB 与各 ready scheduler projection；关闭备用要防止陈旧 outbox/cache 成为假阳性，但不得牺牲打开安全。

### 2.5 版本与官方合并

- 保留官方 upstream ancestry；冲突按语义合并，禁止整文件 `ours/theirs` 覆盖。
- 自定义版本号使用 semver build metadata（如 `v2.5.4+rbXX`），避免后台错误显示官方更新标志，同时仍能识别未来新官方版本。
- 每次发版必须先 commit、push，再 build；不得从未提交的生产工作区构建。
- 发版前准备镜像与 compose 回滚锚点，使用安全维护流程，并验证备用已经可用、健康端点正常、7692 由维护流程恢复。

## 三、审计页既有权威口径

- 页面右上时间筛选必须作用于 KPI、趋势、案卷、路由信号、账号统计和 Guardian 事件。
- Relay 路由案卷与 Guardian 事件均使用服务端分页；Guardian 页大小支持 1 与 5。
- OAuth 漏放只统计实际由受保护 OAuth 发起、最终返回精确 `upstream_error_kind='cyber_policy'` 的 canonical 业务请求。
- Relay 账号返回的 `cyber_policy` 只能进入 Relay CYB/供应商质量统计，绝不能计入 OAuth 漏放。
- `guardian_attempt_only`、探针、hidden retry 和被后续成功吸收的失败不得污染业务 KPI。
- route/account/pin 的最终权威来自 canonical `usage_logs`；prompt filter 只用于同一 `logical_request_id` 的文本和分类补充，不能覆盖最终路由或账号元数据。
- 审计字段必须保留 `route_signals`、`pin_kind`、本轮直接命中/历史归属、账号类型和真实入站/上游端点。

## 四、本轮已批准开发的缺陷与需求

### 4.1 删除错误的时间近邻“归属富化”

已确认生产存在未纳入 Git 的 `/root/codex2api-src/scripts/enrich_misses.py`，由 `codex2api-miss-enrich.timer` 每 3 分钟执行。它把推测的归属块永久写回 `prompt_filter_logs.full_text/text_preview`，存在系统性错误：

- 池子账号只按任意 cyber usage 的时间 ±4 秒取最近值，不使用 `logical_request_id`、账号类型或路由归属。
- sub2 用户只按 bridge 7692、模型和时间 ±4 秒猜测；高并发时可串用户。
- 所有 `source=upstream_cyber_policy` 都被写成“真漏放”，包括 Relay CYB 和无法确认内容性质的上游误判。
- 一旦写错，幂等条件阻止后续纠正。
- 脚本被 Git 忽略，不受正式测试和发版约束。

开发要求：

1. 停止使用和部署该 timer/script；不得继续向 prompt 原文写入推测字段。
2. 案卷以 canonical usage 为权威，通过 `logical_request_id` 精确关联 prompt；账号必须结构化 JOIN accounts。
3. sub2 用户若无可验证的共享 request ID，只能明确显示“未确认/多候选”，不能把时间近邻猜测当事实。
4. 设计一次性、可审计的数据修复：只移除脚本插入的 `【归属】`/`『sub2:...』` 前缀，不破坏原始脱敏请求正文；修复前备份并先做 dry-run 对账。
5. 历史案卷重新以 usage 结构化数据生成，不依赖已污染正文。

### 4.2 OAuth/Relay CYB 案卷统一为 canonical logical request

当前问题：顶部数字来自 `usage_logs` attempt rollup，案卷正文来自逐事件 `prompt_filter_logs`，前端主数字硬编码为“上游尝试”；同一逻辑请求多次 attempt 时会口径分裂。

开发要求：

- 主数显示 canonical 逻辑请求数；副数显示 OAuth/Relay 上游 `cyber_policy` 尝试次数。
- 案卷按 `logical_request_id` 合并为一案，内部展示 attempt timeline；无 logical ID 的 legacy 才按单行。
- OAuth/Relay 案卷都改为服务端分页。
- 后端结构化返回 account name/type、route class/source/signals、pin kind、inbound endpoint、upstream endpoint、final status 与 attempts。
- 页面不得再用正文内人工拼接的“池子账号”作为真实账号。

### 4.3 两次确定性 SQL 注入路由漏放

2026-07-14 17:57 的同一 Node 安全测试脚本发送了 4 个独立逻辑请求。请求要求编写可提取 PostgreSQL 首个用户密码的 SQL injection PoC。

- 本地规则全部识别：`operational_exploit_request=45`、`sql_injection_attack=40`、`generic_exploit=10`，总分 95。
- 当前阈值为 100，因此没有 risk route。
- 2 次因 OAuth 无槽位偶然 overflow 到 Relay；另外 2 次落在 OAuth 账号 54 与 1，均被上游 `cyber_policy` 拦截。
- 这两条是真正的路由漏放，不是 Guardian 探针、服务端重试或案卷重复。

开发要求：增加精确的“SQL 注入 + 凭据/密码提取或数据外传意图”组合 Relay 路由规则，并给出独立 route signal。不得把全局阈值从 100 粗暴降至 95，避免扩大正常技术请求误路由。

### 4.4 超大请求字段感知扫描

2026-07-14 21:01 的 OAuth `cyber_policy` 请求约 765,120 字节；本地完整扫描预算约 81,920，审计持久化预览约 32,000。页面只展示 system/tools 截断片段，不能证明具体触发句；本地只命中 `generic_exploit=10`。

开发要求：

- 保留全 payload 路由判断原则。
- 对 instructions/system、tools/skills、当前用户可见输入分别分配独立、有总上限的扫描预算；用户输入 rescue 不得被巨大工具说明挤掉。
- 跳过不可读 opaque encrypted/tool blob，但不得伪造或解密内容。
- 审计明确标注 `payload_bytes`、`scanned_bytes`、各分区扫描/截断状态和命中分区，避免把 32K 预览误解成完整请求。
- 不能仅凭截断预览把该事件标成“真实恶意 CYB”；运营分类应区分“OAuth 上游 cyber_policy 保护漏放”和“内容性质已确认”。

### 4.5 数据与文案修正

- 删除“所有 upstream cyber_policy 都是真漏放(上游拦→账号风险)”的错误标签。
- 文案区分：OAuth 保护漏放、Relay 供应商 CYB、内容性质未确认、确定性高风险路由漏放。
- 账号显示使用实时/结构化名称，改名后跟随更新；历史物理删除账号可使用安全快照名。
- 案卷说明保持简洁，但关键口径必须可见：逻辑请求、尝试次数、最终账号、是否重试、是否截断。

## 五、Guardian 正式启用是未完成里程碑

### 5.1 当前状态

- 2026-07-15 02:47 实时确认：Guardian persisted/runtime 均为 `monitor`，status `ok`。
- rb14 自 2026-07-14 09:35:10 上线至 2026-07-15 02:45 共记录 185 个 summary、17 个 hourly audit、11 个 `would_quarantine` 影子事件。
- 影子事件涉及动态账号 156、51、50；shadow action 包括 `last_resort` 与 `pool_alert`。monitor 模式没有实际隔离。
- 这些事件尚未逐案完成 canonical replay，不能据此断言全部正确或错误，因此当前不允许直接切 `enforce`。

### 5.2 启用顺序与验收门槛

1. 本轮审计/CYB 路由修复发版时继续保持 `monitor`，严禁夹带 `enforce`。
2. 从新版本成功上线、无重启且关键 Guardian/Relay 配置稳定的时间开始，重新完成至少 24 小时 monitor soak；进程重启、group membership/identity 或关键配置变化后重新计时。
3. 对 soak 内全部 `would_quarantine`/pool-wide 事件逐案回放 canonical final 与 attempt timeline，确认：
   - 没有把 hidden/Guardian/retry-absorbed 失败当用户可见失败；
   - 没有因单次 502 或陈旧并发失败隔离整个健康前门；
   - 替代 peer 有近期 canonical 非探针成功；
   - last-resort 与 pool guard 在容量边界下正确保活；
   - 账号名称变化与动态 membership 不串状态。
4. 验证 `/health`、Relay 实际容量、最终 5xx/route unavailable、sub2 备用接管、7692 状态和控制器收敛均正常。
5. 只有上述证据通过，才在一个独立、可回退的运营变更中把 Guardian 切换为 `enforce`；不得与代码发版同时进行。
6. 切换后至少持续观察 2 小时。出现健康主力误隔离、Relay 正常容量归零、`relay_route_unavailable`/最终 5xx 明显上升、sub2 备用未按预期打开或任何 7692 非授权调度变更，立即恢复 `monitor` 并留存证据。

### 5.3 完成定义

本轮开发不能在“代码已发版”时标记整体完成。只有以下二者之一成立，Guardian 里程碑才算关闭：

- 证据通过并已单独启用 `enforce`，完成至少 2 小时观察；或
- 证据明确证明当前设计仍不安全，保持 `monitor`，记录具体阻断原因和下一轮修复计划，并由用户确认延期。

## 六、验证、发版与回滚最低标准

- 后端：相关 focused tests、完整 `go test ./...`、`go vet ./...`、数据库/admin/auth/proxy race tests。
- 前端：现有全部测试、TypeScript check、production build。
- 运维：failover/maintenance self-tests；错误富化 timer 的停用与不再写入验证；历史清理 dry-run/前后对账。
- 候选验证：隔离 candidate smoke；OAuth/Relay CYB 口径测试；多 attempt 合并；Guardian attempt 排除；账号改名；legacy logical ID；超大 system/tools/user 分区；SQL 凭据提取精确命中；正常 SQL/文档/工具说明反例。
- 发版前：打开并验证合格 sub2 备用；准备 rollback image/compose；不得直接操作 7692；不得恢复 inactive/deleted 账号。
- 发版后：健康、重启数、Relay 实际容量、sub2 bridge、最终逻辑 4xx/5xx/CYB、route invariant、WS 上下文、encrypted owner、no available account、缓存/首字延迟。
- 所有判断排除 `guardian_attempt_only`，并以 canonical final 为业务权威。

## 七、新任务启动指令

新任务必须先阅读本文与项目 `AGENTS.md`，然后：

1. 实时核验 s12 生产 head/image/health/Guardian/sub2 bridge/timer 状态。
2. 在 `/root/codex2api-wt-rb15-audit-routing` 检查 branch 与工作树干净性。
3. 先写可执行开发计划与数据迁移/回滚设计，再实施上述 4.1–4.5。
4. 不修改 sub2 源码或审核配置，不切 Guardian enforce，不触碰账号 status/7692。
5. 完成测试、评审与候选验证后，再请求/确认正式发版步骤。
6. Guardian 正式启用保持为显式未完成里程碑，发版后进入 24 小时 monitor soak 与单独启用流程。

本文不含任何密码、token、API key、cookie 或代理凭据。
