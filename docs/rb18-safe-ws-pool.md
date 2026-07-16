# RB18：安全 WebSocket 持久复用候选

## 目标与边界

本候选解决两个不同问题：

1. 无状态请求按共享 API Key 复用物理 WS 时，可能发生跨用户帧归属和握手头冻结。
2. 固定槽位全忙后创建一次性溢出 WS，会在高并发下重新放大握手量。

它不是“账号级可互换连接池”。最终形态是：一个明确的 Codex `session_id + thread_id` owner 独占一条物理 WS，多个 owner 之间永不交换连接；同一 owner 的多轮请求才允许顺序复用。

生产默认行为不变：`CODEX_WS_STATELESS_ONESHOT=1` 仍是最高优先级硬逃生阀。候选代码不修改账号状态、调度开关、Guardian 或 sub2 源码，也不包含任何账号 ID/名称白名单。合并官方 v2.5.6 后会执行其必要的数据库自动迁移，但新增公开门户均默认关闭，Payload Rules 默认空配置。

## 官方 v2.5.6 合并边界

RB18 基于官方 `v2.5.6`（`dd105d5ad68fcb7854c2770d6f9c69bb727dca8f`）完成语义合并，吸收：

- zstd/gzip/br/deflate 请求体解压和解压后大小保护；
- compaction 请求首字超时豁免；
- 保留 Codex HTTP/2 指纹的 keep-alive PING；
- Payload Rules 及按 API Key/分组匹配；
- 5h 用量窗口可选化、账号备注和公开门户等管理功能；
- 新鲜 OAuth 请求遇到账号侧 403 时换号重试。

RelayBases 的约束优先于官方默认实现：

- Relay 403 可能来自 WAF、内容策略或下游授权，禁止换 Relay 前门、禁止冷却整个 Relay 入口，最终仍按上游 403 返回；
- 带 `previous_response_id` 或加密上下文的 OAuth 403 禁止换号，避免跨账号续链；
- Payload Rules 只在真正发送上游时应用一次，但其改写后的 system/instructions 会进入完整 payload 的 Relay 路由扫描；
- codex2api 本地规则继续只做 Relay 分流，不恢复用户可见拦截，Guardian 继续保持 `monitor`；
- Account Portal 默认关闭；官方 Image Studio Portal 的默认值也在本分支收紧为关闭，必须由管理员显式开启；
- 构建版本使用 `v2.5.6+rb18.<build>`，语义版本比较仍等于官方 v2.5.6，不会错误显示“有新版”。

首个生产发布只能在 `CODEX_WS_STATELESS_ONESHOT=1` 下进行，用于验证官方合并本身；安全 WS 池必须另行按 tagged 账号灰度，不能与版本升级同时全量开启。

## 为什么不能按共享 Key 直接复用

一条物理 WS 同时只能有一个在途响应。HTTP Upgrade 后的认证、设备认证和自定义头均被冻结，不能随下一条 `response.create` 更新。共享 Key 可能代表多个最终用户，因此 Key、内容哈希、随机 `prompt_cache_key` 都不是可靠的跨轮连接 owner。

安全池只接受每轮 `response.create` 请求体中显式且相互一致的：

- `client_metadata.session_id`
- `client_metadata.thread_id`

`turn_id` 是每轮身份，不参与跨轮连接 ownership。owner 同时绑定下游 API Key；池键还包含稳定握手头指纹。候选按官方 Codex 客户端构造稳定握手身份：`Session-Id=session_id`、`Thread-Id=thread_id`、`X-Client-Request-Id=thread_id`。历史上从 `prompt_cache_key` 派生的 `Session_id`/`Conversation_id` 下划线头会被删除，不能与官方 owner 混用。flat 与 nested metadata、请求头与 canonical body 任一冲突都不得进入安全复用。

官方 Codex 请求通常同时携带顶层 `prompt_cache_key`。安全入口因此不再依赖外层是否把请求归类成 “stateless”，也不要求旧的 pool route key 非空：只要当前账号策略为 safe 且 owner 完整，就进入 owner 独占池。safe scope 下 owner 缺失、冲突、API Key 为空、音频或其他不满足条件的非续链请求，会在任何 WS 拨号/业务写入前返回 typed fallback，由外层保留已选账号改走 HTTP；不会回落历史显式 session 池，也不会创建一次性 WS。带 `previous_response_id` 的请求不能搬到 HTTP 或另一条 WS，必须返回 continuation unavailable。只有显式硬 ONESHOT 才主动为非续链请求创建独享 WS。

`X-Codex-Turn-State`、`X-Codex-Turn-Metadata`、traceparent 和 tracestate 是每轮数据，会写入每个 `response.create.client_metadata`，不冻结在复用连接的握手里。`X-Codex-Window-Id` 只在首次拨号时作为兼容握手头发送，但明确排除在复用 fingerprint 外；同一 thread 压缩上下文后 window 变化仍沿用同一 owner 连接，并以本轮 body 为准。任一 owner 或真正的稳定握手身份发生变化，都会使用不同物理连接。

## 配置优先级

1. `CODEX_WS_STATELESS_ONESHOT=1`：最高优先级硬阀；进入该 one-shot 执行路径的非续链请求每次独享物理 WS，任何 safe 标签都不能绕过。依赖连接本地状态的官方续链不会被搬到新 WS。
2. `CODEX_WS_STATELESS_ONESHOT=0` 且 `CODEX_WS_SAFE_POOL_SCOPE=tagged`：只有带 `sys:ws-safe-pool` 标签、且有可靠 owner 的账号/请求进入安全池；未打标签账号继续强制 one-shot，不能因单账号灰度而恢复显式会话或续链复用。
3. `CODEX_WS_SAFE_POOL_SCOPE=all`：所有动态 OAuth 账号均可进入安全池，但请求仍必须有可靠 owner。
4. `CODEX_WS_SAFE_POOL_SCOPE=legacy`：仅用于明确恢复旧固定槽池行为。
5. scope 缺失、disabled 或非法：保持候选前基线；这与 `tagged` 的严格灰度隔离不同，不能用作单账号 canary。

账号级标签：

- `sys:ws-safe-pool`：tagged 灰度开启。
- `sys:ws-oneshot`：账号级强制独享，优先于 scope。
- `sys:ws-safe-pool-slots=N`：账号级不同 owner 物理连接数上限，范围 1–256；不是同一 owner 的可互换槽位数。

运行参数：

- `CODEX_WS_SAFE_POOL_MAX_SLOTS`：默认配置上限 256，但每个账号的实际 owner 连接上限始终收紧到该账号当前动态并发值；显式环境变量或账号标签可继续下调。
- `CODEX_WS_SAFE_POOL_WAIT_MS`：默认 250ms。
- `CODEX_WS_SAFE_POOL_REUSE_FENCE_MS`：默认 100ms。

## 安全状态机

- 每条物理 WS 同时只允许一个 active lease。
- 官方允许的 `response.metadata`、`codex.response.metadata`、`responsesapi.websocket_timing`、`codex.rate_limits` 前导控制帧会被有界缓冲；只有随后合法的 `response.created` 证明本轮身份后才按原顺序释放。前导响应 ID 若存在必须与 created 一致，超出帧数/字节预算立即 fail closed。
- 新租约首个业务事件必须是 `response.created`，且必须带 `response.id`。`sequence_number` 若存在必须非负并严格递增；不要求每帧都有序号，也不假定连续或每轮从 0 开始。
- 同一轮任何可见的 `response.id` 必须保持一致；created 后允许上述官方控制帧省略响应 ID/序号。控制帧若携带响应 ID，仍必须与本轮一致；任何控制帧携带 `item_id`/`item.id` 都在 callback 前拒绝，避免延迟旧控制帧绕过 ownership。其他业务帧继续受 response/item ownership 图约束。
- `output_index → item.id/type`、`item.id → output_index` 和文本内容的 `content_index → part.type` 必须先登记后引用；未知 item、错误 output/content 索引或类型冲突在进入下游 callback 前拒绝。
- `completed/failed/incomplete/done` 必须携带本轮相同 `response.id`；若携带 `response.status`，状态必须与终态事件一致。
- 终止帧先发布 `previous_response_id` 绑定并建立 terminal-release 屏障，再交付下游；上轮 Close 完成 pending 清理和 reuse fence 后才唤醒续链获取者。这样客户端收到 terminal 后立即发下一轮，也不会抢在连接真正释放前误判 busy 或跨槽。
- 取消、下游写失败、Close 1006/1009/1011、未知事件边界、响应 ID/序号冲突、终止后残帧均销毁连接。
- 所有 WS 模式中，一旦真正调用底层写操作，任何返回错误都视为提交结果不确定并禁止自动重放，避免双执行/双计费；只有明确发生在底层写入前的错误才允许重建重试。本机响应读缓冲超过 16 MiB 时虽然为诊断保留 close 1009/`websocket.ErrReadLimit`，仍属于提交后读结果不确定，绝不能误判成上游请求过大后转 HTTP 重放。写结果不确定、提交后读中断和隔离冲突分别记录为 `websocket_write_uncertain`、`websocket_read_uncertain`、`websocket_isolation_violation`，三者均不得换账号重试、转 HTTP、处罚账号或触发鉴权探针。
- 槽位全忙时有界等待；超时返回 `ErrWebsocketLocalCapacity`，由现有外层在“无显式会话且无 `previous_response_id`”时保留同一账号租约降级 HTTP。探针预算耗尽只结束本次准入，不删除健康性尚未证伪的共享 socket，也不进入创建路径重复探针或重拨。不得新建一次性溢出 WS。
- 冷拨号也预占 safe slot，防止多个 owner 同时穿透上限；拨号后、探针后、入池前和真正业务写入前都会重新读取全局逃生阀、scope、账号标签和 fuse。策略在拨号途中关闭时，该连接不得发布到池，也不得发送业务帧。
- 每条连接保留最多 4096 个已完成 response ID；达到上限后退休整条连接，不滑窗遗忘旧 ID。全局 `previous_response_id` 绑定表上限为 65536，使用单调 generation FIFO 做摊销 O(1) 满表驱逐，并以按物理连接的二级摘要避免热路径扫描全部 response ID。默认 bound-idle 物理连接预算仍为全局 512、单账号 128，可通过既有环境变量调低或按压测结果调高。

## 协议边界

官方 WS 事件没有在每一帧回显一个由客户端指定的 lease nonce。某些 delta 只有 `item_id`，裸 `error` 甚至没有 response/item 归属。因此：

- owner 隔离、单飞、item/content 图和终态 fence 可以阻止跨 owner 复用及绝大多数残帧；
- 100ms fence 是缓冲，不是“任意晚到帧不可能出现”的数学证明；
- 如果上游违反其“单连接单飞、终态结束本轮”的协议，发送一整套新的、内部自洽且无可关联 nonce 的旧响应，客户端无法从字段上绝对辨别；
- 要在上游任意违约时仍取得绝对隔离，唯一方案仍是每个逻辑请求一条 WS，即 `CODEX_WS_STATELESS_ONESHOT=1`。

候选的风险边界因此是“同一明确 owner 内的顺序复用”，绝不扩大到跨 owner。音频事件缺少足够归属字段，暂不进入安全复用。

## 账号级运行态保险丝

检测到帧越界、终止后残帧、lease 边界冲突或严格响应校验失败时：

- 仅在当前进程内熔断该动态账号的安全复用；
- 立即关闭该账号空闲安全池连接；
- 在途连接自然结束后销毁；
- 后续无续链请求在任何 WS 写入前保留同一账号降级 HTTP；`previous_response_id` 续链 fail closed；
- 不修改账号 status、schedulable、Guardian 或数据库。

进程重启会清空保险丝。紧急全局回退仍使用 `CODEX_WS_STATELESS_ONESHOT=1` 并安全重建。

逃生阀、scope 关闭、`sys:ws-oneshot` 或 safe-pool 标签撤销也会阻止已有 `previous_response_id` 绕过策略：空闲安全连接立即销毁，在途响应允许自然完成但连接随后销毁。续链不会换一条普通连接伪装成功。整个过程不修改账号业务状态。

## 指标

已认证的 `/api/admin/runtime-status` 现在提供 `websocket` 只读聚合区，既不暴露账号 ID、API Key、owner/response ID，也不改变任何运行态。它包含：

- 配置：`global_oneshot`、scope、配置 slots、等待和 fence；
- 当前量：safe 连接总数、active/idle/bound-idle/retiring、pending dials、response bindings、tracked/fused/compatibility-fused 账号数；
- 进程累计：拨号尝试/成功/失败、复用命中、饱和、隔离 fuse、兼容降级、owner eligible/missing/rejected、请求不适用。

这些值是进程内快照，重启后清零；当前量在并发采集期间允许轻微变化，不能作为同步锁或计费依据。具体 fuse 原因继续进入服务日志，runtime status 只给出聚合数，避免泄露身份信息。

## 灰度门槛

1. 生产保持 ONESHOT=1，完成全量单测、`go test -race` 和高重复竞态测试。
2. 使用 mock WS 故障注入验证：官方格式的无 response_id 旧 delta、旧 created、错误 item/output/content/terminal、序号跳变、取消、1006/1009/1011、busy/capacity、probe 超时、fuse、逃生阀和续链。
3. 先进行不承载真实用户的官方上游兼容探测，确认握手头、首个 sequence 起点和所有实际事件族；无归属未知扩展会退休当前 socket、触发账号级 compatibility fuse，并让后续非续链请求走同账号 HTTP；带旧 response/item 归属的未知事件按隔离冲突处理。
4. 再使用动态标签选择单独候选账号：一次维护同时设置 ONESHOT=0、scope=tagged，再热加账号标签；不写死账号 ID 或名称。
5. 观察 runtime status 中的拨号/复用比、pending dials、bound-idle、Saturations、FuseTrips，以及三类 no-replay 错误、最终 5xx、TTFT、上下文连续性和重复计费。
6. 任何 FuseTrips、串帧、未知 response ID、重复输出或错误归属均立即回 ONESHOT=1。

多实例阶段必须增加实例粘性或 Redis owner + fencing；当前 `previous_response_id` 绑定是进程内状态，不能假设跨实例可见。
