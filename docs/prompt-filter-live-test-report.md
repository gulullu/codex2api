# Relay 路由规则验收说明

更新日期：2026-07-16

本说明取代旧版通用 Prompt Filter 实验记录。旧记录测试的是上游可选审核能力，不代表 RelayBases 当前生产语义。

## 当前生产边界

- sub2 对全部请求负责审核。
- codex2api 检查完整 payload，只生成本地 Relay 路由信号。
- 本地运行模式固定为 `monitor`。
- 旧版二次审查和独立语义服务商池固定关闭。
- SSE 与 WebSocket 输出不扫描、不缓冲、不因本地规则中断。
- Relay 路由失败不回退 OAuth。

## 合并验收矩阵

| 场景 | 必须结果 |
|---|---|
| 普通完整 payload 未命中规则 | 按正常 OAuth 调度 |
| 当前完整 payload 命中路由阈值 | 进入 Relay 账号组 |
| strict 规则或强制 Relay 分类命中 | 作为高置信信号进入 Relay，不返回本地策略错误 |
| 旧数据库 `output.enabled=true` | 管理端回显/保存归一为 `false` |
| SSE 返回包含任意模型文本 | 字节原样透传，不触发本地输出错误 |
| WebSocket 返回包含任意模型文本 | 消息原样透传，不触发策略关闭码 |
| API 尝试开启旧版二次审查 | 保存与回显仍为关闭 |
| API 尝试开启独立语义复核 | 保存与回显仍为关闭 |
| Relay 组无可用账号 | 返回可重试的路由不可用错误，不落入 OAuth |

## 自动化回归

代码包含以下针对性回归：

- 存储配置中输出扫描为 `true` 时，SSE writer 仍原样透传；
- 同样配置下，Responses WebSocket 输出仍原样透传；
- 路由配置强制使用 monitor、禁用旧版 review 和 output interruption；
- 管理端配置归一化不影响输入规范化与规则情报等兼容字段；
- 前端类型检查与单元测试覆盖管理页改动。

发布前仍需运行完整 Go 测试、前端类型检查和前端测试，并通过真实 SSE / WebSocket canary 核对首字、终止帧、usage、连接复用和账号归属。

## 观察重点

发版后重点观察：

- OAuth 漏放案卷与 Relay CYB 案卷；
- `route_signals`、`pin_kind`、最终账号类型和路由来源；
- Relay 最终 5xx、`no_available_account` 与路由越界；
- SSE 首字/终止帧、WS busy-session、continuation 与缓存上下文；
- 是否出现任何本地 `response_policy_violation` 或输出中断信号。

若出现本地规则导致用户可见拒绝或模型输出中断，应视为发布回归，而不是预期审核行为。
