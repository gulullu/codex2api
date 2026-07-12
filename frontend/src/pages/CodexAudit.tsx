import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, BarChart3, CheckCircle2, ChevronDown, CircleHelp, Clock3, Gauge, RefreshCw, ShieldAlert, ShieldCheck, ShieldX, Zap } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '../api'
import PageHeader from '../components/PageHeader'
import StateShell from '../components/StateShell'
import Pagination from '../components/Pagination'
import { useDataLoader } from '../hooks/useDataLoader'
import { formatBeijingTime } from '../utils/time'
import { getErrorMessage } from '../utils/error'
import type { AccountRow, CodexAuditReport, HealthResponse, PromptFilterLog, UsageLog } from '../types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Select } from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

type AuditData = {
  report: CodexAuditReport | null
  health: HealthResponse | null
  accounts: AccountRow[]
}

type Tone = 'ok' | 'warn' | 'bad' | 'neutral'

const chartColors = {
  request: '#2563eb',
  default: '#64748b',
  relayDirect: '#16a34a',
  relayPinned: '#0ea5e9',
  relayProbe: '#7c3aed',
  relayOverflow: '#d97706',
  relayContinuation: '#db2777',
  oauthCyber: '#dc2626',
  relayError: '#f97316',
}

const rangeOptions = [
  { label: '最近 30 分钟', value: '0.5' },
  { label: '最近 1 小时', value: '1' },
  { label: '最近 3 小时', value: '3' },
  { label: '最近 6 小时', value: '6' },
  { label: '最近 12 小时', value: '12' },
  { label: '最近 24 小时', value: '24' },
  { label: '最近 3 天', value: '72' },
  { label: '最近 7 天', value: '168' },
]

const refreshOptions = [
  { label: '手动刷新', value: '0' },
  { label: '每 30 秒', value: '30' },
  { label: '每 1 分钟', value: '60' },
  { label: '每 5 分钟', value: '300' },
  { label: '每 15 分钟', value: '900' },
]

const routeSignalMeta: Record<string, { label: string; description: string }> = {
  technical_cyber_intent: {
    label: '技术性网络安全意图',
    description: '请求包含网络安全、攻击或防护等技术语义；只用于选择 Relay，不等于违规。',
  },
  local_high_risk: {
    label: '本地高风险判定',
    description: '多个本地规则综合判断本次完整请求更适合由 Relay 处理。',
  },
  local_threshold: {
    label: '风险分数达到阈值',
    description: '本地规则累计分数达到配置阈值，因此改走 Relay。',
  },
  explicit_high_risk_rule: {
    label: '明确高风险规则',
    description: '命中被明确标记为高风险的本地分流规则。',
  },
  probe_request: {
    label: '探针请求',
    description: '识别为探针请求，按当前策略统一交由 Relay 处理。',
  },
  oauth_no_dispatch_slot: {
    label: 'OAuth 暂无可用并发',
    description: 'OAuth 账号池当时没有可用并发槽，请求因此转交 Relay。',
  },
  previous_response_owner: {
    label: '沿用上一响应账号',
    description: '请求携带上一响应 ID，需要继续使用创建该响应的原账号。',
  },
}

const routeSourceLabels: Record<string, string> = {
  direct: '规则命中',
  probe: '探针分流',
  overflow: '容量分流',
  continuation: '响应续接',
  pin: '会话固定',
  default: '默认 OAuth',
  legacy: '历史记录',
}

const pinKindLabels: Record<string, string> = {
  previous_response_id: '上一响应',
  prompt_cache_key: '提示缓存',
  conversation_id: '对话标识',
  session_id: '会话标识',
  websocket: 'WebSocket 会话',
}

function describeRouteSignal(signal?: string | null) {
  const key = (signal || '').trim()
  return routeSignalMeta[key] || {
    label: key || '未记录信号',
    description: key
      ? `内部标识 ${key}；该信号只用于选择账号池，不代表请求被本地拦截。`
      : '旧记录没有保存具体路由信号。',
  }
}

function routeSourceLabel(source?: string | null) {
  const key = (source || '').trim()
  return routeSourceLabels[key] || (key ? key : '历史记录（来源未记录）')
}

function pinKindLabel(pinKind?: string | null) {
  const key = (pinKind || '').trim()
  if (!key || key === '-') return '无'
  return pinKindLabels[key] || key
}

function upstreamAccountTypeLabel(accountType?: string | null) {
  const key = (accountType || '').trim()
  if (key === 'openai_responses') return 'Relay API 账号'
  if (key === 'oauth') return 'OAuth 账号'
  return key || '账号类型未记录'
}

function formatRouteSignals(raw?: string | null) {
  const value = (raw || '').trim()
  if (!value) return ''
  try {
    const parsed = JSON.parse(value)
    if (Array.isArray(parsed)) {
      return parsed.map((signal) => describeRouteSignal(String(signal)).label).join('、')
    }
  } catch {
    // Legacy rows may contain a plain signal instead of JSON.
  }
  return value.split(',').map((signal) => describeRouteSignal(signal.trim()).label).join('、')
}

const verdictMeta: Record<string, { label: string; title: string; description: string; tone: Tone }> = {
  normal: {
    label: '正常',
    title: 'Relay 路由态势稳定',
    description: '当前窗口内未发现 OAuth CYB、路由隔离失效或服务故障。',
    tone: 'ok',
  },
  oauth_cyber_risk: {
    label: 'OAuth CYB',
    title: '发现 OAuth 漏放',
    description: '实际由受保护 OAuth 账号发起的请求触发了上游 cyber_policy，请优先复盘路由信号。',
    tone: 'bad',
  },
  route_invariant_violation: {
    label: '路由越界',
    title: 'Relay 隔离约束被破坏',
    description: '存在 Relay 意图却落到错误账号类型、缺少分组或审计字段冲突的请求。',
    tone: 'bad',
  },
  relay_quality_issue: {
    label: 'Relay 质量',
    title: 'Relay 服务商出现策略拦截',
    description: '该信号不计入 OAuth 漏放，但说明 Relay 供应商本身需要关注。',
    tone: 'warn',
  },
  operational_issue: {
    label: '运行异常',
    title: 'Relay 路由或服务运行存在异常',
    description: '存在 Relay 不可用、上游 5xx 或其他运行故障。',
    tone: 'bad',
  },
}

const chartTooltipStyle = {
  background: 'hsl(var(--popover))',
  border: '1px solid hsl(var(--border))',
  borderRadius: 8,
  boxShadow: '0 14px 40px rgba(15, 23, 42, 0.12)',
  color: 'hsl(var(--popover-foreground))',
}

function loadStoredNumber(key: string, fallback: number) {
  if (typeof window === 'undefined') return fallback
  const raw = window.localStorage.getItem(key)
  const parsed = raw ? Number(raw) : NaN
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback
}

export default function CodexAudit() {
  const [rangeHours, setRangeHours] = useState(() => loadStoredNumber('codex_audit_range_hours', 0.5))
  const [refreshSeconds, setRefreshSeconds] = useState(() => loadStoredNumber('codex_audit_refresh_seconds', 60))

  const loadData = useCallback(async (): Promise<AuditData> => {
    const bucketMinutes = rangeHours <= 1 ? 5 : rangeHours <= 6 ? 10 : rangeHours <= 24 ? 30 : 120
    const [report, health, accountsResp] = await Promise.all([
      api.getCodexAuditReport({ hours: rangeHours, bucketMinutes, limit: 30 }),
      api.getHealth(),
      api.getAccounts(),
    ])
    return { report, health, accounts: accountsResp.accounts ?? [] }
  }, [rangeHours])

  const { data, loading, error, reload } = useDataLoader<AuditData>({
    initialData: { report: null, health: null, accounts: [] },
    load: loadData,
  })

  useEffect(() => {
    window.localStorage.setItem('codex_audit_range_hours', String(rangeHours))
  }, [rangeHours])

  useEffect(() => {
    window.localStorage.setItem('codex_audit_refresh_seconds', String(refreshSeconds))
    if (!refreshSeconds) return
    const timer = window.setInterval(() => void reload(), refreshSeconds * 1000)
    return () => window.clearInterval(timer)
  }, [refreshSeconds, reload])

  const report = data.report
  const health = data.health
  const accounts = data.accounts ?? []
  const meta = verdictMeta[report?.verdict || 'normal'] || {
    label: report?.verdict || '-',
    title: '巡检状态待确认',
    description: '当前结论来自后台聚合结果，请结合样本和趋势判断。',
    tone: 'warn' as Tone,
  }

  const timeline = useMemo(() => (report?.timeline || []).map((point) => ({
    ...point,
    label: formatShortTime(point.bucket),
  })), [report?.timeline])

  const errorRate = report?.usage.requests ? (report.usage.errors_4xx + report.usage.errors_5xx) / report.usage.requests : 0
  const relayRate = report?.usage.requests ? report.summary.relay_requests / report.usage.requests : 0
  const relaySuccesses = (report?.relay_routes || []).reduce((sum, row) => sum + row.successes, 0)
  const relaySuccessRate = report?.summary.relay_requests ? relaySuccesses / report.summary.relay_requests : 0
  const relayFailoverSuccessRate = report?.summary.relay_failovers
    ? report.summary.relay_failover_successes / report.summary.relay_failovers
    : 0
  const firstTokenTone: Tone = (report?.usage.first_token_p95_ms || 0) >= 3000 ? 'bad' : (report?.usage.first_token_p95_ms || 0) >= 1500 ? 'warn' : 'ok'
  const errorTone: Tone = errorRate >= 0.05 ? 'bad' : errorRate > 0 ? 'warn' : 'ok'

  return (
    <>
      <PageHeader
        title="审计"
        description="查看请求为何进入 OAuth 或 Relay、上游是否成功，以及是否出现安全策略拦截或会话异常。"
        actions={
          <div className="grid w-full min-w-0 gap-2 sm:w-auto sm:grid-cols-[164px_164px_auto] sm:items-end">
            <HeaderControl label="巡检范围">
              <Select value={String(rangeHours)} onValueChange={(value) => setRangeHours(Number(value))} options={rangeOptions} triggerClassName="h-10 rounded-lg text-sm" />
            </HeaderControl>
            <HeaderControl label="自动刷新">
              <Select value={String(refreshSeconds)} onValueChange={(value) => setRefreshSeconds(Number(value))} options={refreshOptions} triggerClassName="h-10 rounded-lg text-sm" />
            </HeaderControl>
            <Button variant="outline" className="h-10 w-full sm:w-auto" onClick={() => void reload()} disabled={loading}>
              <RefreshCw className={loading ? 'size-3.5 animate-spin' : 'size-3.5'} />
              刷新
            </Button>
          </div>
        }
      />

      <StateShell loading={loading && !report} error={error} isEmpty={!loading && !report} onRetry={() => void reload()} emptyTitle="暂无巡检数据">
        {report ? (
          <div key={rangeHours} className="w-full min-w-0 max-w-full space-y-4">
            <Card className="w-full min-w-0 overflow-hidden border-border/70 bg-gradient-to-br from-background via-background to-muted/30 shadow-sm">
              <CardContent className="min-w-0 p-0">
                <div className="flex min-w-0 flex-col gap-4 border-b border-border/70 p-4 sm:p-5 xl:flex-row xl:items-center xl:justify-between">
                  <div className="flex min-w-0 items-start gap-3 sm:gap-4">
                    <div className={`flex size-11 shrink-0 items-center justify-center rounded-xl ${toneIconClass(meta.tone)} [&>svg]:size-5`}>
                      {meta.tone === 'ok' ? <ShieldCheck /> : meta.tone === 'warn' ? <ShieldAlert /> : <ShieldX />}
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="text-lg font-semibold tracking-tight text-foreground sm:text-xl">{meta.title}</h2>
                        <Badge className={verdictClass(meta.tone)}>{meta.label}</Badge>
                      </div>
                      <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">{meta.description}</p>
                    </div>
                  </div>
                  <div className="grid min-w-0 gap-2 sm:grid-cols-3 xl:w-[720px]">
                    <WindowLine label="历史筛选窗口" value={`${formatBeijingTime(report.window_start)} 至 ${formatBeijingTime(report.window_end)}`} />
                    <WindowLine label="报表生成" value={formatBeijingTime(report.generated_at)} />
                    <WindowLine label="运行健康 · 实时" value={`${health?.status || '-'} · 不受时间筛选`} tone={health?.status === 'ok' ? 'ok' : 'warn'} />
                  </div>
                </div>

                <div className="grid min-w-0 grid-cols-2 gap-3 p-3 sm:grid-cols-3 sm:p-4 xl:grid-cols-6">
                  <AuditMetricGuide />
                  <SignalTile label="请求数（去重）" value={formatNumber(report.usage.requests)} detail={`上游调用 ${formatNumber(report.usage.upstream_attempts)} 次（含重试）· 最终错误 ${formatPercent(errorRate)}`} icon={<Activity />} tone={errorTone} />
                  <SignalTile label="Relay 分流" value={formatNumber(report.summary.relay_requests)} detail={`最终由 Relay 处理 · 占比 ${formatPercent(relayRate)} · 固定 ${formatNumber(report.summary.relay_pinned)} · 续接 ${formatNumber(report.summary.relay_continuation || 0)}`} icon={<ShieldCheck />} tone={report.summary.relay_route_failures ? 'warn' : 'ok'} />
                  <SignalTile label="规则命中 → Relay" value={formatNumber(report.summary.relay_direct)} detail="本轮完整请求命中本地规则，只改变账号池" icon={<Gauge />} tone="ok" />
                  <SignalTile label="探针分流" value={formatNumber(report.summary.relay_probe || 0)} detail="识别为探针请求，直接交由 Relay" icon={<Zap />} tone="ok" />
                  <SignalTile label="OAuth 容量分流" value={formatNumber(report.summary.relay_overflow || 0)} detail="OAuth 暂无可用并发时，改由 Relay 处理" icon={<BarChart3 />} tone="neutral" />
                  <SignalTile label="Relay 成功率" value={formatPercent(relaySuccessRate)} detail={`最终成功 ${formatNumber(relaySuccesses)} / Relay 请求 ${formatNumber(report.summary.relay_requests)}`} icon={<CheckCircle2 />} tone={report.summary.relay_route_failures ? 'warn' : 'ok'} />
                  <SignalTile label="Relay 自动换号" value={formatNumber(report.summary.relay_failovers || 0)} detail={`换号后成功 ${formatNumber(report.summary.relay_failover_successes || 0)} · 成功率 ${formatPercent(relayFailoverSuccessRate)}`} icon={<RefreshCw />} tone={report.summary.relay_failover_failures ? 'warn' : 'ok'} />
                  <SignalTile label="上游 5xx 已吸收" value={formatNumber(report.summary.relay_absorbed_5xx || 0)} detail={`首个 Relay 账号失败，但备用账号接管成功 · 全池失败 ${formatNumber(report.summary.relay_failover_failures || 0)}`} icon={<ShieldCheck />} tone={report.summary.relay_failover_failures ? 'warn' : 'ok'} />
                  <SignalTile label="OAuth 安全拦截" value={formatNumber(report.summary.oauth_cyber_miss_attempts)} detail={`${formatNumber(report.summary.oauth_cyber_miss_requests)} 个请求进入 OAuth 后被上游策略拦截`} icon={<AlertTriangle />} tone={report.summary.oauth_cyber_miss_attempts ? 'bad' : 'ok'} />
                  <SignalTile label="Relay 安全拦截" value={formatNumber(report.summary.relay_cyber_attempts)} detail={`${formatNumber(report.summary.relay_cyber_requests)} 个请求被 Relay 上游策略拦截，不计 OAuth 漏放`} icon={<ShieldAlert />} tone={report.summary.relay_cyber_attempts ? 'warn' : 'ok'} />
                  <SignalTile label="路由异常" value={formatNumber(report.summary.relay_route_failures)} detail={`含 Relay 不可用或 5xx · 落错账号池 ${formatNumber(report.summary.route_invariant_violations)}`} icon={<ShieldX />} tone={(report.summary.relay_route_failures || report.summary.route_invariant_violations) ? 'bad' : 'ok'} />
                  <SignalTile label="会话串扰" value={formatNumber(report.summary.session_bleed)} detail={report.summary.session_bleed ? '上游响应标识不一致，需立即排查' : '未发现其他请求的响应混入当前会话'} icon={<ShieldAlert />} tone={report.summary.session_bleed ? 'bad' : 'ok'} />
                  <SignalTile label="首字延迟 P95" value={formatMS(report.usage.first_token_p95_ms)} detail={`95% 的有效样本在该时间内收到首个响应 · ${formatNumber(report.usage.first_token_samples)} 个样本`} icon={<Clock3 />} tone={firstTokenTone} />
                  <SignalTile label="WebSocket 占比" value={formatPercent(report.usage.websocket_ratio || 0)} detail={`${formatNumber(report.usage.websocket_requests)} 个请求通过 WebSocket 连接上游`} icon={<Zap />} tone={(report.usage.websocket_ratio || 0) >= 0.85 ? 'ok' : 'warn'} />
                </div>

                <div className="border-t border-border/70 p-3 sm:p-4">
                  <AccountPoolTile accounts={accounts} />
                </div>
              </CardContent>
            </Card>

            <div className="grid min-w-0 gap-4 xl:grid-cols-2">
              <CyberPolicyPanel
                title="OAuth 漏放案卷"
                description="仅展示实际由受保护 OAuth 账号发起且返回 cyber_policy 的请求；Relay 账号事件不计入漏放。"
                rows={report.oauth_cyber_cases || []}
                total={report.summary.oauth_cyber_miss_attempts}
                empty="当前窗口内没有 OAuth 漏放"
                tone={report.summary.oauth_cyber_miss_attempts ? 'bad' : 'ok'}
              />
              <CyberPolicyPanel
                title="Relay CYB 案卷"
                description="展示 Relay 账号返回的 cyber_policy，用于供应商质量分析，不计入 OAuth 漏放。"
                rows={report.relay_cyber_cases || []}
                total={report.summary.relay_cyber_attempts}
                empty="当前窗口内 Relay 未返回 cyber_policy"
                tone={report.summary.relay_cyber_attempts ? 'warn' : 'ok'}
              />
            </div>
            <SessionBleedPanel start={report.window_start} end={report.window_end} />

            <div className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.85fr)]">
              <ChartPanel title="请求与 Relay 路由趋势" description="按当前筛选窗口展示请求数，以及默认 OAuth、规则命中、探针、容量分流、响应续接、会话固定和异常的变化。">
                <ResponsiveContainer width="100%" height={286}>
                  <LineChart data={timeline} margin={{ top: 12, right: 18, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="4 4" stroke="hsl(var(--border))" vertical={false} />
                    <XAxis dataKey="label" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <RechartsTooltip contentStyle={chartTooltipStyle} />
                    <Line type="monotone" dataKey="requests" name="请求数（去重）" stroke={chartColors.request} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="default_requests" name="默认 OAuth" stroke={chartColors.default} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_direct" name="规则命中 → Relay" stroke={chartColors.relayDirect} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_pinned" name="会话固定" stroke={chartColors.relayPinned} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_probe" name="探针分流" stroke={chartColors.relayProbe} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_overflow" name="OAuth 容量分流" stroke={chartColors.relayOverflow} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_continuation" name="响应续接" stroke={chartColors.relayContinuation} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="oauth_cyber_attempts" name="OAuth 安全拦截" stroke={chartColors.oauthCyber} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                    <Line type="monotone" dataKey="relay_route_failures" name="Relay 路由异常" stroke={chartColors.relayError} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                  </LineChart>
                </ResponsiveContainer>
              </ChartPanel>

              <ChartPanel title="模型请求分布" description="按有效模型统计请求量，辅助定位风险集中点。">
                <ResponsiveContainer width="100%" height={286}>
                  <BarChart data={(report.models || []).slice(0, 10)} layout="vertical" margin={{ top: 12, right: 18, bottom: 0, left: 4 }}>
                    <CartesianGrid strokeDasharray="4 4" stroke="hsl(var(--border))" horizontal={false} />
                    <XAxis type="number" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <YAxis type="category" dataKey="model" width={128} tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <RechartsTooltip contentStyle={chartTooltipStyle} />
                    <Bar dataKey="requests" name="请求" fill={chartColors.request} radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </ChartPanel>
            </div>

            <div className="grid min-w-0 gap-4 xl:grid-cols-2">
              <Panel title="Relay 路由信号" description="展示本次完整请求命中的本地分流规则；同一请求可同时命中多个信号，各行数量不能相加当作总请求数。信号只决定账号池，不代表违规或本地拦截。">
                <SimpleTable
                  columns={['信号', '含义', '命中请求数', '最近出现']}
                  rows={(report.route_signals || []).map((row) => {
                    const signal = describeRouteSignal(row.signal)
                    return [
                      signal.label,
                      signal.description,
                      formatNumber(row.requests),
                      formatBeijingTime(row.last_seen),
                    ]
                  })}
                  empty="当前窗口内暂无 Relay 路由信号"
                />
              </Panel>

              <Panel title="Relay 账号与分流原因" description="按 Relay 账号和分流原因统计。请求数已合并自动重试，上游调用包含重试；成功、4xx、5xx 按最终结果统计，安全拦截表示上游返回 cyber_policy。">
                <div className="mb-3 rounded-lg border border-border/60 bg-muted/25 px-3 py-2.5 text-xs leading-5 text-muted-foreground">
                  <span className="font-medium text-foreground">分流原因：</span>
                  规则命中＝本轮完整请求命中本地规则；探针分流＝识别为探针；容量分流＝OAuth 暂无可用并发；响应续接＝沿用上一响应的原账号；会话固定＝历史会话绑定。
                </div>
                <SimpleTable
                  columns={['账号', '分流原因', '固定方式', '请求数', '上游调用', '成功请求', '请求错误（4xx）', '服务错误（5xx）', '安全策略拦截']}
                  rows={(report.relay_routes || []).map((row) => [
                    row.account_name || `#${row.account_id}`,
                    routeSourceLabel(row.route_source),
                    pinKindLabel(row.pin_kind),
                    formatNumber(row.requests),
                    formatNumber(row.attempts),
                    formatNumber(row.successes),
                    formatNumber(row.errors_4xx),
                    formatNumber(row.errors_5xx),
                    formatNumber(row.cyber_policy),
                  ])}
                  empty="当前窗口内暂无 Relay 请求"
                />
              </Panel>
            </div>

            <RelayRouteCasesPanel start={report.window_start} end={report.window_end} />

            <Panel title="首字慢请求" description="按当前筛选窗口的首字时间倒序列出最慢样本，用于观察 WS 和上游延迟。">
              <UsageSampleTable rows={report.slow_requests || []} empty="暂无慢请求样本" showFirstToken />
            </Panel>

          </div>
        ) : null}
      </StateShell>
    </>
  )
}

function CyberPolicyPanel({ title, description, rows, total, empty, tone }: { title: string; description: string; rows: PromptFilterLog[]; total: number; empty: string; tone: Tone }) {
  const { pageRows, page, totalPages, setPage, pageSize } = usePaged(rows)
  const clean = total === 0
  const cardClass = tone === 'bad'
    ? 'border-red-500/40 bg-red-500/[0.06]'
    : tone === 'warn'
      ? 'border-amber-500/30 bg-amber-500/[0.05]'
      : 'border-emerald-500/30 bg-emerald-500/[0.05]'
  return (
    <Card className={`w-full min-w-0 overflow-hidden shadow-sm ${cardClass}`}>
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className={`mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl ${toneIconClass(tone)}`}>
              {clean ? <ShieldCheck className="size-5" /> : <ShieldAlert className="size-5" />}
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-foreground">{title}</h3>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{description}</p>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className={`text-2xl font-bold tabular-nums ${toneTextClass(tone)}`}>{formatNumber(total)}</div>
            <div className="text-[11px] leading-tight text-muted-foreground">上游尝试</div>
          </div>
        </div>
        {clean ? (
          <div className="rounded-lg border border-border/60 bg-background/60 p-6 text-center text-xs text-muted-foreground">{empty}</div>
        ) : (
          <>
            <div className="space-y-2">
              {pageRows.map((log) => <AuditLogRow key={log.id} log={log} />)}
            </div>
            {rows.length > pageSize ? (
              <Pagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={rows.length} pageSize={pageSize} />
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function RelayRouteCasesPanel({ start, end }: { start: string; end: string }) {
  const [logs, setLogs] = useState<PromptFilterLog[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    void api.getCodexAuditCases({ kind: 'relay_route', start, end, page, pageSize: AUDIT_PAGE_SIZE })
      .then((res) => {
        if (cancelled) return
        setLogs(res.items ?? [])
        setTotal(res.total ?? 0)
      })
      .catch((err) => {
        if (!cancelled) setError(getErrorMessage(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [end, page, start])

  const totalPages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE))
  return (
    <Panel title="Relay 路由案卷" description="以最终上游调用的账号和分流原因为准；同一请求的自动重试合并为一条，文本来自同一请求的脱敏检查记录。">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs text-muted-foreground">共 {formatNumber(total)} 个请求（已合并重试）</span>
        {loading ? <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground"><RefreshCw className="size-3.5 animate-spin" />加载中</span> : null}
      </div>
      {error ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">{error}</div>
      ) : logs.length ? (
        <>
          <div className="space-y-2">
            {logs.map((log) => <AuditLogRow key={log.id} log={log} />)}
          </div>
          {total > AUDIT_PAGE_SIZE ? (
            <Pagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={total} pageSize={AUDIT_PAGE_SIZE} />
          ) : null}
        </>
      ) : (
        <EmptyState>{loading ? '正在加载 Relay 路由案卷…' : '当前窗口内暂无 Relay 路由样本'}</EmptyState>
      )}
    </Panel>
  )
}

function SessionBleedPanel({ start, end }: { start: string; end: string }) {
  const [logs, setLogs] = useState<PromptFilterLog[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const requestSequence = useRef(0)

  const load = useCallback(async () => {
    const sequence = ++requestSequence.current
    setLoading(true)
    setError(null)
    try {
      const res = await api.getCodexAuditCases({ kind: 'session_bleed', start, end, page, pageSize: AUDIT_PAGE_SIZE })
      if (sequence !== requestSequence.current) return
      setLogs(res.items ?? [])
      setTotal(res.total ?? 0)
    } catch (err) {
      if (sequence !== requestSequence.current) return
      setError(getErrorMessage(err))
    } finally {
      if (sequence === requestSequence.current) setLoading(false)
    }
  }, [end, page, start])

  useEffect(() => {
    void load()
    return () => {
      requestSequence.current++
    }
  }, [load])

  const totalPages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE))
  const clean = total === 0

  return (
    <Card className={clean ? 'w-full min-w-0 overflow-hidden border-emerald-500/30 bg-emerald-500/[0.05] shadow-sm' : 'w-full min-w-0 overflow-hidden border-red-500/50 bg-red-500/[0.08] shadow-sm'}>
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-4 flex items-start justify-between gap-3 max-sm:flex-col">
          <div className="flex items-start gap-3">
            <div className={clean ? 'mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' : 'mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl bg-red-500/15 text-red-600 dark:text-red-400'}>
              <ShieldAlert className="size-5" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-foreground">会话串扰监测 · 当前筛选窗口</h3>
              <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
                在上游 WS 读流上校验 response_id 一致性；案卷与右上角历史时间范围保持同一 start/end 窗口。
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-3 max-sm:w-full max-sm:justify-between">
            <div className="text-right">
              <div className={clean ? 'text-2xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400' : 'text-2xl font-bold tabular-nums text-red-600 dark:text-red-400'}>{total}</div>
              <div className="text-[11px] leading-tight text-muted-foreground">检测到的串扰</div>
            </div>
            <Button variant="outline" onClick={() => void load()} disabled={loading}>
              <RefreshCw className={loading ? 'size-3.5 animate-spin' : 'size-3.5'} />
              刷新
            </Button>
          </div>
        </div>

        {error ? (
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">{error}</div>
        ) : clean ? (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-6 text-center text-xs text-emerald-700 dark:text-emerald-400">
            {loading ? '加载中…' : '✓ 被动监测运行中，未检测到任何会话串扰'}
          </div>
        ) : (
          <>
            <div className="mb-3 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs font-medium text-red-700 dark:text-red-400">
              ⚠️ 检测到 {total} 起会话串扰！请立即排查（多半是 stateless 会话身份被重新引入，或连接复用异常）。
            </div>
            <div className="space-y-2">
              {logs.map((log) => (
                <AuditLogRow key={log.id} log={log} />
              ))}
            </div>
            {total > AUDIT_PAGE_SIZE ? (
              <Pagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={total} pageSize={AUDIT_PAGE_SIZE} />
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function routeCaseBadge(log: PromptFilterLog) {
  const source = (log.route_source || '').trim()
  if (source === 'pin') return `会话固定 · ${pinKindLabel(log.pin_kind)}`
  return source ? routeSourceLabel(source) : 'Relay 分流'
}

function AuditLogRow({ log }: { log: PromptFilterLog }) {
  const [open, setOpen] = useState(false)
  const full = (log.full_text || '').trim()
  const preview = (log.text_preview || '').trim()
  const attempts = log.audit_attempts ?? []
  const badge = log.source === 'session_bleed'
    ? '会话串扰'
    : log.source === 'cyb_relay_routed'
      ? routeCaseBadge(log)
      : '安全策略拦截'
  return (
    <div className="min-w-0 rounded-lg border border-border/60 bg-background/70">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full min-w-0 items-center gap-2 px-3 py-2.5 text-left sm:gap-3"
      >
        <Badge className="shrink-0 border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300">{badge}</Badge>
        <span className="hidden shrink-0 whitespace-nowrap text-[11px] text-muted-foreground sm:inline">{formatBeijingTime(log.created_at)}</span>
        <span className="hidden shrink-0 whitespace-nowrap text-[11px] text-muted-foreground md:inline">{log.endpoint}</span>
        <span className="hidden shrink-0 whitespace-nowrap text-[11px] text-muted-foreground md:inline">{log.model || '-'}</span>
        <span className="min-w-0 flex-1 truncate text-xs text-foreground">{preview || '（改动前的旧记录，未留原始请求）'}</span>
        <ChevronDown className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open ? (
        <div className="border-t border-border/60 px-3 py-3">
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground sm:hidden">
            <span>{formatBeijingTime(log.created_at)}</span>
            <span>{log.endpoint}</span>
            <span>{log.model || '-'}</span>
          </div>
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>账号 {log.account_name || (log.account_id ? `#${log.account_id}` : '-')}</span>
            <span>{upstreamAccountTypeLabel(log.upstream_account_type)}</span>
            <span>分流原因 {routeSourceLabel(log.route_source || log.route_class)}</span>
            <span>固定方式 {pinKindLabel(log.pin_kind)}</span>
            <span>分组 {log.route_group_id || '-'}</span>
            {log.route_signals ? <span>信号 {formatRouteSignals(log.route_signals)}</span> : null}
          </div>
          {attempts.length > 1 ? (
            <div className="mb-3 rounded-md border border-border/60 bg-muted/25 p-2.5">
              <div className="mb-2 text-[11px] font-medium text-foreground">上游尝试链路</div>
              <div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px]">
                {attempts.map((attempt, index) => {
                  const ok = attempt.status_code >= 200 && attempt.status_code < 300
                  return (
                    <div key={`${attempt.account_id}-${attempt.created_at}-${index}`} className="contents">
                      {index > 0 ? <span className="text-muted-foreground">→</span> : null}
                      <span className={`inline-flex min-w-0 items-center gap-1 rounded border px-2 py-1 ${ok ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'}`}>
                        <span className="max-w-40 truncate">{attempt.account_name || `#${attempt.account_id || '-'}`}</span>
                        <span className="font-mono">{attempt.status_code || '-'}</span>
                        <span className="text-[10px] opacity-75">第 {attempt.attempt_index || index + 1} 次</span>
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          ) : null}
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/40 p-3 text-[12px] leading-5 text-foreground">{full || '（无详情）'}</pre>
        </div>
      ) : null}
    </div>
  )
}

function HeaderControl({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="grid w-full min-w-0 gap-1.5 sm:w-[164px]">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  )
}

function AccountPoolTile({ accounts }: { accounts: AccountRow[] }) {
  const relayAccounts = accounts.filter((a) => a.openai_responses_api)
  const active = relayAccounts.filter((a) => a.status === 'active' && a.enabled !== false && a.relay_circuit_state !== 'open')
  const circuitCount = relayAccounts.filter((a) => a.relay_circuit_state === 'open' || a.relay_circuit_state === 'half_open').length
  const healthy = active.length > 0 && active.length === relayAccounts.length && circuitCount === 0
  return (
    <div className="min-w-0 rounded-xl border border-border/60 bg-background/75 p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="flex size-7 items-center justify-center rounded-lg bg-primary/10 text-primary [&>svg]:size-4"><BarChart3 /></div>
          <span className="text-xs font-medium text-muted-foreground">实时账号池 · 不受历史筛选 · 近 7 天配额使用率 / 当前占用并发</span>
        </div>
        <div className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${healthy ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'}`}>
          <span className={`size-1.5 rounded-full ${healthy ? 'bg-emerald-500' : 'bg-amber-500'}`} />
          {active.length}/{relayAccounts.length} 可调度{circuitCount ? ` · 熔断 ${circuitCount}` : ''}
        </div>
      </div>
      <div className="space-y-1.5">
        {relayAccounts.slice(0, 6).map((a) => {
          const pct = Math.round(a.usage_percent_7d ?? 0)
          const busy = a.active_requests ?? 0
          const cap = a.base_concurrency_effective ?? 5
          const circuitState = a.relay_circuit_state || 'closed'
          const isActive = a.status === 'active' && a.enabled !== false && circuitState !== 'open'
          const barColor = pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-amber-500' : 'bg-emerald-500'
          return (
            <div key={a.id} className="flex items-center gap-2 text-xs">
              <span className={`size-1.5 shrink-0 rounded-full ${isActive ? 'bg-emerald-500' : 'bg-muted-foreground/40'}`} />
              <span className="min-w-0 flex-1 truncate text-foreground">{a.email || a.name || `#${a.id}`}</span>
              <span className="hidden shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground sm:inline">{a.plan_type || '-'}</span>
              {circuitState !== 'closed' ? (
                <span
                  className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${circuitState === 'open' ? 'bg-red-500/10 text-red-600 dark:text-red-400' : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'}`}
                  title={[a.relay_circuit_reason, a.relay_circuit_open_until ? `至 ${formatBeijingTime(a.relay_circuit_open_until)}` : ''].filter(Boolean).join(' · ')}
                >
                  {circuitState === 'open' ? '熔断' : `恢复探测 ${a.relay_circuit_probe_successes || 0}/${a.relay_circuit_required_successes || 3}`}
                </span>
              ) : null}
              <div className="hidden h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-muted sm:block">
                <div className={`h-full ${barColor}`} style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
              </div>
              <span className="w-14 shrink-0 text-right tabular-nums text-muted-foreground">7d {pct}%</span>
              <span className="w-9 shrink-0 text-right tabular-nums text-muted-foreground">{busy}/{cap}</span>
            </div>
          )
        })}
        {relayAccounts.length === 0 ? <div className="py-3 text-center text-xs text-muted-foreground">暂无 Relay API 账号</div> : null}
      </div>
    </div>
  )
}

function SignalTile({ label, value, detail, icon, tone, className }: { label: string; value: ReactNode; detail: string; icon: ReactNode; tone: Tone; className?: string }) {
  return (
    <div className={`flex min-h-[132px] min-w-0 flex-col justify-between rounded-xl border border-border/60 bg-background/80 p-3.5 shadow-sm transition-colors hover:border-border sm:p-4 ${className ?? ''}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-medium text-muted-foreground">{label}</div>
          <div className="mt-2 truncate text-2xl font-semibold tracking-tight text-foreground">{value}</div>
        </div>
        <div className={`flex size-9 shrink-0 items-center justify-center rounded-lg ${toneIconClass(tone)} [&>svg]:size-4`}>
          {icon}
        </div>
      </div>
      <div className="mt-3 line-clamp-2 text-xs leading-5 text-muted-foreground">{detail}</div>
    </div>
  )
}

function AuditMetricGuide() {
  const items = [
    {
      title: '请求数 / 上游调用',
      body: '请求数按客户端发起的一轮调用去重，自动重试仍算同一个请求；上游调用是实际请求账号的次数，所以可能更多。',
    },
    {
      title: 'Relay 分流',
      body: '最终由 Relay 账号处理的请求总数，包括规则命中、探针、OAuth 容量分流、响应续接和会话固定。',
    },
    {
      title: '自动换号 / 已吸收 5xx',
      body: '自动换号表示同一逻辑请求先后使用了不同 Relay 账号；已吸收 5xx 表示前一账号返回服务端错误，但备用账号接管后最终成功。',
    },
    {
      title: '规则命中 → Relay',
      body: '当前完整请求（system、skills、tools 和用户输入）命中本地规则后选择 Relay。只改变账号池，不代表违规，也不是本地拦截。',
    },
    {
      title: '安全拦截 / 路由异常',
      body: '安全拦截表示上游返回 cyber_policy；路由异常表示 Relay 不可用、返回 5xx，或请求落入了错误账号池。',
    },
  ]

  return (
    <div className="col-span-full rounded-xl border border-primary/20 bg-primary/[0.04] p-3.5 sm:p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
        <CircleHelp className="size-4 text-primary" />
        这些数字怎么读
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {items.map((item) => (
          <div key={item.title} className="min-w-0">
            <div className="text-xs font-semibold text-foreground">{item.title}</div>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">{item.body}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function WindowLine({ label, value, tone = 'neutral' }: { label: string; value: ReactNode; tone?: Tone }) {
  return (
    <div className="flex min-w-0 flex-col gap-1 rounded-md border border-border/70 bg-background/70 px-3 py-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={`min-w-0 truncate text-xs font-medium sm:text-right ${toneTextClass(tone)}`}>{value}</span>
    </div>
  )
}

function ChartPanel({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Card className="min-w-0 overflow-hidden border-border/70 shadow-sm">
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-4 flex min-w-0 items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-base font-semibold text-foreground">
              <BarChart3 className="size-4 text-primary" />
              {title}
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{description}</p>
          </div>
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

function Panel({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <Card className="min-w-0 overflow-hidden border-border/70 shadow-sm">
      <CardContent className="min-w-0 p-4 sm:p-5">
        <div className="mb-4 min-w-0">
          <h2 className="text-base font-semibold text-foreground">{title}</h2>
          {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

const AUDIT_PAGE_SIZE = 10

// usePaged 对已加载的记录做客户端分页（巡检报表每类样本上限 30，分页即可，无需改后端）。
function usePaged<T>(rows: T[], pageSize = AUDIT_PAGE_SIZE) {
  const [page, setPage] = useState(1)
  const total = rows.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const currentPage = Math.min(Math.max(page, 1), totalPages)
  const pageRows = useMemo(
    () => rows.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [rows, currentPage, pageSize],
  )
  return { pageRows, page: currentPage, totalPages, setPage, total, pageSize }
}

function SimpleTable({ columns, rows, empty }: { columns: string[]; rows: string[][]; empty: string }) {
  const { pageRows, page, totalPages, setPage, total } = usePaged(rows)
  const tableMinWidth = columns.includes('含义') ? 'min-w-[760px]' : columns.length >= 8 ? 'min-w-[980px]' : 'min-w-[560px]'
  if (!rows.length) {
    return <EmptyState>{empty}</EmptyState>
  }
  return (
    <>
      <div className="grid gap-2 sm:hidden">
        {pageRows.map((row, rowIndex) => (
          <MobileTableCard key={rowIndex} columns={columns} row={row} />
        ))}
      </div>
      <div className="hidden w-full max-w-full overflow-x-auto rounded-lg border border-border/70 sm:block">
        <Table className={tableMinWidth}>
          <TableHeader className="bg-muted/40">
            <TableRow>{columns.map((column) => <TableHead key={column} className="text-xs font-semibold text-muted-foreground">{column}</TableHead>)}</TableRow>
          </TableHeader>
          <TableBody>
            {pageRows.map((row, rowIndex) => (
              <TableRow key={rowIndex} className="hover:bg-muted/30">
                {row.map((cell, cellIndex) => {
                  const wrap = columns[cellIndex] === '含义'
                  return (
                    <TableCell key={cellIndex} className={wrap ? 'min-w-[280px] whitespace-normal text-[13px] leading-5 text-muted-foreground' : 'text-[13px]'}>
                      {cell}
                    </TableCell>
                  )
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {total > AUDIT_PAGE_SIZE ? (
        <Pagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={total} pageSize={AUDIT_PAGE_SIZE} />
      ) : null}
    </>
  )
}

function MobileTableCard({ columns, row }: { columns: string[]; row: string[] }) {
  return (
    <div className="min-w-0 rounded-lg border border-border/60 bg-muted/20 p-3">
      <div className="grid grid-cols-2 gap-2">
        {columns.map((column, index) => {
          const wide = column === '账号' || column === '信号' || column === '含义'
          const wrap = wide || column === '分流原因'
          return <MobileField key={column} label={column} value={row[index] || '-'} wide={wide} wrap={wrap} />
        })}
      </div>
    </div>
  )
}

function MobileField({ label, value, wide = false, wrap = false }: { label: string; value: ReactNode; wide?: boolean; wrap?: boolean }) {
  const title = typeof value === 'string' ? value : undefined
  return (
    <div className={`min-w-0 ${wide ? 'col-span-2' : ''}`}>
      <div className="text-[11px] leading-none text-muted-foreground">{label}</div>
      <div className={`mt-1 text-xs font-medium text-foreground ${wrap ? 'line-clamp-3 break-words' : 'truncate'}`} title={title}>
        {value}
      </div>
    </div>
  )
}

function UsageSampleTable({ rows, empty, showFirstToken = false }: { rows: UsageLog[]; empty: string; showFirstToken?: boolean }) {
  const { pageRows, page, totalPages, setPage, total } = usePaged(rows)
  if (!rows.length) {
    return <EmptyState>{empty}</EmptyState>
  }
  return (
    <>
      <div className="grid gap-2 sm:hidden">
        {pageRows.map((row) => (
          <div key={row.id} className="min-w-0 rounded-lg border border-border/60 bg-muted/20 p-3">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-medium text-foreground">{formatBeijingTime(row.created_at)}</div>
                <div className="mt-1 truncate text-xs text-muted-foreground">{row.effective_model || row.model || '-'}</div>
              </div>
              <Badge variant="outline" className="shrink-0 bg-background/70">{row.status_code}</Badge>
            </div>
            <div className="mt-3">
              <MobileField
                label={showFirstToken ? '首字' : '错误'}
                value={showFirstToken ? formatMS(row.first_token_ms) : (row.upstream_error_kind || row.error_message || '-')}
                wide
                wrap={!showFirstToken}
              />
            </div>
          </div>
        ))}
      </div>
      <div className="hidden w-full max-w-full overflow-x-auto rounded-lg border border-border/70 sm:block">
        <Table className="min-w-[620px]">
          <TableHeader className="bg-muted/40">
            <TableRow>
              <TableHead className="text-xs font-semibold text-muted-foreground">时间</TableHead>
              <TableHead className="text-xs font-semibold text-muted-foreground">模型</TableHead>
              <TableHead className="text-xs font-semibold text-muted-foreground">状态</TableHead>
              <TableHead className="text-xs font-semibold text-muted-foreground">{showFirstToken ? '首字' : '错误'}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pageRows.map((row) => (
              <TableRow key={row.id} className="hover:bg-muted/30">
                <TableCell className="whitespace-nowrap text-[12px]">{formatBeijingTime(row.created_at)}</TableCell>
                <TableCell className="text-[12px]">{row.effective_model || row.model || '-'}</TableCell>
                <TableCell><Badge variant="outline">{row.status_code}</Badge></TableCell>
                <TableCell className="max-w-[520px] text-[12px] leading-5 text-muted-foreground">
                  {showFirstToken ? formatMS(row.first_token_ms) : <span className="line-clamp-2">{row.upstream_error_kind || row.error_message || '-'}</span>}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {total > AUDIT_PAGE_SIZE ? (
        <Pagination page={page} totalPages={totalPages} onPageChange={setPage} totalItems={total} pageSize={AUDIT_PAGE_SIZE} />
      ) : null}
    </>
  )
}

function EmptyState({ children, compact = false }: { children: ReactNode; compact?: boolean }) {
  return (
    <div className={`rounded-lg border border-dashed border-border/80 bg-muted/20 text-center text-sm text-muted-foreground ${compact ? 'px-4 py-5' : 'px-6 py-8'}`}>
      {children}
    </div>
  )
}

function verdictClass(tone: Tone) {
  if (tone === 'ok') return 'border-emerald-500/20 bg-emerald-500/12 text-emerald-700 hover:bg-emerald-500/12 dark:text-emerald-300'
  if (tone === 'bad') return 'border-destructive/20 bg-destructive/12 text-destructive hover:bg-destructive/12'
  if (tone === 'warn') return 'border-amber-500/20 bg-amber-500/12 text-amber-700 hover:bg-amber-500/12 dark:text-amber-300'
  return 'border-border bg-muted text-muted-foreground hover:bg-muted'
}

function toneIconClass(tone: Tone) {
  if (tone === 'ok') return 'bg-emerald-500/12 text-emerald-700 dark:text-emerald-300'
  if (tone === 'bad') return 'bg-destructive/12 text-destructive'
  if (tone === 'warn') return 'bg-amber-500/12 text-amber-700 dark:text-amber-300'
  return 'bg-muted text-muted-foreground'
}

function toneTextClass(tone: Tone) {
  if (tone === 'ok') return 'text-emerald-700 dark:text-emerald-300'
  if (tone === 'bad') return 'text-destructive'
  if (tone === 'warn') return 'text-amber-700 dark:text-amber-300'
  return 'text-foreground'
}

function formatNumber(value?: number) {
  return new Intl.NumberFormat('zh-CN').format(value || 0)
}

function formatPercent(value?: number) {
  return `${Math.round((value || 0) * 100)}%`
}

function formatMS(value?: number) {
  if (!value) return '-'
  if (value >= 1000) return `${(value / 1000).toFixed(1)}s`
  return `${value}ms`
}

function formatShortTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
}
