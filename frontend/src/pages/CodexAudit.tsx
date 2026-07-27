import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Database,
  RefreshCw,
  Route,
  ShieldAlert,
  Shuffle,
} from 'lucide-react'
import {
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
import Pagination from '../components/Pagination'
import StateShell from '../components/StateShell'
import { getErrorMessage } from '../utils/error'
import { formatBeijingTime } from '../utils/time'
import type {
  RelayAuditCase,
  RelayAuditCasesPage,
  RelayAuditReport,
} from '../types'
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

type AuditKind = 'relay_route' | 'oauth_cyber' | 'relay_cyber' | 'continuation' | 'session_bleed'

const PAGE_SIZE = 20
const rangeOptions = [
  { label: '最近 30 分钟', value: '0.5' },
  { label: '最近 1 小时', value: '1' },
  { label: '最近 3 小时', value: '3' },
  { label: '最近 6 小时', value: '6' },
  { label: '最近 24 小时', value: '24' },
  { label: '最近 3 天', value: '72' },
  { label: '最近 7 天', value: '168' },
]
const kindOptions: Array<{ label: string; value: AuditKind }> = [
  { label: 'Relay 分流案卷', value: 'relay_route' },
  { label: 'OAuth CYB 漏放', value: 'oauth_cyber' },
  { label: 'Relay CYB', value: 'relay_cyber' },
  { label: '续接请求', value: 'continuation' },
  { label: '会话隔离异常', value: 'session_bleed' },
]

const sourceLabels: Record<string, string> = {
  cyb_rule: 'CYB 规则',
  probe: '探针分流',
  oauth_overflow: 'OAuth 容量溢出',
  relay_continuation: 'Relay 续接',
  cyb_feedback: 'CYB 反馈',
}

function formatNumber(value?: number) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function formatPercent(numerator?: number, denominator?: number) {
  const total = Number(denominator || 0)
  if (total <= 0) return '0.0%'
  return `${((Number(numerator || 0) / total) * 100).toFixed(1)}%`
}

function statusTone(status: number) {
  if (status >= 200 && status < 300) return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
  if (status >= 500 || status === 0) return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'
  return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300'
}

function routeSourceLabel(value?: string) {
  const source = (value || '').trim()
  return sourceLabels[source] || source || '普通请求'
}

function parsedSignals(raw?: string) {
  if (!raw) return []
  try {
    const value = JSON.parse(raw)
    return Array.isArray(value) ? value.map(String).filter(Boolean) : []
  } catch {
    return raw.split(',').map((item) => item.trim()).filter(Boolean)
  }
}

export default function CodexAudit() {
  const [hours, setHours] = useState(() => Number(localStorage.getItem('codex_audit_hours') || 0.5))
  const [kind, setKind] = useState<AuditKind>('relay_route')
  const [page, setPage] = useState(1)
  const [report, setReport] = useState<RelayAuditReport | null>(null)
  const [cases, setCases] = useState<RelayAuditCasesPage | null>(null)
  const [loading, setLoading] = useState(true)
  const [casesLoading, setCasesLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [casesError, setCasesError] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState(0)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const reportRequestSequence = useRef(0)

  const loadReport = useCallback(async () => {
    const sequence = ++reportRequestSequence.current
    setLoading(true)
    setError(null)
    try {
      const bucketMinutes = hours <= 1 ? 5 : hours <= 6 ? 10 : hours <= 24 ? 30 : 120
      const nextReport = await api.getRelayAuditReport({ hours, bucketMinutes })
      if (sequence === reportRequestSequence.current) {
        setReport(nextReport)
      }
    } catch (err) {
      if (sequence === reportRequestSequence.current) {
        setError(getErrorMessage(err))
      }
    } finally {
      if (sequence === reportRequestSequence.current) {
        setLoading(false)
      }
    }
  }, [hours])

  useEffect(() => {
    localStorage.setItem('codex_audit_hours', String(hours))
    setPage(1)
    setExpanded(new Set())
    void loadReport()
  }, [hours, loadReport, refreshToken])

  useEffect(() => {
    if (!report) return
    let cancelled = false
    setCasesLoading(true)
    setCases(null)
    setCasesError(null)
    void api.getRelayAuditCases({
      kind,
      start: report.window_start,
      end: report.window_end,
      page,
      pageSize: PAGE_SIZE,
    }).then((result) => {
      if (!cancelled) setCases(result)
    }).catch((err) => {
      if (!cancelled) setCasesError(getErrorMessage(err))
    }).finally(() => {
      if (!cancelled) setCasesLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [kind, page, report])

  const timeline = useMemo(() => (report?.timeline || []).map((point) => ({
    ...point,
    label: new Date(point.bucket).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
  })), [report?.timeline])

  const toggleExpanded = (requestID: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(requestID)) next.delete(requestID)
      else next.add(requestID)
      return next
    })
  }

  const summary = report?.summary
  const writerProblem = Boolean(report && (report.writer.dropped > 0 || report.writer.failed > 0))
  const totalPages = Math.max(1, Math.ceil((cases?.total || 0) / PAGE_SIZE))
  const firstRelayTriggers = Number(summary?.cyb_rule || 0)
    + Number(summary?.probe || 0)
    + Number(summary?.oauth_overflow || 0)
    + Number(summary?.cyb_feedback || 0)

  return (
    <>
      <PageHeader
        title="Codex 审计"
        description="独立查看 CYB/探针分流、OAuth 容量溢出、续接、漏放和每次实际调用的账号链路。"
        actions={(
          <>
            <div className="w-[150px]">
              <Select
                value={String(hours)}
                onValueChange={(value) => setHours(Number(value))}
                options={rangeOptions}
                compact
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => setRefreshToken((value) => value + 1)} disabled={loading}>
              <RefreshCw className={loading ? 'size-3.5 animate-spin' : 'size-3.5'} />
              刷新
            </Button>
          </>
        )}
      />

      <StateShell
        loading={loading && !report}
        error={error}
        isEmpty={!loading && !report}
        onRetry={() => void loadReport()}
        variant="page"
        emptyTitle="暂无审计数据"
      >
        {report ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
              <MetricCard
                icon={<Database />}
                label="审计请求总数"
                value={summary?.logical_requests}
                detail={writerProblem ? '写入异常，当前比例可能不完整' : '当前时间窗口的逻辑请求'}
                bad={writerProblem}
              />
              <MetricCard
                icon={<Route />}
                label="Relay 逻辑请求"
                value={summary?.relay_requests}
                detail={`实际占比 ${formatPercent(summary?.relay_requests, summary?.logical_requests)} · 上游尝试 ${formatNumber(summary?.route_attempts)}`}
              />
              <MetricCard
                icon={<Shuffle />}
                label="首次触发"
                value={firstRelayTriggers}
                detail={`占总请求 ${formatPercent(firstRelayTriggers, summary?.logical_requests)} · 不含续接`}
              />
              <MetricCard
                icon={<RefreshCw />}
                label="Relay 续接"
                value={summary?.relay_continuation}
                detail={`占总请求 ${formatPercent(summary?.relay_continuation, summary?.logical_requests)} · 不计入首次触发`}
              />
              <MetricCard icon={<ShieldAlert />} label="CYB 规则" value={summary?.cyb_rule} detail={`反馈分流 ${formatNumber(summary?.cyb_feedback)}`} />
              <MetricCard icon={<Activity />} label="探针分流" value={summary?.probe} detail="命中探针签名" />
              <MetricCard icon={<Shuffle />} label="OAuth 溢出" value={summary?.oauth_overflow} detail="无更高优先级候选" />
              <MetricCard icon={<CheckCircle2 />} label="Relay 成功" value={summary?.relay_successes} detail={`最终失败 ${formatNumber(summary?.relay_final_failures)}`} bad={Boolean(summary?.relay_final_failures)} />
              <MetricCard icon={<AlertTriangle />} label="OAuth CYB 漏放" value={summary?.oauth_cyber_misses} detail={`Relay CYB ${formatNumber(summary?.relay_cyber_policies)}`} bad={Boolean(summary?.oauth_cyber_misses)} />
              <MetricCard icon={<RefreshCw />} label="续接回放命中" value={summary?.replay_hits} detail={`未命中 ${formatNumber(summary?.replay_misses)} · 409 ${formatNumber(summary?.replay_unavailable)}`} bad={Boolean(summary?.replay_unavailable)} />
              <MetricCard icon={<ShieldAlert />} label="会话隔离异常" value={summary?.session_bleed} detail="跨请求内容违规计数" bad={Boolean(summary?.session_bleed)} />
            </div>

            <Card className="overflow-hidden">
              <CardContent className="p-4 sm:p-5">
                <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold">分流趋势</h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {formatBeijingTime(report.window_start)} 至 {formatBeijingTime(report.window_end)}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2 text-xs">
                    <Badge variant="outline">续接 {formatNumber(summary?.relay_continuation)}</Badge>
                    <Badge variant="outline">重试 {formatNumber(summary?.retries)}</Badge>
                    <Badge variant="outline">同组换号 {formatNumber(summary?.same_group_switches)}</Badge>
                    <Badge variant="outline">组耗尽 {formatNumber(summary?.group_exhausted)}</Badge>
                  </div>
                </div>
                <div className="h-[280px] min-w-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={timeline} margin={{ top: 8, right: 16, bottom: 0, left: -18 }}>
                      <CartesianGrid strokeDasharray="4 4" stroke="hsl(var(--border))" vertical={false} />
                      <XAxis dataKey="label" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                      <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                      <RechartsTooltip />
                      <Line type="monotone" dataKey="cyb_rule" name="CYB 规则" stroke="#16a34a" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="probe" name="探针" stroke="#7c3aed" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="oauth_overflow" name="OAuth 溢出" stroke="#d97706" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="relay_continuation" name="Relay 续接" stroke="#db2777" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="replay_misses" name="回放未命中" stroke="#f97316" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="oauth_cyber_misses" name="OAuth 漏放" stroke="#dc2626" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-4 xl:grid-cols-2">
              <AuditTableCard title="账号与分流结果" description="按实际选中账号和分流原因聚合，重试不会被当成新的逻辑请求。">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>账号</TableHead>
                      <TableHead>原因</TableHead>
                      <TableHead className="text-right">请求 / 尝试</TableHead>
                      <TableHead className="text-right">成功 / 4xx / 5xx</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(report.relay_routes || []).map((row) => (
                      <TableRow key={`${row.account_id}-${row.route_source}`}>
                        <TableCell>
                          <div className="font-medium">{row.account_name || `#${row.account_id}`}</div>
                          <div className="text-[11px] text-muted-foreground">{row.account_type || '-'}</div>
                        </TableCell>
                        <TableCell>{routeSourceLabel(row.route_source)}</TableCell>
                        <TableCell className="text-right tabular-nums">{formatNumber(row.requests)} / {formatNumber(row.attempts)}</TableCell>
                        <TableCell className="text-right tabular-nums">{formatNumber(row.successes)} / {formatNumber(row.errors_4xx)} / {formatNumber(row.errors_5xx)}</TableCell>
                      </TableRow>
                    ))}
                    {!report.relay_routes?.length ? <EmptyTable colSpan={4} label="当前窗口暂无 Relay 调用" /> : null}
                  </TableBody>
                </Table>
              </AuditTableCard>

              <AuditTableCard title="命中的分流规则" description="一条请求可命中多个规则，规则行数不能直接相加当成总请求数。">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>规则信号</TableHead>
                      <TableHead className="text-right">请求数</TableHead>
                      <TableHead className="text-right">最近出现</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(report.route_signals || []).map((row) => (
                      <TableRow key={row.signal}>
                        <TableCell className="font-mono text-xs">{row.signal}</TableCell>
                        <TableCell className="text-right tabular-nums">{formatNumber(row.requests)}</TableCell>
                        <TableCell className="text-right text-xs text-muted-foreground">{formatBeijingTime(row.last_seen)}</TableCell>
                      </TableRow>
                    ))}
                    {!report.route_signals?.length ? <EmptyTable colSpan={3} label="当前窗口暂无规则命中" /> : null}
                  </TableBody>
                </Table>
              </AuditTableCard>
            </div>

            <Card className="overflow-hidden">
              <CardContent className="p-4 sm:p-5">
                <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">详细案卷</h3>
                    <p className="mt-1 text-xs text-muted-foreground">展开可查看扫描到的请求正文、最终账号和每一次重试/换号。</p>
                  </div>
                  <div className="w-full sm:w-[180px]">
                    <Select
                      value={kind}
                      onValueChange={(value) => {
                        setKind(value as AuditKind)
                        setPage(1)
                        setExpanded(new Set())
                      }}
                      options={kindOptions}
                      compact
                    />
                  </div>
                </div>
                {casesError ? <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{casesError}</div> : null}
                {casesLoading && !cases ? <div className="py-8 text-center text-sm text-muted-foreground">正在加载案卷…</div> : null}
                <div className="space-y-2">
                  {(cases?.items || []).map((item) => (
                    <AuditCaseRow
                      key={item.request_id}
                      item={item}
                      open={expanded.has(item.request_id)}
                      onToggle={() => toggleExpanded(item.request_id)}
                    />
                  ))}
                  {!casesLoading && !cases?.items?.length ? <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">当前窗口没有这类案卷</div> : null}
                </div>
                <Pagination
                  page={page}
                  totalPages={totalPages}
                  onPageChange={setPage}
                  totalItems={cases?.total || 0}
                  pageSize={PAGE_SIZE}
                />
              </CardContent>
            </Card>

            <Card className={writerProblem ? 'border-amber-500/40' : ''}>
              <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4 text-xs">
                <div className="flex items-center gap-2">
                  <Database className="size-4 text-muted-foreground" />
                  <span className="font-medium">审计写入队列</span>
                  <span className="text-muted-foreground">待写 {formatNumber(report.writer.pending)} · 占用 {formatNumber(report.writer.retained_bytes)} B</span>
                </div>
                <div className={writerProblem ? 'text-amber-700 dark:text-amber-300' : 'text-muted-foreground'}>
                  完成 {formatNumber(report.writer.completed)} · 丢弃 {formatNumber(report.writer.dropped)} · 失败 {formatNumber(report.writer.failed)}
                </div>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </StateShell>
    </>
  )
}

function MetricCard({
  icon,
  label,
  value,
  detail,
  bad = false,
}: {
  icon: ReactNode
  label: string
  value?: number
  detail: string
  bad?: boolean
}) {
  return (
    <Card className={bad ? 'border-red-500/30' : ''}>
      <CardContent className="p-4">
        <div className="mb-3 flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary [&>svg]:size-4">{icon}</div>
        <div className="text-2xl font-semibold tabular-nums">{formatNumber(value)}</div>
        <div className="mt-1 text-xs font-medium">{label}</div>
        <div className="mt-1 text-[11px] text-muted-foreground">{detail}</div>
      </CardContent>
    </Card>
  )
}

function AuditTableCard({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="p-4 sm:p-5">
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="mb-3 mt-1 text-xs text-muted-foreground">{description}</p>
        <div className="overflow-x-auto">{children}</div>
      </CardContent>
    </Card>
  )
}

function EmptyTable({ colSpan, label }: { colSpan: number; label: string }) {
  return (
    <TableRow>
      <TableCell colSpan={colSpan} className="h-24 text-center text-muted-foreground">{label}</TableCell>
    </TableRow>
  )
}

function AuditCaseRow({ item, open, onToggle }: { item: RelayAuditCase; open: boolean; onToggle: () => void }) {
  const signals = parsedSignals(item.route_signals)
  const finalAccount = item.final_account_name || (item.final_account_id ? `#${item.final_account_id}` : '未记录')
  return (
    <div className="overflow-hidden rounded-xl border border-border/70 bg-background/60">
      <button type="button" onClick={onToggle} className="flex w-full min-w-0 items-center gap-2 px-3 py-3 text-left sm:gap-3">
        <Badge className={statusTone(item.final_status_code)}>{item.final_status_code || '未完成'}</Badge>
        <span className="hidden shrink-0 text-[11px] text-muted-foreground sm:inline">{formatBeijingTime(item.created_at)}</span>
        <span className="hidden shrink-0 text-xs font-medium md:inline">{routeSourceLabel(item.route_source)}</span>
        <span className="min-w-0 flex-1 truncate text-xs">{item.text_preview || '未保存请求预览'}</span>
        <span className="hidden max-w-40 truncate text-xs text-muted-foreground lg:inline">{finalAccount}</span>
        <ChevronDown className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open ? (
        <div className="space-y-3 border-t border-border/70 p-3">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>请求 {item.request_id}</span>
            <span>{item.endpoint || '-'} · {item.model || '-'}</span>
            <span>API Key {item.api_key_name || item.api_key_masked || `#${item.api_key_id || '-'}`}</span>
            <span>客户端 {item.client_ip || '-'}</span>
            <span>最终账号 {finalAccount}</span>
            <span>传输 {item.final_transport || '-'}</span>
            <span>尝试 {formatNumber(item.attempt_count)}</span>
            {item.has_previous_response_id ? <span>携带 previous_response_id</span> : null}
            {item.replay_status ? <span>回放 {item.replay_status}{item.replay_source ? ` / ${item.replay_source}` : ''}</span> : null}
            {item.scan_truncated ? <span className="text-amber-700 dark:text-amber-300">扫描内容已按上限截断</span> : null}
          </div>
          {signals.length ? (
            <div className="flex flex-wrap gap-1.5">
              {signals.map((signal) => <Badge key={signal} variant="outline" className="font-mono text-[10px]">{signal}</Badge>)}
            </div>
          ) : null}
          {item.attempts?.length ? (
            <div>
              <div className="mb-2 text-[11px] font-medium">上游尝试链路</div>
              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                {item.attempts.map((attempt, index) => (
                  <div key={`${attempt.id}-${attempt.attempt_index}`} className="contents">
                    {index ? <span className="text-muted-foreground">→</span> : null}
                    <span
                      className={`inline-flex max-w-full items-center gap-1.5 rounded-md border px-2 py-1 ${statusTone(attempt.status_code)}`}
                      title={attempt.error_message || attempt.error_kind}
                    >
                      <span className="max-w-44 truncate">{attempt.account_name || `#${attempt.account_id || '-'}`}</span>
                      <span className="font-mono">{attempt.status_code || '-'}</span>
                      <span className="opacity-70">第 {attempt.attempt_index} 次</span>
                      <span className="opacity-70">{attempt.via_websocket ? 'WS' : attempt.transport || 'HTTP'}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {item.final_error_message ? <div className="rounded-md border border-red-500/20 bg-red-500/[0.06] p-2.5 text-xs text-red-700 dark:text-red-300">{item.final_error_message}</div> : null}
          <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-muted/45 p-3 text-xs leading-5">{item.full_text || '（没有保存可展示的请求正文）'}</pre>
        </div>
      ) : null}
    </div>
  )
}
