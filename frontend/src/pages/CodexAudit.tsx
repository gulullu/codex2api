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
  RelayAuditCaseDetail,
  RelayAuditCasesPage,
  RelayAuditReport,
  RelayCYBLearningConfig,
  RelayCYBLearningSummary,
} from '../types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
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
  const [caseDetails, setCaseDetails] = useState<Record<string, RelayAuditCaseDetail>>({})
  const [caseDetailLoading, setCaseDetailLoading] = useState<Set<string>>(new Set())
  const [caseDetailErrors, setCaseDetailErrors] = useState<Record<string, string>>({})
  const [learningConfig, setLearningConfig] = useState<RelayCYBLearningConfig | null>(null)
  const [learningDraft, setLearningDraft] = useState({ enabled: false, model: '' })
  const [learningLoading, setLearningLoading] = useState(true)
  const [learningSaving, setLearningSaving] = useState(false)
  const [learningError, setLearningError] = useState<string | null>(null)
  const [learningSaved, setLearningSaved] = useState(false)
  const reportRequestSequence = useRef(0)
  const casePageGeneration = useRef(0)

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

  const loadLearningConfig = useCallback(async () => {
    setLearningLoading(true)
    setLearningError(null)
    try {
      const config = await api.getRelayCYBLearningConfig()
      setLearningConfig(config)
      setLearningDraft({ enabled: config.enabled, model: config.model || '' })
    } catch (err) {
      setLearningError(getErrorMessage(err))
    } finally {
      setLearningLoading(false)
    }
  }, [])

  useEffect(() => {
    localStorage.setItem('codex_audit_hours', String(hours))
    setPage(1)
    setExpanded(new Set())
    void loadReport()
  }, [hours, loadReport, refreshToken])

  useEffect(() => {
    void loadLearningConfig()
  }, [loadLearningConfig, refreshToken])

  useEffect(() => {
    if (!report) return
    let cancelled = false
    casePageGeneration.current += 1
    setCasesLoading(true)
    setCases(null)
    setCasesError(null)
    setExpanded(new Set())
    setCaseDetails({})
    setCaseDetailLoading(new Set())
    setCaseDetailErrors({})
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
    const opening = !expanded.has(requestID)
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(requestID)) next.delete(requestID)
      else next.add(requestID)
      return next
    })
    if (!opening || caseDetails[requestID] || caseDetailLoading.has(requestID)) return

    const generation = casePageGeneration.current
    setCaseDetailLoading((current) => new Set(current).add(requestID))
    setCaseDetailErrors((current) => {
      const next = { ...current }
      delete next[requestID]
      return next
    })
    void api.getRelayAuditCase(requestID).then((detail) => {
      if (generation !== casePageGeneration.current) return
      setCaseDetails((current) => ({ ...current, [requestID]: detail }))
    }).catch((err) => {
      if (generation !== casePageGeneration.current) return
      setCaseDetailErrors((current) => ({ ...current, [requestID]: getErrorMessage(err) }))
    }).finally(() => {
      if (generation !== casePageGeneration.current) return
      setCaseDetailLoading((current) => {
        const next = new Set(current)
        next.delete(requestID)
        return next
      })
    })
  }

  const saveLearningConfig = async () => {
    if (!learningConfig || learningSaving) return
    setLearningSaving(true)
    setLearningError(null)
    setLearningSaved(false)
    try {
      const config = await api.updateRelayCYBLearningConfig(learningDraft)
      setLearningConfig(config)
      setLearningDraft({ enabled: config.enabled, model: config.model || '' })
      setLearningSaved(true)
    } catch (err) {
      setLearningError(getErrorMessage(err))
    } finally {
      setLearningSaving(false)
    }
  }

  const summary = report?.summary
  const writerProblem = Boolean(report && (report.writer.dropped > 0 || report.writer.failed > 0))
  const totalPages = Math.max(1, Math.ceil((cases?.total || 0) / PAGE_SIZE))
  const firstRelayTriggers = Number(summary?.cyb_rule || 0)
    + Number(summary?.probe || 0)
    + Number(summary?.oauth_overflow || 0)
    + Number(summary?.cyb_feedback || 0)
  const learningChanged = Boolean(learningConfig)
    && (learningDraft.enabled !== learningConfig?.enabled || learningDraft.model !== (learningConfig?.model || ''))
  const learningModelAvailable = Boolean(learningDraft.model)
    && Boolean(learningConfig?.available_models?.includes(learningDraft.model))
  const learningModelOptions = useMemo(() => {
    return (learningConfig?.available_models || []).map((model) => ({ label: model, value: model }))
  }, [learningConfig?.available_models])

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
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-semibold">CYB 漏放自动学习</h3>
                      {learningConfig ? (
                        <Badge variant="outline" className={learningConfig.enabled
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                          : ''}>
                          {learningConfig.enabled ? '已开启' : '已关闭'}
                        </Badge>
                      ) : null}
                    </div>
                    <p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">
                      OAuth 实际触发 CYB 后异步总结规则；本地机械校验通过即自动启用。关闭开关会同时暂停学习与全部自动规则。学习请求固定使用下方 Relay 分组，并从审计、回放缓存与再次学习中排除。
                    </p>
                    {learningConfig ? (
                      <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                        <Badge variant="outline">等待 {formatNumber(learningConfig.stats?.queued)}</Badge>
                        <Badge variant="outline">处理中 {formatNumber(learningConfig.stats?.processing)}</Badge>
                        <Badge variant="outline">待重试 {formatNumber(learningConfig.stats?.retry)}</Badge>
                        <Badge variant="outline">已启用 {formatNumber(learningConfig.stats?.applied)}</Badge>
                        <Badge variant="outline">合并旧规则 {formatNumber(learningConfig.stats?.merged)}</Badge>
                        <Badge variant="outline">校验拒绝 {formatNumber(learningConfig.stats?.rejected)}</Badge>
                        <Badge variant="outline">失败 {formatNumber(learningConfig.stats?.failed)}</Badge>
                        <Badge variant="outline">规则 {formatNumber(learningConfig.stats?.rules)}</Badge>
                        {(learningConfig.sample_writer?.dropped || learningConfig.sample_writer?.failed) ? (
                          <Badge variant="outline" className="border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300">
                            样本写入异常 {formatNumber((learningConfig.sample_writer?.dropped || 0) + (learningConfig.sample_writer?.failed || 0))}
                          </Badge>
                        ) : null}
                      </div>
                    ) : null}
                  </div>

                  <div className="grid w-full shrink-0 gap-3 rounded-xl border border-border/70 bg-muted/20 p-3 sm:grid-cols-[auto_minmax(220px,1fr)_auto] sm:items-end xl:w-auto xl:min-w-[620px]">
                    <label className="flex h-9 items-center gap-2 text-xs font-medium">
                      <Switch
                        checked={learningDraft.enabled}
                        onCheckedChange={(enabled) => {
                          setLearningDraft((current) => ({ ...current, enabled }))
                          setLearningSaved(false)
                        }}
                        disabled={learningLoading || learningSaving || !learningConfig}
                        aria-label="开启 CYB 漏放自动学习"
                      />
                      自动学习
                    </label>
                    <div>
                      <div className="mb-1.5 text-[11px] font-medium text-muted-foreground">学习模型</div>
                      <Select
                        value={learningDraft.model}
                        onValueChange={(model) => {
                          setLearningDraft((current) => ({ ...current, model }))
                          setLearningSaved(false)
                        }}
                        options={learningModelOptions}
                        placeholder={learningLoading ? '正在加载…' : '请选择 Relay 模型'}
                        disabled={learningLoading || learningSaving || !learningConfig}
                        compact
                      />
                    </div>
                    <Button
                      size="sm"
                      onClick={() => void saveLearningConfig()}
                      disabled={!learningChanged || learningSaving || (learningDraft.enabled && !learningModelAvailable)}
                    >
                      {learningSaving ? '保存中…' : '保存'}
                    </Button>
                    <div className="sm:col-span-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                      <span>
                        Relay 分组（只读）：{learningConfig
                          ? learningConfig.relay_group_name || `#${learningConfig.relay_group_id || '-'}`
                          : '正在加载…'}
                      </span>
                      <span>
                        {learningConfig?.internal_requests_excluded ? '内部学习请求已隔离，不会二次触发 CYB' : '等待确认内部学习请求隔离状态'}
                      </span>
                      {learningDraft.model && !learningModelAvailable ? (
                        <span className="text-amber-700 dark:text-amber-300">
                          当前模型已不在 Relay 分组可调度列表中，请重新选择
                        </span>
                      ) : null}
                      {learningConfig?.updated_at ? <span>更新于 {formatBeijingTime(learningConfig.updated_at)}</span> : null}
                    </div>
                  </div>
                </div>
                {learningError ? <div className="mt-3 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{learningError}</div> : null}
                {learningSaved ? <div className="mt-3 text-xs text-emerald-700 dark:text-emerald-300">自动学习设置已保存。</div> : null}
                {learningConfig?.notifications?.length ? (
                  <div className="mt-4 rounded-xl border border-border/70 bg-muted/20 p-3">
                    <div className="mb-2 text-[11px] font-medium">最近 24 小时学习通知</div>
                    <div className="space-y-2">
                      {learningConfig.notifications.slice(0, 5).map((notification) => (
                        <div key={notification.id} className="flex flex-col gap-1 rounded-lg bg-background/70 px-3 py-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2 text-xs font-medium">
                              <span>{notification.title}</span>
                              {notification.count > 1 ? <Badge variant="outline">×{formatNumber(notification.count)}</Badge> : null}
                            </div>
                            <div className="mt-0.5 text-[11px] leading-5 text-muted-foreground">{notification.message}</div>
                          </div>
                          <span className="shrink-0 text-[10px] text-muted-foreground">{formatBeijingTime(notification.created_at)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </CardContent>
            </Card>

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
                      detail={caseDetails[item.request_id]}
                      detailLoading={caseDetailLoading.has(item.request_id)}
                      detailError={caseDetailErrors[item.request_id]}
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

function learningStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    queued: '等待学习',
    processing: '学习中',
    retry: '等待重试',
    applied: '规则已启用',
    merged: '已合并到旧规则',
    rejected: '机械校验未通过',
    failed: '学习失败',
    skipped: '已跳过',
  }
  const value = (status || '').trim()
  return labels[value] || value || '未进入学习'
}

function learningStatusTone(status?: string) {
  switch ((status || '').trim()) {
    case 'applied':
    case 'merged':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
    case 'failed':
    case 'rejected':
      return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'
    case 'processing':
    case 'retry':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300'
    default:
      return ''
  }
}

function accountLabel(account?: Pick<RelayCYBLearningSummary, 'account_id' | 'account_name'>) {
  if (!account) return ''
  if (account.account_name && account.account_id) return `${account.account_name} · #${account.account_id}`
  return account.account_name || (account.account_id ? `#${account.account_id}` : '')
}

function AuditCaseRow({
  item,
  detail,
  detailLoading,
  detailError,
  open,
  onToggle,
}: {
  item: RelayAuditCase
  detail?: RelayAuditCaseDetail
  detailLoading: boolean
  detailError?: string
  open: boolean
  onToggle: () => void
}) {
  const auditCase = detail?.case || item
  const learning = auditCase.cyb_learning || item.cyb_learning
  const miss = detail?.cyb_miss
  const rule = detail?.rule
  const signals = parsedSignals(auditCase.route_signals)
  const routedAccount = auditCase.final_account_name || (auditCase.final_account_id ? `#${auditCase.final_account_id}` : '未记录')
  const actualCYBAccount = accountLabel(learning) || accountLabel(miss)
  const displayedAccount = actualCYBAccount || routedAccount
  const requestText = miss?.redacted_request || auditCase.full_text
  const requestTruncated = miss?.request_truncated ?? learning?.request_truncated ?? auditCase.scan_truncated
  const learningStatus = miss?.learning_status || learning?.status || ''
  const learningModel = miss?.learning_model || learning?.model || rule?.model || ''
  const learningAttempts = miss?.learning_attempts ?? learning?.attempts
  const learningMessage = miss?.learning_error || learning?.message || ''
  return (
    <div className="overflow-hidden rounded-xl border border-border/70 bg-background/60">
      <button type="button" onClick={onToggle} className="flex w-full min-w-0 items-center gap-2 px-3 py-3 text-left sm:gap-3">
        <Badge className={statusTone(auditCase.final_status_code)}>{auditCase.final_status_code || '未完成'}</Badge>
        <span className="hidden shrink-0 text-[11px] text-muted-foreground sm:inline">{formatBeijingTime(auditCase.created_at)}</span>
        <span className="hidden shrink-0 text-xs font-medium md:inline">{routeSourceLabel(auditCase.route_source)}</span>
        <span className="min-w-0 flex-1 truncate text-xs">{auditCase.text_preview || '未保存请求预览'}</span>
        {learningStatus ? <Badge variant="outline" className={`hidden shrink-0 lg:inline-flex ${learningStatusTone(learningStatus)}`}>{learningStatusLabel(learningStatus)}</Badge> : null}
        <span className="hidden max-w-40 truncate text-xs text-muted-foreground xl:inline">{displayedAccount}</span>
        <ChevronDown className={`size-4 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open ? (
        <div className="space-y-3 border-t border-border/70 p-3">
          {detailLoading ? <div className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">正在加载完整案卷…</div> : null}
          {detailError ? <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">完整案卷加载失败：{detailError}</div> : null}
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
            <span>请求 {auditCase.request_id}</span>
            <span>{auditCase.endpoint || '-'} · {auditCase.model || '-'}</span>
            <span>API Key {auditCase.api_key_name || auditCase.api_key_masked || `#${auditCase.api_key_id || '-'}`}</span>
            <span>客户端 {auditCase.client_ip || '-'}</span>
            <span>最终路由账号 {routedAccount}</span>
            {actualCYBAccount ? <span className="font-medium text-foreground">实际触发 CYB 账号 {actualCYBAccount}</span> : null}
            {learning?.account_type || miss?.account_type ? <span>账号类型 {learning?.account_type || miss?.account_type}</span> : null}
            <span>传输 {auditCase.final_transport || '-'}</span>
            <span>尝试 {formatNumber(auditCase.attempt_count)}</span>
            {auditCase.has_previous_response_id ? <span>携带 previous_response_id</span> : null}
            {auditCase.replay_status ? <span>回放 {auditCase.replay_status}{auditCase.replay_source ? ` / ${auditCase.replay_source}` : ''}</span> : null}
            {requestTruncated ? <span className="text-amber-700 dark:text-amber-300">原始请求已按保存上限截断</span> : null}
          </div>
          {signals.length ? (
            <div className="flex flex-wrap gap-1.5">
              {signals.map((signal) => <Badge key={signal} variant="outline" className="font-mono text-[10px]">{signal}</Badge>)}
            </div>
          ) : null}
          {learningStatus ? (
            <div className="rounded-lg border border-border/70 bg-muted/20 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="text-[11px] font-medium">自动学习</div>
                <Badge variant="outline" className={learningStatusTone(learningStatus)}>{learningStatusLabel(learningStatus)}</Badge>
                {learningModel ? <Badge variant="outline">模型 {learningModel}</Badge> : null}
                {learningAttempts !== undefined ? <Badge variant="outline">尝试 {formatNumber(learningAttempts)}</Badge> : null}
                {miss?.next_attempt_at ? <span className="text-[11px] text-muted-foreground">下次重试 {formatBeijingTime(miss.next_attempt_at)}</span> : null}
                {miss?.learned_at ? <span className="text-[11px] text-muted-foreground">完成于 {formatBeijingTime(miss.learned_at)}</span> : null}
              </div>
              {learningMessage ? <div className="mt-2 text-xs text-red-700 dark:text-red-300">{learningMessage}</div> : null}
              {rule ? (
                <div className="mt-3 space-y-2 border-t border-border/70 pt-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-medium">启用规则：{rule.name || `#${rule.id}`}</span>
                    <Badge variant="outline" className={rule.enabled
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                      : 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300'}>
                      {rule.enabled ? '已启用' : '未启用'}
                    </Badge>
                    {rule.model ? <span className="text-[11px] text-muted-foreground">{rule.model}</span> : null}
                  </div>
                  <pre className="overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/45 p-2.5 font-mono text-[11px] leading-5">{rule.pattern || '（未保存规则表达式）'}</pre>
                  {rule.rationale ? <div className="text-xs leading-5 text-muted-foreground">{rule.rationale}</div> : null}
                  {rule.disabled_reason ? <div className="text-xs text-amber-700 dark:text-amber-300">{rule.disabled_reason}</div> : null}
                </div>
              ) : learning?.rule_id ? (
                <div className="mt-2 text-xs text-muted-foreground">启用规则：{learning.rule_name || `#${learning.rule_id}`}</div>
              ) : null}
            </div>
          ) : null}
          {auditCase.attempts?.length ? (
            <div>
              <div className="mb-2 text-[11px] font-medium">上游尝试链路</div>
              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                {auditCase.attempts.map((attempt, index) => (
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
          {auditCase.final_error_message ? <div className="rounded-md border border-red-500/20 bg-red-500/[0.06] p-2.5 text-xs text-red-700 dark:text-red-300">{auditCase.final_error_message}</div> : null}
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2 text-[11px] font-medium">
              <span>{miss ? '原始请求（已脱敏）' : '扫描到的请求正文（已脱敏）'}</span>
              {requestTruncated ? <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300">已截断</Badge> : null}
            </div>
            <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-muted/45 p-3 text-xs leading-5">
              {detailLoading && !requestText ? '（正在加载）' : requestText || '（没有保存可展示的请求正文）'}
            </pre>
          </div>
          {miss?.user_text ? (
            <details className="rounded-lg border border-border/70 bg-muted/20">
              <summary className="cursor-pointer px-3 py-2 text-[11px] font-medium">查看供模型总结的用户文本（已脱敏）</summary>
              <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap break-words border-t border-border/70 p-3 text-xs leading-5">{miss.user_text}</pre>
            </details>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
