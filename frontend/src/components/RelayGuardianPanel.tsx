import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  Clock3,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { api } from '../api'
import Pagination from './Pagination'
import { useConfirmDialog } from '../hooks/useConfirmDialog'
import { useToast } from '../hooks/useToast'
import {
  getRelayGuardianActionAvailability,
  getRelayGuardianEventLabel,
  getRelayGuardianReasonLabel,
  getRelayGuardianShadowActionMeta,
  getRelayGuardianStateMeta,
  getRelayGuardianTriggerLabel,
  resolveRelayGuardianAccountName,
  resolveRelayGuardianState,
  summarizeRelayGuardianEventDetails,
  type RelayGuardianTone,
} from '../lib/relayGuardian'
import type {
  AccountRow,
  RelayGuardianAccountStatus,
  RelayGuardianEvent,
  RelayGuardianEventsResponse,
  RelayGuardianStatusResponse,
} from '../types'
import { getErrorMessage } from '../utils/error'
import { formatBeijingTime } from '../utils/time'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

const PAGE_SIZE_OPTIONS = [10, 20, 50]

export default function RelayGuardianPanel({
  start,
  end,
  refreshToken,
  accounts,
}: {
  start: string
  end: string
  refreshToken: string
  accounts: AccountRow[]
}) {
  const [status, setStatus] = useState<RelayGuardianStatusResponse | null>(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [events, setEvents] = useState<RelayGuardianEventsResponse | null>(null)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [eventsError, setEventsError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [eventsRefresh, setEventsRefresh] = useState(0)
  const [actionAccountIDs, setActionAccountIDs] = useState<Set<number>>(() => new Set())
  const actionAccountIDsRef = useRef(new Set<number>())
  const statusRequestIDRef = useRef(0)
  const { showToast } = useToast()
  const { confirm, confirmDialog } = useConfirmDialog()

  const loadStatus = useCallback(async () => {
    const requestID = statusRequestIDRef.current + 1
    statusRequestIDRef.current = requestID
    setStatusLoading(true)
    setStatusError(null)
    try {
      const response = await api.getRelayGuardianStatus()
      if (statusRequestIDRef.current === requestID) setStatus(response)
    } catch (error) {
      if (statusRequestIDRef.current === requestID) setStatusError(getErrorMessage(error))
    } finally {
      if (statusRequestIDRef.current === requestID) setStatusLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadStatus()
  }, [loadStatus, refreshToken])

  useEffect(() => () => {
    statusRequestIDRef.current += 1
  }, [])

  useEffect(() => {
    setPage(1)
  }, [start, end, pageSize])

  useEffect(() => {
    let cancelled = false
    setEventsLoading(true)
    setEventsError(null)
    void api.getRelayGuardianEvents({ start, end, page, pageSize })
      .then((response) => {
        if (!cancelled) setEvents(response)
      })
      .catch((error) => {
        if (!cancelled) setEventsError(getErrorMessage(error))
      })
      .finally(() => {
        if (!cancelled) setEventsLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [start, end, page, pageSize, refreshToken, eventsRefresh])

  const operationMode = status?.enabled === false ? 'off' : (status?.mode ?? 'monitor')
  const isEnforce = operationMode === 'enforce'
  const stateCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const account of status?.accounts ?? []) {
      const state = resolveRelayGuardianState(account, account.manual_enabled)
      counts.set(state, (counts.get(state) ?? 0) + 1)
    }
    return counts
  }, [status?.accounts])
  const lastResortCount = useMemo(
    () => (status?.accounts ?? []).filter((account) => account.last_resort).length,
    [status?.accounts],
  )
  const currentAccountName = useCallback(
    (accountID: number, recordedName?: string | null) => resolveRelayGuardianAccountName(accountID, accounts, recordedName),
    [accounts],
  )

  const updateStatusAccount = useCallback((next: RelayGuardianAccountStatus) => {
    setStatus((current) => current ? {
      ...current,
      generated_at: new Date().toISOString(),
      accounts: current.accounts.map((account) => account.account_id === next.account_id ? next : account),
    } : current)
  }, [])

  const beginAccountAction = useCallback((accountID: number) => {
    if (actionAccountIDsRef.current.has(accountID)) return false
    actionAccountIDsRef.current.add(accountID)
    setActionAccountIDs(new Set(actionAccountIDsRef.current))
    return true
  }, [])

  const finishAccountAction = useCallback((accountID: number) => {
    actionAccountIDsRef.current.delete(accountID)
    setActionAccountIDs(new Set(actionAccountIDsRef.current))
  }, [])

  const handleRelease = useCallback(async (account: RelayGuardianAccountStatus) => {
    const accepted = await confirm({
      title: '解除 Guardian 运行态？',
      description: (
        <div className="space-y-2">
          <p>将清除 <strong>{currentAccountName(account.account_id, account.account_name)}</strong> 当前由 Guardian 创建的临时隔离或恢复阶段。</p>
          <p className="text-sm text-muted-foreground">不会修改账号的启用开关；若上游仍失败，后续请求仍可能再次触发临时隔离。</p>
        </div>
      ),
      confirmText: '确认解除',
      tone: 'warning',
    })
    if (!accepted) return
    if (!beginAccountAction(account.account_id)) return
    try {
      const next = await api.releaseRelayGuardianAccount(account.account_id, account.generation)
      updateStatusAccount(next)
      await loadStatus()
      showToast('Guardian 运行态已解除；事件将在刷新审计窗口后显示', 'success')
    } catch (error) {
      showToast(getErrorMessage(error), 'error')
      void loadStatus()
    } finally {
      finishAccountAction(account.account_id)
    }
  }, [beginAccountAction, confirm, currentAccountName, finishAccountAction, loadStatus, showToast, updateStatusAccount])

  const handleBypass = useCallback(async (account: RelayGuardianAccountStatus) => {
    const accepted = await confirm({
      title: '临时旁路 10 分钟？',
      description: (
        <div className="space-y-2">
          <p><strong>{currentAccountName(account.account_id, account.account_name)}</strong> 将在 10 分钟内绕过 Guardian 自动临时隔离。</p>
          <p className="text-sm text-muted-foreground">原账号启用开关和快熔断仍然生效；这是应急操作，不会改变账号启用开关，也不会形成永久放行。</p>
        </div>
      ),
      confirmText: '旁路 10 分钟',
      tone: 'warning',
    })
    if (!accepted) return
    if (!beginAccountAction(account.account_id)) return
    try {
      const next = await api.temporarilyBypassRelayGuardianAccount(account.account_id, account.generation, 10)
      updateStatusAccount(next)
      await loadStatus()
      showToast('已临时旁路 Guardian 10 分钟；事件将在刷新审计窗口后显示', 'success')
    } catch (error) {
      showToast(getErrorMessage(error), 'error')
      void loadStatus()
    } finally {
      finishAccountAction(account.account_id)
    }
  }, [beginAccountAction, confirm, currentAccountName, finishAccountAction, loadStatus, showToast, updateStatusAccount])

  const totalPages = Math.max(1, Math.ceil((events?.total ?? 0) / pageSize))

  return (
    <>
      <Card className="min-w-0 overflow-hidden border-border/70 shadow-sm">
        <CardContent className="min-w-0 p-4 sm:p-5">
          <div className="flex min-w-0 flex-col gap-3 border-b border-border/70 pb-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <div className={`mt-0.5 flex size-10 shrink-0 items-center justify-center rounded-xl ${isEnforce ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'}`}>
                {isEnforce ? <ShieldCheck className="size-5" /> : <ShieldAlert className="size-5" />}
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold text-foreground">Relay Health Guardian</h2>
                  <Badge className={isEnforce ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300'}>
                    {!status ? statusLoading ? '加载中' : '状态未知' : operationMode === 'off' ? '已关闭' : isEnforce ? '执行模式' : '监控模式'}
                  </Badge>
                </div>
                <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">
                  识别持续故障，并管理临时隔离与渐进恢复。
                </p>
              </div>
            </div>
            <Button variant="outline" size="sm" className="self-start" onClick={() => void loadStatus()} disabled={statusLoading}>
              <RefreshCw className={statusLoading ? 'size-3.5 animate-spin' : 'size-3.5'} />
              刷新状态
            </Button>
          </div>

          {status && !isEnforce ? (
            <div className="mt-4 flex items-start gap-2 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3 text-sm leading-6 text-amber-800 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              {operationMode === 'off' ? (
                <span><strong>Guardian 已关闭。</strong> 当前不执行慢性故障判断，也没有可解除或临时旁路的运行态。</span>
              ) : (
                <span><strong>监控模式：</strong>只记录建议动作，不改变账号调度。</span>
              )}
            </div>
          ) : null}

          {statusError ? (
            <div className="mt-4 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">{statusError}</div>
          ) : null}

          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <GuardianSummary label="受管账号" value={status?.accounts.length ?? 0} detail={`${status?.scan_interval_seconds ?? '-'} 秒扫描一次`} />
            <GuardianSummary label="需关注" value={(stateCounts.get('suspect') ?? 0) + (stateCounts.get('would_quarantine') ?? 0)} detail={`观察 ${stateCounts.get('suspect') ?? 0} · 建议隔离 ${stateCounts.get('would_quarantine') ?? 0}`} tone="warn" />
            <GuardianSummary label="恢复中" value={(stateCounts.get('quarantined') ?? 0) + (stateCounts.get('half_open') ?? 0) + (stateCounts.get('probation') ?? 0)} detail={`隔离 ${stateCounts.get('quarantined') ?? 0} · 探测/试运行 ${(stateCounts.get('half_open') ?? 0) + (stateCounts.get('probation') ?? 0)}`} tone="info" />
            <GuardianSummary label="最后兜底" value={lastResortCount} detail="仅在普通账号不可用时参与" tone={lastResortCount ? 'warn' : 'neutral'} />
          </div>

          <div className="mt-4 grid min-w-0 gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {(status?.accounts ?? []).map((account) => (
              <GuardianAccountCard
                key={account.account_id}
                account={account}
                accountName={currentAccountName(account.account_id, account.account_name)}
                mode={operationMode}
                busy={actionAccountIDs.has(account.account_id)}
                onRelease={() => void handleRelease(account)}
                onBypass={() => void handleBypass(account)}
              />
            ))}
            {!statusLoading && !statusError && (status?.accounts.length ?? 0) === 0 ? (
              <div className="col-span-full rounded-xl border border-border/60 bg-muted/20 p-6 text-center text-sm text-muted-foreground">暂无受管 Relay 账号</div>
            ) : null}
          </div>

          <div className="mt-4 flex flex-wrap gap-x-4 gap-y-1 border-t border-border/70 pt-3 text-[11px] text-muted-foreground">
            <span>状态生成：{status?.generated_at ? formatBeijingTime(status.generated_at) : '-'}</span>
            <span>Guardian 心跳：{status?.heartbeat_at ? formatBeijingTime(status.heartbeat_at) : '-'}</span>
            <span>人工禁用优先。</span>
          </div>
        </CardContent>
      </Card>

      <Card className="min-w-0 overflow-hidden border-border/70 shadow-sm">
        <CardContent className="min-w-0 p-4 sm:p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-foreground">Guardian 事件</h2>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">
                当前筛选窗口内的判断与恢复动作。
              </p>
              <p className="mt-1 text-xs text-muted-foreground">{formatBeijingTime(start)} 至 {formatBeijingTime(end)}</p>
            </div>
            <Button variant="outline" size="sm" className="self-start" onClick={() => setEventsRefresh((value) => value + 1)} disabled={eventsLoading}>
              <RefreshCw className={eventsLoading ? 'size-3.5 animate-spin' : 'size-3.5'} />
              刷新事件
            </Button>
          </div>

          {eventsError ? (
            <div className="mt-4 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">{eventsError}</div>
          ) : null}

          <div className="mt-4 space-y-2">
            {(events?.items ?? []).map((event) => <GuardianEventRow key={event.id} event={event} accounts={accounts} />)}
            {!eventsLoading && !eventsError && (events?.items.length ?? 0) === 0 ? (
              <div className="rounded-xl border border-border/60 bg-muted/20 p-6 text-center text-sm text-muted-foreground">当前筛选窗口内暂无 Guardian 事件</div>
            ) : null}
          </div>

          {(events?.total ?? 0) > 0 ? (
            <Pagination
              page={Math.min(page, totalPages)}
              totalPages={totalPages}
              onPageChange={setPage}
              totalItems={events?.total ?? 0}
              pageSize={pageSize}
              onPageSizeChange={setPageSize}
              pageSizeOptions={PAGE_SIZE_OPTIONS}
            />
          ) : null}
        </CardContent>
      </Card>
      {confirmDialog}
    </>
  )
}

function GuardianSummary({ label, value, detail, tone = 'neutral' }: { label: string; value: number; detail: string; tone?: RelayGuardianTone }) {
  return (
    <div className={`rounded-xl border p-3.5 ${tonePanelClass(tone)}`}>
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="mt-1.5 text-2xl font-semibold tabular-nums text-foreground">{value.toLocaleString('zh-CN')}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</div>
    </div>
  )
}

function GuardianAccountCard({
  account,
  accountName,
  mode,
  busy,
  onRelease,
  onBypass,
}: {
  account: RelayGuardianAccountStatus
  accountName: string
  mode: string
  busy: boolean
  onRelease: () => void
  onBypass: () => void
}) {
  const state = resolveRelayGuardianState(account, account.manual_enabled)
  const meta = getRelayGuardianStateMeta(state)
  const availability = getRelayGuardianActionAvailability(mode, account, account.manual_enabled)
  const shadow = account.shadow_action ? getRelayGuardianShadowActionMeta(account.shadow_action) : null
  const recoveryRequired = account.probation_required_successes || account.circuit_required_successes || 0
  const recoverySuccesses = account.probation_required_successes
    ? account.probation_successes
    : account.circuit_probe_successes
  const disabledReason = mode !== 'enforce'
    ? mode === 'off' ? 'Guardian 已关闭' : '监控模式只记录不执行'
    : availability.reason

  return (
    <article className={`flex min-w-0 flex-col rounded-xl border p-3.5 ${tonePanelClass(meta.tone)}`}>
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-foreground" title={accountName}>{accountName}</div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">运行态第 {account.generation} 代</div>
        </div>
        <Badge className={toneBadgeClass(meta.tone)}>{meta.label}</Badge>
      </div>

      <p className="mt-3 text-xs leading-5 text-muted-foreground">{account.reason ? getRelayGuardianReasonLabel(account.reason) : meta.description}</p>

      {shadow ? (
        <div className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.06] px-2.5 py-2 text-xs leading-5 text-amber-800 dark:text-amber-300">
          <strong>监控结论：{shadow.label}。</strong> {shadow.description}
        </div>
      ) : null}

      <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <GuardianField label="统计窗口" value={formatDuration(account.window_seconds)} />
        <GuardianField label="窗口失败" value={String(account.failure_count)} />
        <GuardianField label="用户可见失败" value={String(account.user_visible_failures)} />
        <GuardianField label="强网关失败" value={String(account.strong_gateway_failures)} />
        <GuardianField label="临时隔离至" value={account.quarantine_until ? formatBeijingTime(account.quarantine_until) : '-'} wide />
        <GuardianField label="恢复进度" value={recoveryRequired > 0 ? `${recoverySuccesses}/${recoveryRequired}${account.probation_percent > 0 ? ` · ${account.probation_percent}% 并发上限` : ''}` : '-'} wide />
        <GuardianField label="调度保护" value={account.last_resort ? `最后兜底 · 并发上限 ${account.last_resort_cap || '-'}` : '正常优先级'} wide />
        <GuardianField label="最近动作" value={account.last_action_at ? formatBeijingTime(account.last_action_at) : '-'} wide />
      </dl>

      <div className="mt-3 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
        <span className="rounded bg-background/70 px-1.5 py-0.5">当前{account.effective_schedulable ? '可调度' : '不可调度'}</span>
        <span className="rounded bg-background/70 px-1.5 py-0.5">触发源 {getRelayGuardianTriggerLabel(account.trigger_source)}</span>
        <span className="rounded bg-background/70 px-1.5 py-0.5">快熔断 {account.circuit_state || '-'}</span>
      </div>

      <div className="mt-auto grid grid-cols-2 gap-2 border-t border-border/60 pt-3">
        <Button variant="outline" size="sm" disabled={busy || !availability.canRelease} title={!availability.canRelease ? disabledReason || '当前状态无需解除' : '只解除 Guardian 运行态'} onClick={onRelease}>
          <RotateCcw className={busy ? 'size-3.5 animate-spin' : 'size-3.5'} />
          人工解除
        </Button>
        <Button variant="outline" size="sm" disabled={busy || !availability.canBypass} title={!availability.canBypass ? disabledReason || '当前已在临时旁路' : '10 分钟内绕过 Guardian 自动临时隔离'} onClick={onBypass}>
          <Clock3 className="size-3.5" />
          旁路 10 分钟
        </Button>
      </div>
    </article>
  )
}

function GuardianField({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={`min-w-0 rounded-lg border border-border/50 bg-background/60 px-2.5 py-2 ${wide ? 'col-span-2' : ''}`}>
      <dt className="text-[10px] text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words font-medium text-foreground" title={value}>{value}</dd>
    </div>
  )
}

function GuardianEventRow({ event, accounts }: { event: RelayGuardianEvent; accounts: AccountRow[] }) {
  const from = getRelayGuardianStateMeta(event.from_state)
  const to = getRelayGuardianStateMeta(event.to_state)
  const details = summarizeRelayGuardianEventDetails(event.details)
  const accountLabel = resolveRelayGuardianAccountName(event.account_id, accounts, event.account_name)
  const hasTransition = Boolean(event.from_state?.trim() || event.to_state?.trim())
  return (
    <article className="min-w-0 rounded-xl border border-border/60 bg-muted/15 p-3.5">
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Badge variant="outline" className="bg-background/80">{getRelayGuardianEventLabel(event.event_type)}</Badge>
            <span className="truncate text-sm font-semibold text-foreground">{accountLabel}</span>
            {hasTransition ? <span className="text-xs text-muted-foreground">{from.label} → {to.label}</span> : null}
          </div>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{getRelayGuardianReasonLabel(event.reason)}</p>
        </div>
        <time className="shrink-0 text-[11px] text-muted-foreground">{formatBeijingTime(event.created_at)}</time>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <GuardianField label="统计窗口" value={formatDuration(event.window_seconds)} />
        <GuardianField label="窗口失败" value={String(event.failure_count)} />
        <GuardianField label="用户可见" value={String(event.user_visible_failures)} />
        <GuardianField label="强网关" value={String(event.strong_gateway_failures)} />
      </div>

      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        <span>操作者 {actorLabel(event.actor)}</span>
        <span>触发源 {getRelayGuardianTriggerLabel(event.trigger_source)}</span>
        <span>隔离时长 {event.quarantine_seconds ? formatDuration(event.quarantine_seconds) : '-'}</span>
        <span>代次 {event.generation}</span>
        {(event.logical_request_ids?.length ?? 0) > 0 ? <span title={event.logical_request_ids?.join('\n')}>关联请求 {event.logical_request_ids?.length}</span> : null}
      </div>
      {details.summary ? (
        <div className="mt-2 rounded-lg border border-border/50 bg-background/70 px-2.5 py-2 text-xs leading-5 text-foreground">
          {details.summary}
        </div>
      ) : null}
      {details.raw && details.raw !== details.summary ? (
        <details className="mt-2 rounded-lg border border-border/50 bg-background/50 px-2.5 py-2 text-[11px] text-muted-foreground">
          <summary className="cursor-pointer select-none font-medium">高级详情（原始数据）</summary>
          <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[10px] leading-4">{details.raw}</pre>
        </details>
      ) : null}
    </article>
  )
}

function actorLabel(actor: string) {
  if (actor === 'guardian') return 'Guardian 自动化'
  if (actor === 'admin') return '管理员'
  if (actor === 'system') return '系统'
  return actor || '-'
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return '-'
  if (seconds % 3600 === 0) return `${seconds / 3600} 小时`
  if (seconds % 60 === 0) return `${seconds / 60} 分钟`
  return `${seconds} 秒`
}

function toneBadgeClass(tone: RelayGuardianTone) {
  if (tone === 'ok') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
  if (tone === 'warn') return 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300'
  if (tone === 'bad') return 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'
  if (tone === 'info') return 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300'
  return 'border-border bg-muted text-muted-foreground'
}

function tonePanelClass(tone: RelayGuardianTone) {
  if (tone === 'ok') return 'border-emerald-500/20 bg-emerald-500/[0.04]'
  if (tone === 'warn') return 'border-amber-500/25 bg-amber-500/[0.05]'
  if (tone === 'bad') return 'border-red-500/25 bg-red-500/[0.05]'
  if (tone === 'info') return 'border-sky-500/25 bg-sky-500/[0.05]'
  return 'border-border/60 bg-muted/15'
}
