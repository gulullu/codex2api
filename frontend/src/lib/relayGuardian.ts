import type {
  AccountRow,
  RelayGuardianAccountStatus,
  RelayGuardianMode,
  RelayGuardianState,
  RelayGuardianStatusResponse,
} from '../types'

export type RelayGuardianTone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral'

export const relayGuardianStateMeta: Record<RelayGuardianState, {
  label: string
  description: string
  tone: RelayGuardianTone
}> = {
  healthy: {
    label: '健康',
    description: '当前未达到慢性故障阈值，可正常参与 Relay 调度。',
    tone: 'ok',
  },
  suspect: {
    label: '观察中',
    description: '仅观察，不影响调度；尚未达到临时隔离条件。',
    tone: 'warn',
  },
  would_quarantine: {
    label: '本应临时隔离',
    description: '监控模式已命中临时隔离条件，但只记录，不改变调度。',
    tone: 'warn',
  },
  quarantined: {
    label: '临时隔离',
    description: '账号暂不参与 Relay 调度，等待隔离到期和恢复探测。',
    tone: 'bad',
  },
  half_open: {
    label: '恢复探测',
    description: '临时隔离到期，当前只放行受控探测请求。',
    tone: 'info',
  },
  probation: {
    label: '试运行',
    description: '恢复探测通过，正在按受限流量验证稳定性。',
    tone: 'info',
  },
  temporary_bypass: {
    label: '临时旁路',
    description: '人工暂时绕过 Guardian 自动临时隔离，原账号开关不变。',
    tone: 'warn',
  },
  manual_disabled: {
    label: '人工禁用',
    description: '原账号开关已关闭，人工设置优先于 Guardian 运行态。',
    tone: 'neutral',
  },
}

export function getRelayGuardianStateMeta(state?: string | null) {
  const known = state as RelayGuardianState
  return relayGuardianStateMeta[known] ?? {
    label: state?.trim() || '状态未知',
    description: '后台返回了尚未识别的 Guardian 状态。',
    tone: 'neutral' as const,
  }
}

export function getRelayGuardianShadowActionMeta(action?: string | null) {
  const actions: Record<string, { label: string; description: string }> = {
    quarantine: {
      label: '本应临时隔离',
      description: '若切换到执行模式，本轮会暂时停止该账号参与调度。',
    },
    last_resort: {
      label: '本应降为最后兜底',
      description: '当前容量不足以安全隔离；执行模式会把该账号降到最后优先级并限制并发。',
    },
    pool_alert: {
      label: 'Relay 池级关联故障',
      description: '同类故障同时影响多个账号，执行模式也只告警，不会批量隔离。',
    },
  }
  return actions[action || ''] ?? {
    label: action?.trim() || '无影子动作',
    description: action ? '后台返回了尚未识别的监控结论。' : '当前没有达到需要执行动作的阈值。',
  }
}

export function resolveRelayGuardianState(
  status?: RelayGuardianAccountStatus | null,
  accountEnabled = true,
): RelayGuardianState {
  if (!accountEnabled || status?.manual_enabled === false) return 'manual_disabled'
  return status?.state ?? 'healthy'
}

export function getRelayGuardianRecoveryProgress(
  status: RelayGuardianAccountStatus,
  accountEnabled = status.manual_enabled,
) {
  const state = resolveRelayGuardianState(status, accountEnabled)
  if (state === 'probation') {
    const successes = Math.max(0, status.probation_successes || 0)
    const required = Math.max(0, status.probation_required_successes || 0)
    const progress = required > 0 ? `${successes}/${required}` : '试运行中'
    return status.probation_percent > 0 ? `${progress} · ${status.probation_percent}% 并发上限` : progress
  }
  if (status.circuit_state === 'half_open') {
    const successes = Math.max(0, status.circuit_probe_successes || 0)
    const required = Math.max(0, status.circuit_required_successes || 0)
    return required > 0 ? `${successes}/${required}` : '恢复探测中'
  }
  if (state === 'half_open') return '恢复探测中'
  return '-'
}

export function getRelayGuardianWeakConfirmation(status: RelayGuardianAccountStatus) {
  const count = Math.max(0, status.weak_confirmation_count || 0)
  const required = Math.max(0, status.weak_confirmation_required || 0)
  if (
    resolveRelayGuardianState(status, status.manual_enabled) === 'suspect'
    && status.reason === 'weak_reliability_confirming'
    && required > 0
    && count > 0
    && count < required
  ) return `${count}/${required}`
  return '-'
}

export function formatRelayGuardianFailureRate(status: RelayGuardianAccountStatus) {
  if (!Number.isFinite(status.reliability_total) || status.reliability_total <= 0) return '-'
  const rate = Number.isFinite(status.failure_rate_percent) ? Math.max(0, status.failure_rate_percent) : 0
  const lowerBound = Number.isFinite(status.failure_rate_lower_bound_percent)
    ? Math.max(0, status.failure_rate_lower_bound_percent)
    : 0
  const formatPercent = (value: number) => value.toLocaleString('zh-CN', { maximumFractionDigits: 2 })
  return `${formatPercent(rate)}% · 可信下限 ${formatPercent(lowerBound)}%`
}

export function getRelayGuardianActionAvailability(
  mode: RelayGuardianMode,
  status?: RelayGuardianAccountStatus | null,
  accountEnabled = true,
) {
  const state = resolveRelayGuardianState(status, accountEnabled)
  if (mode === 'off') {
    return {
      canRelease: false,
      canBypass: false,
      reason: 'Guardian 已关闭，没有可解除或旁路的运行态。',
    }
  }
  if (mode !== 'enforce') {
    return {
      canRelease: false,
      canBypass: false,
      reason: '监控模式只记录不执行，没有可解除或旁路的运行态。',
    }
  }
  if (state === 'manual_disabled') {
    return {
      canRelease: false,
      canBypass: false,
      reason: '账号已由人工禁用，请使用原账号开关处理。',
    }
  }
  // 人工解除只把自动隔离推进到半开；其余恢复状态没有安全的重复解除语义。
  const releasable = new Set<RelayGuardianState>(['quarantined'])
  const bypassable = new Set<RelayGuardianState>([
    'quarantined',
    'half_open',
    'probation',
  ])
  return {
    canRelease: releasable.has(state),
    canBypass: bypassable.has(state),
    reason: state === 'healthy'
      ? '账号当前健康，无需解除或临时旁路。'
      : '',
  }
}

export function mergeRelayGuardianAccounts(
  accounts: AccountRow[],
  guardian: RelayGuardianStatusResponse | null,
): AccountRow[] {
  if (!guardian) return accounts
  const byID = new Map(guardian.accounts.map((status) => [status.account_id, status]))
  return accounts.map((account) => {
    const status = byID.get(account.id)
    if (!status) return account
    if (account.enabled !== false && status.manual_enabled !== false) {
      return { ...account, relay_guardian: status }
    }
    return {
      ...account,
      relay_guardian: {
        ...status,
        manual_enabled: false,
        state: 'manual_disabled',
        effective_schedulable: false,
      },
    }
  })
}

export function buildRelayGuardianEventsQuery(params: {
  start: string
  end: string
  page: number
  pageSize: number
}) {
  const search = new URLSearchParams()
  search.set('start', params.start)
  search.set('end', params.end)
  search.set('page', String(params.page))
  search.set('page_size', String(params.pageSize))
  return search.toString()
}

export function getRelayGuardianEventLabel(eventType: string) {
  const labels: Record<string, string> = {
    observed: '故障观测',
    failure_observed: '故障观测',
    suspect: '进入观察',
    suspected: '进入观察',
    would_quarantine: '本应临时隔离',
    quarantine: '临时隔离',
    quarantined: '临时隔离',
    half_open: '恢复探测',
    half_open_started: '恢复探测',
    probation: '进入试运行',
    probation_10: '试运行 10%',
    probation_50: '试运行 50%',
    recovered: '恢复健康',
    healthy: '恢复健康',
    release: '人工解除',
    manual_release: '人工解除',
    bypass: '临时旁路',
    temporary_bypass: '临时旁路',
    bypass_expired: '临时旁路到期',
    temporary_bypass_expired: '临时旁路到期',
    last_resort: '降为最后兜底',
    pool_wide: 'Relay 池级关联故障',
    summary: '5 分钟状态汇总',
    audit: '每小时完整审计',
  }
  return labels[eventType] || eventType || 'Guardian 事件'
}

export function resolveRelayGuardianAccountName(
  accountID: number,
  currentAccounts: Array<Pick<AccountRow, 'id' | 'name' | 'email'>>,
  recordedName?: string | null,
) {
  if (accountID <= 0) return 'Relay 池'
  const current = currentAccounts.find((account) => account.id === accountID)
  const currentName = current?.name?.trim() || current?.email?.trim()
  if (currentName) return currentName
  const historical = (recordedName || '').trim()
  if (historical && !/^relay-\d+$/i.test(historical)) return historical
  return `账号 #${accountID}`
}

export function getRelayGuardianReasonLabel(reason?: string | null) {
  const value = (reason || '').trim()
  const labels: Record<string, string> = {
    periodic_summary: '周期状态汇总',
    hourly_full_audit: '每小时完整复核',
    pool_wide_failure_guard: '多个账号出现同类故障，已启用池级保护',
    one_quarantine_per_scan_guard: '本轮已隔离其他账号，当前账号降为最后兜底',
    shadow_quarantine: '已达到临时隔离条件（监控模式未执行）',
    runtime_state_unavailable: 'Guardian 运行态暂不可用',
    mode_transition: 'Guardian 运行模式已切换',
    last_available_relay: '仅剩当前 Relay 账号，无法安全隔离',
    capacity_warmup: '容量基线预热中，暂不自动隔离',
    insufficient_remaining_capacity: '隔离后剩余并发不足，已降为最后兜底',
    recent_failure_observed: '近期出现上游失败，继续观察',
    weak_reliability_confirming: '弱失败率偏高，等待下一窗口确认',
    weak_reliability_below_threshold: '弱失败率低于隔离阈值',
  }
  if (labels[value]) return labels[value]
  const upstream = value.match(/^upstream_http_(\d{3})$/)
  if (upstream) return `上游返回 HTTP ${upstream[1]}`
  const recovery = value.match(/^recovery_upstream_http_(\d{3})$/)
  if (recovery) return `恢复探测返回 HTTP ${recovery[1]}`
  return value || '未记录原因'
}

export function getRelayGuardianTriggerLabel(trigger?: string | null) {
  const value = (trigger || '').trim()
  const labels: Record<string, string> = {
    '5m': '5 分钟周期汇总',
    '1h': '1 小时完整复核',
    user_visible_10m: '10 分钟内用户可见失败',
    user_visible_60m: '60 分钟内用户可见失败',
    strong_gateway_5m: '5 分钟内强网关失败',
    recovery_failure: '恢复阶段再次失败',
    user_visible_2_in_10m: '10 分钟内 2 个用户可见失败',
    strong_gateway_3_in_5m: '5 分钟内 3 个强网关失败',
    user_visible_4_in_60m: '60 分钟内 4 个用户可见失败',
    weak_reliability_10m: '10 分钟弱失败率可信偏高',
    weak_reliability_60m: '60 分钟弱失败率持续偏高',
    weak_reliability_catastrophic_10m: '10 分钟弱失败集中爆发',
    catastrophic_10m: '10 分钟弱失败集中爆发',
    user_visible_rate_10m: '10 分钟弱失败率可信偏高',
    user_visible_rate_60m: '60 分钟弱失败率持续偏高',
    probation_complete: '试运行完成',
    manual_release: '管理员手动解除',
    temporary_bypass: '管理员临时旁路',
  }
  if (labels[value]) return labels[value]
  const recovery = value.match(/^recovery_failure_(\d{3})$/)
  if (recovery) return `恢复阶段再次收到 HTTP ${recovery[1]}`
  return value.replace(/_/g, ' ') || '-'
}

type GuardianDetails = Record<string, unknown>

function parseGuardianDetails(details: unknown): { value: GuardianDetails | null; raw: string } {
  if (details === null || details === undefined || details === '') return { value: null, raw: '' }
  if (typeof details === 'string') {
    const raw = details.trim()
    if (!raw) return { value: null, raw: '' }
    try {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { value: parsed as GuardianDetails, raw: JSON.stringify(parsed, null, 2) }
      }
    } catch {
      return { value: null, raw }
    }
    return { value: null, raw }
  }
  try {
    const raw = JSON.stringify(details, null, 2)
    return {
      value: details && typeof details === 'object' && !Array.isArray(details) ? details as GuardianDetails : null,
      raw,
    }
  } catch {
    return { value: null, raw: String(details) }
  }
}

function detailNumber(value: unknown) {
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) ? number : 0
}

function formatDetailTime(value: unknown) {
  if (!value) return ''
  const date = new Date(String(value))
  if (Number.isNaN(date.getTime())) return String(value)
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

function formatWindowID(value: unknown) {
  const text = String(value || '').trim()
  if (!text) return ''
  const token = text.includes('/') ? text.slice(text.lastIndexOf('/') + 1) : text
  const match = token.match(/^(\d+)(m|h|s)$/i)
  if (!match) return text
  const unit = match[2].toLowerCase() === 'h' ? '小时' : match[2].toLowerCase() === 'm' ? '分钟' : '秒'
  return `${match[1]} ${unit}`
}

function modeLabel(value: unknown) {
  if (value === 'monitor') return '监控（只记录，不调整调度）'
  if (value === 'enforce') return '执行'
  if (value === 'off') return '关闭'
  return value ? String(value) : ''
}

function countSummary(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const counts = value as GuardianDetails
  const configured = detailNumber(counts.configured)
  const healthy = detailNumber(counts.healthy)
  const parts = [`共 ${configured} 个账号`, `健康 ${healthy}`]
  const labels: Array<[string, string]> = [
    ['suspect', '观察中'],
    ['would_quarantine', '本应隔离'],
    ['quarantined', '已隔离'],
    ['half_open', '恢复探测'],
    ['probation', '试运行'],
    ['temporary_bypass', '临时旁路'],
    ['last_resort', '最后兜底'],
    ['manual_disabled', '人工禁用'],
    ['unknown', '状态未知'],
  ]
  for (const [key, label] of labels) {
    const count = detailNumber(counts[key])
    if (count > 0) parts.push(`${label} ${count}`)
  }
  return parts.join('，')
}

export function summarizeRelayGuardianEventDetails(details: unknown) {
  const parsed = parseGuardianDetails(details)
  const value = parsed.value
  if (!value) return { summary: parsed.raw, raw: parsed.raw }
  const parts: string[] = []
  const counts = countSummary(value.counts)
  if (counts) parts.push(`账号状态：${counts}`)
  const mode = modeLabel(value.mode)
  if (mode) parts.push(`运行模式：${mode}`)
  const affected = detailNumber(value.affected)
  const enabled = detailNumber(value.enabled)
  if (affected > 0 || enabled > 0) parts.push(`同类故障影响：${affected}/${enabled} 个账号`)
  const auditRows = detailNumber(value.audit_rows)
  const incrementalRows = detailNumber(value.incremental_rows)
  if (auditRows > 0 || incrementalRows > 0) parts.push(`扫描记录：增量 ${incrementalRows} 条，小时复核 ${auditRows} 条`)
  const probationPercent = detailNumber(value.probation_percent)
  if (probationPercent > 0) parts.push(`试运行流量：${probationPercent}%`)
  const shadow = getRelayGuardianShadowActionMeta(String(value.shadow_action || ''))
  if (value.shadow_action) parts.push(`监控结论：${shadow.label}`)
  const protectedUntil = formatDetailTime(value.protected_until)
  if (protectedUntil) parts.push(`池级保护至：${protectedUntil}`)
  const quarantineUntil = formatDetailTime(value.quarantine_until)
  if (quarantineUntil && !String(value.quarantine_until).startsWith('0001-')) parts.push(`临时隔离至：${quarantineUntil}`)
  const window = formatWindowID(value.window_id)
  if (window) parts.push(`统计周期：${window}`)
  return { summary: parts.join('；') || '已记录 Guardian 运行详情', raw: parsed.raw }
}
