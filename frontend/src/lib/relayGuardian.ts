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
    description: '已出现可归因故障，但尚未达到临时隔离阈值。',
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
