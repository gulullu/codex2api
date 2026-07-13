export type CodexAuditTone = 'ok' | 'warn' | 'bad' | 'neutral'

export interface CodexAuditOperationalInput {
  verdict?: string | null
  totalRequests: number
  final5xx: number
  relayRequests: number
  relayRouteFailures: number
  oauthCyberAttempts?: number
  relayCyberAttempts?: number
  routeInvariantViolations?: number
  sessionBleed?: number
  healthStatus?: string | null
  guardianStatus?: string | null
  relayConfigured?: number
  relaySchedulable?: number
  timeline?: Array<{
    requests?: number
    errors_5xx?: number
    relay_requests?: number
    relay_direct?: number
    relay_pinned?: number
    relay_probe?: number
    relay_overflow?: number
    relay_continuation?: number
    relay_legacy_unknown?: number
    relay_route_failures?: number
  }>
}

export interface CodexAuditPresentation {
  label: string
  title: string
  description: string
  tone: CodexAuditTone
  healthScore: number
  relayFailureRate: number
  final5xxRate: number
  worstFailureRate: number
  recentRecovered: boolean
}

export type CodexAuditFindingKey = 'oauth_cyber' | 'route_safety' | 'session_bleed' | 'metadata_conflict'

export interface CodexAuditFindingInput {
  oauthCyberRequests?: number
  oauthCyberAttempts?: number
  routeInvariantViolations?: number
  routePoolViolations?: number
  encryptedOwnerViolations?: number
  sessionBleed?: number
  routeMetadataConflicts?: number
}

export interface CodexAuditFinding {
  key: CodexAuditFindingKey
  label: string
  value: number
  detail: string
  tone: CodexAuditTone
}

const operationalThresholds = {
  stableScore: 99.5,
  attentionScore: 95,
}

function finiteCount(value: number | undefined) {
  return Number.isFinite(value) && (value ?? 0) > 0 ? Number(value) : 0
}

function percent(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0%'
  if (value >= 1) return '100%'
  const percentage = value * 100
  return `${percentage >= 10 ? percentage.toFixed(1) : percentage.toFixed(2)}%`
}

export function formatCodexAuditHealthScore(value: number) {
  return Number.isInteger(value) ? String(value) : value.toFixed(2)
}

export function calculateRelayWindowHealthScore(relayRequests: number, relayRouteFailures: number) {
  const failures = finiteCount(relayRouteFailures)
  const requests = Math.max(finiteCount(relayRequests), failures, 1)
  const failureRate = Math.min(1, failures / requests)
  const healthScore = Math.round((100 - failureRate * 100) * 100) / 100
  return { healthScore, failureRate }
}

export function calculateOperationalWindowHealthScore(
  totalRequests: number,
  final5xx: number,
  relayRequests: number,
  relayRouteFailures: number,
) {
  const { failureRate: relayFailureRate } = calculateRelayWindowHealthScore(relayRequests, relayRouteFailures)
  const finalFailures = finiteCount(final5xx)
  const requests = Math.max(finiteCount(totalRequests), finalFailures, 1)
  const final5xxRate = Math.min(1, finalFailures / requests)
  const worstFailureRate = Math.max(relayFailureRate, final5xxRate)
  const healthScore = Math.round((100 - worstFailureRate * 100) * 100) / 100
  return { healthScore, relayFailureRate, final5xxRate, worstFailureRate }
}

function timelineRelayRequests(point: NonNullable<CodexAuditOperationalInput['timeline']>[number]) {
  const explicit = finiteCount(point.relay_requests)
  if (explicit > 0) return explicit
  return finiteCount(point.relay_direct)
    + finiteCount(point.relay_pinned)
    + finiteCount(point.relay_probe)
    + finiteCount(point.relay_overflow)
    + finiteCount(point.relay_continuation)
    + finiteCount(point.relay_legacy_unknown)
}

function hasCleanActiveBuckets(
  timeline: CodexAuditOperationalInput['timeline'],
  active: (point: NonNullable<CodexAuditOperationalInput['timeline']>[number]) => boolean,
  failed: (point: NonNullable<CodexAuditOperationalInput['timeline']>[number]) => boolean,
  requiredBuckets: number,
) {
  if (!timeline || requiredBuckets <= 0) return false
  const activeBuckets = timeline.filter(active)
  if (activeBuckets.length < requiredBuckets) return false
  return activeBuckets.slice(-requiredBuckets).every((point) => !failed(point))
}

export function relayWindowRecentlyRecovered(
  timeline: CodexAuditOperationalInput['timeline'],
  requiredBuckets = 2,
) {
  return hasCleanActiveBuckets(
    timeline,
    (point) => timelineRelayRequests(point) > 0 || finiteCount(point.relay_route_failures) > 0,
    (point) => finiteCount(point.relay_route_failures) > 0,
    requiredBuckets,
  )
}

export function final5xxWindowRecentlyRecovered(
  timeline: CodexAuditOperationalInput['timeline'],
  requiredBuckets = 2,
) {
  return hasCleanActiveBuckets(
    timeline,
    (point) => finiteCount(point.requests) > 0 || finiteCount(point.errors_5xx) > 0,
    (point) => finiteCount(point.errors_5xx) > 0,
    requiredBuckets,
  )
}

export function operationalWindowRecentlyRecovered(
  timeline: CodexAuditOperationalInput['timeline'],
  relayRouteFailures: number,
  final5xx: number,
  requiredBuckets = 2,
) {
  const needsRelayRecovery = finiteCount(relayRouteFailures) > 0
  const needsFinal5xxRecovery = finiteCount(final5xx) > 0
  if (!needsRelayRecovery && !needsFinal5xxRecovery) return false
  return (!needsRelayRecovery || relayWindowRecentlyRecovered(timeline, requiredBuckets))
    && (!needsFinal5xxRecovery || final5xxWindowRecentlyRecovered(timeline, requiredBuckets))
}

export function getCodexAuditFindings(input: CodexAuditFindingInput): CodexAuditFinding[] {
  const oauthCyberAttempts = finiteCount(input.oauthCyberAttempts)
  const oauthCyberRequests = finiteCount(input.oauthCyberRequests) || oauthCyberAttempts
  const severeUnion = finiteCount(input.routeInvariantViolations)
  const routePool = finiteCount(input.routePoolViolations)
  const encryptedOwner = finiteCount(input.encryptedOwnerViolations)
  const sessionBleed = finiteCount(input.sessionBleed)
  const metadata = finiteCount(input.routeMetadataConflicts)
  const routeBreakdown = routePool > 0 || encryptedOwner > 0
    ? `跨池异常 ${routePool} · 加密归属异常 ${encryptedOwner}`
    : `严重约束 ${severeUnion}`

  return [
    {
      key: 'oauth_cyber',
      label: 'OAuth 漏放',
      value: oauthCyberRequests,
      detail: oauthCyberRequests > 0 ? `${oauthCyberAttempts} 次 OAuth 上游 cyber_policy 拦截，需复盘本地路由。` : '未发现 OAuth 上游策略拦截。',
      tone: oauthCyberRequests > 0 ? 'bad' : 'ok',
    },
    {
      key: 'route_safety',
      label: '路由安全约束',
      value: severeUnion,
      detail: severeUnion > 0 ? routeBreakdown : '未发现账号池越界或加密归属冲突。',
      tone: severeUnion > 0 ? 'bad' : 'ok',
    },
    {
      key: 'session_bleed',
      label: '会话串扰',
      value: sessionBleed,
      detail: sessionBleed > 0 ? '检测到响应标识不一致，需立即复盘。' : '未检测到会话响应标识串扰。',
      tone: sessionBleed > 0 ? 'bad' : 'ok',
    },
    {
      key: 'metadata_conflict',
      label: '审计字段冲突',
      value: metadata,
      detail: metadata > 0 ? '路由审计字段缺失或不一致，不等同于账号池越界。' : '路由审计字段一致。',
      tone: metadata > 0 ? 'warn' : 'ok',
    },
  ]
}

export function getCodexAuditPresentation(input: CodexAuditOperationalInput): CodexAuditPresentation {
  const relayFailures = finiteCount(input.relayRouteFailures)
  const relayRequests = finiteCount(input.relayRequests)
  const final5xx = finiteCount(input.final5xx)
  const totalRequests = finiteCount(input.totalRequests)
  const { healthScore, relayFailureRate, final5xxRate, worstFailureRate } = calculateOperationalWindowHealthScore(
    totalRequests,
    final5xx,
    relayRequests,
    relayFailures,
  )
  const hasWindowFailures = relayFailures > 0 || final5xx > 0
  const recentRecovered = hasWindowFailures && operationalWindowRecentlyRecovered(input.timeline, relayFailures, final5xx)
  const liveStatus = (input.healthStatus || '').trim().toLowerCase()
  const liveHealthy = liveStatus === 'ok'
  const guardianStatus = (input.guardianStatus || '').trim().toLowerCase()
  const guardianDegraded = Boolean(guardianStatus && !['healthy', 'ok', 'disabled'].includes(guardianStatus))
  const relayHealthPresent = input.relayConfigured !== undefined || input.relaySchedulable !== undefined
  const relayConfigured = finiteCount(input.relayConfigured)
  const relaySchedulable = finiteCount(input.relaySchedulable)
  const relayCapacityUnavailable = relayHealthPresent && relaySchedulable === 0
  const liveUnhealthy = Boolean(liveStatus && !liveHealthy) || relayCapacityUnavailable
  const base = { healthScore, relayFailureRate, final5xxRate, worstFailureRate, recentRecovered }
  const measurements = `Relay 最终失败 ${relayFailures}/${relayRequests}（${percent(relayFailureRate)}）；全站最终 5xx ${final5xx}/${totalRequests}（${percent(final5xxRate)}）；运行健康分 ${formatCodexAuditHealthScore(healthScore)}。`

  if (liveUnhealthy) {
    const liveReason = relayCapacityUnavailable
      ? relayConfigured === 0
        ? '当前未配置 Relay 账号'
        : `当前 ${relayConfigured} 个 Relay 账号中没有可调度账号`
      : `实时健康检查为 ${liveStatus}`
    return {
      ...base,
      label: '当前异常',
      title: '服务当前未处于健康状态',
      description: `${liveReason}；${measurements}`,
      tone: 'bad',
    }
  }
  if (hasWindowFailures) {
    if (liveHealthy && recentRecovered && !guardianDegraded) {
      return {
        ...base,
        label: '已恢复',
        title: '窗口历史波动已恢复',
        description: `${measurements} 相应来源最近两个活跃时间段均无同类失败，实时健康正常。`,
        tone: 'ok',
      }
    }
    if (guardianDegraded && healthScore >= operationalThresholds.attentionScore) {
      return {
        ...base,
        label: '检测到波动',
        title: 'Guardian 检测到 Relay 波动',
        description: `${measurements} 当前仍有 ${relaySchedulable}/${relayConfigured} 个 Relay 账号可调度，服务容量尚在。`,
        tone: 'warn',
      }
    }
    if (healthScore >= operationalThresholds.stableScore) {
      return {
        ...base,
        label: '轻微波动',
        title: liveHealthy ? '服务当前正常，窗口内有轻微波动' : '窗口内有轻微波动',
        description: `${measurements}${liveHealthy ? ' 实时健康正常。' : ''}`,
        tone: 'ok',
      }
    }
    if (healthScore >= operationalThresholds.attentionScore) {
      return {
        ...base,
        label: '需关注',
        title: liveHealthy ? '服务当前正常，窗口质量需关注' : '窗口质量需关注',
        description: `${measurements}${liveHealthy ? ' 实时健康正常。' : ''}`,
        tone: 'warn',
      }
    }
    return {
      ...base,
      label: '运行异常',
      title: '窗口运行质量异常',
      description: `${measurements}${liveHealthy ? ' 实时接口仍可用，但失败率已超过红色阈值。' : ''}`,
      tone: 'bad',
    }
  }
  if (guardianDegraded) {
    return {
      ...base,
      label: '检测到波动',
      title: 'Guardian 检测到 Relay 波动',
      description: `当前仍有 ${relaySchedulable}/${relayConfigured} 个 Relay 账号可调度，服务容量尚在。`,
      tone: 'warn',
    }
  }
  return {
    ...base,
    label: '正常',
    title: '服务运行态势稳定',
    description: liveHealthy ? '筛选窗口内未发现运行故障，实时健康正常。' : '筛选窗口内未发现 Relay 或全站最终 5xx 运行故障。',
    tone: 'ok',
  }
}

export function getRelayWindowHealthStandard() {
  return {
    stableScore: operationalThresholds.stableScore,
    attentionScore: operationalThresholds.attentionScore,
    description: '运行健康分按 Relay 最终失败率与全站最终 5xx 率中较高者计算；99.5 分及以上稳定，95–99.4 分需关注，低于 95 分为窗口质量异常。',
  }
}
