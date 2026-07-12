export type CodexAuditTone = 'ok' | 'warn' | 'bad' | 'neutral'

export interface CodexAuditOperationalInput {
  verdict?: string | null
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
  recentRecovered: boolean
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

function scoreLabel(value: number) {
  if (value > 99.9 && value < 100) return value.toFixed(2)
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}

export function calculateRelayWindowHealthScore(relayRequests: number, relayRouteFailures: number) {
  const failures = finiteCount(relayRouteFailures)
  const requests = Math.max(finiteCount(relayRequests), failures, 1)
  const failureRate = Math.min(1, failures / requests)
  const healthScore = Math.round((100 - failureRate * 100) * 100) / 100
  return { healthScore, failureRate }
}

export function relayWindowRecentlyRecovered(
  timeline: CodexAuditOperationalInput['timeline'],
  requiredBuckets = 2,
) {
  if (!timeline || requiredBuckets <= 0) return false
  const activeBuckets = timeline.filter((point) => finiteCount(point.requests) > 0)
  if (activeBuckets.length < requiredBuckets) return false
  return activeBuckets
    .slice(-requiredBuckets)
    .every((point) => finiteCount(point.relay_route_failures) === 0)
}

export function getCodexAuditPresentation(input: CodexAuditOperationalInput): CodexAuditPresentation {
  const relayFailures = finiteCount(input.relayRouteFailures)
  const relayRequests = finiteCount(input.relayRequests)
  const { healthScore, failureRate: relayFailureRate } = calculateRelayWindowHealthScore(relayRequests, relayFailures)
  const recentRecovered = relayFailures > 0 && relayWindowRecentlyRecovered(input.timeline)
  const liveStatus = (input.healthStatus || '').trim().toLowerCase()
  const liveHealthy = liveStatus === 'ok'
  const guardianStatus = (input.guardianStatus || '').trim().toLowerCase()
  const guardianDegraded = Boolean(guardianStatus && !['healthy', 'ok', 'disabled'].includes(guardianStatus))
  const relayConfigured = finiteCount(input.relayConfigured)
  const relaySchedulable = finiteCount(input.relaySchedulable)
  const relayCapacityUnavailable = relayConfigured > 0 && relaySchedulable === 0
  const liveUnhealthy = Boolean(liveStatus && !liveHealthy) || relayCapacityUnavailable
  const base = { healthScore, relayFailureRate, recentRecovered }

  if (finiteCount(input.oauthCyberAttempts) > 0) {
    return {
      ...base,
      label: 'OAuth CYB',
      title: '发现 OAuth 漏放',
      description: '受保护 OAuth 账号返回了上游安全策略拦截，请优先复盘路由。',
      tone: 'bad',
    }
  }
  if (finiteCount(input.routeInvariantViolations) > 0) {
    return {
      ...base,
      label: '路由越界',
      title: 'Relay 隔离约束被破坏',
      description: '发现请求落错账号池或审计字段冲突，请立即排查。',
      tone: 'bad',
    }
  }
  if (finiteCount(input.sessionBleed) > 0) {
    return {
      ...base,
      label: '会话串扰',
      title: '发现会话响应标识不一致',
      description: '窗口内检测到会话串扰信号，请立即排查。',
      tone: 'bad',
    }
  }
  if (liveUnhealthy) {
    const liveReason = relayCapacityUnavailable
      ? `当前 ${relayConfigured} 个 Relay 账号中没有可调度账号`
      : `实时健康检查为 ${liveStatus}`
    return {
      ...base,
      label: '当前异常',
      title: '服务当前未处于健康状态',
      description: `${liveReason}；窗口 Relay 失败 ${relayFailures}/${relayRequests}，健康分 ${scoreLabel(healthScore)}。`,
      tone: 'bad',
    }
  }
  if (relayFailures > 0) {
    const measurements = `窗口 Relay 失败 ${relayFailures}/${relayRequests}（${percent(relayFailureRate)}），健康分 ${scoreLabel(healthScore)}。`
    if (liveHealthy && recentRecovered && !guardianDegraded) {
      return {
        ...base,
        label: '已恢复',
        title: 'Relay 历史波动已恢复',
        description: `${measurements} 最近两个有请求的时间段未再出现 Relay 失败，实时健康正常。`,
        tone: 'ok',
      }
    }
    if (guardianDegraded && healthScore >= operationalThresholds.attentionScore) {
      return {
        ...base,
        label: '检测到波动',
        title: 'Guardian 检测到 Relay 波动',
        description: `${measurements}当前仍有 ${relaySchedulable}/${relayConfigured} 个 Relay 账号可调度，服务容量尚在。`,
        tone: 'warn',
      }
    }
    if (healthScore >= operationalThresholds.stableScore) {
      return {
        ...base,
        label: '轻微波动',
        title: liveHealthy ? 'Relay 当前正常，窗口内有轻微波动' : 'Relay 窗口内有轻微波动',
        description: `${measurements}${liveHealthy ? ' 实时健康正常。' : ''}`,
        tone: 'ok',
      }
    }
    if (healthScore >= operationalThresholds.attentionScore) {
      return {
        ...base,
        label: '需关注',
        title: liveHealthy ? 'Relay 当前正常，窗口质量需关注' : 'Relay 窗口质量需关注',
        description: `${measurements}${liveHealthy ? ' 实时健康正常。' : ''}`,
        tone: 'warn',
      }
    }
    return {
      ...base,
      label: '运行异常',
      title: 'Relay 窗口质量异常',
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
  if (finiteCount(input.relayCyberAttempts) > 0) {
    return {
      ...base,
      label: 'Relay 策略',
      title: 'Relay 上游出现安全策略拦截',
      description: '仅影响 Relay 供应商质量分析，不计入 OAuth 漏放或运行故障。',
      tone: 'warn',
    }
  }

  return {
    ...base,
    label: '正常',
    title: 'Relay 路由态势稳定',
    description: liveHealthy ? '筛选窗口内无 Relay 失败，实时健康正常。' : '筛选窗口内未发现 Relay 失败或安全路由异常。',
    tone: 'ok',
  }
}

export function getRelayWindowHealthStandard() {
  return {
    stableScore: operationalThresholds.stableScore,
    attentionScore: operationalThresholds.attentionScore,
    description: '健康分按 100 ×（1 − Relay 最终失败数 ÷ Relay 请求数）计算；99.5 分及以上稳定，95–99.4 分需关注，低于 95 分为窗口质量异常。',
  }
}
