import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

const sourceURL = new URL('../src/lib/codexAuditPresentation.ts', import.meta.url)
const source = await readFile(sourceURL, 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ES2022,
    target: ts.ScriptTarget.ES2020,
  },
  fileName: sourceURL.pathname,
})
const moduleURL = `data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`
const {
  calculateOperationalWindowHealthScore,
  calculateRelayWindowHealthScore,
  final5xxWindowRecentlyRecovered,
  formatCodexAuditHealthScore,
  getCodexAuditPresentation,
  getRelayWindowHealthStandard,
  operationalWindowRecentlyRecovered,
  relayWindowRecentlyRecovered,
} = await import(moduleURL)

test('health score formatting preserves threshold precision', () => {
  assert.equal(formatCodexAuditHealthScore(99.49), '99.49')
  assert.equal(formatCodexAuditHealthScore(94.99), '94.99')
  assert.equal(formatCodexAuditHealthScore(100), '100')
})

function presentation(overrides = {}) {
  return getCodexAuditPresentation({
    verdict: 'normal',
    totalRequests: 1000,
    final5xx: 0,
    relayRequests: 1000,
    relayRouteFailures: 0,
    healthStatus: 'ok',
    timeline: [],
    ...overrides,
  })
}

test('relay health score is 100 when no relay request failed', () => {
  assert.deepEqual(calculateRelayWindowHealthScore(2052, 0), { healthScore: 100, failureRate: 0 })
})

test('one failure among many requests stays above the stable threshold', () => {
  const result = calculateRelayWindowHealthScore(2052, 1)
  assert.equal(result.healthScore, 99.95)
  assert.ok(result.failureRate > 0 && result.failureRate < 0.001)
  assert.equal(presentation({ relayRequests: 2052, relayRouteFailures: 1 }).tone, 'ok')
})

test('health score remains bounded when legacy counts are inconsistent', () => {
  assert.deepEqual(calculateRelayWindowHealthScore(1, 2), { healthScore: 0, failureRate: 1 })
})

test('operational health score uses the worse of relay failures and site-wide final 5xx', () => {
  assert.deepEqual(calculateOperationalWindowHealthScore(1000, 20, 500, 5), {
    healthScore: 98,
    relayFailureRate: 0.01,
    final5xxRate: 0.02,
    worstFailureRate: 0.02,
  })
  assert.equal(calculateOperationalWindowHealthScore(1000, 2, 100, 4).healthScore, 96)
})

test('recent relay recovery requires two relay-active clean buckets', () => {
  assert.equal(relayWindowRecentlyRecovered([
    { requests: 3, relay_direct: 3, relay_route_failures: 1 },
    { requests: 0, relay_direct: 0, relay_route_failures: 0 },
    { requests: 8, relay_direct: 8, relay_route_failures: 0 },
  ]), false)
  assert.equal(relayWindowRecentlyRecovered([
    { requests: 3, relay_direct: 3, relay_route_failures: 1 },
    { requests: 8, relay_probe: 8, relay_route_failures: 0 },
    { requests: 9, relay_overflow: 9, relay_route_failures: 0 },
  ]), true)
})

test('OAuth-only clean buckets cannot prove relay recovery', () => {
  const timeline = [
    { requests: 3, relay_direct: 3, relay_route_failures: 1 },
    { requests: 8, relay_route_failures: 0 },
    { requests: 9, relay_route_failures: 0 },
  ]
  assert.equal(relayWindowRecentlyRecovered(timeline), false)
  assert.equal(operationalWindowRecentlyRecovered(timeline, 1, 0), false)
})

test('a relay failure bucket cannot disappear when its source counters are incomplete', () => {
  assert.equal(relayWindowRecentlyRecovered([
    { requests: 4, relay_direct: 4, relay_route_failures: 0 },
    { requests: 5, relay_probe: 5, relay_route_failures: 0 },
    { requests: 6, relay_route_failures: 1 },
  ]), false)
})

test('site-wide final 5xx recovery requires two globally active clean buckets', () => {
  const timeline = [
    { requests: 4, errors_5xx: 1 },
    { requests: 0, errors_5xx: 0 },
    { requests: 8, errors_5xx: 0 },
    { requests: 9, errors_5xx: 0 },
  ]
  assert.equal(final5xxWindowRecentlyRecovered(timeline), true)
  assert.equal(operationalWindowRecentlyRecovered(timeline, 0, 1), true)
})

test('an obsolete operational verdict cannot turn non-relay failures into a relay incident', () => {
  const result = presentation({ verdict: 'operational_issue', relayRouteFailures: 0 })
  assert.equal(result.label, '正常')
  assert.equal(result.tone, 'ok')
})

test('a recovered relay incident is shown as recovered instead of permanently red', () => {
  const result = presentation({
    relayRequests: 100,
    relayRouteFailures: 8,
    timeline: [
      { requests: 20, relay_direct: 20, relay_route_failures: 8 },
      { requests: 20, relay_direct: 20, relay_route_failures: 0 },
      { requests: 20, relay_direct: 20, relay_route_failures: 0 },
    ],
  })
  assert.equal(result.label, '已恢复')
  assert.equal(result.tone, 'ok')
  assert.match(result.description, /最近两个/)
})

test('a moderate relay failure ratio is a warning with a numeric score', () => {
  const result = presentation({ relayRequests: 100, relayRouteFailures: 3 })
  assert.equal(result.label, '需关注')
  assert.equal(result.tone, 'warn')
  assert.equal(result.healthScore, 97)
})

test('site-wide final 5xx can make the window unhealthy even when relay is clean', () => {
  const result = presentation({ totalRequests: 100, final5xx: 6, relayRequests: 80, relayRouteFailures: 0 })
  assert.equal(result.label, '运行异常')
  assert.equal(result.tone, 'bad')
  assert.equal(result.healthScore, 94)
  assert.match(result.description, /Relay 最终失败 0\/80/)
  assert.match(result.description, /全站最终 5xx 6\/100/)
})

test('a poor active window remains red until clean recent buckets prove recovery', () => {
  const result = presentation({ relayRequests: 100, relayRouteFailures: 12 })
  assert.equal(result.label, '运行异常')
  assert.equal(result.tone, 'bad')
  assert.match(result.description, /红色阈值/)
})

test('a non-ok live health check is always a current red incident', () => {
  const result = presentation({ healthStatus: 'degraded' })
  assert.equal(result.label, '当前异常')
  assert.equal(result.tone, 'bad')
})

test('guardian degraded with relay capacity remaining is a yellow fluctuation', () => {
  const result = presentation({
    guardianStatus: 'degraded',
    relayConfigured: 3,
    relaySchedulable: 3,
  })
  assert.equal(result.label, '检测到波动')
  assert.equal(result.tone, 'warn')
  assert.match(result.description, /3\/3.*可调度/)
})

test('a minor relay failure plus guardian degradation stays yellow instead of red', () => {
  const result = presentation({
    relayRequests: 1000,
    relayRouteFailures: 1,
    guardianStatus: 'degraded',
    relayConfigured: 3,
    relaySchedulable: 2,
  })
  assert.equal(result.label, '检测到波动')
  assert.equal(result.tone, 'warn')
  assert.match(result.description, /2\/3.*容量尚在/)
})

test('zero schedulable relay capacity is a current red incident', () => {
  const result = presentation({
    relayConfigured: 3,
    relaySchedulable: 0,
  })
  assert.equal(result.label, '当前异常')
  assert.equal(result.tone, 'bad')
  assert.match(result.description, /没有可调度账号/)
})

test('present relay health with no configured account is red and says unconfigured', () => {
  const result = presentation({ relayConfigured: 0, relaySchedulable: 0 })
  assert.equal(result.label, '当前异常')
  assert.equal(result.tone, 'bad')
  assert.match(result.description, /未配置 Relay 账号/)
})

test('present relay health with zero schedulable is red even without a configured count', () => {
  const result = presentation({ relaySchedulable: 0 })
  assert.equal(result.label, '当前异常')
  assert.equal(result.tone, 'bad')
})

test('clean recent buckets turn green only after guardian degradation clears', () => {
  const timeline = [
    { requests: 10, relay_direct: 10, relay_route_failures: 2 },
    { requests: 10, relay_direct: 10, relay_route_failures: 0 },
    { requests: 10, relay_direct: 10, relay_route_failures: 0 },
  ]
  assert.equal(presentation({ relayRequests: 30, relayRouteFailures: 2, timeline, guardianStatus: 'degraded', relayConfigured: 3, relaySchedulable: 3 }).tone, 'bad')
  assert.equal(presentation({ relayRequests: 30, relayRouteFailures: 2, timeline, guardianStatus: 'healthy', relayConfigured: 3, relaySchedulable: 3 }).label, '已恢复')
})

test('security and routing invariants take precedence over quality scoring', () => {
  assert.equal(presentation({ oauthCyberAttempts: 1 }).label, 'OAuth CYB')
  assert.equal(presentation({ routeInvariantViolations: 1 }).label, '路由越界')
  assert.equal(presentation({ sessionBleed: 1 }).label, '会话串扰')
})

test('relay cyber policy is quality warning and not an operational failure', () => {
  const result = presentation({ relayCyberAttempts: 2 })
  assert.equal(result.label, 'Relay 策略')
  assert.equal(result.tone, 'warn')
  assert.match(result.description, /不计入.*运行故障/)
})

test('health score standards are explicit and stable', () => {
  assert.deepEqual(getRelayWindowHealthStandard(), {
    stableScore: 99.5,
    attentionScore: 95,
    description: '运行健康分按 Relay 最终失败率与全站最终 5xx 率中较高者计算；99.5 分及以上稳定，95–99.4 分需关注，低于 95 分为窗口质量异常。',
  })
})
