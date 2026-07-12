import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

const sourceURL = new URL('../src/lib/relayGuardian.ts', import.meta.url)
const source = await readFile(sourceURL, 'utf8')
const panelSource = await readFile(new URL('../src/components/RelayGuardianPanel.tsx', import.meta.url), 'utf8')
const auditPageSource = await readFile(new URL('../src/pages/CodexAudit.tsx', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ES2022,
    target: ts.ScriptTarget.ES2020,
  },
  fileName: sourceURL.pathname,
})
const moduleURL = `data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`
const {
  buildRelayGuardianEventsQuery,
  getRelayGuardianActionAvailability,
  getRelayGuardianEventLabel,
  getRelayGuardianReasonLabel,
  getRelayGuardianShadowActionMeta,
  getRelayGuardianStateMeta,
  getRelayGuardianTriggerLabel,
  mergeRelayGuardianAccounts,
  resolveRelayGuardianAccountName,
  resolveRelayGuardianState,
  summarizeRelayGuardianEventDetails,
} = await import(moduleURL)

function guardianAccount(overrides = {}) {
  return {
    account_id: 51,
    account_name: 'relay-51',
    manual_enabled: true,
    state: 'quarantined',
    effective_schedulable: false,
    reason: 'two user-visible failures in ten minutes',
    trigger_source: 'slow_failure_window',
    generation: 7,
    window_seconds: 600,
    failure_count: 2,
    user_visible_failures: 2,
    strong_gateway_failures: 0,
    would_quarantine: false,
    quarantine_until: '2026-07-12T19:00:00+08:00',
    backoff_level: 0,
    probation_percent: 0,
    probation_successes: 0,
    probation_required_successes: 20,
    circuit_state: 'closed',
    circuit_probe_successes: 0,
    circuit_required_successes: 3,
    ...overrides,
  }
}

test('manual account disable always wins over guardian runtime state', () => {
  const status = guardianAccount({ state: 'healthy', manual_enabled: true })
  assert.equal(resolveRelayGuardianState(status, false), 'manual_disabled')

  const [merged] = mergeRelayGuardianAccounts(
    [{ id: 51, enabled: false, openai_responses_api: true }],
    {
      enabled: true,
      mode: 'enforce',
      generated_at: '2026-07-12T18:00:00+08:00',
      scan_interval_seconds: 60,
      accounts: [status],
    },
  )
  assert.equal(merged.relay_guardian.state, 'manual_disabled')
  assert.equal(merged.relay_guardian.effective_schedulable, false)
})

test('monitor mode describes would-quarantine but disables runtime actions', () => {
  const status = guardianAccount({ state: 'would_quarantine', would_quarantine: true })
  const availability = getRelayGuardianActionAvailability('monitor', status, true)

  assert.equal(getRelayGuardianStateMeta(status.state).label, '本应临时隔离')
  assert.equal(availability.canRelease, false)
  assert.equal(availability.canBypass, false)
  assert.match(availability.reason, /只记录不执行/)
})

test('off mode disables every runtime action', () => {
  const availability = getRelayGuardianActionAvailability('off', guardianAccount(), true)
  assert.equal(availability.canRelease, false)
  assert.equal(availability.canBypass, false)
  assert.match(availability.reason, /已关闭/)
})

test('enforce mode allows generation-guarded recovery actions only where useful', () => {
  const quarantined = getRelayGuardianActionAvailability('enforce', guardianAccount(), true)
  assert.equal(quarantined.canRelease, true)
  assert.equal(quarantined.canBypass, true)

  const halfOpen = getRelayGuardianActionAvailability(
    'enforce',
    guardianAccount({ state: 'half_open' }),
    true,
  )
  assert.equal(halfOpen.canRelease, false)
  assert.equal(halfOpen.canBypass, true)

  const probation = getRelayGuardianActionAvailability(
    'enforce',
    guardianAccount({ state: 'probation', probation_percent: 10 }),
    true,
  )
  assert.equal(probation.canRelease, false)
  assert.equal(probation.canBypass, true)

  const suspect = getRelayGuardianActionAvailability('enforce', guardianAccount({ state: 'suspect' }), true)
  assert.equal(suspect.canRelease, false)
  assert.equal(suspect.canBypass, false)

  const healthy = getRelayGuardianActionAvailability(
    'enforce',
    guardianAccount({ state: 'healthy', effective_schedulable: true }),
    true,
  )
  assert.equal(healthy.canRelease, false)
  assert.equal(healthy.canBypass, false)
})

test('event query carries the audit window and pagination exactly', () => {
  const query = new URLSearchParams(buildRelayGuardianEventsQuery({
    start: '2026-07-12T17:00:00+08:00',
    end: '2026-07-12T18:00:00+08:00',
    page: 3,
    pageSize: 5,
  }))

  assert.equal(query.get('start'), '2026-07-12T17:00:00+08:00')
  assert.equal(query.get('end'), '2026-07-12T18:00:00+08:00')
  assert.equal(query.get('page'), '3')
  assert.equal(query.get('page_size'), '5')
})

test('guardian event pagination defaults to five and keeps compact and larger choices', () => {
  assert.match(panelSource, /const PAGE_SIZE_OPTIONS = \[1, 5, 10, 20, 50\]/)
  assert.match(panelSource, /const \[pageSize, setPageSize\] = useState\(5\)/)
})

test('core guardian event names have operator-friendly Chinese labels', () => {
  assert.equal(getRelayGuardianEventLabel('quarantined'), '临时隔离')
  assert.equal(getRelayGuardianEventLabel('manual_release'), '人工解除')
  assert.equal(getRelayGuardianEventLabel('bypass'), '临时旁路')
  assert.equal(getRelayGuardianEventLabel('probation_10'), '试运行 10%')
  assert.equal(getRelayGuardianEventLabel('probation_50'), '试运行 50%')
  assert.equal(getRelayGuardianEventLabel('temporary_bypass_expired'), '临时旁路到期')
  assert.equal(getRelayGuardianEventLabel('last_resort'), '降为最后兜底')
  assert.equal(getRelayGuardianEventLabel('pool_wide'), 'Relay 池级关联故障')
  assert.equal(getRelayGuardianEventLabel('summary'), '5 分钟状态汇总')
  assert.equal(getRelayGuardianEventLabel('audit'), '每小时完整审计')
})

test('monitor shadow actions explain the action enforce mode would take', () => {
  assert.equal(getRelayGuardianShadowActionMeta('quarantine').label, '本应临时隔离')
  assert.equal(getRelayGuardianShadowActionMeta('last_resort').label, '本应降为最后兜底')
  assert.equal(getRelayGuardianShadowActionMeta('pool_alert').label, 'Relay 池级关联故障')
  assert.match(getRelayGuardianShadowActionMeta('pool_alert').description, /不.*批量隔离/)
})

test('current account name overrides stale guardian event names', () => {
  assert.equal(resolveRelayGuardianAccountName(50, [
    { id: 50, name: '主 Relay 账号', email: 'old@example.com' },
  ], 'relay-50'), '主 Relay 账号')
})

test('account rename is reflected by the latest accounts response', () => {
  const before = [{ id: 50, name: '旧名称', email: '' }]
  const after = [{ id: 50, name: '新名称', email: '' }]
  assert.equal(resolveRelayGuardianAccountName(50, before, 'relay-50'), '旧名称')
  assert.equal(resolveRelayGuardianAccountName(50, after, 'relay-50'), '新名称')
})

test('generic relay-number names are not exposed when current account is unavailable', () => {
  assert.equal(resolveRelayGuardianAccountName(51, [], 'relay-51'), '账号 #51')
  assert.equal(resolveRelayGuardianAccountName(0, [], ''), 'Relay 池')
})

test('real historical names remain a safe fallback for deleted accounts', () => {
  assert.equal(resolveRelayGuardianAccountName(53, [], '备用供应商'), '备用供应商')
})

test('periodic summary details are converted to operator-friendly Chinese', () => {
  const result = summarizeRelayGuardianEventDetails({
    counts: { configured: 3, healthy: 3 },
    event_time: '2026-07-13T01:27:26.254707597+08:00',
    mode: 'monitor',
    window_id: '2026-07-12T17:25:00Z/5m',
  })
  assert.match(result.summary, /共 3 个账号，健康 3/)
  assert.match(result.summary, /监控（只记录，不调整调度）/)
  assert.match(result.summary, /统计周期：5 分钟/)
  assert.match(result.raw, /"configured": 3/)
})

test('periodic summary includes temporary bypass accounts', () => {
  const result = summarizeRelayGuardianEventDetails({
    counts: { configured: 3, healthy: 2, temporary_bypass: 1 },
    window_id: '2026-07-13T01:25:00Z/5m',
  })
  assert.match(result.summary, /临时旁路 1/)
})

test('hourly audit and pool correlation fields receive readable summaries', () => {
  const audit = summarizeRelayGuardianEventDetails({ audit_rows: 81, incremental_rows: 5, window_id: '2026-07-13T01:00:00Z/1h' })
  assert.match(audit.summary, /增量 5 条，小时复核 81 条/)
  assert.match(audit.summary, /1 小时/)

  const pool = summarizeRelayGuardianEventDetails({ affected: 2, enabled: 3, protected_until: '2026-07-13T02:00:00+08:00' })
  assert.match(pool.summary, /2\/3 个账号/)
  assert.match(pool.summary, /池级保护至/)
})

test('known guardian reasons and triggers are translated', () => {
  assert.equal(getRelayGuardianReasonLabel('periodic_summary'), '周期状态汇总')
  assert.equal(getRelayGuardianReasonLabel('upstream_http_502'), '上游返回 HTTP 502')
  assert.equal(getRelayGuardianReasonLabel('last_available_relay'), '仅剩当前 Relay 账号，无法安全隔离')
  assert.equal(getRelayGuardianReasonLabel('capacity_warmup'), '容量基线预热中，暂不自动隔离')
  assert.equal(getRelayGuardianReasonLabel('insufficient_remaining_capacity'), '隔离后剩余并发不足，已降为最后兜底')
  assert.equal(getRelayGuardianTriggerLabel('user_visible_2_in_10m'), '10 分钟内 2 个用户可见失败')
  assert.equal(getRelayGuardianTriggerLabel('strong_gateway_3_in_5m'), '5 分钟内 3 个强网关失败')
  assert.equal(getRelayGuardianTriggerLabel('user_visible_4_in_60m'), '60 分钟内 4 个用户可见失败')
  assert.equal(getRelayGuardianTriggerLabel('recovery_failure_502'), '恢复阶段再次收到 HTTP 502')
  assert.equal(getRelayGuardianTriggerLabel('probation_complete'), '试运行完成')
  assert.equal(getRelayGuardianTriggerLabel('manual_release'), '管理员手动解除')
  assert.equal(getRelayGuardianTriggerLabel('temporary_bypass'), '管理员临时旁路')
})

test('guardian refresh controls delegate to the parent audit reload', () => {
  assert.match(panelSource, /onRefresh: \(\) => void \| Promise<unknown>/)
  assert.match(panelSource, /await onRefresh\(\)/)
  assert.match(auditPageSource, /<RelayGuardianPanel[\s\S]*?onRefresh=\{reload\}/)
})
