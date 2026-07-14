import assert from 'node:assert/strict'
import test from 'node:test'

import { formatAuditScanCoverage, stripLegacyAuditAttribution } from './codexAuditCase.ts'

test('retired sub2 attribution prefixes are never rendered as case evidence', () => {
  assert.equal(
    stripLegacyAuditAttribution('『sub2: guessed-user@example.com』 actual request'),
    'actual request',
  )
  assert.equal(
    stripLegacyAuditAttribution('【归属】\nsub2 用户: guessed@example.com\n池子账号: wrong-relay\n\nactual request'),
    'actual request',
  )
})

test('malformed attribution-only legacy values are hidden instead of trusted', () => {
  assert.equal(
    stripLegacyAuditAttribution('【归属】\nsub2 用户: guessed@example.com\n池子账号: wrong-relay'),
    '',
  )
})

test('ordinary request content is preserved', () => {
  const content = 'Explain why the body mentions 【归属】 without treating it as metadata.'
  assert.equal(stripLegacyAuditAttribution(content), content)
})

test('partition scan coverage is concise and readable', () => {
  assert.equal(
    formatAuditScanCoverage({
      payload_bytes: 765432,
      scanned_bytes: 163840,
      scan_truncated: true,
      scan_details: '{"mode":"partitioned_json"}',
    }),
    '分区扫描 160 KB / 747.5 KB（已截断）',
  )
})

test('legacy fallback and malformed details keep authoritative byte coverage visible', () => {
  assert.equal(
    formatAuditScanCoverage({
      payload_bytes: 765432,
      scanned_bytes: 32768,
      scan_truncated: true,
      scan_details: '{"mode":"legacy_full"}',
    }),
    '兼容扫描 32 KB / 747.5 KB（已截断）',
  )
  assert.equal(
    formatAuditScanCoverage({
      payload_bytes: 200,
      scanned_bytes: 100,
      scan_details: 'not-json',
    }),
    '扫描 100 B / 200 B',
  )
  assert.equal(formatAuditScanCoverage({}), '')
})
