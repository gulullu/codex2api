import assert from 'node:assert/strict'
import test from 'node:test'

import { stripLegacyAuditAttribution } from './codexAuditCase.ts'

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
