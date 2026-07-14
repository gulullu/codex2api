export function stripLegacyAuditAttribution(value?: string) {
  let result = (value || '').replace(/\r\n/g, '\n').replace(/^『sub2:[^』]*』\s*/, '')
  if (result.startsWith('【归属】\n')) {
    const boundary = result.indexOf('\n\n')
    // Attribution written by the retired enrichment job is not authoritative.
    // If its bounded header is malformed, hide the value rather than exposing a
    // guessed user/account as case evidence.
    result = boundary >= 0 && boundary <= 2048 ? result.slice(boundary + 2) : ''
  }
  return result.trim()
}
