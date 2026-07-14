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

type AuditScanCoverage = {
  payload_bytes?: number
  scanned_bytes?: number
  scan_truncated?: boolean
  scan_details?: string
}

function formatAuditBytes(value: number) {
  const bytes = Number.isFinite(value) ? Math.max(0, value) : 0
  if (bytes < 1024) return `${Math.round(bytes)} B`
  if (bytes < 1024 * 1024) {
    const kb = Math.round((bytes / 1024) * 10) / 10
    return `${kb.toLocaleString('en-US', { maximumFractionDigits: 1 })} KB`
  }
  const mb = Math.round((bytes / 1024 / 1024) * 10) / 10
  return `${mb.toLocaleString('en-US', { maximumFractionDigits: 1 })} MB`
}

export function formatAuditScanCoverage(value: AuditScanCoverage) {
  const payloadBytes = Number(value.payload_bytes) || 0
  const scannedBytes = Number(value.scanned_bytes) || 0
  if (payloadBytes <= 0 && scannedBytes <= 0) return ''

  let mode = '扫描'
  try {
    const details = JSON.parse(value.scan_details || '{}') as { mode?: unknown }
    if (details.mode === 'partitioned_json') mode = '分区扫描'
    else if (details.mode === 'legacy_full') mode = '兼容扫描'
    else if (details.mode === 'direct_text') mode = '文本扫描'
  } catch {
    // Corrupt historical metadata must not hide the authoritative byte counts.
  }

  const effectivePayload = payloadBytes > 0 ? payloadBytes : scannedBytes
  const coverage = `${formatAuditBytes(scannedBytes)} / ${formatAuditBytes(effectivePayload)}`
  return `${mode} ${coverage}${value.scan_truncated ? '（已截断）' : ''}`
}
