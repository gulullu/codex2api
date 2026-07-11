const SENSITIVE_COPY_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'api-key',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'authentication',
  'client-secret',
  'x-client-secret',
])

const SENSITIVE_COPY_HEADER_SUFFIXES = [
  '-api-key',
  '-auth-token',
  '-access-token',
  '-client-secret',
]

export function isSensitiveCopiedHeaderName(name: string): boolean {
  const normalized = name.trim().toLowerCase()
  if (!normalized) return false
  return (
    SENSITIVE_COPY_HEADER_NAMES.has(normalized) ||
    SENSITIVE_COPY_HEADER_SUFFIXES.some((suffix) => normalized.endsWith(suffix))
  )
}

export function filterCopiedCustomHeaders(
  headers?: Record<string, string> | null,
): Record<string, string> {
  const safeHeaders: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!isSensitiveCopiedHeaderName(name)) {
      safeHeaders[name] = value
    }
  }
  return safeHeaders
}
