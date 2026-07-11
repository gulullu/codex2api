import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

const sourceURL = new URL('../src/lib/sensitiveHeaders.ts', import.meta.url)
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
  filterCopiedCustomHeaders,
  isSensitiveCopiedHeaderName,
} = await import(moduleURL)

test('sensitive authentication headers are recognized case-insensitively', () => {
  for (const name of [
    'Authorization',
    ' proxy-authorization ',
    'COOKIE',
    'Set-Cookie',
    'X-API-Key',
    'api-key',
    'x-auth-token',
    'X-Access-Token',
    'Vendor-Api-Key',
    'CF-Access-Client-Secret',
  ]) {
    assert.equal(isSensitiveCopiedHeaderName(name), true, name)
  }
})

test('copy filtering drops credentials and preserves non-sensitive metadata', () => {
  const sourceHeaders = {
    Authorization: 'Bearer old-secret',
    'x-API-key': 'old-api-key',
    'X-Auth-Token': 'old-auth-token',
    'X-Access-Token': 'old-access-token',
    Cookie: 'session=old',
    'X-Trace-Id': 'trace-123',
    'OpenAI-Organization': 'org-123',
    'X-Feature-Flag': 'enabled',
  }

  assert.deepEqual(filterCopiedCustomHeaders(sourceHeaders), {
    'X-Trace-Id': 'trace-123',
    'OpenAI-Organization': 'org-123',
    'X-Feature-Flag': 'enabled',
  })
  assert.equal(sourceHeaders.Authorization, 'Bearer old-secret')
})
