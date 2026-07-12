import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

async function transpileModuleURL(relativePath) {
  const sourceURL = new URL(relativePath, import.meta.url)
  const source = await readFile(sourceURL, 'utf8')
  const compiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2020,
    },
    fileName: sourceURL.pathname,
  })
  return compiled.outputText
}

const sensitiveHeadersSource = await transpileModuleURL(
  '../src/lib/sensitiveHeaders.ts',
)
const sensitiveHeadersURL = `data:text/javascript;base64,${Buffer.from(sensitiveHeadersSource).toString('base64')}`
let copySource = await transpileModuleURL('../src/lib/openAIResponsesCopy.ts')
copySource = copySource.replace(
  /from ['"]\.\/sensitiveHeaders['"]/,
  `from '${sensitiveHeadersURL}'`,
)
const copyModuleURL = `data:text/javascript;base64,${Buffer.from(copySource).toString('base64')}`
const {
  buildFreshOpenAIResponsesDraft,
  buildOpenAIResponsesCopyDraft,
  DEFAULT_RESPONSES_BASE_CONCURRENCY,
} = await import(copyModuleURL)

test('fresh Responses API key account defaults to concurrency 100 and Warm bypass off', () => {
  const draft = buildFreshOpenAIResponsesDraft()

  assert.equal(DEFAULT_RESPONSES_BASE_CONCURRENCY, 100)
  assert.equal(draft.base_concurrency_override, 100)
  assert.equal(draft.skip_warm_tier, false)
})

test('copy draft falls back to safe defaults when scheduler values are absent', () => {
  const draft = buildOpenAIResponsesCopyDraft({
    openai_responses_api: true,
    name: 'relay',
    base_concurrency_override: null,
  })

  assert.equal(draft.base_concurrency_override, 100)
  assert.equal(draft.skip_warm_tier, false)
})

test('copy draft preserves explicit concurrency and Warm bypass values', () => {
  const draft = buildOpenAIResponsesCopyDraft({
    openai_responses_api: true,
    name: 'relay',
    base_concurrency_override: 10000,
    skip_warm_tier: true,
  })

  assert.equal(draft.base_concurrency_override, 10000)
  assert.equal(draft.skip_warm_tier, true)
})
