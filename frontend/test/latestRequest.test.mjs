import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import ts from 'typescript'

const sourceURL = new URL('../src/lib/latestRequest.ts', import.meta.url)
const source = await readFile(sourceURL, 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ES2022,
    target: ts.ScriptTarget.ES2020,
  },
  fileName: sourceURL.pathname,
})
const moduleURL = `data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`
const { createLatestRequestTracker, runLatestRequest } = await import(moduleURL)

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function stateCallbacks(state) {
  return {
    onStart: () => {
      state.loading = true
      state.error = null
    },
    onSuccess: (value) => {
      state.data = value
      state.error = null
    },
    onError: (error) => {
      state.error = error.message
    },
    onFinish: () => {
      state.loading = false
    },
  }
}

test('newer audit request wins when an older filter response resolves last', async () => {
  const tracker = createLatestRequestTracker()
  const state = { data: null, error: null, loading: false }
  const sevenDays = deferred()
  const thirtyMinutes = deferred()

  const oldRun = runLatestRequest(tracker, () => sevenDays.promise, stateCallbacks(state))
  const newRun = runLatestRequest(tracker, () => thirtyMinutes.promise, stateCallbacks(state))

  thirtyMinutes.resolve({ range: '30m' })
  assert.deepEqual(await newRun, { range: '30m' })
  assert.deepEqual(state, { data: { range: '30m' }, error: null, loading: false })

  sevenDays.resolve({ range: '7d' })
  assert.equal(await oldRun, null)
  assert.deepEqual(state, { data: { range: '30m' }, error: null, loading: false })
})

test('stale failures cannot replace the newest data or loading state', async () => {
  const tracker = createLatestRequestTracker()
  const state = { data: null, error: null, loading: false }
  const oldRequest = deferred()
  const newestRequest = deferred()

  const oldRun = runLatestRequest(tracker, () => oldRequest.promise, stateCallbacks(state))
  const newRun = runLatestRequest(tracker, () => newestRequest.promise, stateCallbacks(state))
  newestRequest.resolve({ range: '1h' })
  await newRun

  oldRequest.reject(new Error('stale 7d failure'))
  assert.equal(await oldRun, null)
  assert.deepEqual(state, { data: { range: '1h' }, error: null, loading: false })
})

test('invalidating on unmount suppresses every late callback', async () => {
  const tracker = createLatestRequestTracker()
  const state = { data: null, error: null, loading: false }
  const request = deferred()
  const run = runLatestRequest(tracker, () => request.promise, stateCallbacks(state))
  assert.equal(state.loading, true)

  tracker.invalidate()
  request.resolve({ range: '24h' })
  assert.equal(await run, null)
  assert.deepEqual(state, { data: null, error: null, loading: true })
})
