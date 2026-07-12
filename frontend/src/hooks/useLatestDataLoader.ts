import { useCallback, useEffect, useRef, useState } from 'react'
import { createLatestRequestTracker, runLatestRequest } from '../lib/latestRequest'
import { getErrorMessage } from '../utils/error'

interface UseLatestDataLoaderOptions<T> {
  initialData: T
  load: () => Promise<T>
  onError?: (message: string, error: unknown) => void
}

// A page-scoped loader for filterable reports. Unlike the general loader,
// only the newest invocation may publish data, error, or loading state.
export function useLatestDataLoader<T>({
  initialData,
  load,
  onError,
}: UseLatestDataLoaderOptions<T>) {
  const [data, setData] = useState<T>(initialData)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const trackerRef = useRef<ReturnType<typeof createLatestRequestTracker> | null>(null)
  if (trackerRef.current === null) trackerRef.current = createLatestRequestTracker()
  const tracker = trackerRef.current

  useEffect(() => {
    tracker.activate()
    return () => tracker.invalidate()
  }, [tracker])

  const run = useCallback(async () => {
    return runLatestRequest(tracker, load, {
      onStart: () => {
        setLoading(true)
        setError(null)
      },
      onSuccess: (nextData) => {
        setData(nextData)
        setError(null)
      },
      onError: (loadError) => {
        const message = getErrorMessage(loadError)
        setError(message)
        onError?.(message, loadError)
      },
      onFinish: () => {
        setLoading(false)
      },
    })
  }, [load, onError, tracker])

  useEffect(() => {
    void run()
  }, [run])

  const reload = useCallback(() => run(), [run])

  return {
    data,
    setData,
    loading,
    error,
    reload,
  }
}
