export interface LatestRequestTicket {
  isCurrent: () => boolean
}

export interface LatestRequestTracker {
  begin: () => LatestRequestTicket
  activate: () => void
  invalidate: () => void
}

export interface LatestRequestCallbacks<T> {
  onStart?: () => void
  onSuccess: (value: T) => void
  onError: (error: unknown) => void
  onFinish?: () => void
}

// Tracks one logical consumer, not one transport request. A newer invocation
// invalidates every older ticket so late responses cannot roll the UI back to
// an earlier filter window. invalidate() also fences callbacks after unmount.
export function createLatestRequestTracker(): LatestRequestTracker {
  let generation = 0
  let active = true

  return {
    begin() {
      const ticketGeneration = ++generation
      return {
        isCurrent: () => active && generation === ticketGeneration,
      }
    },
    activate() {
      active = true
    },
    invalidate() {
      active = false
      generation += 1
    },
  }
}

export async function runLatestRequest<T>(
  tracker: LatestRequestTracker,
  load: () => Promise<T>,
  callbacks: LatestRequestCallbacks<T>,
): Promise<T | null> {
  const ticket = tracker.begin()
  if (!ticket.isCurrent()) return null
  callbacks.onStart?.()

  try {
    const value = await load()
    if (!ticket.isCurrent()) return null
    callbacks.onSuccess(value)
    return value
  } catch (error) {
    if (!ticket.isCurrent()) return null
    callbacks.onError(error)
    return null
  } finally {
    if (ticket.isCurrent()) callbacks.onFinish?.()
  }
}
