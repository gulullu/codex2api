package wsrelay

import (
	"fmt"
	"testing"
	"time"

	"github.com/codex2api/proxy"
)

func setIdleReclaimTestSettings(t *testing.T, enabled bool, percent int, idleSeconds int) {
	t.Helper()
	previous := proxy.CurrentRuntimeSettings()
	t.Cleanup(func() { proxy.ApplyRuntimeSettings(previous) })
	next := previous
	next.CodexWSIdleReclaimEnabled = enabled
	next.CodexWSIdleReclaimPercent = percent
	next.CodexWSIdleReclaimIdleSec = idleSeconds
	proxy.ApplyRuntimeSettings(next)
}

func makeBusinessIdle(wc *WsConnection, now time.Time, idle time.Duration) {
	wc.lastBusinessUsed.Store(now.Add(-idle).UnixNano())
}

func TestControlPongDoesNotRefreshBusinessIdle(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Stop)
	wc := addConnectedConn(t, m, 101, "pong-separation")
	staleBusiness := time.Now().Add(-20 * time.Minute).UnixNano()
	staleTransport := time.Now().Add(-time.Minute).UnixNano()
	wc.lastBusinessUsed.Store(staleBusiness)
	wc.lastUsed.Store(staleTransport)

	wc.handleControlPong("heartbeat")

	if got := wc.lastBusinessUsed.Load(); got != staleBusiness {
		t.Fatalf("business timestamp after Pong = %d, want unchanged %d", got, staleBusiness)
	}
	if got := wc.lastUsed.Load(); got <= staleTransport {
		t.Fatalf("legacy transport timestamp after Pong = %d, want newer than %d", got, staleTransport)
	}
}

func TestIdleReclaimDisabledPreservesConnection(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 0, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 102, "disabled")
	makeBusinessIdle(wc, now, 30*time.Minute)

	m.reclaimBusinessIdleConnections(now)

	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("disabled idle reclaimer changed the legacy connection lifecycle")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.Enabled || snapshot.Eligible != 0 || snapshot.Reclaimed != 0 {
		t.Fatalf("disabled snapshot = %+v, want inert", snapshot)
	}
}

func TestIdleReclaimObserveOnlyCountsWithoutMutation(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 108, "observe-only")
	makeBusinessIdle(wc, now, 6*time.Minute)

	m.reclaimBusinessIdleConnections(now)

	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("observe-only idle reclaimer changed the connection lifecycle")
	}
	if m.ConnectionCount() != 1 || m.SessionCount() != 1 {
		t.Fatalf("observe-only changed pool sizes: connections=%d sessions=%d", m.ConnectionCount(), m.SessionCount())
	}
	snapshot := m.IdleReclaimRuntimeSnapshot()
	if snapshot.Enabled || !snapshot.ObserveOnly || snapshot.Seen != 1 || snapshot.IdleCandidate != 1 ||
		snapshot.SampleHit != 1 || snapshot.Eligible != 1 || snapshot.WouldReclaim != 1 ||
		snapshot.Reclaimed != 0 || snapshot.SkippedRateLimit != 0 || snapshot.PendingReconnects != 0 || snapshot.Reconnect != 0 {
		t.Fatalf("observe-only snapshot = %+v, want one safe dry-run candidate and no lifecycle metrics", snapshot)
	}
}

func TestIdleReclaimObserveOnlyScansPastEnforceCap(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	const candidates = idleReclaimMaxPerPass + 4
	for i := 0; i < candidates; i++ {
		wc := addConnectedConn(t, m, int64(120+i), fmt.Sprintf("observe-many-%d", i))
		makeBusinessIdle(wc, now, 6*time.Minute)
	}

	m.reclaimBusinessIdleConnections(now)

	snapshot := m.IdleReclaimRuntimeSnapshot()
	if snapshot.WouldReclaim != candidates || snapshot.Reclaimed != 0 || snapshot.SkippedRateLimit != 0 {
		t.Fatalf("observe-only snapshot = %+v, want all %d candidates observed without enforcing the cap", snapshot, candidates)
	}
	if got := m.ConnectionCount(); got != candidates {
		t.Fatalf("observe-only connection count = %d, want %d", got, candidates)
	}
	if got := m.SessionCount(); got != candidates {
		t.Fatalf("observe-only session count = %d, want %d", got, candidates)
	}
}

func TestIdleReclaimObserveOnlyDoesNotWaitForWriter(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 140, "observe-writer-busy")
	makeBusinessIdle(wc, now, 6*time.Minute)
	wc.writeMu.Lock()
	started := time.Now()
	m.reclaimBusinessIdleConnections(now)
	elapsed := time.Since(started)
	wc.writeMu.Unlock()

	if elapsed > 100*time.Millisecond {
		t.Fatalf("observe-only waited %s for writeMu, want non-blocking TryLock", elapsed)
	}
	if !wc.IsConnected() || m.ConnectionCount() != 1 || m.SessionCount() != 1 {
		t.Fatal("observe-only changed a writer-busy connection")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.SkippedBusy != 1 || snapshot.WouldReclaim != 0 || snapshot.Reclaimed != 0 {
		t.Fatalf("writer-busy snapshot = %+v, want one non-blocking busy skip", snapshot)
	}
}

func TestIdleReclaimObserveOnlyPreservesContinuationContext(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 109, "observe-bound")
	m.BindResponseConn("resp_observe_bound", wc, "observe-bound", 109, "key-A")
	makeBusinessIdle(wc, now, 6*time.Minute)

	m.reclaimBusinessIdleConnections(now)

	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("observe-only idle reclaimer closed continuation context")
	}
	if got, _ := m.lookupResponseConn("resp_observe_bound", 109, "key-A"); got != wc {
		t.Fatal("observe-only idle reclaimer removed continuation binding")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.SkippedContext != 1 || snapshot.WouldReclaim != 0 ||
		snapshot.Reclaimed != 0 || snapshot.PendingReconnects != 0 || snapshot.Reconnect != 0 {
		t.Fatalf("observe-only bound snapshot = %+v, want one protected context", snapshot)
	}
}

func TestIdleReclaimObserveToEnforceHotSwitch(t *testing.T) {
	setIdleReclaimTestSettings(t, false, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 110, "hot-switch")
	makeBusinessIdle(wc, now, 6*time.Minute)

	m.reclaimBusinessIdleConnections(now)
	if !wc.IsConnected() {
		t.Fatal("observe phase closed connection")
	}
	next := proxy.CurrentRuntimeSettings()
	next.CodexWSIdleReclaimEnabled = true
	proxy.ApplyRuntimeSettings(next)
	m.reclaimBusinessIdleConnections(now.Add(30 * time.Second))

	if _, ok := m.connections.Load(wc.PoolKey); ok || wc.IsConnected() {
		t.Fatal("enforce phase did not reclaim the previously observed idle connection")
	}
	snapshot := m.IdleReclaimRuntimeSnapshot()
	if !snapshot.Enabled || snapshot.ObserveOnly || snapshot.WouldReclaim != 2 || snapshot.Reclaimed != 1 || snapshot.PendingReconnects != 1 {
		t.Fatalf("hot-switch snapshot = %+v, want observe then one enforced reclaim", snapshot)
	}
}

func TestIdleReclaimClosesOnlyUnboundBusinessIdleConnection(t *testing.T) {
	setIdleReclaimTestSettings(t, true, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 103, "unbound-idle")
	makeBusinessIdle(wc, now, 6*time.Minute)

	m.reclaimBusinessIdleConnections(now)

	if _, ok := m.connections.Load(wc.PoolKey); ok || wc.IsConnected() {
		t.Fatal("eligible unbound business-idle connection was not reclaimed")
	}
	snapshot := m.IdleReclaimRuntimeSnapshot()
	if snapshot.Eligible != 1 || snapshot.Reclaimed != 1 || snapshot.SkippedBusy != 0 || snapshot.SkippedContext != 0 {
		t.Fatalf("snapshot = %+v, want one eligible reclaim", snapshot)
	}
	if snapshot.PendingReconnects != 1 {
		t.Fatalf("pending reconnect keys = %d, want 1", snapshot.PendingReconnects)
	}
	m.noteIdleReclaimReconnect(wc.PoolKey, now.Add(time.Second))
	if snapshot = m.IdleReclaimRuntimeSnapshot(); snapshot.Reconnect != 1 || snapshot.PendingReconnects != 0 {
		t.Fatalf("snapshot after reconnect = %+v, want reconnect=1 and no pending key", snapshot)
	}
}

func TestIdleReclaimPreservesLiveContinuationBinding(t *testing.T) {
	setIdleReclaimTestSettings(t, true, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 104, "bound-idle")
	m.BindResponseConn("resp_bound_idle", wc, "bound-idle", 104, "key-A")
	makeBusinessIdle(wc, now, 6*time.Minute)

	m.reclaimBusinessIdleConnections(now)

	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		t.Fatal("idle reclaimer closed unique previous_response_id context")
	}
	if got, _ := m.lookupResponseConn("resp_bound_idle", 104, "key-A"); got != wc {
		t.Fatal("idle reclaimer removed a live continuation binding")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.Eligible != 1 || snapshot.Reclaimed != 0 || snapshot.SkippedContext != 1 {
		t.Fatalf("snapshot = %+v, want one context-protected skip", snapshot)
	}
}

func TestIdleReclaimSkipsPendingAndReadLeaseBusy(t *testing.T) {
	setIdleReclaimTestSettings(t, true, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()

	pendingConn := addConnectedConn(t, m, 105, "pending")
	makeBusinessIdle(pendingConn, now, 6*time.Minute)
	pending := pendingConn.session.AddPendingRequest("pending")
	t.Cleanup(func() { pendingConn.session.RemovePendingRequest(pending.RequestID) })

	leaseConn := addConnectedConn(t, m, 106, "read-lease")
	makeBusinessIdle(leaseConn, now, 6*time.Minute)
	if err := leaseConn.BeginReadLease("lease-only-busy"); err != nil {
		t.Fatalf("BeginReadLease: %v", err)
	}

	m.reclaimBusinessIdleConnections(now)

	if !pendingConn.IsConnected() || !leaseConn.IsConnected() {
		t.Fatal("idle reclaimer interrupted a pending request or active read lease")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.Eligible != 2 || snapshot.SkippedBusy != 2 || snapshot.Reclaimed != 0 {
		t.Fatalf("snapshot = %+v, want two busy skips", snapshot)
	}
}

func TestIdleReclaimSerializesWithConcurrentLeaseActivation(t *testing.T) {
	setIdleReclaimTestSettings(t, true, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	wc := addConnectedConn(t, m, 107, "raced-lease")
	makeBusinessIdle(wc, now, 6*time.Minute)

	accountLock := m.accountLock(107)
	accountLock.Lock()
	done := make(chan struct{})
	go func() {
		m.reclaimBusinessIdleConnections(now)
		close(done)
	}()
	pending := wc.session.AddPendingRequest("raced-lease")
	if err := wc.BeginReadLease(pending.RequestID); err != nil {
		accountLock.Unlock()
		t.Fatalf("BeginReadLease: %v", err)
	}
	accountLock.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle reclaimer did not finish after account lock release")
	}
	if !wc.IsConnected() {
		t.Fatal("raced lease activation was interrupted by idle reclaim")
	}
	if snapshot := m.IdleReclaimRuntimeSnapshot(); snapshot.SkippedBusy != 1 || snapshot.Reclaimed != 0 {
		t.Fatalf("snapshot = %+v, want raced lease busy skip", snapshot)
	}
	wc.session.RemovePendingRequest(pending.RequestID)
}

func TestIdleReclaimPoolKeySamplingIsStableMonotonicAndDistributed(t *testing.T) {
	counts := map[int]int{5: 0, 20: 0, 50: 0}
	sameAccountHits := 0
	sameAccountMisses := 0
	for i := 0; i < 10000; i++ {
		poolKey := fmt.Sprintf("%d|wss://example.test/responses|session-%d|proxy-%d", i%137+1, i, i%31)
		first := idleReclaimPoolKeySampled(poolKey, 20)
		if repeat := idleReclaimPoolKeySampled(poolKey, 20); repeat != first {
			t.Fatalf("pool key %d changed buckets between evaluations", i)
		}
		if idleReclaimPoolKeySampled(poolKey, 5) && !first {
			t.Fatalf("pool key %d sampled at 5%% but not 20%%", i)
		}
		if first && !idleReclaimPoolKeySampled(poolKey, 50) {
			t.Fatalf("pool key %d sampled at 20%% but not 50%%", i)
		}
		if !idleReclaimPoolKeySampled(poolKey, 100) {
			t.Fatalf("pool key %d not sampled at 100%%", i)
		}
		for _, percent := range []int{5, 20, 50} {
			if idleReclaimPoolKeySampled(poolKey, percent) {
				counts[percent]++
			}
		}
		sameAccountKey := fmt.Sprintf("42|wss://example.test/responses|same-account-session-%d|", i)
		if idleReclaimPoolKeySampled(sameAccountKey, 20) {
			sameAccountHits++
		} else {
			sameAccountMisses++
		}
	}
	for percent, count := range counts {
		want := percent * 100
		if count < want-350 || count > want+350 {
			t.Fatalf("%d%% distribution = %d/10000, outside conservative tolerance", percent, count)
		}
	}
	if idleReclaimPoolKeySampled("1|wss://example.test|session", 17) || idleReclaimPoolKeySampled("", 100) {
		t.Fatal("invalid rollout or empty PoolKey widened the canary")
	}
	if sameAccountHits == 0 || sameAccountMisses == 0 {
		t.Fatalf("same dynamic account did not split across PoolKey buckets: hits=%d misses=%d", sameAccountHits, sameAccountMisses)
	}
}

func TestIdleReclaimLimitsActualClosesPerPass(t *testing.T) {
	setIdleReclaimTestSettings(t, true, 100, 5*60)
	m := NewManager()
	t.Cleanup(m.Stop)
	now := time.Now()
	for i := 0; i < idleReclaimMaxPerPass+4; i++ {
		wc := addConnectedConn(t, m, int64(200+i), fmt.Sprintf("rate-%d", i))
		makeBusinessIdle(wc, now, 6*time.Minute)
	}

	m.reclaimBusinessIdleConnections(now)
	snapshot := m.IdleReclaimRuntimeSnapshot()
	if snapshot.Reclaimed != idleReclaimMaxPerPass || snapshot.SkippedRateLimit != 1 || snapshot.WouldReclaim != idleReclaimMaxPerPass {
		t.Fatalf("first limited pass snapshot = %+v, want reclaimed=8 cap_stops=1 would=8", snapshot)
	}
	if got := m.ConnectionCount(); got != 4 {
		t.Fatalf("connections after first limited pass = %d, want 4", got)
	}

	m.reclaimBusinessIdleConnections(now.Add(30 * time.Second))
	snapshot = m.IdleReclaimRuntimeSnapshot()
	if snapshot.Reclaimed != idleReclaimMaxPerPass+4 || snapshot.SkippedRateLimit != 1 {
		t.Fatalf("second limited pass snapshot = %+v, want all 12 reclaimed without another cap stop", snapshot)
	}
	if got := m.ConnectionCount(); got != 0 {
		t.Fatalf("connections after second limited pass = %d, want 0", got)
	}
}
