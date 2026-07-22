package wsrelay

import (
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
	setIdleReclaimTestSettings(t, false, 100, 5*60)
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

func TestIdleReclaimAccountSamplingIsStableAndMonotonic(t *testing.T) {
	for accountID := int64(1); accountID <= 1000; accountID++ {
		first := idleReclaimAccountSampled(accountID, 20)
		if repeat := idleReclaimAccountSampled(accountID, 20); repeat != first {
			t.Fatalf("account %d changed buckets between evaluations", accountID)
		}
		if idleReclaimAccountSampled(accountID, 5) && !first {
			t.Fatalf("account %d sampled at 5%% but not 20%%", accountID)
		}
		if first && !idleReclaimAccountSampled(accountID, 50) {
			t.Fatalf("account %d sampled at 20%% but not 50%%", accountID)
		}
		if !idleReclaimAccountSampled(accountID, 100) {
			t.Fatalf("account %d not sampled at 100%%", accountID)
		}
	}
	if idleReclaimAccountSampled(1, 17) || idleReclaimAccountSampled(0, 100) {
		t.Fatal("invalid rollout or invalid account widened the canary")
	}
}
