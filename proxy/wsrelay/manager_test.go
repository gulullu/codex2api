package wsrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
	"github.com/gorilla/websocket"
)

func TestSessionBusyAcquireErrorPreservesSentinel(t *testing.T) {
	err := newSessionBusyAcquireError(30 * time.Second)
	if !errors.Is(err, proxy.ErrWebsocketSessionBusy) {
		t.Fatalf("errors.Is(%v, ErrWebsocketSessionBusy) = false", err)
	}
	if !strings.Contains(err.Error(), "waiting for busy session") {
		t.Fatalf("error message = %q, want busy-session detail", err)
	}
	interrupted := newSessionBusyAcquireError(5*time.Second, context.DeadlineExceeded)
	if !errors.Is(interrupted, proxy.ErrWebsocketSessionBusy) || !errors.Is(interrupted, context.DeadlineExceeded) {
		t.Fatalf("interrupted error = %v, want busy and deadline sentinels", interrupted)
	}
}

func TestLocalCapacityAcquireErrorPreservesSentinel(t *testing.T) {
	err := newLocalCapacityAcquireError(30 * time.Second)
	if !errors.Is(err, proxy.ErrWebsocketLocalCapacity) {
		t.Fatalf("errors.Is(%v, ErrWebsocketLocalCapacity) = false", err)
	}
	if !strings.Contains(err.Error(), "account connection capacity") {
		t.Fatalf("error message = %q, want capacity detail", err)
	}
	interrupted := newLocalCapacityAcquireError(5*time.Second, context.DeadlineExceeded)
	if !errors.Is(interrupted, proxy.ErrWebsocketLocalCapacity) || !errors.Is(interrupted, context.DeadlineExceeded) {
		t.Fatalf("interrupted error = %v, want capacity and deadline sentinels", interrupted)
	}
}

func TestManagerStopIdempotent(t *testing.T) {
	manager := NewManager()

	for i := 0; i < 3; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Stop call %d panicked: %v", i+1, r)
				}
			}()
			manager.Stop()
		}()
	}
}

func TestManagerStopConcurrent(t *testing.T) {
	manager := NewManager()

	const callers = 32
	start := make(chan struct{})
	panicCh := make(chan any, callers)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)

	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCh <- r
				}
			}()
			<-start
			manager.Stop()
		}()
	}

	close(start)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Stop calls timed out")
	}
	close(panicCh)

	for r := range panicCh {
		t.Fatalf("concurrent Stop panicked: %v", r)
	}
}

func TestContinuationSocketLimitsFromEnv(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "")
		t.Setenv(continuationPerAccountLimitEnv, "")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != defaultContinuationGlobalLimit || perAccountLimit != defaultContinuationPerAccountLimit {
			t.Fatalf("default limits = (%d, %d), want (%d, %d)", globalLimit, perAccountLimit, defaultContinuationGlobalLimit, defaultContinuationPerAccountLimit)
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "64")
		t.Setenv(continuationPerAccountLimitEnv, "32")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != 64 || perAccountLimit != 32 {
			t.Fatalf("valid limits = (%d, %d), want (64, 32)", globalLimit, perAccountLimit)
		}
	})

	t.Run("invalid fallback", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "not-a-number")
		t.Setenv(continuationPerAccountLimitEnv, "0")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != defaultContinuationGlobalLimit || perAccountLimit != defaultContinuationPerAccountLimit {
			t.Fatalf("invalid limits = (%d, %d), want fallbacks (%d, %d)", globalLimit, perAccountLimit, defaultContinuationGlobalLimit, defaultContinuationPerAccountLimit)
		}
	})

	t.Run("upper bound fallback and per-account clamp", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "16")
		t.Setenv(continuationPerAccountLimitEnv, "4097")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != 16 || perAccountLimit != 16 {
			t.Fatalf("clamped limits = (%d, %d), want (16, 16)", globalLimit, perAccountLimit)
		}
	})

	t.Run("negative values fallback", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "-1")
		t.Setenv(continuationPerAccountLimitEnv, "-9")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != defaultContinuationGlobalLimit || perAccountLimit != defaultContinuationPerAccountLimit {
			t.Fatalf("negative limits = (%d, %d), want fallbacks (%d, %d)", globalLimit, perAccountLimit, defaultContinuationGlobalLimit, defaultContinuationPerAccountLimit)
		}
	})

	t.Run("global upper bound fallback", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "4097")
		t.Setenv(continuationPerAccountLimitEnv, "64")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != defaultContinuationGlobalLimit || perAccountLimit != 64 {
			t.Fatalf("global upper-bound limits = (%d, %d), want (%d, 64)", globalLimit, perAccountLimit, defaultContinuationGlobalLimit)
		}
	})

	t.Run("valid per-account value clamps to valid global", func(t *testing.T) {
		t.Setenv(continuationGlobalLimitEnv, "16")
		t.Setenv(continuationPerAccountLimitEnv, "32")
		globalLimit, perAccountLimit := continuationSocketLimitsFromEnv()
		if globalLimit != 16 || perAccountLimit != 16 {
			t.Fatalf("valid clamped limits = (%d, %d), want (16, 16)", globalLimit, perAccountLimit)
		}
	})
}

func TestRemoveConnectionUsesEffectiveProxyKey(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{DBID: 42, ProxyURL: " http://proxy-a.example:8080 "}
	wsURL := "wss://example.test/responses"
	sessionKey := "session-1"
	proxyURL := effectiveProxyURL(account, "")
	key := manager.poolKey(account.ID(), wsURL, sessionKey, proxyURL)

	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{session: session, URL: wsURL, PoolKey: key}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)

	manager.RemoveConnection(account.ID(), wsURL, sessionKey, effectiveProxyURL(account, ""))

	if _, ok := manager.connections.Load(key); ok {
		t.Fatal("expected connection stored under effective proxy key to be removed")
	}
	if _, ok := manager.sessions.Load(key); ok {
		t.Fatal("expected session stored under effective proxy key to be removed")
	}
	if conn.IsConnected() {
		t.Fatal("expected removed connection to be closed")
	}
}

func TestAcquireConnectionReusesIdleConnectedConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	// 测试环境无真实 WebSocket 连接，注入探活函数跳过 Ping
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	account := &auth.Account{DBID: 42}
	wsURL := "wss://example.test/responses"
	key := manager.poolKey(account.ID(), wsURL, "session-1", "")

	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{
		account:  account,
		session:  session,
		URL:      wsURL,
		PoolKey:  key,
		httpResp: &http.Response{StatusCode: http.StatusSwitchingProtocols},
	}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)

	got, pr, err := manager.AcquireConnection(context.Background(), account, wsURL, "session-1", http.Header{}, "")
	if err != nil {
		t.Fatalf("AcquireConnection() error = %v", err)
	}
	if got != conn {
		t.Fatal("expected existing connection to be reused")
	}
	if pr == nil {
		t.Fatal("expected pending request reservation")
	}
	if session.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want %d", session.PendingCount(), 1)
	}
	session.RemovePendingRequest(pr.RequestID)
}

func TestAcquireConnectionProbeDoesNotBlockDifferentPoolKey(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 4}
	wsURL := "wss://example.test/responses"
	slowConn, _ := newTestSlotConnection(manager, account, wsURL, "session-slow")
	fastConn, _ := newTestSlotConnection(manager, account, wsURL, "session-fast")

	slowProbeStarted := make(chan struct{})
	releaseSlowProbe := make(chan struct{})
	var releaseOnce sync.Once
	releaseSlow := func() { releaseOnce.Do(func() { close(releaseSlowProbe) }) }
	defer releaseSlow()
	var startedOnce sync.Once
	manager.probeFunc = func(wc *WsConnection) bool {
		if wc == slowConn {
			startedOnce.Do(func() { close(slowProbeStarted) })
			<-releaseSlowProbe
		}
		return true
	}

	type result struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	slowResult := make(chan result, 1)
	go func() {
		wc, pending, err := manager.AcquireConnection(context.Background(), account, wsURL, "session-slow", http.Header{}, "")
		slowResult <- result{wc: wc, pending: pending, err: err}
	}()
	select {
	case <-slowProbeStarted:
	case <-time.After(time.Second):
		t.Fatal("slow pool-key probe did not start")
	}

	fastResult := make(chan result, 1)
	go func() {
		wc, pending, err := manager.AcquireConnection(context.Background(), account, wsURL, "session-fast", http.Header{}, "")
		fastResult <- result{wc: wc, pending: pending, err: err}
	}()
	select {
	case got := <-fastResult:
		if got.err != nil || got.wc != fastConn || got.pending == nil {
			t.Fatalf("fast acquire = (%p, %v, %v), want existing healthy connection", got.wc, got.pending, got.err)
		}
		got.wc.session.RemovePendingRequest(got.pending.RequestID)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("different pool-key acquire was blocked by another connection's network probe")
	}
	releaseSlow()
	slow := <-slowResult
	if slow.err != nil || slow.wc != slowConn || slow.pending == nil {
		t.Fatalf("slow acquire after probe release = (%p, %v, %v)", slow.wc, slow.pending, slow.err)
	}
	slow.wc.session.RemovePendingRequest(slow.pending.RequestID)
}

func TestPoolKeyIncludesSessionKey(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	keyA := manager.poolKey(42, "wss://example.test/responses", "session-a", "")
	keyB := manager.poolKey(42, "wss://example.test/responses", "session-b", "")
	if keyA == keyB {
		t.Fatal("expected different session keys to produce different pool keys")
	}
}

func TestPoolKeyKeepsSameSessionStable(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	keyA := manager.poolKey(42, "wss://example.test/responses", "session-a", "http://proxy-a")
	keyB := manager.poolKey(42, "wss://example.test/responses", "session-a", "http://proxy-a")
	if keyA != keyB {
		t.Fatal("expected identical session keys to produce the same pool key")
	}
}

func TestPoolKeyIncludesProxyScope(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	keyA := manager.poolKey(42, "wss://example.test/responses", "session-a", "http://proxy-a")
	keyB := manager.poolKey(42, "wss://example.test/responses", "session-a", "http://proxy-b")
	if keyA == keyB {
		t.Fatal("expected different proxies to produce different pool keys")
	}
}

func TestCanReuseConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	t.Run("idle connected session can be reused", func(t *testing.T) {
		session := NewSession(42, manager)
		session.SetConnected(true)
		conn := &WsConnection{session: session}
		conn.SetState(StateConnected)
		conn.Touch()

		if !canReuseConnection(conn) {
			t.Fatal("expected connection to be reusable")
		}
	})

	t.Run("pending request blocks reuse", func(t *testing.T) {
		session := NewSession(42, manager)
		session.SetConnected(true)
		pending := session.AddPendingRequest("session-a")
		t.Cleanup(func() { session.RemovePendingRequest(pending.RequestID) })

		conn := &WsConnection{session: session}
		conn.SetState(StateConnected)
		conn.Touch()

		if canReuseConnection(conn) {
			t.Fatal("expected connection with pending request to be non-reusable")
		}
	})

	t.Run("expired connection cannot be reused", func(t *testing.T) {
		session := NewSession(42, manager)
		session.SetConnected(true)
		conn := &WsConnection{session: session}
		conn.SetState(StateConnected)
		conn.lastUsed.Store(time.Now().Add(-IdleTimeout - time.Second).UnixNano())

		if canReuseConnection(conn) {
			t.Fatal("expected expired connection to be non-reusable")
		}
	})
}

func TestAcquireConnectionWaitsWhileSessionHasPendingRequest(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	account := &auth.Account{DBID: 42}
	wsURL := "wss://example.test/responses"
	key := manager.poolKey(account.ID(), wsURL, "session-1", "")

	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	blocking := session.AddPendingRequest("session-1")
	t.Cleanup(func() { session.RemovePendingRequest(blocking.RequestID) })

	conn := &WsConnection{
		session:  session,
		URL:      wsURL,
		PoolKey:  key,
		httpResp: &http.Response{StatusCode: http.StatusSwitchingProtocols},
	}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, _, err := manager.AcquireConnection(ctx, account, wsURL, "session-1", http.Header{}, "")
	if !errors.Is(err, proxy.ErrWebsocketSessionBusy) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire error = %v, want busy-session and deadline sentinels", err)
	}
}

func TestAcquireConnectionCapsIdleConnectionsAtAccountConcurrency(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 2}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	connections := make([]*WsConnection, 0, 3)

	for i := 0; i < 3; i++ {
		wc, pending, err := manager.AcquireConnection(
			context.Background(),
			account,
			wsURL,
			fmt.Sprintf("session-%d", i),
			http.Header{},
			"",
		)
		if err != nil {
			t.Fatalf("AcquireConnection(%d) error = %v", i, err)
		}
		wc.session.RemovePendingRequest(pending.RequestID)
		manager.ReleaseConnection(wc)
		connections = append(connections, wc)
		time.Sleep(2 * time.Millisecond)
	}

	if got := manager.ConnectionCount(); got != 2 {
		t.Fatalf("ConnectionCount = %d, want account concurrency cap 2", got)
	}
	if connections[0].IsConnected() {
		t.Fatal("oldest idle connection should be evicted when the account cap is reached")
	}
}

func TestAcquireConnectionTrimsIdleConnectionsAfterDynamicLimitDecrease(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 3}
	wsURL := "wss://example.test/responses"
	connections := make([]*WsConnection, 0, 3)

	for i := 0; i < 3; i++ {
		wc, _ := newTestSlotConnection(manager, account, wsURL, fmt.Sprintf("session-%d", i))
		connections = append(connections, wc)
	}
	if got := manager.ConnectionCount(); got != 3 {
		t.Fatalf("ConnectionCount before limit decrease = %d, want 3", got)
	}

	account.Mu().Lock()
	account.DynamicConcurrencyLimit = 1
	account.Mu().Unlock()
	protected := connections[1]
	got, pending, err := manager.AcquireConnection(
		context.Background(), account, wsURL, "session-1", http.Header{}, "",
	)
	if err != nil {
		t.Fatalf("AcquireConnection after limit decrease error = %v", err)
	}
	if got != protected {
		t.Fatal("existing session connection should be reused after the limit decrease")
	}
	if count := manager.ConnectionCount(); count != 1 {
		t.Fatalf("ConnectionCount after limit decrease = %d, want 1", count)
	}
	if !protected.IsConnected() {
		t.Fatal("the connection selected for reuse must remain connected")
	}
	for i, wc := range connections {
		if wc != protected && wc.IsConnected() {
			t.Fatalf("idle connection %d remained connected after the limit decreased", i)
		}
	}
	got.session.RemovePendingRequest(pending.RequestID)
}

func TestAcquireConnectionCountsPendingDialTowardAccountCap(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	started := make(chan struct{})
	release := make(chan struct{})
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			close(started)
		}
		<-release
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	type acquireResult struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	firstResult := make(chan acquireResult, 1)
	go func() {
		wc, pending, err := manager.AcquireConnection(
			context.Background(), account, wsURL, "session-first", http.Header{}, "",
		)
		firstResult <- acquireResult{wc: wc, pending: pending, err: err}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first websocket dial did not reach the server")
	}

	secondCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, _, secondErr := manager.AcquireConnection(
		secondCtx, account, wsURL, "session-second", http.Header{}, "",
	)
	if secondErr == nil {
		t.Fatal("second dial should wait for account connection capacity")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("websocket dial attempts = %d, want 1 while first dial is pending", got)
	}

	close(release)
	result := <-firstResult
	if result.err != nil {
		t.Fatalf("first AcquireConnection error = %v", result.err)
	}
	result.wc.session.RemovePendingRequest(result.pending.RequestID)
}

func TestStoreToInitialLeaseIsAtomicAcrossAccountPoolKeys(t *testing.T) {
	tests := []struct {
		name     string
		reusable bool
	}{
		{name: "direct"},
		{name: "reusable", reusable: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			secondDialed := make(chan struct{})
			var dialCount atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				if dialCount.Add(1) == 2 {
					close(secondDialed)
				}
				defer conn.Close()
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
				}
			}))
			t.Cleanup(server.Close)

			manager := NewManager()
			t.Cleanup(manager.Stop)
			account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 2}
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
			firstStoredCh := make(chan *WsConnection, 1)
			releaseFirstStore := make(chan struct{})
			var hookCount atomic.Int32
			manager.afterConnectionStored = func(wc *WsConnection) {
				if hookCount.Add(1) == 1 {
					firstStoredCh <- wc
					<-releaseFirstStore
				}
			}

			type acquireResult struct {
				wc      *WsConnection
				pending *PendingRequest
				err     error
			}
			acquire := func(session string) <-chan acquireResult {
				result := make(chan acquireResult, 1)
				go func() {
					if tc.reusable {
						wc, pending, _, err := manager.AcquireReusableConnection(
							context.Background(), account, wsURL, session, "fallback-"+session, 1, http.Header{}, "",
						)
						result <- acquireResult{wc: wc, pending: pending, err: err}
						return
					}
					wc, pending, err := manager.AcquireConnection(
						context.Background(), account, wsURL, session, http.Header{}, "",
					)
					result <- acquireResult{wc: wc, pending: pending, err: err}
				}()
				return result
			}

			firstResultCh := acquire("first")
			var firstStored *WsConnection
			select {
			case firstStored = <-firstStoredCh:
			case <-time.After(time.Second):
				t.Fatal("first connection did not reach the Store-to-lease transition")
			}
			secondResultCh := acquire("second")

			// The correct implementation keeps the account lock across Store and
			// the initial lease, so the second pool key cannot inspect the first
			// socket in this deliberately widened transition window. The buggy
			// implementation dials the second socket and evicts the first one.
			select {
			case <-secondDialed:
			case <-time.After(100 * time.Millisecond):
			}
			evictedBeforeLease := !firstStored.IsConnected()
			close(releaseFirstStore)

			await := func(name string, resultCh <-chan acquireResult) acquireResult {
				t.Helper()
				select {
				case result := <-resultCh:
					if result.err != nil {
						t.Fatalf("%s acquire failed: %v", name, result.err)
					}
					if result.wc == nil || result.pending == nil {
						t.Fatalf("%s acquire returned an incomplete result", name)
					}
					return result
				case <-time.After(2 * time.Second):
					t.Fatalf("%s acquire timed out", name)
					return acquireResult{}
				}
			}
			firstResult := await("first", firstResultCh)
			secondResult := await("second", secondResultCh)
			firstResult.wc.session.RemovePendingRequest(firstResult.pending.RequestID)
			secondResult.wc.session.RemovePendingRequest(secondResult.pending.RequestID)

			if evictedBeforeLease {
				t.Fatal("newly stored connection was evicted before its initial request lease was installed")
			}
			if firstResult.wc != firstStored {
				t.Fatal("first acquire had to redial because its initially stored connection was evicted")
			}
			if got := manager.ConnectionCount(); got != 2 {
				t.Fatalf("ConnectionCount = %d, want 2", got)
			}
		})
	}
}

func TestAcquireConnectionEvictsUnboundIdleBeforeResponseBoundIdle(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	bound, boundPending, err := manager.AcquireConnection(context.Background(), account, wsURL, "bound", http.Header{}, "")
	if err != nil {
		t.Fatalf("acquire bound connection: %v", err)
	}
	bound.session.RemovePendingRequest(boundPending.RequestID)
	manager.BindResponseConn("resp_bound", bound, "bound", account.ID(), "key-A")
	manager.ReleaseConnection(bound)
	time.Sleep(2 * time.Millisecond)

	unbound, unboundPending, err := manager.AcquireConnection(context.Background(), account, wsURL, "unbound", http.Header{}, "")
	if err != nil {
		t.Fatalf("acquire unbound connection: %v", err)
	}
	unbound.session.RemovePendingRequest(unboundPending.RequestID)
	manager.ReleaseConnection(unbound)
	time.Sleep(2 * time.Millisecond)

	newest, newestPending, err := manager.AcquireConnection(context.Background(), account, wsURL, "newest", http.Header{}, "")
	if err != nil {
		t.Fatalf("acquire newest connection: %v", err)
	}
	newest.session.RemovePendingRequest(newestPending.RequestID)

	if !bound.IsConnected() {
		t.Fatal("response-bound idle connection should survive while an unbound idle peer can be evicted")
	}
	if unbound.IsConnected() {
		t.Fatal("unbound idle connection should be evicted before a response-bound idle peer")
	}
	if got, _ := manager.lookupResponseConn("resp_bound", account.ID(), "key-A"); got != bound {
		t.Fatal("previous_response_id binding was lost despite available unbound eviction capacity")
	}
	if got := manager.ConnectionCount(); got != 2 {
		t.Fatalf("ConnectionCount = %d, want bound context plus one ordinary-cap connection", got)
	}
}

func TestBoundIdleContextDoesNotConsumeOrdinaryDynamicCapacity(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	bound, boundPending, err := manager.AcquireConnection(context.Background(), account, wsURL, "bound", http.Header{}, "")
	if err != nil {
		t.Fatalf("acquire bound connection: %v", err)
	}
	bound.session.RemovePendingRequest(boundPending.RequestID)
	manager.BindResponseConn("resp_bound", bound, "bound", account.ID(), "key-A")
	manager.ReleaseConnection(bound)

	newest, pending, err := manager.AcquireConnection(context.Background(), account, wsURL, "new-active", http.Header{}, "")
	if err != nil {
		t.Fatalf("new active connection should fit beside bound-idle context: %v", err)
	}
	defer newest.session.RemovePendingRequest(pending.RequestID)
	if !bound.IsConnected() {
		t.Fatal("bound-idle continuation connection was evicted for ordinary capacity")
	}
	if got, _ := manager.lookupResponseConn("resp_bound", account.ID(), "key-A"); got != bound {
		t.Fatal("previous_response_id binding was lost after admitting new active capacity")
	}
	if got := manager.ConnectionCount(); got != 2 {
		t.Fatalf("ConnectionCount = %d, want one bound context plus one active connection", got)
	}
}

func TestActiveBoundConnectionStillConsumesDynamicCapacity(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var dialCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialCount.Add(1)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	bound, session := newTestSlotConnection(manager, account, wsURL, "bound-active")
	pending := session.AddPendingRequest("bound-active")
	manager.BindResponseConn("resp_active", bound, "bound-active", account.ID(), "key-A")
	// A long response may be quiet for more than IdleTimeout while only control
	// Pong frames arrive. It is still active capacity and must not be evicted.
	bound.lastUsed.Store(time.Now().Add(-IdleTimeout - time.Second).UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := manager.AcquireConnection(ctx, account, wsURL, "new", http.Header{}, ""); !errors.Is(err, proxy.ErrWebsocketLocalCapacity) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capacity-blocked acquire error = %v, want local-capacity and deadline sentinels", err)
	}
	if got := dialCount.Load(); got != 0 {
		t.Fatalf("physical dial count = %d, want 0 while active bound capacity is full", got)
	}
	if !bound.IsConnected() {
		t.Fatal("capacity check interrupted the active bound connection")
	}
	session.RemovePendingRequest(pending.RequestID)
}

func TestReleaseUnboundConnectionsConvergesToDynamicCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 2}
	wsURL := "wss://example.test/responses"
	first, firstSession := newTestSlotConnection(manager, account, wsURL, "first")
	second, secondSession := newTestSlotConnection(manager, account, wsURL, "second")
	firstPending := firstSession.AddPendingRequest("first")
	secondPending := secondSession.AddPendingRequest("second")

	account.Mu().Lock()
	account.DynamicConcurrencyLimit = 1
	account.Mu().Unlock()
	firstSession.RemovePendingRequest(firstPending.RequestID)
	manager.ReleaseConnection(first)
	if !first.IsConnected() || !second.IsConnected() {
		t.Fatal("first completion interrupted another active connection")
	}
	secondSession.RemovePendingRequest(secondPending.RequestID)
	manager.ReleaseConnection(second)
	if first.IsConnected() {
		t.Fatal("older unbound idle connection was not trimmed after both requests completed")
	}
	if !second.IsConnected() {
		t.Fatal("newly released protected connection should survive convergence")
	}
	if got := manager.ConnectionCount(); got != 1 {
		t.Fatalf("ConnectionCount after unbound convergence = %d, want 1", got)
	}
}

func TestExpiredResponseBindingReturnsConnectionToOrdinaryCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "expired-bound")
	manager.BindResponseConn("resp_expired", wc, "expired-bound", account.ID(), "key-A")
	manager.respConnMu.Lock()
	binding := manager.respConnBindings["resp_expired"]
	binding.expiresAt = time.Now().Add(-time.Second)
	manager.respConnBindings["resp_expired"] = binding
	manager.respConnMu.Unlock()

	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	available := manager.ensureAccountConnectionCapacity(account.ID(), 1, "new-key", 0)
	accountLock.Unlock()
	if !available {
		t.Fatal("expired continuation binding did not release ordinary capacity")
	}
	if wc.IsConnected() {
		t.Fatal("idle connection with only expired bindings was not recyclable")
	}
	if got, _ := manager.lookupResponseConn("resp_expired", account.ID(), "key-A"); got != nil {
		t.Fatal("expired response binding remained resolvable")
	}
}

func TestCleanupReclaimsExpiredBindingDespiteHeartbeatActivity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "wss://example.test/responses"
	expiredBound, expiredSession := newTestSlotConnection(manager, account, wsURL, "expired-heartbeat")
	manager.BindResponseConn("resp_heartbeat", expiredBound, "expired-heartbeat", account.ID(), "key-A")
	manager.respConnMu.Lock()
	binding := manager.respConnBindings["resp_heartbeat"]
	binding.expiresAt = time.Now().Add(-time.Second)
	manager.respConnBindings["resp_heartbeat"] = binding
	manager.respConnMu.Unlock()
	// Simulate recent business use after this older response binding. The
	// binding expiry must be processed independently of the fresher socket use.
	expiredBound.Touch()
	expiredSession.Touch()

	active, activeSession := newTestSlotConnection(manager, account, wsURL, "active")
	activePending := activeSession.AddPendingRequest("active")
	manager.evictExpired()

	if expiredBound.IsConnected() {
		t.Fatal("cleanup retained an idle connection after its only continuation binding expired")
	}
	if !active.IsConnected() {
		t.Fatal("cleanup interrupted active ordinary capacity")
	}
	if got, _ := manager.lookupResponseConn("resp_heartbeat", account.ID(), "key-A"); got != nil {
		t.Fatal("cleanup left the expired heartbeat-refreshed binding resolvable")
	}
	activeSession.RemovePendingRequest(activePending.RequestID)
}

func TestExpiredBindingDoesNotOverridePongKeepaliveWithinOrdinaryCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, session := newTestSlotConnection(manager, account, "wss://example.test/responses", "pong-idle")
	manager.BindResponseConn("resp_pong_idle", wc, "pong-idle", account.ID(), "key-A")
	manager.respConnMu.Lock()
	binding := manager.respConnBindings["resp_pong_idle"]
	binding.expiresAt = time.Now().Add(-time.Second)
	manager.respConnBindings["resp_pong_idle"] = binding
	manager.respConnMu.Unlock()

	stale := time.Now().Add(-IdleTimeout - time.Second).UnixNano()
	wc.lastUsed.Store(stale)
	for i := 0; i < 5; i++ {
		wc.handleControlPong(fmt.Sprintf("heartbeat-%d", i))
	}
	if wc.lastUsed.Load() <= stale {
		t.Fatal("control Pong did not refresh socket keepalive before cleanup")
	}
	if session.IsExpired() {
		t.Fatal("setup failed: Pong should keep session transport liveness fresh")
	}

	manager.evictExpired()

	if !wc.IsConnected() {
		t.Fatal("binding expiry closed a Pong-live socket that fits ordinary capacity")
	}
	if got, ok := manager.connections.Load(wc.PoolKey); !ok || got != wc {
		t.Fatal("binding expiry removed the Pong-live ordinary connection")
	}
	if got, _ := manager.lookupResponseConn("resp_pong_idle", account.ID(), "key-A"); got != nil {
		t.Fatal("cleanup left the expired continuation binding resolvable")
	}
}

func TestCleanupPreservesQuietPendingConnectionUntilItDrains(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, session := newTestSlotConnection(manager, account, "wss://example.test/responses", "quiet-pending")
	pending := session.AddPendingRequest("quiet-pending")
	wc.lastUsed.Store(time.Now().Add(-IdleTimeout - time.Second).UnixNano())
	session.mu.Lock()
	session.LastActiveAt = time.Now().Add(-IdleTimeout - time.Second)
	session.mu.Unlock()

	manager.evictExpired()

	if !wc.IsConnected() {
		t.Fatal("cleanup interrupted a quiet in-flight response after IdleTimeout")
	}
	if got, ok := manager.connections.Load(wc.PoolKey); !ok || got != wc {
		t.Fatal("cleanup removed a quiet in-flight connection from the pool")
	}
	if got, ok := manager.sessions.Load(wc.PoolKey); !ok || got != session {
		t.Fatal("cleanup independently removed the session of an active connection")
	}

	session.RemovePendingRequest(pending.RequestID)
	manager.evictExpired()

	if wc.IsConnected() {
		t.Fatal("drained connection did not converge after its business idle TTL had expired")
	}
	if _, ok := manager.sessions.Load(wc.PoolKey); ok {
		t.Fatal("drained idle-expired connection left its session behind")
	}
}

func TestCleanupKeepsBusinessActiveConnectionWhenSessionTimestampIsStale(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, session := newTestSlotConnection(manager, account, "wss://example.test/responses", "business-active")
	pending := session.AddPendingRequest("business-active")
	t.Cleanup(func() { session.RemovePendingRequest(pending.RequestID) })
	session.mu.Lock()
	session.LastActiveAt = time.Now().Add(-IdleTimeout - time.Second)
	session.mu.Unlock()
	// Business frames update the connection timestamp even if no Pong arrives.
	wc.Touch()

	manager.evictExpired()

	if !wc.IsConnected() {
		t.Fatal("cleanup interrupted a connection with recent business activity")
	}
	if got, ok := manager.sessions.Load(wc.PoolKey); !ok || got != session {
		t.Fatal("stale Session.LastActiveAt overrode the live connection lifecycle")
	}
}

func TestReleaseConnectionRefreshesBusinessLastUsed(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "release-touch")
	stale := time.Now().Add(-IdleTimeout - time.Second).UnixNano()
	wc.lastUsed.Store(stale)

	manager.ReleaseConnection(wc)

	if got := wc.lastUsed.Load(); got <= stale {
		t.Fatalf("ReleaseConnection lastUsed = %d, want newer than %d", got, stale)
	}
	if wc.IsExpired() {
		t.Fatal("business release did not refresh the connection idle deadline")
	}
}

func TestCapacityEvictionRacingWithBindReclassifiesContinuation(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wc, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "bind-race")
	snapshotTaken := make(chan struct{})
	releaseCapacity := make(chan struct{})
	manager.beforeCapacityEviction = func() {
		close(snapshotTaken)
		<-releaseCapacity
	}
	capacityResult := make(chan bool, 1)
	go func() {
		accountLock := manager.accountLock(account.ID())
		accountLock.Lock()
		available := manager.ensureAccountConnectionCapacity(account.ID(), 1, "new-key", 0)
		accountLock.Unlock()
		capacityResult <- available
	}()
	select {
	case <-snapshotTaken:
	case <-time.After(time.Second):
		t.Fatal("capacity check did not reach the binding snapshot barrier")
	}
	manager.BindResponseConn("resp_race_capacity", wc, "bind-race", account.ID(), "key-A")
	close(releaseCapacity)
	select {
	case available := <-capacityResult:
		if !available {
			t.Fatal("newly bound idle connection was not reclassified out of ordinary capacity")
		}
	case <-time.After(time.Second):
		t.Fatal("capacity check did not finish")
	}
	if !wc.IsConnected() {
		t.Fatal("capacity eviction won after a live response binding was published")
	}
	if got, _ := manager.lookupResponseConn("resp_race_capacity", account.ID(), "key-A"); got != wc {
		t.Fatal("raced response binding was not preserved")
	}
}

func setTestResponseBindingExpiry(t *testing.T, manager *Manager, responseID string, expiresAt time.Time) {
	t.Helper()
	manager.respConnMu.Lock()
	binding, ok := manager.respConnBindings[responseID]
	if !ok {
		manager.respConnMu.Unlock()
		t.Fatalf("missing response binding %q", responseID)
	}
	binding.expiresAt = expiresAt
	manager.respConnBindings[responseID] = binding
	manager.respConnMu.Unlock()
}

func TestContinuationPerAccountBudgetEvictsOldestBindingGenerationOnRelease(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.continuationGlobalLimit = 10
	manager.continuationPerAccountLimit = 2
	account := &auth.Account{DBID: 101, DynamicConcurrencyLimit: 1}
	wsURL := "wss://example.test/responses"
	oldest, _ := newTestSlotConnection(manager, account, wsURL, "oldest")
	middle, _ := newTestSlotConnection(manager, account, wsURL, "middle")
	newest, _ := newTestSlotConnection(manager, account, wsURL, "newest")

	manager.BindResponseConn("resp_oldest_a", oldest, "oldest", account.ID(), "key-A")
	manager.BindResponseConn("resp_oldest_b", oldest, "oldest", account.ID(), "key-A")
	manager.BindResponseConn("resp_middle", middle, "middle", account.ID(), "key-A")
	manager.BindResponseConn("resp_newest", newest, "newest", account.ID(), "key-A")
	// Make socket lastUsed newest via Pong; continuation LRU must still use the
	// newest Bind generation and sacrifice this oldest generation.
	oldest.handleControlPong("keepalive")

	manager.ReleaseConnection(newest)

	if oldest.IsConnected() {
		t.Fatal("per-account continuation budget did not evict the oldest binding generation")
	}
	if !middle.IsConnected() || !newest.IsConnected() {
		t.Fatal("per-account continuation budget evicted a newer generation")
	}
	for _, responseID := range []string{"resp_oldest_a", "resp_oldest_b"} {
		if got, _ := manager.lookupResponseConn(responseID, account.ID(), "key-A"); got != nil {
			t.Fatalf("evicted socket retained binding %q", responseID)
		}
	}
}

func TestContinuationGlobalBudgetEvictsAcrossDynamicAccountIDs(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.continuationGlobalLimit = 2
	manager.continuationPerAccountLimit = 2
	type boundConn struct {
		account *auth.Account
		wc      *WsConnection
		respID  string
	}
	connections := make([]boundConn, 0, 3)
	for _, accountID := range []int64{101, 207, 999} {
		account := &auth.Account{DBID: accountID, DynamicConcurrencyLimit: 1}
		wc, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", fmt.Sprintf("account-%d", accountID))
		responseID := fmt.Sprintf("resp_account_%d", accountID)
		manager.BindResponseConn(responseID, wc, wc.session.ID, accountID, "key-A")
		connections = append(connections, boundConn{account: account, wc: wc, respID: responseID})
	}

	manager.enforceContinuationSocketBudgets()

	if connections[0].wc.IsConnected() {
		t.Fatal("global continuation budget did not evict the oldest cross-account generation")
	}
	for _, connection := range connections[1:] {
		if !connection.wc.IsConnected() {
			t.Fatalf("global continuation budget evicted newer account %d", connection.account.ID())
		}
	}
}

func TestContinuationBudgetNeverEvictsActiveBoundConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.continuationGlobalLimit = 1
	manager.continuationPerAccountLimit = 1
	account := &auth.Account{DBID: 314, DynamicConcurrencyLimit: 1}
	active, activeSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "active-bound")
	idle, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "idle-bound")
	manager.BindResponseConn("resp_active_budget", active, "active-bound", account.ID(), "key-A")
	manager.BindResponseConn("resp_idle_budget", idle, "idle-bound", account.ID(), "key-A")
	pending := activeSession.AddPendingRequest("active-bound")

	manager.enforceContinuationSocketBudgets()

	if !active.IsConnected() || !idle.IsConnected() {
		t.Fatal("bound-idle budget counted or evicted an active pending connection")
	}
	activeSession.RemovePendingRequest(pending.RequestID)
}

func TestPreferredBoundIdleActivationRespectsOrdinaryCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 808, DynamicConcurrencyLimit: 1}
	active, activeSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "ordinary-active")
	bound, boundSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "preferred-bound")
	manager.BindResponseConn("resp_preferred_capacity", bound, "preferred-bound", account.ID(), "key-A")
	activePending := activeSession.AddPendingRequest("ordinary-active")

	got, pending, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_preferred_capacity", account.ID(), "key-A")
	if got != nil || pending != nil {
		t.Fatal("preferred bound-idle activation exceeded strict ordinary account capacity")
	}
	if !errors.Is(err, proxy.ErrWebsocketLocalCapacity) {
		t.Fatalf("preferred capacity error = %v, want ErrWebsocketLocalCapacity", err)
	}
	if boundSession.PendingCount() != 0 {
		t.Fatal("rejected preferred activation left a pending request behind")
	}
	if !active.IsConnected() || !bound.IsConnected() {
		t.Fatal("capacity rejection killed an active or continuation socket")
	}
	if gotBound, _ := manager.lookupResponseConn("resp_preferred_capacity", account.ID(), "key-A"); gotBound != bound {
		t.Fatal("capacity rejection destroyed the preserved continuation binding")
	}
	activeSession.RemovePendingRequest(activePending.RequestID)
}

func TestPreferredBoundIdleActivationEvictsOrdinaryIdleForCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 809, DynamicConcurrencyLimit: 1}
	ordinaryIdle, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "ordinary-idle")
	bound, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "preferred-bound")
	manager.BindResponseConn("resp_preferred_reclaim", bound, "preferred-bound", account.ID(), "key-A")

	got, pending, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_preferred_reclaim", account.ID(), "key-A")
	if err != nil || got != bound || pending == nil {
		t.Fatalf("preferred activation = (%p, %v, %v), want reclaimed bound connection", got, pending, err)
	}
	if ordinaryIdle.IsConnected() {
		t.Fatal("ordinary idle socket was not evicted before bound-idle activation")
	}
	if !bound.IsConnected() {
		t.Fatal("preferred continuation was killed while reclaiming capacity")
	}
	bound.session.RemovePendingRequest(pending.RequestID)
}

func TestUnboundIdleActivationAtExactCapacityDoesNotDoubleCount(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 810, DynamicConcurrencyLimit: 1}
	unbound, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "unbound-exact")
	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	admitted := manager.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), unbound)
	accountLock.Unlock()
	if !admitted {
		t.Fatal("unbound idle reuse was double-counted at the exact ordinary limit")
	}
}

func TestUnboundIdleActivationCountsPendingCreatesAfterLimitDecrease(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 811, DynamicConcurrencyLimit: 1}
	unbound, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "unbound-pending")
	manager.capacityMu.Lock()
	manager.pendingCreates = make(map[int64]int)
	manager.pendingCreates[account.ID()] = 1
	manager.capacityMu.Unlock()
	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	admitted := manager.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), unbound)
	accountLock.Unlock()
	if admitted {
		t.Fatal("unbound idle activation ignored an already reserved pending dial")
	}
	if !unbound.IsConnected() {
		t.Fatal("capacity rejection killed the protected unbound socket")
	}
	manager.releaseAccountConnectionCapacity(account.ID())
}

func TestExpiredBindingActivationDoesNotBypassLoweredLimit(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 812, DynamicConcurrencyLimit: 1}
	active, activeSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "lowered-active")
	candidate, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "expired-candidate")
	manager.BindResponseConn("resp_expired_activation", candidate, "expired-candidate", account.ID(), "key-A")
	setTestResponseBindingExpiry(t, manager, "resp_expired_activation", time.Now().Add(-time.Second))
	activePending := activeSession.AddPendingRequest("lowered-active")

	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	admitted := manager.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), candidate)
	accountLock.Unlock()
	if admitted {
		t.Fatal("expired binding bypassed the lowered ordinary capacity limit")
	}
	if !active.IsConnected() || !candidate.IsConnected() {
		t.Fatal("capacity rejection killed an active or protected candidate socket")
	}
	activeSession.RemovePendingRequest(activePending.RequestID)
}

func TestStaleActivationCandidateIsRejectedAfterCleanup(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 815, DynamicConcurrencyLimit: 1}
	candidate, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "stale-candidate")
	candidate.lastUsed.Store(time.Now().Add(-IdleTimeout - time.Second).UnixNano())

	accountLock := manager.accountLock(account.ID())
	accountLock.Lock()
	admitted := manager.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), candidate)
	accountLock.Unlock()
	if admitted {
		t.Fatal("stale activation candidate was admitted after being reclaimed")
	}
	if candidate.IsConnected() {
		t.Fatal("stale activation candidate was not reclaimed")
	}
}

func TestNormalBoundIdleReuseRespectsOrdinaryCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 813, DynamicConcurrencyLimit: 1}
	active, activeSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "normal-active")
	bound, boundSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "normal-bound")
	manager.BindResponseConn("resp_normal_capacity", bound, "normal-bound", account.ID(), "key-A")
	activePending := activeSession.AddPendingRequest("normal-active")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	got, pending, err := manager.AcquireConnection(ctx, account, bound.URL, "normal-bound", http.Header{}, "")
	if err == nil || got != nil || pending != nil {
		t.Fatal("normal key reuse activated bound-idle beyond ordinary capacity")
	}
	if boundSession.PendingCount() != 0 || !active.IsConnected() || !bound.IsConnected() {
		t.Fatal("rejected normal reuse changed pending or connection ownership")
	}
	activeSession.RemovePendingRequest(activePending.RequestID)
}

func TestReusableBoundIdleReuseRespectsOrdinaryCapacity(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 814, DynamicConcurrencyLimit: 1}
	active, activeSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "reusable-active")
	bound, boundSession := newTestSlotConnection(manager, account, "wss://example.test/responses", "reusable#0")
	manager.BindResponseConn("resp_reusable_capacity", bound, "reusable#0", account.ID(), "key-A")
	activePending := activeSession.AddPendingRequest("reusable-active")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	got, pending, _, err := manager.AcquireReusableConnection(ctx, account, bound.URL, "reusable", "reusable-fallback", 1, http.Header{}, "")
	if err == nil || got != nil || pending != nil {
		t.Fatal("reusable slot activated bound-idle beyond ordinary capacity")
	}
	if boundSession.PendingCount() != 0 || !active.IsConnected() || !bound.IsConnected() {
		t.Fatal("rejected reusable activation changed pending or connection ownership")
	}
	activeSession.RemovePendingRequest(activePending.RequestID)
}

func TestContinuationBudgetRevalidatesConcurrentPreferredAcquire(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	manager.continuationGlobalLimit = 1
	manager.continuationPerAccountLimit = 1
	account := &auth.Account{DBID: 1618, DynamicConcurrencyLimit: 1}
	oldCandidate, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "acquire-candidate")
	other, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "acquire-other")
	manager.BindResponseConn("resp_acquire_candidate", oldCandidate, "acquire-candidate", account.ID(), "key-A")
	manager.BindResponseConn("resp_acquire_other", other, "acquire-other", account.ID(), "key-A")
	base := time.Now()
	setTestResponseBindingExpiry(t, manager, "resp_acquire_candidate", base.Add(time.Minute))
	setTestResponseBindingExpiry(t, manager, "resp_acquire_other", base.Add(2*time.Minute))

	snapshotReady := make(chan struct{})
	releaseRevalidation := make(chan struct{})
	var hookCalls atomic.Int32
	manager.beforeContinuationRevalidation = func(*WsConnection) {
		if hookCalls.Add(1) == 1 {
			close(snapshotReady)
			<-releaseRevalidation
		}
	}
	done := make(chan struct{})
	go func() {
		manager.enforceContinuationSocketBudgets()
		close(done)
	}()
	select {
	case <-snapshotReady:
	case <-time.After(time.Second):
		t.Fatal("continuation trim did not reach the preferred-acquire barrier")
	}

	acquired, pending, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_acquire_candidate", account.ID(), "key-A")
	if err != nil || acquired != oldCandidate || pending == nil {
		t.Fatalf("preferred continuation = (%p, %v, %v), want acquired while trim awaited revalidation", acquired, pending, err)
	}
	close(releaseRevalidation)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("continuation trim did not finish after preferred acquire")
	}

	if !oldCandidate.IsConnected() || !other.IsConnected() {
		t.Fatal("continuation trim evicted a socket after it became active")
	}
	oldCandidate.session.RemovePendingRequest(pending.RequestID)
}

func TestCleanupConvergesContinuationSocketBudget(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.continuationGlobalLimit = 1
	manager.continuationPerAccountLimit = 1
	account := &auth.Account{DBID: 4242, DynamicConcurrencyLimit: 1}
	oldest, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "cleanup-oldest")
	newest, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "cleanup-newest")
	manager.BindResponseConn("resp_cleanup_oldest", oldest, "cleanup-oldest", account.ID(), "key-A")
	manager.BindResponseConn("resp_cleanup_newest", newest, "cleanup-newest", account.ID(), "key-A")

	manager.evictExpired()

	if oldest.IsConnected() {
		t.Fatal("cleanup did not converge the continuation socket budget")
	}
	if !newest.IsConnected() {
		t.Fatal("cleanup evicted the newer continuation generation")
	}
}

func TestContinuationBudgetRevalidatesNewBindingGenerationBeforeEviction(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.continuationGlobalLimit = 1
	manager.continuationPerAccountLimit = 1
	account := &auth.Account{DBID: 2718, DynamicConcurrencyLimit: 1}
	oldCandidate, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "old-candidate")
	other, _ := newTestSlotConnection(manager, account, "wss://example.test/responses", "other")
	manager.BindResponseConn("resp_old_candidate", oldCandidate, "old-candidate", account.ID(), "key-A")
	manager.BindResponseConn("resp_other", other, "other", account.ID(), "key-A")
	// All expiries are intentionally identical. Wall-clock expiry cannot serve
	// as a generation: the monotonic Bind generation must make oldCandidate the
	// initial victim and then detect its concurrent renewal exactly.
	identicalExpiry := time.Now().Add(2 * time.Minute)
	setTestResponseBindingExpiry(t, manager, "resp_old_candidate", identicalExpiry)
	setTestResponseBindingExpiry(t, manager, "resp_other", identicalExpiry)

	snapshotReady := make(chan struct{})
	releaseRevalidation := make(chan struct{})
	var hookCalls atomic.Int32
	manager.beforeContinuationRevalidation = func(*WsConnection) {
		if hookCalls.Add(1) == 1 {
			close(snapshotReady)
			<-releaseRevalidation
		}
	}
	done := make(chan struct{})
	go func() {
		manager.enforceContinuationSocketBudgets()
		close(done)
	}()
	select {
	case <-snapshotReady:
	case <-time.After(time.Second):
		t.Fatal("continuation trim did not reach the revalidation barrier")
	}
	manager.BindResponseConn("resp_old_candidate_new", oldCandidate, "old-candidate", account.ID(), "key-A")
	setTestResponseBindingExpiry(t, manager, "resp_old_candidate_new", identicalExpiry)
	close(releaseRevalidation)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("continuation trim did not finish after revalidation release")
	}

	if !oldCandidate.IsConnected() {
		t.Fatal("continuation trim evicted a candidate after its binding generation was renewed")
	}
	if other.IsConnected() {
		t.Fatal("continuation trim did not reselect the now-oldest binding generation")
	}
	if got, _ := manager.lookupResponseConn("resp_old_candidate_new", account.ID(), "key-A"); got != oldCandidate {
		t.Fatal("renewed continuation binding was lost during budget revalidation")
	}
	if got, _ := manager.lookupResponseConn("resp_other", account.ID(), "key-A"); got != nil {
		t.Fatal("evicted continuation left a stale response binding")
	}
}

func TestTrimAfterLimitDecreaseEvictsUnboundBeforeResponseBound(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(*WsConnection) bool { return true }
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 3}
	wsURL := "wss://example.test/responses"
	bound, _ := newTestSlotConnection(manager, account, wsURL, "bound")
	manager.BindResponseConn("resp_bound", bound, "bound", account.ID(), "key-A")
	time.Sleep(2 * time.Millisecond)
	unbound, _ := newTestSlotConnection(manager, account, wsURL, "unbound")
	time.Sleep(2 * time.Millisecond)
	protected, _ := newTestSlotConnection(manager, account, wsURL, "protected")

	account.Mu().Lock()
	account.DynamicConcurrencyLimit = 1
	account.Mu().Unlock()
	got, pending, err := manager.AcquireConnection(context.Background(), account, wsURL, "protected", http.Header{}, "")
	if err != nil {
		t.Fatalf("AcquireConnection after limit decrease: %v", err)
	}
	got.session.RemovePendingRequest(pending.RequestID)

	if got != protected || !protected.IsConnected() {
		t.Fatal("protected connection should remain selected and connected")
	}
	if !bound.IsConnected() {
		t.Fatal("response-bound idle connection should survive trim while an unbound peer exists")
	}
	if unbound.IsConnected() {
		t.Fatal("unbound idle connection should be trimmed first")
	}
	if got := manager.ConnectionCount(); got != 2 {
		t.Fatalf("ConnectionCount = %d, want 2", got)
	}
}

func TestDiscardConnectionRemovesOnlyItsResponseBindings(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	wc1 := newBoundTestConn(t, manager, 7, "one")
	wc2 := newBoundTestConn(t, manager, 7, "two")
	manager.BindResponseConn("resp_one_a", wc1, "one", 7, "key-A")
	manager.BindResponseConn("resp_one_b", wc1, "one", 7, "key-A")
	manager.BindResponseConn("resp_two", wc2, "two", 7, "key-A")

	manager.DiscardConnection(wc1)

	manager.respConnMu.Lock()
	defer manager.respConnMu.Unlock()
	if _, ok := manager.respConnBindings["resp_one_a"]; ok {
		t.Fatal("discarded connection retained resp_one_a binding")
	}
	if _, ok := manager.respConnBindings["resp_one_b"]; ok {
		t.Fatal("discarded connection retained resp_one_b binding")
	}
	if binding, ok := manager.respConnBindings["resp_two"]; !ok || binding.conn != wc2 {
		t.Fatal("discarding one connection removed an unrelated live binding")
	}
}

func TestManagerStopClosesPendingRequests(t *testing.T) {
	manager := NewManager()
	account := &auth.Account{DBID: 42}
	wc, session := newTestSlotConnection(manager, account, "wss://example.test/responses", "active")
	pending := session.AddPendingRequest("active")

	manager.Stop()

	select {
	case <-pending.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel the pending request")
	}
	if got := session.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after Stop = %d, want 0", got)
	}
	if wc.IsConnected() {
		t.Fatal("Stop left the connection connected")
	}
}

func TestEvictDisconnectedConnectionClosesPendingRequests(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42}
	wc, session := newTestSlotConnection(manager, account, "wss://example.test/responses", "expired")
	pending := session.AddPendingRequest("expired")
	wc.SetState(StateDisconnected)

	manager.evictExpired()

	select {
	case <-pending.Ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("disconnected-connection eviction did not cancel the pending request")
	}
	if got := session.PendingCount(); got != 0 {
		t.Fatalf("PendingCount after eviction = %d, want 0", got)
	}
	if _, ok := manager.connections.Load(wc.PoolKey); ok {
		t.Fatal("disconnected connection remained in the pool")
	}
}

func TestBindResponseConnRacingWithDiscardCannotPublishStaleBinding(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	wc := newBoundTestConn(t, manager, 7, "race")

	// Hold the publication lock so both operations reach the critical ordering
	// point deterministically. Discard must first remove/close the connection;
	// after the lock is released, Bind must reject that dead pointer regardless
	// of which waiter acquires the mutex first.
	manager.respConnMu.Lock()
	bindStarted := make(chan struct{})
	bindDone := make(chan struct{})
	go func() {
		close(bindStarted)
		manager.BindResponseConn("resp_race", wc, "race", 7, "key-A")
		close(bindDone)
	}()
	<-bindStarted

	discardStarted := make(chan struct{})
	discardDone := make(chan struct{})
	go func() {
		close(discardStarted)
		manager.DiscardConnection(wc)
		close(discardDone)
	}()
	<-discardStarted

	stateRemoved := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, pooled := manager.connections.Load(wc.PoolKey)
		if !pooled && !wc.IsConnected() {
			stateRemoved = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	manager.respConnMu.Unlock()
	if !stateRemoved {
		t.Fatal("Discard blocked on binding cleanup before making the connection unselectable")
	}

	select {
	case <-bindDone:
	case <-time.After(time.Second):
		t.Fatal("BindResponseConn did not finish")
	}
	select {
	case <-discardDone:
	case <-time.After(time.Second):
		t.Fatal("DiscardConnection did not finish")
	}

	manager.respConnMu.Lock()
	_, stale := manager.respConnBindings["resp_race"]
	manager.respConnMu.Unlock()
	if stale {
		t.Fatal("BindResponseConn published a stale binding for a discarded connection")
	}
}

func TestManagerStopCancelsInFlightDialAndRejectsNewAcquires(t *testing.T) {
	dialStarted := make(chan struct{})
	var startOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(dialStarted) })
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	acquireDone := make(chan error, 1)
	go func() {
		_, _, err := manager.AcquireConnection(context.Background(), account, wsURL, "blocked", http.Header{}, "")
		acquireDone <- err
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("AcquireConnection did not enter the handshake")
	}
	stopDone := make(chan struct{})
	go func() {
		manager.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not cancel and drain the in-flight handshake")
	}
	select {
	case err := <-acquireDone:
		if err == nil {
			t.Fatal("in-flight acquire unexpectedly succeeded after Stop")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight acquire did not return after Stop")
	}
	if got := manager.ConnectionCount(); got != 0 {
		t.Fatalf("ConnectionCount after Stop = %d, want 0", got)
	}
	if got := manager.SessionCount(); got != 0 {
		t.Fatalf("SessionCount after Stop = %d, want 0", got)
	}
	manager.capacityMu.Lock()
	pendingCreates := len(manager.pendingCreates)
	manager.capacityMu.Unlock()
	if pendingCreates != 0 {
		t.Fatalf("pendingCreates entries after Stop = %d, want 0", pendingCreates)
	}
	if _, _, err := manager.AcquireConnection(context.Background(), account, wsURL, "after-stop", http.Header{}, ""); !errors.Is(err, ErrManagerStopped) {
		t.Fatalf("AcquireConnection after Stop error = %v, want ErrManagerStopped", err)
	}
}

func TestHandshakeSessionIsPublishedOnlyAfterSuccessfulPromotion(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	handshakeArrived := make(chan struct{})
	releaseHandshake := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHandshake) }) }
	defer release()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handshakeArrived)
		<-releaseHandshake
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	type acquireResult struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	resultCh := make(chan acquireResult, 1)
	go func() {
		wc, pending, err := manager.AcquireConnection(context.Background(), account, wsURL, "long-handshake", http.Header{}, "")
		resultCh <- acquireResult{wc: wc, pending: pending, err: err}
	}()
	select {
	case <-handshakeArrived:
	case <-time.After(time.Second):
		t.Fatal("acquire did not reach the handshake barrier")
	}
	if got := manager.SessionCount(); got != 0 {
		t.Fatalf("SessionCount during incomplete handshake = %d, want 0", got)
	}
	manager.evictExpired()
	if got := manager.SessionCount(); got != 0 {
		t.Fatalf("cleanup published or retained an incomplete-handshake session: %d", got)
	}
	release()

	select {
	case result := <-resultCh:
		if result.err != nil || result.wc == nil || result.pending == nil {
			t.Fatalf("acquire after handshake release = (%p, %p, %v)", result.wc, result.pending, result.err)
		}
		if got := manager.SessionCount(); got != 1 {
			t.Fatalf("SessionCount after promotion = %d, want 1", got)
		}
		if session, ok := manager.GetSession(account.ID(), wsURL, "long-handshake", ""); !ok || session != result.wc.session {
			t.Fatal("promoted connection session was not published under its pool key")
		}
		result.wc.session.RemovePendingRequest(result.pending.RequestID)
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not finish after handshake release")
	}
}

func TestManagerStopWaitsForStoreTransitionAndLeavesNoRevivedState(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 1}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	stored := make(chan struct{})
	releaseStore := make(chan struct{})
	var storeOnce sync.Once
	manager.afterConnectionStored = func(*WsConnection) {
		storeOnce.Do(func() { close(stored) })
		<-releaseStore
	}
	acquireDone := make(chan error, 1)
	go func() {
		_, _, err := manager.AcquireConnection(context.Background(), account, wsURL, "store-race", http.Header{}, "")
		acquireDone <- err
	}()
	select {
	case <-stored:
	case <-time.After(time.Second):
		t.Fatal("acquire did not reach the Store-to-lease transition")
	}

	stopDone := make(chan struct{})
	go func() {
		manager.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
		t.Fatal("Stop returned while a Store-to-lease transition was still admitted")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseStore)
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not finish after the Store-to-lease transition drained")
	}
	select {
	case err := <-acquireDone:
		if err == nil {
			t.Fatal("acquire unexpectedly succeeded through concurrent Stop")
		}
	case <-time.After(time.Second):
		t.Fatal("acquire did not return after Store-to-lease release")
	}
	if got := manager.ConnectionCount(); got != 0 {
		t.Fatalf("ConnectionCount after Stop/store race = %d, want 0", got)
	}
	if got := manager.SessionCount(); got != 0 {
		t.Fatalf("SessionCount after Stop/store race = %d, want 0", got)
	}
}

func TestPendingDialsRevalidateLoweredDynamicLimitBeforeStore(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	handshakeArrived := make(chan struct{}, 2)
	releaseHandshakes := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshakeArrived <- struct{}{}
		<-releaseHandshakes
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 2}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type acquireResult struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	results := make(chan acquireResult, 2)
	var maxStored atomic.Int32
	manager.afterConnectionStored = func(*WsConnection) {
		count := int32(manager.ConnectionCount())
		for {
			old := maxStored.Load()
			if count <= old || maxStored.CompareAndSwap(old, count) {
				break
			}
		}
	}
	for _, sessionKey := range []string{"first", "second"} {
		sessionKey := sessionKey
		go func() {
			wc, pending, err := manager.AcquireConnection(ctx, account, wsURL, sessionKey, http.Header{}, "")
			results <- acquireResult{wc: wc, pending: pending, err: err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-handshakeArrived:
		case <-time.After(time.Second):
			t.Fatal("both pending dials did not reach the handshake barrier")
		}
	}
	account.Mu().Lock()
	account.DynamicConcurrencyLimit = 1
	account.Mu().Unlock()
	close(releaseHandshakes)

	var winner acquireResult
	select {
	case winner = <-results:
		if winner.err != nil || winner.wc == nil || winner.pending == nil {
			t.Fatalf("first completed acquire = (%p, %p, %v), want one admitted connection", winner.wc, winner.pending, winner.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("neither pending dial was admitted under the lowered limit")
	}
	cancel()
	select {
	case loser := <-results:
		if loser.err == nil {
			t.Fatal("second pending dial was admitted after the limit dropped to one")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("excess pending dial did not exit after cancellation")
	}
	if got := maxStored.Load(); got > 1 {
		t.Fatalf("maximum stored connections after 2->1 limit change = %d, want <= 1", got)
	}
	if !winner.wc.IsConnected() {
		t.Fatal("admitted busy connection was interrupted while rejecting the excess dial")
	}
	winner.wc.session.RemovePendingRequest(winner.pending.RequestID)
	manager.capacityMu.Lock()
	pendingCreates := len(manager.pendingCreates)
	manager.capacityMu.Unlock()
	if pendingCreates != 0 {
		t.Fatalf("pendingCreates entries after both dials completed = %d, want 0", pendingCreates)
	}
}

func TestReplaceConnectionExcludesConcurrentSameKeyAcquire(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var dialCount atomic.Int32
	dialed := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialCount.Add(1)
		dialed <- struct{}{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 2}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	old, _ := newTestSlotConnection(manager, account, wsURL, "replace")
	removed := make(chan struct{})
	releaseReplacement := make(chan struct{})
	manager.afterReplacementRemoved = func(string) {
		close(removed)
		<-releaseReplacement
	}
	type acquireResult struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	replaceResult := make(chan acquireResult, 1)
	go func() {
		wc, pending, err := manager.ReplaceConnection(context.Background(), account, wsURL, "replace", http.Header{}, "")
		replaceResult <- acquireResult{wc: wc, pending: pending, err: err}
	}()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("ReplaceConnection did not remove the old connection")
	}
	if old.IsConnected() {
		t.Fatal("old connection remained connected after replacement removal")
	}

	concurrentCtx, cancelConcurrent := context.WithCancel(context.Background())
	concurrentResult := make(chan error, 1)
	go func() {
		_, _, err := manager.AcquireConnection(concurrentCtx, account, wsURL, "replace", http.Header{}, "")
		concurrentResult <- err
	}()
	select {
	case <-dialed:
		t.Fatal("concurrent same-key acquire passed the replacement gate")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseReplacement)

	var replacement acquireResult
	select {
	case replacement = <-replaceResult:
		if replacement.err != nil || replacement.wc == nil || replacement.pending == nil {
			t.Fatalf("ReplaceConnection result = (%p, %p, %v)", replacement.wc, replacement.pending, replacement.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReplaceConnection did not complete")
	}
	cancelConcurrent()
	select {
	case err := <-concurrentResult:
		if err == nil {
			t.Fatal("concurrent same-key acquire unexpectedly succeeded while replacement lease was busy")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent same-key acquire did not exit after cancellation")
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("physical dial count = %d, want exactly one replacement dial", got)
	}
	replacement.wc.session.RemovePendingRequest(replacement.pending.RequestID)
}

func TestManagerLockStripingIsStableAndBounded(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	keyLocks := make(map[*sync.Mutex]struct{})
	replacementLocks := make(map[*sync.Mutex]struct{})
	accountLocks := make(map[*sync.Mutex]struct{})
	for i := 0; i < managerLockStripeCount*8; i++ {
		key := fmt.Sprintf("oneshot-%d-%d", i, i*7919)
		keyLocks[manager.keyLock(key)] = struct{}{}
		replacementLocks[manager.replacementLock(key)] = struct{}{}
		accountLocks[manager.accountLock(int64(i))] = struct{}{}
	}
	if len(keyLocks) > managerLockStripeCount || len(replacementLocks) > managerLockStripeCount || len(accountLocks) > managerLockStripeCount {
		t.Fatalf("lock stripes exceeded fixed bound: key=%d replacement=%d account=%d limit=%d", len(keyLocks), len(replacementLocks), len(accountLocks), managerLockStripeCount)
	}
	if manager.keyLock("stable") != manager.keyLock("stable") {
		t.Fatal("same pool key did not resolve to a stable lock stripe")
	}
	if manager.accountLock(42) != manager.accountLock(42) {
		t.Fatal("same account did not resolve to a stable lock stripe")
	}
}

func newTestSlotConnection(manager *Manager, account *auth.Account, wsURL, slotSession string) (*WsConnection, *Session) {
	key := manager.poolKey(account.ID(), wsURL, slotSession, "")
	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{
		account:  account,
		session:  session,
		URL:      wsURL,
		PoolKey:  key,
		httpResp: &http.Response{StatusCode: http.StatusSwitchingProtocols},
	}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)
	return conn, session
}

func TestAcquireReusableConnectionReusesIdleSlot(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	account := &auth.Account{DBID: 42}
	wsURL := "wss://example.test/responses"
	conn, _ := newTestSlotConnection(manager, account, wsURL, "cache-key#0")

	got, pr, usedKey, err := manager.AcquireReusableConnection(context.Background(), account, wsURL, "cache-key", "stateless-xyz", 4, http.Header{}, "")
	if err != nil {
		t.Fatalf("AcquireReusableConnection() error = %v", err)
	}
	if got != conn {
		t.Fatal("expected idle slot connection to be reused")
	}
	if usedKey != "cache-key#0" {
		t.Fatalf("usedKey = %q, want cache-key#0", usedKey)
	}
	got.session.RemovePendingRequest(pr.RequestID)
}

func TestAcquireReusableConnectionProbeDoesNotBlockDifferentPoolKey(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 4}
	wsURL := "wss://example.test/responses"
	slowConn, _ := newTestSlotConnection(manager, account, wsURL, "slow-cache#0")
	fastConn, _ := newTestSlotConnection(manager, account, wsURL, "fast-cache#0")

	slowProbeStarted := make(chan struct{})
	releaseSlowProbe := make(chan struct{})
	var releaseOnce sync.Once
	releaseSlow := func() { releaseOnce.Do(func() { close(releaseSlowProbe) }) }
	defer releaseSlow()
	var startedOnce sync.Once
	manager.probeFunc = func(wc *WsConnection) bool {
		if wc == slowConn {
			startedOnce.Do(func() { close(slowProbeStarted) })
			<-releaseSlowProbe
		}
		return true
	}

	type result struct {
		wc      *WsConnection
		pending *PendingRequest
		key     string
		err     error
	}
	slowResult := make(chan result, 1)
	go func() {
		wc, pending, key, err := manager.AcquireReusableConnection(context.Background(), account, wsURL, "slow-cache", "slow-fallback", 4, http.Header{}, "")
		slowResult <- result{wc: wc, pending: pending, key: key, err: err}
	}()
	select {
	case <-slowProbeStarted:
	case <-time.After(time.Second):
		t.Fatal("slow reusable-slot probe did not start")
	}

	fastResult := make(chan result, 1)
	go func() {
		wc, pending, key, err := manager.AcquireReusableConnection(context.Background(), account, wsURL, "fast-cache", "fast-fallback", 4, http.Header{}, "")
		fastResult <- result{wc: wc, pending: pending, key: key, err: err}
	}()
	select {
	case got := <-fastResult:
		if got.err != nil || got.wc != fastConn || got.pending == nil || got.key != "fast-cache#0" {
			t.Fatalf("fast reusable acquire = (%p, %v, %q, %v), want healthy fast-cache#0", got.wc, got.pending, got.key, got.err)
		}
		got.wc.session.RemovePendingRequest(got.pending.RequestID)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("different reusable pool key was blocked by another connection's network probe")
	}
	releaseSlow()
	slow := <-slowResult
	if slow.err != nil || slow.wc != slowConn || slow.pending == nil || slow.key != "slow-cache#0" {
		t.Fatalf("slow reusable acquire after probe release = (%p, %v, %q, %v)", slow.wc, slow.pending, slow.key, slow.err)
	}
	slow.wc.session.RemovePendingRequest(slow.pending.RequestID)
}

func TestAcquireReusableConnectionSkipsBusySlot(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	account := &auth.Account{DBID: 42}
	wsURL := "wss://example.test/responses"
	busyConn, busySession := newTestSlotConnection(manager, account, wsURL, "cache-key#0")
	busySession.AddPendingRequest("cache-key#0") // 占用 slot 0
	busyConn.lastUsed.Store(time.Now().Add(-IdleTimeout - time.Second).UnixNano())
	idleConn, _ := newTestSlotConnection(manager, account, wsURL, "cache-key#1")

	got, pr, usedKey, err := manager.AcquireReusableConnection(context.Background(), account, wsURL, "cache-key", "stateless-xyz", 4, http.Header{}, "")
	if err != nil {
		t.Fatalf("AcquireReusableConnection() error = %v", err)
	}
	if got != idleConn {
		t.Fatal("expected busy slot 0 to be skipped and idle slot 1 reused")
	}
	if usedKey != "cache-key#1" {
		t.Fatalf("usedKey = %q, want cache-key#1", usedKey)
	}
	if !busyConn.IsConnected() {
		t.Fatal("slot scan evicted a quiet but still in-flight connection")
	}
	got.session.RemovePendingRequest(pr.RequestID)
}

// ==================== 续链亲和(response_id → 连接绑定) ====================

func newBoundTestConn(t *testing.T, manager *Manager, accountID int64, sessionKey string) *WsConnection {
	t.Helper()
	key := manager.poolKey(accountID, "wss://example.test/responses", sessionKey, "")
	session := NewSession(accountID, manager)
	session.SetConnected(true)
	wc := &WsConnection{session: session, URL: "wss://example.test/responses", PoolKey: key}
	wc.SetState(StateConnected)
	wc.Touch()
	manager.connections.Store(key, wc)
	manager.sessions.Store(key, session)
	return wc
}

func TestBindAndLookupResponseConn(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	wc := newBoundTestConn(t, manager, 7, "base#0")
	manager.BindResponseConn("resp_abc", wc, "base#0", 7, "key-A")

	got, slotKey := manager.lookupResponseConn("resp_abc", 7, "key-A")
	if got != wc {
		t.Fatal("lookup should return the bound connection")
	}
	if slotKey != "base#0" {
		t.Fatalf("slotKey = %q, want base#0", slotKey)
	}

	// 账号不匹配 → miss(续链换号后不得复用别人账号的连接)
	if got, _ := manager.lookupResponseConn("resp_abc", 8, "key-A"); got != nil {
		t.Fatal("lookup with wrong account must miss")
	}

	// 连接被移出池(销毁/重建) → miss
	manager.connections.Delete(wc.PoolKey)
	if got, _ := manager.lookupResponseConn("resp_abc", 7, "key-A"); got != nil {
		t.Fatal("lookup after conn removed from pool must miss")
	}
}

func TestLookupResponseConnRejectsRebuiltSlot(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	wc := newBoundTestConn(t, manager, 7, "base#0")
	manager.BindResponseConn("resp_old", wc, "base#0", 7, "key-A")

	// 同 PoolKey 槽位被重建为新连接:旧绑定必须失效(指针校验)
	replacement := &WsConnection{session: NewSession(7, manager), URL: wc.URL, PoolKey: wc.PoolKey}
	replacement.SetState(StateConnected)
	replacement.Touch()
	manager.connections.Store(wc.PoolKey, replacement)

	if got, _ := manager.lookupResponseConn("resp_old", 7, "key-A"); got != nil {
		t.Fatal("binding to a replaced connection must miss")
	}
}

func TestAcquirePreferredConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	wc := newBoundTestConn(t, manager, 7, "base#3")
	manager.BindResponseConn("resp_chain", wc, "base#3", 7, "key-A")

	got, pr, slotKey, err := manager.AcquirePreferredConnection(context.Background(), "resp_chain", 7, "key-A")
	if err != nil || got != wc {
		t.Fatalf("AcquirePreferredConnection = (%p, %v), want bound connection", got, err)
	}
	if pr == nil {
		t.Fatal("pending request must be registered")
	}
	if slotKey != "base#3" {
		t.Fatalf("slotKey = %q, want base#3", slotKey)
	}
	if wc.session.PendingCount() != 1 {
		t.Fatalf("PendingCount = %d, want 1", wc.session.PendingCount())
	}

	// 连接忙(已有在途请求)时不等待，也绝不能回退到另一条连接。
	got2, pr2, _, busyErr := manager.AcquirePreferredConnection(context.Background(), "resp_chain", 7, "key-A")
	if got2 != nil || pr2 != nil {
		t.Fatal("busy preferred connection must not be acquired")
	}
	if !errors.Is(busyErr, proxy.ErrWebsocketSessionBusy) {
		t.Fatalf("busy preferred error = %v, want ErrWebsocketSessionBusy", busyErr)
	}

	missing, missingPending, missingKey, missingErr := manager.AcquirePreferredConnection(context.Background(), "resp_missing", 7, "key-A")
	if missing != nil || missingPending != nil || missingKey != "" || !errors.Is(missingErr, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("missing binding = (%p, %v, %q, %v), want continuation-unavailable", missing, missingPending, missingKey, missingErr)
	}
}

func TestAcquirePreferredConnectionProbeDoesNotBlockDifferentPoolKey(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	slowConn := newBoundTestConn(t, manager, 7, "slow#0")
	fastConn := newBoundTestConn(t, manager, 7, "fast#0")
	manager.BindResponseConn("resp_slow", slowConn, "slow#0", 7, "key-A")
	manager.BindResponseConn("resp_fast", fastConn, "fast#0", 7, "key-A")

	slowProbeStarted := make(chan struct{})
	releaseSlowProbe := make(chan struct{})
	var releaseOnce sync.Once
	releaseSlow := func() { releaseOnce.Do(func() { close(releaseSlowProbe) }) }
	defer releaseSlow()
	var startedOnce sync.Once
	manager.probeFunc = func(wc *WsConnection) bool {
		if wc == slowConn {
			startedOnce.Do(func() { close(slowProbeStarted) })
			<-releaseSlowProbe
		}
		return true
	}

	type result struct {
		wc      *WsConnection
		pending *PendingRequest
		key     string
		err     error
	}
	slowResult := make(chan result, 1)
	go func() {
		wc, pending, key, err := manager.AcquirePreferredConnection(context.Background(), "resp_slow", 7, "key-A")
		slowResult <- result{wc: wc, pending: pending, key: key, err: err}
	}()
	select {
	case <-slowProbeStarted:
	case <-time.After(time.Second):
		t.Fatal("slow preferred-connection probe did not start")
	}

	fastResult := make(chan result, 1)
	go func() {
		wc, pending, key, err := manager.AcquirePreferredConnection(context.Background(), "resp_fast", 7, "key-A")
		fastResult <- result{wc: wc, pending: pending, key: key, err: err}
	}()
	select {
	case got := <-fastResult:
		if got.err != nil || got.wc != fastConn || got.pending == nil || got.key != "fast#0" {
			t.Fatalf("fast preferred acquire = (%p, %v, %q, %v), want healthy fast#0", got.wc, got.pending, got.key, got.err)
		}
		got.wc.session.RemovePendingRequest(got.pending.RequestID)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("different preferred pool key was blocked by another connection's network probe")
	}
	releaseSlow()
	slow := <-slowResult
	if slow.err != nil || slow.wc != slowConn || slow.pending == nil || slow.key != "slow#0" {
		t.Fatalf("slow preferred acquire after probe release = (%p, %v, %q, %v)", slow.wc, slow.pending, slow.key, slow.err)
	}
	slow.wc.session.RemovePendingRequest(slow.pending.RequestID)
}

func TestAcquirePreferredConnectionProbeFailureEvicts(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.probeFunc = func(wc *WsConnection) bool { return false }

	wc := newBoundTestConn(t, manager, 7, "base#0")
	manager.BindResponseConn("resp_dead", wc, "base#0", 7, "key-A")

	got, pr, _, err := manager.AcquirePreferredConnection(context.Background(), "resp_dead", 7, "key-A")
	if got != nil || pr != nil {
		t.Fatal("dead preferred connection must not be acquired")
	}
	if !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("dead preferred connection error = %v, want continuation-unavailable", err)
	}
	if _, ok := manager.connections.Load(wc.PoolKey); ok {
		t.Fatal("dead connection must be evicted from pool")
	}
}

func TestAcquirePreferredConnectionProbeHonorsRequestCancellation(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	wc := newBoundTestConn(t, manager, 7, "base#0")
	manager.BindResponseConn("resp_cancelled_probe", wc, "base#0", 7, "key-A")
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	var startOnce sync.Once
	manager.probeFunc = func(*WsConnection) bool {
		startOnce.Do(func() { close(probeStarted) })
		<-releaseProbe
		return true
	}
	t.Cleanup(func() { close(releaseProbe) })

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	got, pending, _, err := manager.AcquirePreferredConnection(ctx, "resp_cancelled_probe", 7, "key-A")
	if got != nil || pending != nil {
		t.Fatal("cancelled preferred probe unexpectedly acquired the bound connection")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled preferred probe error = %v, want context deadline exceeded", err)
	}
	if !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("cancelled preferred probe error = %v, want continuation-unavailable classification", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("cancelled preferred probe took %v, want prompt request cancellation", elapsed)
	}
	select {
	case <-probeStarted:
	default:
		t.Fatal("preferred probe hook never started")
	}
	if !wc.IsConnected() {
		t.Fatal("request cancellation discarded a potentially healthy continuation connection")
	}
	if gotBound, _ := manager.lookupResponseConn("resp_cancelled_probe", 7, "key-A"); gotBound != wc {
		t.Fatal("request cancellation destroyed the continuation binding")
	}
	if wc.session.PendingCount() != 0 {
		t.Fatal("cancelled preferred probe leaked a pending request")
	}
}

func TestProbeWithContextRejectsCanceledRecentInboundFastPath(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	wc := newBoundTestConn(t, manager, 7, "recent#0")
	wc.touchInbound()
	if !wc.recentInboundWithin(probeRecencyWindow) || !wc.readPumpReusable() {
		t.Fatal("test connection did not qualify for the recent-inbound fast path")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if manager.probeWithContext(ctx, wc) {
		t.Fatal("canceled context was accepted by the recent-inbound probe fast path")
	}
}

func TestAcquirePreferredConnectionCancellationWhileWaitingForKeyLockDoesNotReserve(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	wc := newBoundTestConn(t, manager, 7, "locked#0")
	manager.BindResponseConn("resp_locked_cancel", wc, "locked#0", 7, "key-A")

	lock := manager.keyLock(wc.PoolKey)
	manager.lockPoolKey(wc.PoolKey, lock)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		wc      *WsConnection
		pending *PendingRequest
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		got, pending, _, err := manager.AcquirePreferredConnection(ctx, "resp_locked_cancel", 7, "key-A")
		resultCh <- result{wc: got, pending: pending, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	lock.Unlock()

	select {
	case got := <-resultCh:
		if got.wc != nil || got.pending != nil {
			t.Fatal("canceled lock waiter reserved the continuation connection")
		}
		if !errors.Is(got.err, context.Canceled) || !errors.Is(got.err, proxy.ErrWebsocketContinuationUnavailable) {
			t.Fatalf("lock-wait cancellation error = %v, want context and continuation sentinels", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled preferred acquisition did not return after the key lock was released")
	}
	if wc.session.PendingCount() != 0 {
		t.Fatalf("canceled lock waiter leaked %d pending requests", wc.session.PendingCount())
	}
}

func TestBindResponseConnBounded(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	wc := newBoundTestConn(t, manager, 7, "base#0")
	for i := 0; i < responseConnBindingMaxEntries; i++ {
		manager.BindResponseConn(fmt.Sprintf("resp_%d", i), wc, "base#0", 7, "key-A")
	}
	// Windows can return the same timestamp for a burst of time.Now calls. Force
	// every live ID to the same expiry: the oldest monotonic Bind generation must
	// still be removed deterministically rather than a random map entry.
	manager.respConnMu.Lock()
	identicalExpiry := time.Now().Add(2 * time.Minute)
	for responseID, binding := range manager.respConnBindings {
		binding.expiresAt = identicalExpiry
		manager.respConnBindings[responseID] = binding
	}
	manager.respConnMu.Unlock()

	newestID := fmt.Sprintf("resp_%d", responseConnBindingMaxEntries)
	manager.BindResponseConn(newestID, wc, "base#0", 7, "key-A")
	manager.respConnMu.Lock()
	size := len(manager.respConnBindings)
	_, oldestStillPresent := manager.respConnBindings["resp_0"]
	_, newestPresent := manager.respConnBindings[newestID]
	manager.respConnMu.Unlock()
	if size != responseConnBindingMaxEntries {
		t.Fatalf("binding map size = %d, want hard cap %d", size, responseConnBindingMaxEntries)
	}
	if oldestStillPresent || !newestPresent {
		t.Fatalf("full binding table did not replace oldest ID with newest: oldest=%v newest=%v", oldestStillPresent, newestPresent)
	}
}

func TestBindResponseConnFullTablePrunesDeadPointersBeforeReplacingLiveIDs(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	live := newBoundTestConn(t, manager, 7, "live")
	dead := &WsConnection{PoolKey: "dead"}
	dead.SetState(StateDisconnected)
	manager.respConnMu.Lock()
	manager.respConnBindings = make(map[string]responseConnBinding, responseConnBindingMaxEntries)
	for i := 0; i < responseConnBindingMaxEntries; i++ {
		manager.respConnBindings[fmt.Sprintf("dead_%d", i)] = responseConnBinding{
			conn:      dead,
			expiresAt: time.Now().Add(time.Minute),
		}
	}
	manager.respConnMu.Unlock()

	manager.BindResponseConn("resp_live_after_churn", live, "live", 7, "key-A")

	manager.respConnMu.Lock()
	size := len(manager.respConnBindings)
	binding, present := manager.respConnBindings["resp_live_after_churn"]
	manager.respConnMu.Unlock()
	if size != 1 || !present || binding.conn != live {
		t.Fatalf("full-table stale cleanup = size %d present %v conn %p, want one live binding %p", size, present, binding.conn, live)
	}
}

func TestLookupResponseConnIsolatesAPIKeys(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	wc := newBoundTestConn(t, manager, 7, "base#0")
	manager.BindResponseConn("resp_owned", wc, "base#0", 7, "key-A")

	// 别的 API Key 拿着同一个 response_id 不得命中(防跨 Key 定向挤连接)
	if got, _ := manager.lookupResponseConn("resp_owned", 7, "key-B"); got != nil {
		t.Fatal("lookup with different api key must miss")
	}
	if got, _ := manager.lookupResponseConn("resp_owned", 7, ""); got != nil {
		t.Fatal("lookup with empty api key must miss when binding has one")
	}
	if got, _ := manager.lookupResponseConn("resp_owned", 7, "key-A"); got != wc {
		t.Fatal("owner api key must hit")
	}
}

// 上游对 WS upgrade 回 401 时，结构化握手错误必须原样穿透 AcquireConnection
// 的传播链（不被二次包装），执行器才能把它还原成真实状态码的 HTTP 响应；
// 否则 401 在使用日志里只会以 transport/598 出现且账号不触发 unauthorized 冷却。
func TestAcquireConnectionDial401ReturnsTypedHandshakeError(t *testing.T) {
	upstreamBody := `{"error":{"message":"Provided authentication token is expired.","type":"invalid_request_error","code":"token_expired"}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{DBID: 42}
	wsURL := strings.Replace(upstream.URL, "http://", "ws://", 1)

	_, _, err := manager.AcquireConnection(context.Background(), account, wsURL, "session-1", http.Header{}, "")
	if err == nil {
		t.Fatal("expected handshake error")
	}

	var hs *HandshakeHTTPError
	if !errors.As(err, &hs) {
		t.Fatalf("expected *HandshakeHTTPError to survive propagation, got %T: %v", err, err)
	}
	if hs.StatusCode != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want 401", hs.StatusCode)
	}

	resp, ok := handshakeUnauthorizedHTTPResponse(err)
	if !ok {
		t.Fatal("expected 401 handshake error to convert to HTTP response")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("converted StatusCode = %d, want 401", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	// readHTTPErrorBody 会重排 JSON 键序，按字段断言。
	if !strings.Contains(string(got), `"code":"token_expired"`) || strings.Contains(string(got), "websocket handshake failed") {
		t.Fatalf("converted body should be raw upstream json, got %q", got)
	}
}
