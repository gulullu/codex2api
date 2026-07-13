package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func TestRelayCircuitAttemptFinishIsIdempotent(t *testing.T) {
	store, account := newRelayCircuitProxyTestStore(t)
	permit, ok := store.BeginRelayCircuitRequest(account)
	if !ok {
		t.Fatal("relay circuit permit denied")
	}
	attempt := newRelayCircuitAttempt(store, permit)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempt.Failure(503)
		}()
	}
	wg.Wait()

	snapshot := store.RelayCircuitSnapshot(account.ID())
	if snapshot.WeakFailures != 1 {
		t.Fatalf("duplicate finish counted %d failures, want 1", snapshot.WeakFailures)
	}
}

func TestRelayCircuitAttemptUpstreamTransportFailureBoundaries(t *testing.T) {
	tests := []struct {
		name                  string
		kind                  string
		softFirstTokenTimeout bool
		requestContext        func() context.Context
		wantRecorded          bool
	}{
		{
			name:           "live relay transport failure",
			kind:           "transport",
			requestContext: context.Background,
			wantRecorded:   true,
		},
		{
			name:                  "soft first token timeout",
			kind:                  "transport",
			softFirstTokenTimeout: true,
			requestContext:        context.Background,
		},
		{
			name:           "websocket message too big fallback",
			kind:           upstreamErrorKindMessageTooBig,
			requestContext: context.Background,
		},
		{
			name:           "websocket policy violation",
			kind:           upstreamErrorKindWebsocketPolicy,
			requestContext: context.Background,
		},
		{
			name: "downstream canceled",
			kind: "transport",
			requestContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name:           "unclassified request error",
			requestContext: context.Background,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, account := newRelayCircuitProxyTestStore(t)
			permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "logical-transport-boundary")
			if !ok {
				t.Fatal("relay circuit permit denied")
			}
			attempt := newRelayCircuitAttempt(store, permit)
			got := attempt.UpstreamTransportFailure(test.requestContext(), test.kind, test.softFirstTokenTimeout)
			if got != test.wantRecorded {
				t.Fatalf("UpstreamTransportFailure()=%t, want %t", got, test.wantRecorded)
			}
			if !got {
				attempt.Abandon()
			}

			snapshot := store.RelayCircuitSnapshot(account.ID())
			if test.wantRecorded {
				if snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 ||
					snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus || snapshot.Reason != "upstream_transport_failure" {
					t.Fatalf("recorded transport snapshot=%+v", snapshot)
				}
				return
			}
			if snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.LastStatusCode != 0 {
				t.Fatalf("excluded boundary contaminated breaker evidence: %+v", snapshot)
			}
		})
	}
}

func TestRelayWebsocketClosePolicyDoesNotContaminateCircuit(t *testing.T) {
	tests := []struct {
		code            int
		wantKind        string
		wantPenalize    bool
		wantStrongFault bool
	}{
		{code: websocket.ClosePolicyViolation, wantKind: upstreamErrorKindWebsocketPolicy},
		{code: websocket.CloseAbnormalClosure, wantKind: "transport", wantPenalize: true, wantStrongFault: true},
		{code: websocket.CloseInternalServerErr, wantKind: "transport", wantPenalize: true, wantStrongFault: true},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(test.code), func(t *testing.T) {
			readErr := fmt.Errorf("websocket read error: %w", &websocket.CloseError{Code: test.code, Text: "test close"})
			outcome := classifyStreamOutcome(nil, readErr, nil, false)
			if outcome.failureKind != test.wantKind || outcome.penalize != test.wantPenalize || !outcome.verifyAccountAuth {
				t.Fatalf("outcome=%+v want kind=%q penalize=%t verify=true", outcome, test.wantKind, test.wantPenalize)
			}

			store, account := newRelayCircuitProxyTestStore(t)
			permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "logical-ws-close-"+strconv.Itoa(test.code))
			if !ok {
				t.Fatal("relay circuit permit denied")
			}
			attempt := newRelayCircuitAttempt(store, permit)
			gotStrong := attempt.FinishStreamOutcome(context.Background(), outcome, isFirstTokenTimeoutOutcome(outcome))
			attempt.Release(store, account)
			if gotStrong != test.wantStrongFault {
				t.Fatalf("strong fault=%t want %t", gotStrong, test.wantStrongFault)
			}
			snapshot := store.RelayCircuitSnapshot(account.ID())
			if test.wantStrongFault {
				if snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
					t.Fatalf("transport close circuit=%+v", snapshot)
				}
				return
			}
			if snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.LastStatusCode != 0 {
				t.Fatalf("policy close contaminated circuit=%+v", snapshot)
			}
		})
	}
}

func TestStreamReadTimeoutIsStrongButFirstTokenGuardTimeoutIsSoft(t *testing.T) {
	tests := []struct {
		name            string
		outcome         streamOutcome
		wantStrongFault bool
	}{
		{name: "upstream read timeout", outcome: classifyStreamOutcome(nil, context.DeadlineExceeded, nil, false), wantStrongFault: true},
		{name: "local first token guard", outcome: firstTokenTimeoutOutcome(time.Second)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, account := newRelayCircuitProxyTestStore(t)
			permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "logical-timeout-"+test.name)
			if !ok {
				t.Fatal("relay circuit permit denied")
			}
			attempt := newRelayCircuitAttempt(store, permit)
			gotStrong := attempt.FinishStreamOutcome(context.Background(), test.outcome, isFirstTokenTimeoutOutcome(test.outcome))
			attempt.Release(store, account)
			if gotStrong != test.wantStrongFault {
				t.Fatalf("strong fault=%t want %t; outcome=%+v", gotStrong, test.wantStrongFault, test.outcome)
			}
			snapshot := store.RelayCircuitSnapshot(account.ID())
			if test.wantStrongFault {
				if snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 {
					t.Fatalf("read timeout circuit=%+v", snapshot)
				}
				return
			}
			if snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 {
				t.Fatalf("soft timeout contaminated circuit=%+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitAttemptInactiveTransportFailureIsIgnored(t *testing.T) {
	attempt := inactiveRelayCircuitAttempt()
	if attempt.UpstreamTransportFailure(context.Background(), "transport", false) {
		t.Fatal("inactive non-Relay attempt recorded transport failure")
	}
}

func TestUpstreamErrorKindClassifiesCloudflare5xxAsServer(t *testing.T) {
	for _, statusCode := range []int{520, 521, 522, 523, 524, 525, 526, 527, 530} {
		if got := upstreamErrorKind(statusCode, nil, codex429Decision{}); got != "server" {
			t.Fatalf("status %d kind=%q, want server", statusCode, got)
		}
	}
}

func TestRelayCircuitConcurrentSelectAndBeginAllowsThreeProbationUpstreams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenCache := cache.NewMemory(1)
	t.Cleanup(func() { _ = tokenCache.Close() })
	accountID := int64(92)
	record, err := json.Marshal(map[string]any{
		"state":         auth.RelayCircuitOpen,
		"generation":    2,
		"reason":        "upstream_http_502",
		"open_until":    time.Now().Add(-time.Second),
		"backoff_level": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tokenCache.SetRuntime(context.Background(), "relay-circuit-breaker", strconv.FormatInt(accountID, 10), json.RawMessage(record), time.Hour); err != nil {
		t.Fatal(err)
	}

	store := auth.NewStore(nil, tokenCache, &database.SystemSettings{
		MaxConcurrency:                           100,
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              7,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	t.Cleanup(store.Stop)
	account := &auth.Account{
		DBID:         accountID,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "test-key",
		GroupIDs:     []int64{7},
		Status:       auth.StatusReady,
	}
	store.AddAccount(account)
	handler := NewHandler(store, nil, nil, nil)

	const workers = 64
	start := make(chan struct{})
	releaseWinner := make(chan struct{})
	results := make(chan bool, workers)
	var upstreamHits atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			selected, _, _, attempt := handler.nextCircuitPermittedRoutedAccountForSession(
				ctx,
				"",
				0,
				newRetryAccountExclusions(),
				nil,
				promptRiskDecision{Disposition: promptRiskDispositionRelay},
			)
			if selected == nil {
				results <- false
				return
			}
			upstreamHits.Add(1)
			results <- true
			<-releaseWinner
			attempt.Release(store, selected)
		}()
	}
	close(start)

	selectedCount := 0
	for i := 0; i < workers; i++ {
		if <-results {
			selectedCount++
		}
	}
	if selectedCount != 3 || upstreamHits.Load() != 3 {
		t.Fatalf("probation selected=%d upstream=%d, want 3/3", selectedCount, upstreamHits.Load())
	}
	if snapshot := store.RelayCircuitSnapshot(accountID); !snapshot.ProbeInFlight {
		t.Fatalf("winner did not hold half-open lease: %+v", snapshot)
	}
	close(releaseWinner)
	wg.Wait()
	if active := atomic.LoadInt64(&account.ActiveRequests); active != 0 {
		t.Fatalf("ActiveRequests=%d after rejected selections released, want 0", active)
	}
}

func newRelayCircuitProxyTestStore(t *testing.T) (*auth.Store, *auth.Account) {
	t.Helper()
	tokenCache := cache.NewMemory(1)
	t.Cleanup(func() { _ = tokenCache.Close() })
	store := auth.NewStore(nil, tokenCache, &database.SystemSettings{
		MaxConcurrency:                           100,
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              7,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	t.Cleanup(store.Stop)
	account := &auth.Account{
		DBID:         91,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "test-key",
		GroupIDs:     []int64{7},
		Status:       auth.StatusReady,
	}
	store.AddAccount(account)
	return store, account
}
