package proxy

import (
	"context"
	"encoding/json"
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

func TestUpstreamErrorKindClassifiesCloudflare5xxAsServer(t *testing.T) {
	for _, statusCode := range []int{520, 521, 522, 523, 524, 525, 526, 527, 530} {
		if got := upstreamErrorKind(statusCode, nil, codex429Decision{}); got != "server" {
			t.Fatalf("status %d kind=%q, want server", statusCode, got)
		}
	}
}

func TestRelayCircuitConcurrentSelectAndBeginAllowsOneHalfOpenUpstream(t *testing.T) {
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
	if selectedCount != 1 || upstreamHits.Load() != 1 {
		t.Fatalf("half-open selected=%d upstream=%d, want 1/1", selectedCount, upstreamHits.Load())
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
