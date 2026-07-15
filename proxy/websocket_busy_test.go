package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func TestShouldFallbackWebsocketLocalContentionToHTTPProtectsExplicitContext(t *testing.T) {
	busyErr := fmt.Errorf("%w: timed out waiting for busy session", ErrWebsocketSessionBusy)
	stateless := requestSessionIdentity{upstreamSeed: "derived"}
	if !shouldFallbackWebsocketLocalContentionToHTTP(busyErr, true, []byte(`{"input":"hello"}`), stateless) {
		t.Fatal("stateless busy WebSocket request should fall back to same-account HTTP")
	}
	capacityErr := fmt.Errorf("%w: timed out waiting for local capacity", ErrWebsocketLocalCapacity)
	if !shouldFallbackWebsocketLocalContentionToHTTP(capacityErr, true, []byte(`{"input":"hello"}`), stateless) {
		t.Fatal("stateless local-capacity request should fall back to same-account HTTP")
	}
	if shouldFallbackWebsocketLocalContentionToHTTP(busyErr, true, []byte(`{"previous_response_id":"resp_1","input":"next"}`), stateless) {
		t.Fatal("previous_response_id request must not cross from busy WebSocket to HTTP")
	}
	continuationErr := fmt.Errorf("%w: response binding missing", ErrWebsocketContinuationUnavailable)
	if shouldFallbackWebsocketLocalContentionToHTTP(continuationErr, true, []byte(`{"input":"next"}`), stateless) {
		t.Fatal("unavailable WebSocket continuation must never fall back to HTTP")
	}
	explicit := requestSessionIdentity{upstreamSeed: "session", explicitUpstreamID: "session"}
	if shouldFallbackWebsocketLocalContentionToHTTP(busyErr, true, []byte(`{"input":"hello"}`), explicit) {
		t.Fatal("explicit upstream session must not cross from busy WebSocket to HTTP")
	}
	if shouldFallbackWebsocketLocalContentionToHTTP(errors.New("connection reset"), true, []byte(`{"input":"hello"}`), stateless) {
		t.Fatal("ordinary transport errors must keep the configured retry policy")
	}
}

func TestResponsesHTTPIngressBusySessionFallsBackToSameAccountHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
		resinCfg.Store(previousResin)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	ApplyRuntimeSettings(nextSettings)

	var wsCalls atomic.Int32
	wsAccountIDs := make(chan int64, 2)
	WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
		wsCalls.Add(1)
		wsAccountIDs <- account.ID()
		return nil, fmt.Errorf("%w: acquire timed out waiting for busy session", ErrWebsocketSessionBusy)
	}

	var httpCalls atomic.Int32
	httpAccountIDs := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		httpAccountIDs <- r.Header.Get("X-Resin-Account")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.output_text.delta","delta":"busy-http-fallback"}`+"\n\n"+
				`data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}`+"\n\n")
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "busy-fallback.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)

	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, MaxRetries: 3, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	primary.SetDispatchCountLimit(1)
	store.AddAccount(primary)
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	body := []byte(`{"model":"gpt-5.4","input":"hello","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req
	handler.Responses(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "busy-http-fallback") {
		t.Fatalf("status=%d body=%s, want HTTP fallback success", recorder.Code, recorder.Body.String())
	}
	if wsCalls.Load() != 1 || httpCalls.Load() != 1 {
		t.Fatalf("calls ws=%d http=%d, want 1/1", wsCalls.Load(), httpCalls.Load())
	}
	wsAccountID := <-wsAccountIDs
	if got := <-httpAccountIDs; got != fmt.Sprint(wsAccountID) {
		t.Fatalf("HTTP fallback account=%q, want retained account %d", got, wsAccountID)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
		t.Fatalf("dispatch counts primary=%d secondary=%d, want 1/0", gotPrimary, gotSecondary)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
	}
	rows := waitForRetryUsageLogs(t, db, 2)
	if len(rows) != 2 {
		t.Fatalf("usage rows=%d, want hidden busy + canonical success", len(rows))
	}
	var hidden, canonical int
	var hiddenLogicalID, canonicalLogicalID string
	for _, row := range rows {
		if row.AttemptIndex == 1 && row.StatusCode == http.StatusBadGateway {
			hidden++
			hiddenLogicalID = row.LogicalRequestID
			if row.UpstreamErrorKind != upstreamErrorKindWebsocketBusy || row.AttemptIndex != 1 || row.StatusCode != http.StatusBadGateway {
				t.Fatalf("hidden row=%+v", row)
			}
		} else {
			canonical++
			canonicalLogicalID = row.LogicalRequestID
			if row.StatusCode != http.StatusOK || row.AttemptIndex != 2 {
				t.Fatalf("canonical row=%+v", row)
			}
		}
	}
	if hidden != 1 || canonical != 1 {
		t.Fatalf("hidden=%d canonical=%d, want 1/1", hidden, canonical)
	}
	if hiddenLogicalID == "" || hiddenLogicalID != canonicalLogicalID {
		t.Fatalf("logical request IDs hidden=%q canonical=%q", hiddenLogicalID, canonicalLogicalID)
	}
}

func TestResponsesBusyExplicitSessionFailsOncePreservesAffinityAndPersistsCanonical(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	ApplyRuntimeSettings(nextSettings)

	var wsCalls atomic.Int32
	var selectedAccountID atomic.Int64
	WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
		wsCalls.Add(1)
		selectedAccountID.Store(account.ID())
		return nil, fmt.Errorf("%w: acquire timed out waiting for busy session", ErrWebsocketSessionBusy)
	}

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "busy-terminal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, MaxRetries: 3, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	body := []byte(`{"model":"gpt-5.4","input":"next","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session_id", "explicit-session-1")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req
	handler.Responses(ctx)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", recorder.Code, recorder.Body.String())
	}
	if wsCalls.Load() != 1 {
		t.Fatalf("WebSocket attempts=%d, want exactly 1", wsCalls.Load())
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
	}
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(req.Header, body), 0)
	bound, _ := store.NextForSession(affinityKey, 0, nil)
	if bound == nil {
		t.Fatal("explicit session affinity disappeared after busy failure")
	}
	if got, want := bound.ID(), selectedAccountID.Load(); got != want {
		store.Release(bound)
		t.Fatalf("bound account=%d, want original busy account=%d", got, want)
	}
	store.Release(bound)
	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 || rows[0].StatusCode != http.StatusBadGateway || rows[0].AttemptIndex != 1 || rows[0].LogicalRequestID == "" {
		t.Fatalf("terminal usage rows=%+v, want one canonical 502", rows)
	}
}

func TestResponsesUnavailablePreviousResponseFailsOnceWithoutFallbackOrRotation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	ApplyRuntimeSettings(nextSettings)

	var wsCalls atomic.Int32
	WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
		wsCalls.Add(1)
		return nil, fmt.Errorf("%w: response binding is missing", ErrWebsocketContinuationUnavailable)
	}

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "continuation-terminal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, MaxRetries: 3, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	body := []byte(`{"model":"gpt-5.4","previous_response_id":"resp_missing","input":"continue","stream":true}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.Responses(ctx)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want terminal 502", recorder.Code, recorder.Body.String())
	}
	if wsCalls.Load() != 1 {
		t.Fatalf("WebSocket attempts=%d, want exactly one continuation attempt", wsCalls.Load())
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
		t.Fatalf("dispatch counts primary=%d secondary=%d, want no rotation", gotPrimary, gotSecondary)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
	}
	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 || rows[0].LogicalRequestID == "" || rows[0].StatusCode != http.StatusBadGateway || rows[0].UpstreamErrorKind != upstreamErrorKindWebsocketContinuation {
		t.Fatalf("continuation terminal rows=%+v, want one canonical local-continuity 502", rows)
	}
}

func TestResponsesExplicitBusySessionTTFTWinsWithoutFallbackOrRotation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
	})
	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	nextSettings.FirstTokenTimeoutSec = 1
	ApplyRuntimeSettings(nextSettings)

	var wsCalls atomic.Int32
	var selectedAccountID atomic.Int64
	WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
		wsCalls.Add(1)
		selectedAccountID.Store(account.ID())
		<-ctx.Done()
		return nil, fmt.Errorf("%w: acquire canceled after TTFT: %v", ErrWebsocketSessionBusy, ctx.Err())
	}

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "busy-ttft.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, MaxRetries: 3, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	body := []byte(`{"model":"gpt-5.4","input":"next","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session_id", "explicit-ttft-session")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req
	started := time.Now()
	handler.Responses(ctx)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d body=%s, want TTFT 504", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("TTFT elapsed=%s, want about one second and no 30s acquire wait", elapsed)
	}
	if wsCalls.Load() != 1 {
		t.Fatalf("WebSocket attempts=%d, want exactly one explicit-session attempt", wsCalls.Load())
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
		t.Fatalf("dispatch counts primary=%d secondary=%d, want no rotation", gotPrimary, gotSecondary)
	}
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(req.Header, body), 0)
	bound, _ := store.NextForSession(affinityKey, 0, nil)
	if bound == nil || bound.ID() != selectedAccountID.Load() {
		if bound != nil {
			store.Release(bound)
		}
		t.Fatalf("explicit TTFT affinity account=%v, want original %d", bound, selectedAccountID.Load())
	}
	store.Release(bound)
	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 || rows[0].StatusCode != http.StatusGatewayTimeout || rows[0].UpstreamErrorKind != upstreamErrorKindWebsocketBusy || rows[0].LogicalRequestID == "" {
		t.Fatalf("TTFT canonical rows=%+v, want one 504 with local busy kind", rows)
	}
}

func TestCompatibilityEndpointsFallbackLocalWebsocketContentionToSameAccountHTTP(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		body   string
		err    error
		invoke func(*Handler, *gin.Context)
	}{
		{
			name: "chat busy session",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}]}`,
			err:  fmt.Errorf("%w: acquire timed out waiting for busy session", ErrWebsocketSessionBusy),
			invoke: func(handler *Handler, ctx *gin.Context) {
				handler.ChatCompletions(ctx)
			},
		},
		{
			name: "messages local capacity",
			path: "/v1/messages",
			body: `{"model":"claude-opus-4-6","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}`,
			err:  fmt.Errorf("%w: acquire timed out waiting for account connection capacity", ErrWebsocketLocalCapacity),
			invoke: func(handler *Handler, ctx *gin.Context) {
				handler.Messages(ctx)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			previousExec := WebsocketExecuteFunc
			previousSettings := CurrentRuntimeSettings()
			previousResin := resinCfg.Load()
			t.Cleanup(func() {
				WebsocketExecuteFunc = previousExec
				ApplyRuntimeSettings(previousSettings)
				resinCfg.Store(previousResin)
			})
			nextSettings := previousSettings
			nextSettings.CodexForceWebsocket = true
			ApplyRuntimeSettings(nextSettings)

			var wsCalls atomic.Int32
			wsAccountIDs := make(chan int64, 2)
			WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
				wsCalls.Add(1)
				wsAccountIDs <- account.ID()
				return nil, tc.err
			}

			var httpCalls atomic.Int32
			httpAccountIDs := make(chan string, 2)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpCalls.Add(1)
				httpAccountIDs <- r.Header.Get("X-Resin-Account")
				w.Header().Set("Content-Type", "text/event-stream")
				for _, event := range []string{
					`{"type":"response.created","response":{"id":"resp_contention_test"}}`,
					`{"type":"response.output_item.added","item":{"type":"message"}}`,
					`{"type":"response.output_text.delta","delta":"http-fallback"}`,
					`{"type":"response.output_text.done"}`,
					`{"type":"response.completed","response":{"id":"resp_contention_test","status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`,
				} {
					_, _ = io.WriteString(w, "data: "+event+"\n\n")
				}
			}))
			t.Cleanup(upstream.Close)
			SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

			store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1, TestModel: "gpt-5.4"})
			t.Cleanup(store.Stop)
			primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
			primary.SetDispatchCountLimit(1)
			secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
			store.AddAccount(primary)
			store.AddAccount(secondary)
			handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)

			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			ctx.Request.Header.Set("Content-Type", "application/json")
			tc.invoke(handler, ctx)

			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "http-fallback") {
				t.Fatalf("fallback response status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if gotWS, gotHTTP := wsCalls.Load(), httpCalls.Load(); gotWS != 1 || gotHTTP != 1 {
				t.Fatalf("upstream calls WS=%d HTTP=%d, want 1/1", gotWS, gotHTTP)
			}
			wsAccountID := <-wsAccountIDs
			if got := <-httpAccountIDs; got != fmt.Sprint(wsAccountID) {
				t.Fatalf("HTTP fallback account=%q, want retained account %d", got, wsAccountID)
			}
			if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
				t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
			}
			if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
				t.Fatalf("dispatch counts primary=%d secondary=%d, want 1/0", gotPrimary, gotSecondary)
			}
		})
	}
}

func TestResponsesWebsocketIngressFallsBackLocalContentionToSameAccountHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		resinCfg.Store(previousResin)
	})

	var wsCalls atomic.Int32
	wsAccountIDs := make(chan int64, 2)
	WebsocketExecuteFunc = func(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
		wsCalls.Add(1)
		wsAccountIDs <- account.ID()
		return nil, fmt.Errorf("%w: acquire timed out waiting for account connection capacity", ErrWebsocketLocalCapacity)
	}

	var httpCalls atomic.Int32
	httpAccountIDs := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		httpAccountIDs <- r.Header.Get("X-Resin-Account")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.output_text.delta","delta":"ws-ingress-http-fallback"}`+"\n\n"+
				`data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}`+"\n\n")
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	primary.SetDispatchCountLimit(1)
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)

	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v status=%d", err, resp.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"model":"gpt-5.4","input":"hello"}`)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, first, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read fallback event: %v", err)
	}
	if !strings.Contains(string(first), "ws-ingress-http-fallback") {
		t.Fatalf("unexpected fallback event: %s", first)
	}
	_, second, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read terminal event: %v", err)
	}
	if !strings.Contains(string(second), "response.completed") {
		t.Fatalf("unexpected terminal event: %s", second)
	}
	if gotWS, gotHTTP := wsCalls.Load(), httpCalls.Load(); gotWS != 1 || gotHTTP != 1 {
		t.Fatalf("upstream calls WS=%d HTTP=%d, want 1/1", gotWS, gotHTTP)
	}
	wsAccountID := <-wsAccountIDs
	if got := <-httpAccountIDs; got != fmt.Sprint(wsAccountID) {
		t.Fatalf("HTTP fallback account=%q, want retained account %d", got, wsAccountID)
	}
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt64(&primary.ActiveRequests) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
	}
}

func TestPendingFinalFailurePreservesOAuthAccountClass(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "pending-oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	handler := NewHandler(nil, db, &config.Config{}, nil)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.4","input":"hello"}`))
	setUpstreamAccountContext(ctx, &auth.Account{DBID: 77, AccessToken: "oauth-token"})
	pending := rememberPendingFinalFailure(ctx, retryAttemptUsageSpec{
		AccountID:         77,
		Endpoint:          "/v1/responses",
		Model:             "gpt-5.4",
		EffectiveModel:    "gpt-5.4",
		StatusCode:        http.StatusBadGateway,
		Attempt:           1,
		UpstreamErrorKind: upstreamErrorKindWebsocketBusy,
		ErrorMessage:      "busy session exhausted",
	})
	handler.logPendingFinalFailure(ctx, pending)

	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 {
		t.Fatalf("usage rows=%d, want 1", len(rows))
	}
	row := rows[0]
	if row.AccountID != 0 || row.StatusCode != http.StatusBadGateway || row.UpstreamAccountType != "oauth" {
		t.Fatalf("pending final row account=%d status=%d type=%q, want 0/502/oauth", row.AccountID, row.StatusCode, row.UpstreamAccountType)
	}
}
