package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

func TestInboundResponsesWebsocketContextBoundLargeFrameWritesErrorAndCloses1009(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
		resinCfg.Store(previousResin)
	})
	settings := previousSettings
	settings.CodexForceWebsocket = true
	ApplyRuntimeSettings(settings)

	var websocketDecisions atomic.Int32
	var selectedAccountID atomic.Int64
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, requestBody []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		if strings.TrimSpace(sessionID) == "" || IsStatelessWebsocketSessionID(sessionID) {
			t.Errorf("inbound context-bound request reached WS preflight with non-explicit session %q", sessionID)
		}
		if got := gjson.GetBytes(requestBody, "previous_response_id").String(); got != "resp_preflight_owner" {
			t.Errorf("inbound previous_response_id=%q", got)
		}
		websocketDecisions.Add(1)
		selectedAccountID.Store(account.ID())
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: true,
		}
	}

	var httpUpstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpUpstreamCalls.Add(1)
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"unexpected":"upstream call"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, dbPath := newWebsocketPreflightUsageDB(t, "context-bound-inbound")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      1,
		MaxRetries:          3,
		MaxRateLimitRetries: 3,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	secondary := &auth.Account{DBID: 2, AccessToken: "at-2", PlanType: "free", AccountID: "acct-2"}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	requestBody := []byte(`{"model":"gpt-5.4","previous_response_id":"resp_preflight_owner","input":"continue"}`)
	handshakeHeaders := http.Header{"Session_id": []string{"explicit-inbound-preflight-session"}}
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(handshakeHeaders, requestBody), 0)
	store.BindSessionAffinity(affinityKey, primary, "")
	beforePrimaryHealth := snapshotPreflightAccountHealth(primary)
	beforeSecondaryHealth := snapshotPreflightAccountHealth(secondary)

	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", handshakeHeaders)
	if err != nil {
		if response != nil {
			t.Fatalf("dial inbound websocket: %v status=%d", err, response.StatusCode)
		}
		t.Fatalf("dial inbound websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteMessage(websocket.TextMessage, requestBody); err != nil {
		t.Fatalf("write inbound request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, errorFrame, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read local error frame: %v", err)
	}
	if got := gjson.GetBytes(errorFrame, "type").String(); got != "error" {
		t.Fatalf("error frame type=%q body=%s", got, errorFrame)
	}
	if got := gjson.GetBytes(errorFrame, "error.code").String(); got != websocketLargeFrameContextBoundKind {
		t.Fatalf("error frame code=%q body=%s", got, errorFrame)
	}
	if got := gjson.GetBytes(errorFrame, "error.type").String(); got != "invalid_request_error" {
		t.Fatalf("error frame error.type=%q body=%s", got, errorFrame)
	}
	_, _, closeReadErr := conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(closeReadErr, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
		t.Fatalf("close error=%v want websocket close 1009", closeReadErr)
	}
	if !strings.Contains(closeErr.Text, "exceeds the configured safe limit") {
		t.Fatalf("close reason=%q missing local large-frame explanation", closeErr.Text)
	}

	if websocketDecisions.Load() != 1 || httpUpstreamCalls.Load() != 0 {
		t.Fatalf("transport decisions=%d HTTP upstream=%d, want 1 pre-write decision and 0 upstream calls", websocketDecisions.Load(), httpUpstreamCalls.Load())
	}
	if got := selectedAccountID.Load(); got != primary.ID() {
		t.Fatalf("selected account=%d want=%d", got, primary.ID())
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d, want 0/0", gotPrimary, gotSecondary)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
		t.Fatalf("dispatch counts primary=%d secondary=%d, want 1/0", gotPrimary, gotSecondary)
	}
	if after := snapshotPreflightAccountHealth(primary); after != beforePrimaryHealth {
		t.Fatalf("inbound local 413 polluted primary health\nbefore=%+v\nafter=%+v", beforePrimaryHealth, after)
	}
	if after := snapshotPreflightAccountHealth(secondary); after != beforeSecondaryHealth {
		t.Fatalf("inbound local 413 polluted secondary health\nbefore=%+v\nafter=%+v", beforeSecondaryHealth, after)
	}

	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 {
		t.Fatalf("usage rows=%d want exactly 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.AccountID != 0 || row.StatusCode != http.StatusRequestEntityTooLarge || row.UpstreamErrorKind != websocketLargeFrameContextBoundKind || row.ViaWebsocket || row.LogicalRequestID == "" {
		t.Fatalf("canonical row=%+v, want account-neutral local 413 and ViaWebsocket=false", row)
	}
	var signals []string
	if err := json.Unmarshal([]byte(row.RouteSignals), &signals); err != nil || len(signals) != 1 || signals[0] != websocketLargeFrameContextBoundKind {
		t.Fatalf("canonical route_signals=%q want exactly one context-bound signal: %v", row.RouteSignals, err)
	}
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	var guardianAttemptOnly bool
	if err := rawDB.QueryRowContext(t.Context(), `SELECT guardian_attempt_only FROM usage_logs WHERE logical_request_id = ?`, row.LogicalRequestID).Scan(&guardianAttemptOnly); err != nil {
		t.Fatalf("read guardian_attempt_only: %v", err)
	}
	if guardianAttemptOnly {
		t.Fatal("inbound local 413 canonical row was incorrectly marked guardian_attempt_only")
	}

	bound, _ := store.NextForSession(affinityKey, 0, nil)
	if bound == nil || bound.ID() != primary.ID() {
		if bound != nil {
			store.Release(bound)
		}
		t.Fatalf("inbound session affinity account=%v want original %d", bound, primary.ID())
	}
	store.Release(bound)
}

func TestInboundResponsesWebsocketUnboundLargeFrameStillStrict(t *testing.T) {
	t.Setenv(websocketContextBoundHTTPPreflightEnv, "")
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
		resinCfg.Store(previousResin)
	})
	settings := previousSettings
	settings.CodexForceWebsocket = true
	ApplyRuntimeSettings(settings)

	var websocketDecisions atomic.Int32
	WebsocketExecuteFunc = func(_ context.Context, _ *auth.Account, _ []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		websocketDecisions.Add(1)
		if !IsStatelessWebsocketSessionID(sessionID) {
			t.Errorf("unbound inbound WS session=%q want stateless", sessionID)
		}
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: false,
		}
	}

	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"unexpected":"strict inbound WS reached HTTP"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, dbPath := newWebsocketPreflightUsageDB(t, "inbound-unbound-strict")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      1,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 1, AccessToken: "oauth-token", PlanType: "pro", AccountID: "acct-1", Status: auth.StatusReady}
	store.AddAccount(account)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if response != nil {
			t.Fatalf("dial inbound websocket: %v status=%d", err, response.StatusCode)
		}
		t.Fatalf("dial inbound websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"model":"gpt-5.4","input":"large first turn"}`)); err != nil {
		t.Fatalf("write unbound large turn: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, errorFrame, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read local error frame: %v", err)
	}
	if got := gjson.GetBytes(errorFrame, "type").String(); got != "error" {
		t.Fatalf("error frame type=%q body=%s", got, errorFrame)
	}
	if got := gjson.GetBytes(errorFrame, "error.code").String(); got != websocketLargeFrameContextBoundKind {
		t.Fatalf("error frame code=%q body=%s", got, errorFrame)
	}
	_, _, closeReadErr := conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(closeReadErr, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
		t.Fatalf("close error=%v want websocket close 1009", closeReadErr)
	}
	if websocketDecisions.Load() != 1 || upstreamCalls.Load() != 0 {
		t.Fatalf("decisions=%d upstream HTTP calls=%d want 1/0", websocketDecisions.Load(), upstreamCalls.Load())
	}
	if got := atomic.LoadInt64(&account.ActiveRequests); got != 0 {
		t.Fatalf("active leases=%d want 0", got)
	}

	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 {
		t.Fatalf("usage rows=%d want exactly 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.AccountID != 0 || row.StatusCode != http.StatusRequestEntityTooLarge || row.UpstreamErrorKind != websocketLargeFrameContextBoundKind || row.ViaWebsocket {
		t.Fatalf("canonical row=%+v want account-neutral strict 413", row)
	}
	var signals []string
	if err := json.Unmarshal([]byte(row.RouteSignals), &signals); err != nil || len(signals) != 1 || signals[0] != websocketLargeFrameContextBoundKind {
		t.Fatalf("route_signals=%q want exactly one strict context signal: %v", row.RouteSignals, err)
	}
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rawDB.Close()
	var guardianAttemptOnly bool
	if err := rawDB.QueryRowContext(t.Context(), `SELECT guardian_attempt_only FROM usage_logs WHERE logical_request_id = ?`, row.LogicalRequestID).Scan(&guardianAttemptOnly); err != nil {
		t.Fatalf("read guardian_attempt_only: %v", err)
	}
	if guardianAttemptOnly {
		t.Fatal("strict inbound WS 413 was incorrectly hidden")
	}
}
