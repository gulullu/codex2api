package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/codex2api/security/promptfilter"
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

func TestInboundResponsesWebsocketNextRelayTurnDoesNotInheritLargeFrameHTTPReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousExec := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		resinCfg.Store(previousResin)
	})

	var websocketDecisions atomic.Int32
	WebsocketExecuteFunc = func(_ context.Context, _ *auth.Account, _ []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		if got := websocketDecisions.Add(1); got != 1 {
			t.Errorf("Relay turn unexpectedly called the Codex WS executor; decisions=%d", got)
		}
		return nil, &WebsocketFramePreflightError{FrameBytes: 17 * 1024 * 1024, LimitBytes: 16 * 1024 * 1024}
	}

	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			fmt.Sprintf(`data: {"type":"response.output_text.delta","delta":"turn-%d"}`, call)+"\n\n"+
				`data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}`+"\n\n",
		)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, _ := newWebsocketPreflightUsageDB(t, "inbound-next-relay-turn")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:                           1,
		MaxRetries:                               0,
		MaxRateLimitRetries:                      0,
		TestConcurrency:                          1,
		TestModel:                                "gpt-5.4",
		PromptFilterEnabled:                      true,
		PromptFilterMode:                         "monitor",
		PromptFilterThreshold:                    50,
		PromptFilterStrictThreshold:              120,
		PromptFilterMaxTextLength:                promptfilter.DefaultMaxTextLength,
		PromptFilterCustomPatterns: promptfilter.MarshalCustomPatterns([]promptfilter.PatternConfig{{
			Name: "rb23_two_turn_relay", Pattern: `rb23 force relay turn`, Weight: 100, Category: "rb23-test",
		}}),
		PromptFilterDisabledPatterns:             "[]",
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              relayFailoverGroupID,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	t.Cleanup(store.Stop)
	account := &auth.Account{DBID: 1, AccessToken: "oauth-token", PlanType: "pro", AccountID: "acct-1", Status: auth.StatusReady}
	store.AddAccount(account)
	relayAccount := &auth.Account{
		DBID:         2,
		Name:         "rb23-relay-second-turn",
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      upstream.URL,
		APIKey:       "relay-key",
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     []int64{relayFailoverGroupID},
	}
	store.AddAccount(relayAccount)
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

	readTurn := func(wantDelta string) {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, delta, readErr := conn.ReadMessage()
		if readErr != nil {
			t.Fatalf("read %s delta: %v", wantDelta, readErr)
		}
		if got := gjson.GetBytes(delta, "delta").String(); got != wantDelta {
			t.Fatalf("delta=%q want=%q body=%s", got, wantDelta, delta)
		}
		_, terminal, readErr := conn.ReadMessage()
		if readErr != nil {
			t.Fatalf("read %s terminal: %v", wantDelta, readErr)
		}
		if got := gjson.GetBytes(terminal, "type").String(); got != "response.completed" {
			t.Fatalf("terminal type=%q body=%s", got, terminal)
		}
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"model":"gpt-5.4","input":"first turn"}`)); err != nil {
		t.Fatalf("write first turn: %v", err)
	}
	readTurn("turn-1")
	firstRows := waitForRetryUsageLogs(t, db, 1)
	if len(firstRows) != 1 || !strings.Contains(firstRows[0].RouteSignals, websocketLargeFrameHTTPPreflightReason) || firstRows[0].ViaWebsocket {
		t.Fatalf("first turn canonical rows=%+v want HTTP preflight reason and ViaWebsocket=false", firstRows)
	}

	// A high-risk second turn routes to the configured Relay group. It reuses
	// the same inbound Gin context while bypassing the Codex WS observer, which
	// exercises the exact stale-reason regression.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"model":"gpt-5.4","input":"rb23 force relay turn"}`)); err != nil {
		t.Fatalf("write second turn: %v", err)
	}
	readTurn("turn-2")

	rows := waitForRetryUsageLogs(t, db, 2)
	if len(rows) != 2 {
		t.Fatalf("usage rows=%d want exactly 2: %+v", len(rows), rows)
	}
	var first, second *database.UsageLog
	if rows[0].ID < rows[1].ID {
		first, second = rows[0], rows[1]
	} else {
		first, second = rows[1], rows[0]
	}
	if !strings.Contains(first.RouteSignals, websocketLargeFrameHTTPPreflightReason) {
		t.Fatalf("first turn route_signals=%q missing HTTP preflight reason", first.RouteSignals)
	}
	var firstSignals []string
	if err := json.Unmarshal([]byte(first.RouteSignals), &firstSignals); err != nil || len(firstSignals) != 1 || firstSignals[0] != websocketLargeFrameHTTPPreflightReason {
		t.Fatalf("first turn route_signals=%q want exactly one HTTP preflight signal: %v", first.RouteSignals, err)
	}
	if strings.Contains(second.RouteSignals, websocketLargeFrameHTTPPreflightReason) || strings.Contains(second.RouteSignals, websocketLargeFrameContextBoundKind) {
		t.Fatalf("Relay turn inherited stale WS preflight route_signals=%q", second.RouteSignals)
	}
	if first.LogicalRequestID == "" || second.LogicalRequestID == "" || first.LogicalRequestID == second.LogicalRequestID {
		t.Fatalf("logical request IDs first=%q second=%q, want two distinct canonical requests", first.LogicalRequestID, second.LogicalRequestID)
	}
	if second.UpstreamAccountType != "openai_responses" {
		t.Fatalf("second turn upstream account type=%q, want openai_responses Relay path", second.UpstreamAccountType)
	}
	if second.ViaWebsocket {
		t.Fatal("Relay turn was incorrectly recorded as websocket")
	}
	if websocketDecisions.Load() != 1 || upstreamCalls.Load() != 2 {
		t.Fatalf("decisions=%d upstream HTTP calls=%d want 1/2", websocketDecisions.Load(), upstreamCalls.Load())
	}
}
