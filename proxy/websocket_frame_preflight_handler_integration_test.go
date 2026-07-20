package proxy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/codex2api/cache"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type preflightAccountHealthSnapshot struct {
	status                  auth.AccountStatus
	healthTier              auth.AccountHealthTier
	failureStreak           int
	successStreak           int
	lastFailureAt           time.Time
	lastServerErrorAt       time.Time
	cooldownUtil            time.Time
	cooldownReason          string
	errorMessage            string
	recentResults           [20]uint8
	recentResultsIndex      int
	recentResultsCount      int
	dynamicConcurrencyLimit int64
	schedulerScore          float64
	dispatchScore           float64
}

func snapshotPreflightAccountHealth(account *auth.Account) preflightAccountHealthSnapshot {
	account.Mu().RLock()
	defer account.Mu().RUnlock()
	return preflightAccountHealthSnapshot{
		status:                  account.Status,
		healthTier:              account.HealthTier,
		failureStreak:           account.FailureStreak,
		successStreak:           account.SuccessStreak,
		lastFailureAt:           account.LastFailureAt,
		lastServerErrorAt:       account.LastServerErrorAt,
		cooldownUtil:            account.CooldownUtil,
		cooldownReason:          account.CooldownReason,
		errorMessage:            account.ErrorMsg,
		recentResults:           account.RecentResults,
		recentResultsIndex:      account.RecentResultsIdx,
		recentResultsCount:      account.RecentResultsCnt,
		dynamicConcurrencyLimit: account.DynamicConcurrencyLimit,
		schedulerScore:          account.SchedulerScore,
		dispatchScore:           account.DispatchScore,
	}
}

func newWebsocketPreflightUsageDB(t *testing.T, name string) (*database.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), name+".db")
	db, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	return db, dbPath
}

func TestPreviousResponseLargeWebsocketFrameRemainsLocal413ForHTTPResponses(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		body          string
		invoke        func(*Handler, *gin.Context)
		assertPayload func(*testing.T, []byte)
	}{
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-5.4","previous_response_id":"resp-owner","input":"continue","stream":false}`,
			invoke: func(handler *Handler, c *gin.Context) {
				handler.Responses(c)
			},
			assertPayload: func(t *testing.T, body []byte) {
				t.Helper()
				if got := gjson.GetBytes(body, "error.code").String(); got != websocketLargeFrameContextBoundKind {
					t.Fatalf("Responses error.code=%q body=%s", got, body)
				}
				if got := gjson.GetBytes(body, "error.type").String(); got != "invalid_request_error" {
					t.Fatalf("Responses error.type=%q body=%s", got, body)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, _ []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
				if strings.TrimSpace(sessionID) == "" || IsStatelessWebsocketSessionID(sessionID) {
					t.Errorf("context-bound %s request reached WS preflight with non-explicit session %q", test.name, sessionID)
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

			db, dbPath := newWebsocketPreflightUsageDB(t, "context-bound-"+strings.ReplaceAll(test.name, " ", "-"))
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

			rawBody := []byte(test.body)
			req := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(rawBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Session_id", "explicit-preflight-session")
			affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(req.Header, rawBody), 0)
			store.BindSessionAffinity(affinityKey, primary, "")
			beforeHealth := snapshotPreflightAccountHealth(primary)
			beforeSecondaryHealth := snapshotPreflightAccountHealth(secondary)

			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = req
			test.invoke(handler, c)

			if recorder.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d want=413 body=%s", recorder.Code, recorder.Body.String())
			}
			test.assertPayload(t, recorder.Body.Bytes())
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
			if afterHealth := snapshotPreflightAccountHealth(primary); afterHealth != beforeHealth {
				t.Fatalf("local 413 polluted account health\nbefore=%+v\nafter=%+v", beforeHealth, afterHealth)
			}
			if afterHealth := snapshotPreflightAccountHealth(secondary); afterHealth != beforeSecondaryHealth {
				t.Fatalf("local 413 polluted secondary account health\nbefore=%+v\nafter=%+v", beforeSecondaryHealth, afterHealth)
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
			if err := json.Unmarshal([]byte(row.RouteSignals), &signals); err != nil {
				t.Fatalf("canonical route_signals=%q invalid JSON: %v", row.RouteSignals, err)
			}
			if len(signals) != 1 || signals[0] != websocketLargeFrameContextBoundKind {
				t.Fatalf("canonical route_signals=%q want exactly one context-bound signal", row.RouteSignals)
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
				t.Fatal("local 413 canonical row was incorrectly marked guardian_attempt_only")
			}

			// Check the pre-existing binding only after the request/usage assertions;
			// NextForSession acquires a lease and would otherwise perturb counters.
			bound, _ := store.NextForSession(affinityKey, 0, nil)
			if bound == nil || bound.ID() != primary.ID() {
				if bound != nil {
					store.Release(bound)
				}
				t.Fatalf("session affinity account=%v want original %d", bound, primary.ID())
			}
			store.Release(bound)
		})
	}
}

func TestResponsesHTTPPreviousResponseStrictPolicyOverridesPreparedUnboundFrame(t *testing.T) {
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
	WebsocketExecuteFunc = func(_ context.Context, _ *auth.Account, requestBody []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		websocketDecisions.Add(1)
		continuation := strings.TrimSpace(gjson.GetBytes(requestBody, "previous_response_id").String()) != ""
		contextBound := continuation || (strings.TrimSpace(sessionID) != "" && !IsStatelessWebsocketSessionID(sessionID))
		if continuation {
			t.Fatalf("prepared OAuth body unexpectedly retained previous_response_id: %s", requestBody)
		}
		if !IsStatelessWebsocketSessionID(sessionID) {
			t.Fatalf("prepared previous_response request session=%q want stateless", sessionID)
		}
		if contextBound {
			t.Fatalf("test setup expected executor-local ContextBound=false")
		}
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: contextBound,
		}
	}

	var httpUpstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpUpstreamCalls.Add(1)
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, `{"unexpected":"strict policy reached HTTP"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, _ := newWebsocketPreflightUsageDB(t, "previous-response-prepared-unbound")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      1,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	store.AddAccount(&auth.Account{DBID: 21, AccessToken: "at-21", PlanType: "pro", AccountID: "acct-21", Status: auth.StatusReady})
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	requestBody := []byte(`{"model":"gpt-5.4","previous_response_id":"resp_raw_owner","stream":false,"input":"continue with screenshot"}`)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(requestBody))
	c.Request.Header.Set("Content-Type", "application/json")
	handler.Responses(c)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want=413 body=%s", recorder.Code, recorder.Body.String())
	}
	if got := gjson.GetBytes(recorder.Body.Bytes(), "error.code").String(); got != websocketLargeFrameContextBoundKind {
		t.Fatalf("error.code=%q want=%q body=%s", got, websocketLargeFrameContextBoundKind, recorder.Body.String())
	}
	if websocketDecisions.Load() != 1 || httpUpstreamCalls.Load() != 0 {
		t.Fatalf("WS decisions=%d HTTP upstream=%d want 1/0", websocketDecisions.Load(), httpUpstreamCalls.Load())
	}
}

func TestResponsesHTTPExplicitSessionLargeFrameUsesSameAccountHTTP(t *testing.T) {
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
	var websocketAccountID atomic.Int64
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, _ []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		if sessionID != "explicit-preflight-session" {
			t.Errorf("explicit HTTP ingress WS session=%q", sessionID)
		}
		websocketDecisions.Add(1)
		websocketAccountID.Store(account.ID())
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: true,
		}
	}

	var httpUpstreamCalls atomic.Int32
	var httpAccountID atomic.Int64
	var httpBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpUpstreamCalls.Add(1)
		if value := strings.TrimSpace(r.Header.Get("X-Resin-Account")); value != "" {
			var parsed int64
			_, _ = fmt.Sscan(value, &parsed)
			httpAccountID.Store(parsed)
		}
		httpBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.completed","response":{"id":"resp_explicit_session_large","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}`+"\n\n",
		)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, dbPath := newWebsocketPreflightUsageDB(t, "explicit-session-same-account-http")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	primary := &auth.Account{DBID: 11, AccessToken: "at-11", PlanType: "pro", AccountID: "acct-11", Status: auth.StatusReady}
	secondary := &auth.Account{DBID: 12, AccessToken: "at-12", PlanType: "free", AccountID: "acct-12", Status: auth.StatusReady}
	store.AddAccount(primary)
	store.AddAccount(secondary)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	requestBody := []byte(`{"model":"gpt-5.4","stream":false,"input":"large screenshot"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session_id", "explicit-preflight-session")
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(req.Header, requestBody), 0)
	store.BindSessionAffinity(affinityKey, primary, "")
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = req
	handler.Responses(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
	}
	if websocketDecisions.Load() != 1 || httpUpstreamCalls.Load() != 1 {
		t.Fatalf("WS decisions=%d HTTP upstream=%d want 1/1", websocketDecisions.Load(), httpUpstreamCalls.Load())
	}
	if websocketAccountID.Load() != primary.ID() || httpAccountID.Load() != primary.ID() {
		t.Fatalf("account changed WS=%d HTTP=%d want selected=%d", websocketAccountID.Load(), httpAccountID.Load(), primary.ID())
	}
	if got := gjson.GetBytes(httpBody, "prompt_cache_key").String(); got != "explicit-preflight-session" {
		t.Fatalf("HTTP prompt_cache_key=%q body=%s", got, httpBody)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.TotalRequests), atomic.LoadInt64(&secondary.TotalRequests); gotPrimary != 1 || gotSecondary != 0 {
		t.Fatalf("dispatch counts primary=%d secondary=%d want 1/0", gotPrimary, gotSecondary)
	}
	if gotPrimary, gotSecondary := atomic.LoadInt64(&primary.ActiveRequests), atomic.LoadInt64(&secondary.ActiveRequests); gotPrimary != 0 || gotSecondary != 0 {
		t.Fatalf("active leases primary=%d secondary=%d want 0/0", gotPrimary, gotSecondary)
	}

	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 {
		t.Fatalf("usage rows=%d want exactly 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.AccountID != primary.ID() || row.StatusCode != http.StatusOK || row.ViaWebsocket || row.LogicalRequestID == "" {
		t.Fatalf("canonical row=%+v, want one successful same-account HTTP row", row)
	}
	var signals []string
	if err := json.Unmarshal([]byte(row.RouteSignals), &signals); err != nil {
		t.Fatalf("route_signals=%q invalid JSON: %v", row.RouteSignals, err)
	}
	newReasonCount := 0
	for _, signal := range signals {
		if signal == websocketLargeFrameSameAccountHTTPReason {
			newReasonCount++
		}
		if signal == websocketLargeFrameContextBoundKind {
			t.Fatalf("successful HTTP fallback retained local 413 signal: %q", row.RouteSignals)
		}
	}
	if newReasonCount != 1 {
		t.Fatalf("route_signals=%q want same-account HTTP reason exactly once", row.RouteSignals)
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
		t.Fatal("successful same-account HTTP row was incorrectly hidden")
	}
}

func TestResponsesRetryFromOAuthLargeFrameHTTPToRelayClearsTransportSignal(t *testing.T) {
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
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, _ []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		websocketDecisions.Add(1)
		if account.ID() != 31 || sessionID != "retry-large-session" {
			t.Fatalf("WS preflight account=%d session=%q want OAuth 31 and explicit session", account.ID(), sessionID)
		}
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: true,
		}
	}

	var oauthHTTPCalls atomic.Int32
	oauthUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oauthHTTPCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"message":"retry OAuth HTTP on Relay","type":"server_error"}}`)
	}))
	t.Cleanup(oauthUpstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: oauthUpstream.URL, PlatformName: "test"})

	var relayHTTPCalls atomic.Int32
	relayUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayHTTPCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_relay_retry_success","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}`)
	}))
	t.Cleanup(relayUpstream.Close)

	db, _ := newWebsocketPreflightUsageDB(t, "oauth-large-http-retry-relay")
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      2,
		MaxRetries:          1,
		MaxRateLimitRetries: 0,
		TestConcurrency:     1,
		TestModel:           "gpt-5.4",
	})
	t.Cleanup(store.Stop)
	store.SetCybRelayConfig(auth.CybRelayConfig{Enabled: true, GroupID: relayFailoverGroupID})
	oauthAccount := &auth.Account{DBID: 31, AccessToken: "oauth-31", PlanType: "pro", AccountID: "acct-31", Status: auth.StatusReady}
	relayAccount := &auth.Account{
		DBID:         32,
		Name:         "relay-32",
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      relayUpstream.URL,
		APIKey:       "relay-key",
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     []int64{relayFailoverGroupID},
	}
	store.AddAccount(oauthAccount)
	store.AddAccount(relayAccount)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)

	requestBody := []byte(`{"model":"gpt-5.4","stream":false,"input":"large screenshot retry"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session_id", "retry-large-session")
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = req
	handler.Responses(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
	}
	if websocketDecisions.Load() != 1 || oauthHTTPCalls.Load() != 1 || relayHTTPCalls.Load() != 1 {
		t.Fatalf("WS decisions=%d OAuth HTTP=%d Relay HTTP=%d want 1/1/1", websocketDecisions.Load(), oauthHTTPCalls.Load(), relayHTTPCalls.Load())
	}
	rows := waitForRetryUsageLogs(t, db, 2)
	if len(rows) != 2 {
		t.Fatalf("usage rows=%d want 2: %+v", len(rows), rows)
	}
	var hidden, canonical *database.UsageLog
	for _, row := range rows {
		if row.AccountID == oauthAccount.ID() {
			hidden = row
		} else if row.AccountID == relayAccount.ID() {
			canonical = row
		}
	}
	if hidden == nil || canonical == nil {
		t.Fatalf("hidden=%+v canonical=%+v rows=%+v", hidden, canonical, rows)
	}
	if hidden.AccountID != oauthAccount.ID() || hidden.StatusCode != http.StatusInternalServerError {
		t.Fatalf("hidden OAuth attempt=%+v", hidden)
	}
	if canonical.AccountID != relayAccount.ID() || canonical.StatusCode != http.StatusOK || canonical.ViaWebsocket {
		t.Fatalf("canonical Relay success=%+v", canonical)
	}
	containsSignal := func(raw, want string) bool {
		var signals []string
		if err := json.Unmarshal([]byte(raw), &signals); err != nil {
			t.Fatalf("route_signals=%q invalid JSON: %v", raw, err)
		}
		for _, signal := range signals {
			if signal == want {
				return true
			}
		}
		return false
	}
	if !containsSignal(hidden.RouteSignals, websocketLargeFrameSameAccountHTTPReason) {
		t.Fatalf("hidden attempt lost its transport signal: %q", hidden.RouteSignals)
	}
	for _, leaked := range []string{websocketLargeFrameSameAccountHTTPReason, websocketLargeFrameHTTPPreflightReason, websocketLargeFrameContextBoundKind} {
		if containsSignal(canonical.RouteSignals, leaked) {
			t.Fatalf("canonical Relay row inherited %q from OAuth attempt: %q", leaked, canonical.RouteSignals)
		}
	}
}

func TestEncryptedOwnerLargeUnboundWebsocketFrameFallsBackToSameAccountHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	enableEncryptedContextAffinity(t)
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
	var websocketAccountID atomic.Int64
	var websocketBody []byte
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, body []byte, sessionID string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		if !IsStatelessWebsocketSessionID(sessionID) {
			t.Errorf("unbound encrypted-owner request WS session=%q, want stateless", sessionID)
		}
		websocketDecisions.Add(1)
		websocketAccountID.Store(account.ID())
		websocketBody = append([]byte(nil), body...)
		return nil, &WebsocketFramePreflightError{FrameBytes: 17 * 1024 * 1024, LimitBytes: 16 * 1024 * 1024}
	}

	var httpUpstreamCalls atomic.Int32
	var httpAccountID atomic.Int64
	var httpBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpUpstreamCalls.Add(1)
		if value := strings.TrimSpace(r.Header.Get("X-Resin-Account")); value != "" {
			var parsed int64
			_, _ = fmt.Sscan(value, &parsed)
			httpAccountID.Store(parsed)
		}
		httpBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.completed","response":{"id":"resp_encrypted_owner","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}`+"\n\n",
		)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	db, dbPath := newWebsocketPreflightUsageDB(t, "encrypted-owner-http-fallback")
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2, MaxRetries: 0, MaxRateLimitRetries: 0, TestConcurrency: 1, TestModel: "gpt-5.4"})
	t.Cleanup(store.Stop)
	ordinary := &auth.Account{DBID: 1, AccessToken: "ordinary-oauth", PlanType: "pro", AccountID: "ordinary", Status: auth.StatusReady}
	owner := &auth.Account{DBID: 2, AccessToken: "owner-oauth", PlanType: "free", AccountID: "owner", Status: auth.StatusReady}
	store.AddAccount(ordinary)
	store.AddAccount(owner)
	handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
	handler.SetRuntimeCache(cache.NewMemory(16))
	capture := newEncryptedContextCapture(101)
	capture.Observe([]byte(`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"rb23-owner-cipher"}}`))
	handler.commitEncryptedContextCapture(owner, capture)

	requestBody := []byte(`{"model":"gpt-5.4","stream":false,"input":[{"type":"reasoning","encrypted_content":"rb23-owner-cipher"},{"role":"user","content":"continue"}]}`)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Set(contextAPIKeyID, int64(101))
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(requestBody))
	c.Request.Header.Set("Content-Type", "application/json")
	handler.Responses(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want=200 body=%s", recorder.Code, recorder.Body.String())
	}
	if websocketDecisions.Load() != 1 || httpUpstreamCalls.Load() != 1 {
		t.Fatalf("WS decisions=%d HTTP upstream=%d want 1/1", websocketDecisions.Load(), httpUpstreamCalls.Load())
	}
	if websocketAccountID.Load() != owner.ID() || httpAccountID.Load() != owner.ID() {
		t.Fatalf("owner routing WS=%d HTTP=%d want same encrypted owner %d", websocketAccountID.Load(), httpAccountID.Load(), owner.ID())
	}
	if got := gjson.GetBytes(websocketBody, "input.0.encrypted_content").String(); got != "rb23-owner-cipher" {
		t.Fatalf("WS candidate encrypted_content=%q", got)
	}
	if got := gjson.GetBytes(httpBody, "input.0.encrypted_content").String(); got != "rb23-owner-cipher" {
		t.Fatalf("HTTP fallback encrypted_content=%q body=%s", got, httpBody)
	}
	if gotOwner, gotOrdinary := atomic.LoadInt64(&owner.TotalRequests), atomic.LoadInt64(&ordinary.TotalRequests); gotOwner != 1 || gotOrdinary != 0 {
		t.Fatalf("dispatch counts owner=%d ordinary=%d want 1/0", gotOwner, gotOrdinary)
	}
	if gotOwner, gotOrdinary := atomic.LoadInt64(&owner.ActiveRequests), atomic.LoadInt64(&ordinary.ActiveRequests); gotOwner != 0 || gotOrdinary != 0 {
		t.Fatalf("active leases owner=%d ordinary=%d want 0/0", gotOwner, gotOrdinary)
	}

	rows := waitForRetryUsageLogs(t, db, 1)
	if len(rows) != 1 {
		t.Fatalf("usage rows=%d want exactly 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.AccountID != owner.ID() || row.StatusCode != http.StatusOK || row.ViaWebsocket || row.PinKind != encryptedContextPinKind || row.LogicalRequestID == "" {
		t.Fatalf("encrypted-owner canonical row=%+v", row)
	}
	var signals []string
	if err := json.Unmarshal([]byte(row.RouteSignals), &signals); err != nil {
		t.Fatalf("route_signals=%q invalid JSON: %v", row.RouteSignals, err)
	}
	wantSignals := map[string]int{encryptedOwnerHitSignal: 0, websocketLargeFrameHTTPPreflightReason: 0}
	for _, signal := range signals {
		if _, ok := wantSignals[signal]; ok {
			wantSignals[signal]++
		}
	}
	if wantSignals[encryptedOwnerHitSignal] != 1 || wantSignals[websocketLargeFrameHTTPPreflightReason] != 1 {
		t.Fatalf("route_signals=%q want owner-hit and HTTP-preflight exactly once", row.RouteSignals)
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
		t.Fatal("encrypted-owner canonical row was incorrectly marked guardian_attempt_only")
	}
}
