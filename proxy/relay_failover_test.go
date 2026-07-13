package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const relayFailoverGroupID int64 = 9101

func relayFailoverAccount(id int64, baseURL, key string, priority int64) *auth.Account {
	account := &auth.Account{
		DBID:         id,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      baseURL,
		APIKey:       key,
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     []int64{relayFailoverGroupID},
	}
	account.SetSchedulerPriority(priority)
	return account
}

func newRelayFailoverStore(firstURL, secondURL string) *auth.Store {
	return newRelayFailoverStoreWithRetries(firstURL, secondURL, 1)
}

func newRelayFailoverStoreWithRetries(firstURL, secondURL string, maxRetries int) *auth.Store {
	return newRelayFailoverStoreWithRetryPolicy(firstURL, secondURL, maxRetries, "")
}

func newRelayFailoverStoreWithRetryPolicy(firstURL, secondURL string, maxRetries int, transportRetryPolicy string) *auth.Store {
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:                           4,
		MaxRetries:                               maxRetries,
		MaxRateLimitRetries:                      1,
		RetryIntervalMS:                          0,
		TransportRetryPolicy:                     transportRetryPolicy,
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              relayFailoverGroupID,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	store.AddAccount(relayFailoverAccount(101, firstURL, "sk-first", 10))
	store.AddAccount(relayFailoverAccount(102, secondURL, "sk-second", 0))
	return store
}

func newSingleRelayFailoverStore(upstreamURL string, maxRetries int) *auth.Store {
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:                           4,
		MaxRetries:                               maxRetries,
		MaxRateLimitRetries:                      1,
		RetryIntervalMS:                          0,
		TransportRetryPolicy:                     "sticky",
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              relayFailoverGroupID,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	store.AddAccount(relayFailoverAccount(101, upstreamURL, "sk-only", 10))
	return store
}

func newAbruptTransportCloseServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("test response writer does not support hijacking")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack upstream connection: %v", err)
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(server.Close)
	return server
}

func closedLoopbackURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed loopback address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved loopback address: %v", err)
	}
	return "http://" + address
}

func writeRelayTestSuccess(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !gjson.GetBytes(body, "stream").Bool() {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_failover_ok","object":"response","status":"completed","model":"gpt-5.4","output":[],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, event := range []string{
		`{"type":"response.created","response":{"id":"resp_failover_ok"}}`,
		`{"type":"response.output_item.added","item":{"type":"message"}}`,
		`{"type":"response.output_text.delta","delta":"OK"}`,
		`{"type":"response.output_text.done"}`,
		`{"type":"response.completed","response":{"id":"resp_failover_ok","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}`,
	} {
		_, _ = io.WriteString(w, "data: "+event+"\n\n")
	}
}

func runRelayTextHandler(t *testing.T, handler *Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	switch path {
	case "/v1/responses":
		handler.Responses(ctx)
	case "/v1/responses/compact":
		handler.ResponsesCompact(ctx)
	case "/v1/chat/completions":
		handler.ChatCompletions(ctx)
	case "/v1/messages":
		handler.Messages(ctx)
	default:
		t.Fatalf("unsupported path %s", path)
	}
	return recorder
}

func waitRelayTransportUsageRows(t *testing.T, db *database.DB, want int) []database.RelayGuardianUsageRow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, err := db.ListRelayGuardianUsage(
			context.Background(),
			relayFailoverGroupID,
			time.Now().Add(-time.Minute),
			time.Now().Add(time.Minute),
			100,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("usage rows=%d want at least %d", len(rows), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayTextHTTPGatewayFailureSwitchesAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name       string
		path       string
		statusCode int
		body       string
	}{
		{name: "responses 502", path: "/v1/responses", statusCode: http.StatusBadGateway, body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "responses 504", path: "/v1/responses", statusCode: http.StatusGatewayTimeout, body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "responses cloudflare 524", path: "/v1/responses", statusCode: 524, body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "compact 502", path: "/v1/responses/compact", statusCode: http.StatusBadGateway, body: `{"model":"gpt-5.4","input":"hello"}`},
		{name: "chat 502", path: "/v1/chat/completions", statusCode: http.StatusBadGateway, body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}]}`},
		{name: "messages 502", path: "/v1/messages", statusCode: http.StatusBadGateway, body: `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var firstHits, secondHits atomic.Int32
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				firstHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.statusCode)
				_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"gateway failed"}}`)
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				secondHits.Add(1)
				if got := r.Header.Get("Authorization"); got != "Bearer sk-second" {
					t.Errorf("fallback Authorization = %q", got)
				}
				writeRelayTestSuccess(w, r)
			}))
			defer second.Close()

			store := newRelayFailoverStore(first.URL, second.URL)
			handler := NewHandler(store, nil, nil, nil)
			recorder := runRelayTextHandler(t, handler, test.path, []byte(test.body))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			if firstHits.Load() != 1 || secondHits.Load() != 1 {
				t.Fatalf("attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
			}
			if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 || snapshot.PostSuspectFailures != 0 {
				t.Fatalf("first account circuit = %+v, want one pre-suspect failure", snapshot)
			}

			secondRecorder := runRelayTextHandler(t, handler, test.path, []byte(test.body))
			if secondRecorder.Code != http.StatusOK {
				t.Fatalf("second logical request status = %d, want 200; body=%s", secondRecorder.Code, secondRecorder.Body.String())
			}
			if firstHits.Load() != 2 || secondHits.Load() != 2 {
				t.Fatalf("suspect account was not admitted at reduced capacity: first=%d second=%d", firstHits.Load(), secondHits.Load())
			}
			if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 2 || snapshot.PostSuspectFailures != 1 {
				t.Fatalf("first account circuit after second request = %+v, want two distinct failures with one post-suspect", snapshot)
			}
		})
	}
}

func TestRelayStickyTransportFailureSwitchesFrontDoor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.4","input":"hello"}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var firstHits, secondHits atomic.Int32
			first := newAbruptTransportCloseServer(t, &firstHits)
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				secondHits.Add(1)
				writeRelayTestSuccess(w, r)
			}))
			defer second.Close()

			store := newRelayFailoverStoreWithRetryPolicy(first.URL, second.URL, 1, "sticky")
			handler := NewHandler(store, nil, nil, nil)
			recorder := runRelayTextHandler(t, handler, test.path, []byte(test.body))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if firstHits.Load() != 1 || secondHits.Load() != 1 {
				t.Fatalf("sticky Relay transport attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
			}
			if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect ||
				snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
				t.Fatalf("first Relay transport circuit=%+v", snapshot)
			}
		})
	}
}

func TestRelayTransportUsageHasOneCanonicalFinalRow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name            string
		secondSucceeds  bool
		wantHTTPStatus  int
		wantFinalStatus int
	}{
		{name: "retry_exhausted", wantHTTPStatus: http.StatusBadGateway, wantFinalStatus: http.StatusBadGateway},
		{name: "retry_succeeds", secondSucceeds: true, wantHTTPStatus: http.StatusOK, wantFinalStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var firstHits, secondHits atomic.Int32
			first := newAbruptTransportCloseServer(t, &firstHits)
			var second *httptest.Server
			if tt.secondSucceeds {
				second = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					secondHits.Add(1)
					writeRelayTestSuccess(w, r)
				}))
				t.Cleanup(second.Close)
			} else {
				second = newAbruptTransportCloseServer(t, &secondHits)
			}

			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "transport-usage.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
			t.Cleanup(func() { _ = db.Close() })
			store := newRelayFailoverStoreWithRetryPolicy(first.URL, second.URL, 1, "sticky")
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, nil, nil)
			recorder := runRelayTextHandler(t, handler, "/v1/responses", []byte(
				`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":false}`,
			))
			if recorder.Code != tt.wantHTTPStatus {
				t.Fatalf("status=%d want %d; body=%s", recorder.Code, tt.wantHTTPStatus, recorder.Body.String())
			}
			if firstHits.Load() != 1 || secondHits.Load() != 1 {
				t.Fatalf("transport attempts first=%d second=%d, want 1/1", firstHits.Load(), secondHits.Load())
			}

			rows := waitRelayTransportUsageRows(t, db, 2)
			if len(rows) != 2 {
				t.Fatalf("usage rows=%d want exactly 2: %+v", len(rows), rows)
			}
			logicalID := rows[0].LogicalRequestID
			if logicalID == "" || rows[1].LogicalRequestID != logicalID {
				t.Fatalf("retry rows do not share one logical request: %+v", rows)
			}
			hidden := 0
			canonical := 0
			for _, row := range rows {
				if row.GuardianAttemptOnly {
					hidden++
					if row.StatusCode != http.StatusBadGateway {
						t.Fatalf("hidden transport status=%d want 502", row.StatusCode)
					}
					continue
				}
				canonical++
				if row.StatusCode != tt.wantFinalStatus {
					t.Fatalf("canonical final status=%d want %d", row.StatusCode, tt.wantFinalStatus)
				}
			}
			if hidden != 1 || canonical != 1 {
				t.Fatalf("hidden=%d canonical=%d want 1/1; rows=%+v", hidden, canonical, rows)
			}
		})
	}
}

func TestRelayRequestTransportPoolExhaustionPreservesCanonicalGatewayError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":false}`},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary."}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newAbruptTransportCloseServer(t, &hits)
			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "request-exhaustion.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
			t.Cleanup(func() { _ = db.Close() })
			store := newSingleRelayFailoverStore(upstream.URL, 1)
			t.Cleanup(store.Stop)
			recorder := runRelayTextHandler(t, NewHandler(store, db, nil, nil), test.path, []byte(test.body))
			if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "relay_route_unavailable") {
				t.Fatalf("status=%d body=%s, want last real request transport failure", recorder.Code, recorder.Body.String())
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits=%d want 1 before hard exclusion", hits.Load())
			}
			rows := waitRelayTransportUsageRows(t, db, 2)
			if len(rows) != 2 {
				t.Fatalf("usage rows=%d want 2: %+v", len(rows), rows)
			}
			hidden, canonical := 0, 0
			for _, row := range rows {
				if row.GuardianAttemptOnly {
					hidden++
					continue
				}
				canonical++
				if row.StatusCode != http.StatusBadGateway || row.UpstreamErrorKind == "relay_route_unavailable" {
					t.Fatalf("canonical row=%+v, want upstream 502", row)
				}
			}
			if hidden != 1 || canonical != 1 {
				t.Fatalf("rows=%+v, want exactly one hidden and one canonical", rows)
			}
		})
	}
}

func TestPendingEncryptedRelayOwnerFailureDoesNotCreateAuditViolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "encrypted-pending-final.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	store := newSingleRelayFailoverStore("https://relay.invalid", 1)
	t.Cleanup(store.Stop)
	handler := NewHandler(store, db, nil, nil)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	beginLogicalRequest(ctx)

	ownerDecision := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		RouteSource: cybRelayRouteSourcePin,
		PinKind:     encryptedContextPinKind,
		RoutePinned: true,
		Signals:     []string{encryptedOwnerHitSignal},
		Reason:      "continued on encrypted owner",
	}
	setPromptRiskDecisionContext(ctx, ownerDecision, relayFailoverGroupID)
	pending := rememberPendingFinalFailure(ctx, retryAttemptUsageSpec{
		Endpoint:          "/v1/responses",
		Model:             "gpt-5.4",
		EffectiveModel:    "gpt-5.4",
		StatusCode:        http.StatusBadGateway,
		UpstreamErrorKind: "transport",
		ErrorMessage:      "owner transport failed",
	})
	currentDecision, ok := promptRiskDecisionFromContext(ctx)
	if !ok {
		t.Fatal("missing current route decision")
	}
	currentDecision.Signals[0] = "mutated_after_snapshot"
	if pending.routeDecision == nil || len(pending.routeDecision.Signals) != 1 || pending.routeDecision.Signals[0] != encryptedOwnerHitSignal {
		t.Fatalf("pending route decision was shallow-copied: %+v", pending.routeDecision)
	}
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:           []string{"opaque-fingerprint"},
		NeedsDowngrade: true,
		Signals:        []string{encryptedOwnerHitSignal, encryptedOwnerUnavailableSignal, encryptedContextDowngradeSignal},
	})
	handler.logPendingFinalFailure(ctx, pending)

	logs := waitForRetryUsageLogs(t, db, 1)
	if len(logs) != 1 {
		t.Fatalf("usage logs=%d want 1", len(logs))
	}
	row := logs[0]
	if row.AccountID != 0 || row.RouteClass != cybRelayRouteClass || row.RouteSource != cybRelayRouteSourceContinuation ||
		row.PinKind != "" || row.RouteGroupID != relayFailoverGroupID || row.UpstreamAccountType != auth.UpstreamOpenAIResponses ||
		strings.Contains(row.RouteSignals, encryptedOwnerHitSignal) {
		t.Fatalf("pending encrypted owner canonical metadata=%+v", row)
	}
	report, err := db.BuildCodexAuditReport(context.Background(), database.CodexAuditQuery{
		Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Minute), BucketMinutes: 5, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.EncryptedOwnerViolations != 0 || report.Summary.RouteInvariantViolations != 0 || report.Summary.RouteMetadataConflicts != 0 {
		t.Fatalf("pending encrypted owner canonical triggered audit violation: %+v", report.Summary)
	}
}

func TestEncryptedRelayOwnerFailureThroughHandlerKeepsOneNeutralCanonicalRow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	enableEncryptedContextAffinity(t)

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"temporary gateway failure"}}`)
	}))
	defer upstream.Close()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "encrypted-handler-final.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })

	store := newSingleRelayFailoverStore(upstream.URL, 1)
	t.Cleanup(store.Stop)
	owner := store.FindByID(101)
	if owner == nil {
		t.Fatal("missing Relay owner account")
	}
	handler := NewHandler(store, db, nil, nil)
	handler.SetRuntimeCache(cache.NewMemory(16))
	capture := newEncryptedContextCapture(101)
	capture.Observe([]byte(`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"owner-cipher"}}`))
	handler.commitEncryptedContextCapture(owner, capture)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set(contextAPIKeyID, int64(101))
	requestContext, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{
		"model":"gpt-5.4",
		"stream":false,
		"input":[{"type":"reasoning","encrypted_content":"owner-cipher"},{"role":"user","content":"continue"}]
	}`))).WithContext(requestContext)
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.Responses(ctx)

	logs := waitForRetryUsageLogs(t, db, 2)
	if len(logs) != 2 {
		t.Fatalf("usage logs=%d want exactly 2: %+v", len(logs), logs)
	}
	var ownerAttempt, final *database.UsageLog
	for _, row := range logs {
		switch row.AccountID {
		case owner.ID():
			ownerAttempt = row
		case 0:
			final = row
		}
	}
	if upstreamHits.Load() != 1 || ownerAttempt == nil || final == nil {
		t.Fatalf("upstream hits=%d ownerAttempt=%+v final=%+v", upstreamHits.Load(), ownerAttempt, final)
	}
	if ownerAttempt.PinKind != encryptedContextPinKind || ownerAttempt.RouteSource != cybRelayRouteSourcePin ||
		!strings.Contains(ownerAttempt.RouteSignals, encryptedOwnerHitSignal) {
		t.Fatalf("owner attempt route metadata=%+v", ownerAttempt)
	}
	if final.StatusCode != http.StatusBadGateway || final.RouteClass != cybRelayRouteClass ||
		final.RouteSource != cybRelayRouteSourceContinuation || final.PinKind != "" ||
		strings.Contains(final.RouteSignals, encryptedOwnerHitSignal) ||
		!strings.Contains(final.RouteSignals, encryptedOwnerUnavailableSignal) ||
		!strings.Contains(final.RouteSignals, encryptedContextDowngradeSignal) {
		t.Fatalf("account-neutral final metadata=%+v", final)
	}
	if ownerAttempt.LogicalRequestID == "" || ownerAttempt.LogicalRequestID != final.LogicalRequestID {
		t.Fatalf("logical request IDs owner=%q final=%q", ownerAttempt.LogicalRequestID, final.LogicalRequestID)
	}

	report, err := db.BuildCodexAuditReport(context.Background(), database.CodexAuditQuery{
		Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Minute), BucketMinutes: 5, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.EncryptedOwnerViolations != 0 || report.Summary.RouteInvariantViolations != 0 || report.Summary.RouteMetadataConflicts != 0 {
		t.Fatalf("handler encrypted owner failure triggered audit violation: %+v", report.Summary)
	}
}

func TestRelayStickyConnectionRefusedSwitchesFrontDoor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var fallbackHits atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer fallback.Close()

	store := newRelayFailoverStoreWithRetryPolicy(closedLoopbackURL(t), fallback.URL, 1, "sticky")
	recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), "/v1/responses", []byte(`{"model":"gpt-5.4","input":"hello","stream":false}`))
	if recorder.Code != http.StatusOK || fallbackHits.Load() != 1 {
		t.Fatalf("connection-refused fallback status=%d hits=%d body=%s", recorder.Code, fallbackHits.Load(), recorder.Body.String())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect ||
		snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
		t.Fatalf("connection-refused circuit=%+v", snapshot)
	}
}

func TestOrdinaryAccountStickyTransportRetryDoesNotRotate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := newAbruptTransportCloseServer(t, &firstHits)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:       4,
		MaxRetries:           1,
		RetryIntervalMS:      0,
		TransportRetryPolicy: "sticky",
	})
	firstAccount := relayFailoverAccount(201, first.URL, "sk-first", 10)
	firstAccount.GroupIDs = nil
	secondAccount := relayFailoverAccount(202, second.URL, "sk-second", 0)
	secondAccount.GroupIDs = nil
	store.AddAccount(firstAccount)
	store.AddAccount(secondAccount)

	recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), "/v1/responses", []byte(`{"model":"gpt-5.4","input":"hello","stream":false}`))
	if recorder.Code == http.StatusOK {
		t.Fatalf("ordinary sticky request unexpectedly rotated to healthy account: %s", recorder.Body.String())
	}
	if firstHits.Load() != 2 || secondHits.Load() != 0 {
		t.Fatalf("ordinary sticky attempts first=%d second=%d, want 2 then 0", firstHits.Load(), secondHits.Load())
	}
}

func TestRelayStreamEOFBeforeOutputSwitchesFrontDoor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := newRelayFailoverStoreWithRetryPolicy(first.URL, second.URL, 1, "sticky")
	recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), "/v1/responses", []byte(`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"type":"response.completed"`) {
		t.Fatalf("fallback stream status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("pre-output EOF attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect ||
		snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
		t.Fatalf("pre-output EOF circuit=%+v", snapshot)
	}
}

func TestRelayStreamEOFBeforeOutputReturnsCanonicalGatewayError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "stream-final.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
			t.Cleanup(func() { _ = db.Close() })
			store := newSingleRelayFailoverStore(upstream.URL, 0)
			t.Cleanup(store.Stop)
			recorder := runRelayTextHandler(t, NewHandler(store, db, nil, nil), test.path, []byte(test.body))
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d want 502; body=%s", recorder.Code, recorder.Body.String())
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits=%d want 1", hits.Load())
			}
			rows := waitRelayTransportUsageRows(t, db, 2)
			if len(rows) != 2 || !rows[0].GuardianAttemptOnly || rows[1].GuardianAttemptOnly || rows[1].StatusCode != http.StatusBadGateway {
				t.Fatalf("stream rows=%+v, want one hidden attempt and one canonical 502", rows)
			}
			if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 {
				t.Fatalf("stream EOF circuit=%+v, want one strong failure", snapshot)
			}
		})
	}
}

func TestRelayStreamEOFPoolExhaustionPreservesOneCanonicalGatewayError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "stream-exhaustion.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	store := newSingleRelayFailoverStore(upstream.URL, 1)
	t.Cleanup(store.Stop)
	recorder := runRelayTextHandler(t, NewHandler(store, db, nil, nil), "/v1/responses", []byte(
		`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`,
	))
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "relay_route_unavailable") {
		t.Fatalf("status=%d body=%s, want last real stream failure", recorder.Code, recorder.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits=%d want 1 before hard exclusion", hits.Load())
	}
	rows := waitRelayTransportUsageRows(t, db, 2)
	hidden, canonical := 0, 0
	for _, row := range rows {
		if row.GuardianAttemptOnly {
			hidden++
			continue
		}
		canonical++
		if row.StatusCode != http.StatusBadGateway || row.UpstreamErrorKind == "relay_route_unavailable" {
			t.Fatalf("canonical row=%+v, want upstream 502", row)
		}
	}
	if hidden != 1 || canonical != 1 || len(rows) != 2 {
		t.Fatalf("rows=%+v, want exactly one hidden and one canonical", rows)
	}
}

func TestRelayStreamEOFAfterOutputDoesNotReplayButRecordsEvidence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_partial_transport"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"partial-transport"}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := newRelayFailoverStoreWithRetryPolicy(first.URL, second.URL, 1, "sticky")
	recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), "/v1/responses", []byte(`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`))
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("post-output EOF attempts first=%d second=%d, want no replay", firstHits.Load(), secondHits.Load())
	}
	if !strings.Contains(recorder.Body.String(), `"delta":"partial-transport"`) {
		t.Fatalf("partial output was not preserved: %s", recorder.Body.String())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect ||
		snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
		t.Fatalf("post-output EOF circuit=%+v", snapshot)
	}
}

func TestResponsesSSEFailureAfterOutputDoesNotReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_partial"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"partial"}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"boom","status_code":502}}}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), nil, nil, nil)
	recorder := runRelayTextHandler(t, handler, "/v1/responses", []byte(`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`))
	body := recorder.Body.String()
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("attempts first=%d second=%d, want no replay after SSE output", firstHits.Load(), secondHits.Load())
	}
	if !strings.Contains(body, `"delta":"partial"`) || !strings.Contains(body, `"type":"response.failed"`) {
		t.Fatalf("partial Responses stream did not preserve terminal failure: %s", body)
	}
}

func TestRelayFiveIndependent503FailuresOpenCircuit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var primaryHits, fallbackHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"temporarily unavailable"}}`)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer fallback.Close()

	store := newRelayFailoverStore(primary.URL, fallback.URL)
	handler := NewHandler(store, nil, nil, nil)
	body := []byte(`{"model":"gpt-5.4","input":"hello","stream":false}`)
	for logicalRequest := 1; logicalRequest <= 5; logicalRequest++ {
		recorder := runRelayTextHandler(t, handler, "/v1/responses", body)
		if recorder.Code != http.StatusOK {
			t.Fatalf("logical request %d status=%d body=%s", logicalRequest, recorder.Code, recorder.Body.String())
		}
	}
	if primaryHits.Load() != 5 || fallbackHits.Load() != 5 {
		t.Fatalf("five failovers primary=%d fallback=%d, want 5/5", primaryHits.Load(), fallbackHits.Load())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitOpen || snapshot.LastStatusCode != http.StatusServiceUnavailable {
		t.Fatalf("primary circuit after five 503s = %+v", snapshot)
	}

	recorder := runRelayTextHandler(t, handler, "/v1/responses", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("post-open request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if primaryHits.Load() != 5 || fallbackHits.Load() != 6 {
		t.Fatalf("open primary was retried: primary=%d fallback=%d", primaryHits.Load(), fallbackHits.Load())
	}
}

func TestAllRelayHTTPFailuresReturnLastRealUpstreamError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"hello","stream":false}`},
		{name: "compact", path: "/v1/responses/compact", body: `{"model":"gpt-5.4","input":"hello"}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","messages":[{"role":"user","content":"hello"}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"first gateway"}}`)
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"second gateway"}}`)
			}))
			defer second.Close()

			store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
			recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), test.path, []byte(test.body))
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status=%d want 502; body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "second gateway") {
				t.Fatalf("last real upstream error was replaced: %s", recorder.Body.String())
			}
		})
	}
}

func TestRelayHTTPRetryRowsHaveOneCanonicalFinal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	failed := func(message string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"`+message+`"}}`)
		}))
	}
	first := failed("first retryable gateway")
	defer first.Close()
	second := failed("final gateway")
	defer second.Close()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "http-status-usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 1)
	t.Cleanup(store.Stop)
	recorder := runRelayTextHandler(t, NewHandler(store, db, nil, nil), "/v1/responses", []byte(
		`{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":false}`,
	))
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "final gateway") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	rows := waitRelayTransportUsageRows(t, db, 2)
	if len(rows) != 2 || !rows[0].GuardianAttemptOnly || rows[1].GuardianAttemptOnly || rows[1].StatusCode != http.StatusBadGateway {
		t.Fatalf("retry rows=%+v, want hidden attempt then one canonical 502", rows)
	}
}

func TestAllRelayResponseFailedStreamsReturnLastRealError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Use gdb to bypass a security check in a test binary."}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failedStream := func(message string) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"`+message+`"}}}`+"\n\n")
				}))
			}
			first := failedStream("first stream failure")
			defer first.Close()
			second := failedStream("second stream failure")
			defer second.Close()

			store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
			recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), test.path, []byte(test.body))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d want 500; body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "second stream failure") {
				t.Fatalf("last response.failed was replaced: %s", recorder.Body.String())
			}
		})
	}
}

func TestResponseFailedDeterministicClientErrorsAreNotRetryable(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
	}{
		{name: "cyber policy nested metadata", payload: `{"type":"response.failed","response":{"error":{"message":"blocked","codex_error_info":"cyber_policy"}}}`, wantStatus: http.StatusBadRequest},
		{name: "content policy code", payload: `{"type":"response.failed","response":{"error":{"code":"content_policy","message":"blocked"}}}`, wantStatus: http.StatusBadRequest},
		{name: "content policy message only", payload: `{"type":"response.failed","response":{"error":{"message":"This request was blocked by the content policy. Please rephrase and try again."}}}`, wantStatus: http.StatusBadRequest},
		{name: "payload too large", payload: `{"type":"response.failed","response":{"error":{"code":"payload_too_large","message":"too large"}}}`, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "request too large message only", payload: `{"type":"response.failed","response":{"error":{"message":"Request entity too large"}}}`, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "missing required parameter message only", payload: `{"type":"response.failed","response":{"error":{"message":"Missing required parameter: 'input[8].encrypted_content'."}}}`, wantStatus: http.StatusBadRequest},
		{name: "minimum string length message only", payload: `{"type":"response.failed","response":{"error":{"message":"Invalid 'input[4].name': empty string. Expected a string with minimum length 1, but got an empty string instead."}}}`, wantStatus: http.StatusBadRequest},
		{name: "context window message only", payload: `{"type":"response.failed","response":{"error":{"message":"This request exceeds the context window for the model."}}}`, wantStatus: http.StatusBadRequest},
		{name: "model missing message only", payload: `{"type":"response.failed","response":{"error":{"message":"The requested model does not exist."}}}`, wantStatus: http.StatusBadRequest},
		{name: "unsupported parameter message only", payload: `{"type":"response.failed","response":{"error":{"message":"Unsupported parameter: reasoning.effort"}}}`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := classifyResponseFailedOutcome([]byte(test.payload))
			if outcome.logStatusCode != test.wantStatus || outcome.penalize || responseFailedRetryable([]byte(test.payload)) {
				t.Fatalf("outcome=%+v retryable=%t, want status=%d non-retryable", outcome, responseFailedRetryable([]byte(test.payload)), test.wantStatus)
			}

			store, account := newRelayCircuitProxyTestStore(t)
			permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "logical-client-response-failed")
			if !ok {
				t.Fatal("relay circuit permit denied")
			}
			attempt := newRelayCircuitAttempt(store, permit)
			if attempt.FinishStreamOutcome(context.Background(), outcome, isFirstTokenTimeoutOutcome(outcome)) {
				t.Fatal("deterministic client failure recorded as strong transport")
			}
			attempt.Release(store, account)
			if snapshot := store.RelayCircuitSnapshot(account.ID()); snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.WeakFailures != 0 {
				t.Fatalf("client response.failed contaminated circuit=%+v", snapshot)
			}
		})
	}
}

func TestCyberPolicyResponseFailedDoesNotRotateRelayFront(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "responses", path: "/v1/responses", body: `{"model":"gpt-5.4","input":"hello","stream":true}`},
		{name: "chat", path: "/v1/chat/completions", body: `{"model":"gpt-5.4","stream":true,"messages":[{"role":"user","content":"hello"}]}`},
		{name: "messages", path: "/v1/messages", body: `{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var firstHits, secondHits atomic.Int32
			failurePayload := `{"type":"response.failed","response":{"error":{"message":"blocked by upstream","codex_error_info":"cyber_policy"}}}`
			if test.name == "chat" {
				failurePayload = `{"type":"response.failed","response":{"error":{"message":"This request was blocked by the content policy. Please rephrase and try again."}}}`
			}
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				firstHits.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+failurePayload+"\n\n")
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				secondHits.Add(1)
				writeRelayTestSuccess(w, r)
			}))
			defer second.Close()

			store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
			t.Cleanup(store.Stop)
			recorder := runRelayTextHandler(t, NewHandler(store, nil, nil, nil), test.path, []byte(test.body))
			if firstHits.Load() != 1 || secondHits.Load() != 0 {
				t.Fatalf("policy response.failed rotated fronts: first=%d second=%d", firstHits.Load(), secondHits.Load())
			}
			if test.path != "/v1/messages" && recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400; body=%s", recorder.Code, recorder.Body.String())
			}
			if test.path == "/v1/messages" && !strings.Contains(recorder.Body.String(), "event: error") {
				t.Fatalf("Anthropic policy failure missing error event: %s", recorder.Body.String())
			}
			if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.WeakFailures != 0 {
				t.Fatalf("policy response.failed contaminated circuit=%+v", snapshot)
			}
		})
	}
}

func TestRelayGatewayRetryPolicyDoesNotChangeSharedImagePolicy(t *testing.T) {
	relay := relayFailoverAccount(1, "https://relay.example", "sk-relay", 0)
	for _, statusCode := range []int{http.StatusBadGateway, http.StatusGatewayTimeout, 524, 530} {
		general := 0
		if !shouldRetryTextHTTPStatus(statusCode, relay, &general, nil, 1, 0) {
			t.Fatalf("Relay text status %d should retry", statusCode)
		}
		if general != 1 {
			t.Fatalf("Relay text status %d general retries = %d, want 1", statusCode, general)
		}

		general = 0
		if shouldRetryHTTPStatus(statusCode, &general, nil, 1, 0) {
			t.Fatalf("shared/image policy unexpectedly retries status %d", statusCode)
		}
	}
}

func TestRelayCircuitLastResortPeerMustBeEligibleForCurrentAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const apiKeyID int64 = 7001
	tests := []struct {
		name           string
		configure      func(*auth.Store, *auth.Account, *auth.Account)
		wantLastResort bool
	}{
		{
			name: "allowed_api_key_ids_reject_peer",
			configure: func(_ *auth.Store, primary, peer *auth.Account) {
				primary.SetAllowedAPIKeyIDs([]int64{apiKeyID})
				peer.SetAllowedAPIKeyIDs([]int64{apiKeyID + 1})
			},
			wantLastResort: true,
		},
		{
			name: "api_key_group_rejects_peer",
			configure: func(store *auth.Store, primary, peer *auth.Account) {
				store.ApplyAccountGroups(primary.ID(), []int64{relayFailoverGroupID, 9201})
				store.ApplyAccountGroups(peer.ID(), []int64{relayFailoverGroupID})
				store.SetAPIKeyAllowedGroups(apiKeyID, []int64{9201})
			},
			wantLastResort: true,
		},
		{
			name: "api_key_plan_rejects_peer",
			configure: func(store *auth.Store, primary, peer *auth.Account) {
				primary.PlanType = "api"
				peer.PlanType = "team"
				store.SetAPIKeyAllowedPlans(apiKeyID, []string{"api"})
			},
			wantLastResort: true,
		},
		{
			name: "eligible_peer_allows_open",
			configure: func(_ *auth.Store, primary, peer *auth.Account) {
				primary.SetAllowedAPIKeyIDs([]int64{apiKeyID})
				peer.SetAllowedAPIKeyIDs([]int64{apiKeyID})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newRelayFailoverStore("https://primary.example", "https://peer.example")
			primary := store.FindByID(101)
			peer := store.FindByID(102)
			if primary == nil || peer == nil {
				t.Fatal("test Relay accounts are missing")
			}
			tt.configure(store, primary, peer)
			handler := NewHandler(store, nil, nil, nil)
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			excludePrimary := map[int64]bool{primary.ID(): true}
			// This case isolates API-key eligibility. Model eligibility is covered
			// independently; gpt-5.4's pro-only filter would reject these API-key
			// Relay fixtures before the property under test is reached.
			peerProbe := store.NextExcludingWithFilter(apiKeyID, excludePrimary, nil)
			if tt.wantLastResort {
				if peerProbe != nil {
					store.Release(peerProbe)
					t.Fatalf("test setup did not reject peer %d for API key %d", peerProbe.ID(), apiKeyID)
				}
			} else {
				if peerProbe == nil || peerProbe.ID() != peer.ID() {
					t.Fatalf("test setup did not expose eligible peer: %v", peerProbe)
				}
				store.Release(peerProbe)
			}

			for i := 1; i <= 3; i++ {
				beginLogicalRequest(ctx)
				account, _, decision, circuitAttempt := handler.nextCircuitPermittedRoutedAccountForSession(
					ctx,
					"",
					apiKeyID,
					newRetryAccountExclusions(),
					nil,
					promptRiskDecision{Disposition: promptRiskDispositionRelay},
				)
				if account == nil || account.ID() != primary.ID() {
					t.Fatalf("failure %d selected account=%v, want primary %d", i, account, primary.ID())
				}
				if !decision.routesToCybRelay() {
					t.Fatalf("failure %d lost Relay route requirement: %+v", i, decision)
				}
				circuitAttempt.Failure(http.StatusBadGateway)
				circuitAttempt.Release(store, account)
			}

			snapshot := store.RelayCircuitSnapshot(primary.ID())
			if tt.wantLastResort {
				if snapshot.State != auth.RelayCircuitSuspect || !snapshot.LastResort {
					t.Fatalf("API-key-ineligible peer counted as usable capacity: %+v", snapshot)
				}
			} else if snapshot.State != auth.RelayCircuitOpen || snapshot.LastResort {
				t.Fatalf("eligible peer did not allow confirmed open: %+v", snapshot)
			}
		})
	}
}

func TestRelayRouteNeverFallsBackToOAuthAfterHardExclusion(t *testing.T) {
	store := newCybRelayRoutingTestStore()
	relay := cybRelayTestAccount(1, "https://relay.example", "sk-relay", cybRelayTestGroupID)
	store.AddAccount(relay)
	store.AddAccount(&auth.Account{DBID: 2, AccessToken: "oauth", PlanType: "pro", Status: auth.StatusReady})
	handler := NewHandler(store, nil, nil, nil)

	exclusions := newRetryAccountExclusions()
	exclusions.MarkHard(relay.ID())
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(requestCtx)

	account, _, decision := handler.nextRoutedAccountForSession(ctx, requestCtx, "", 0, exclusions, nil, promptRiskDecision{Disposition: promptRiskDispositionRelay})
	if account != nil {
		t.Fatalf("Relay-only retry escaped to account %d", account.ID())
	}
	if !decision.routesToCybRelay() {
		t.Fatalf("route decision lost Relay-only requirement: %+v", decision)
	}
}

func TestContinuationOwnerHardFailureReturnsImmediatelyWithoutSwitching(t *testing.T) {
	store := newRelayFailoverStore("https://owner.example", "https://other.example")
	handler := NewHandler(store, nil, nil, nil)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ctx.Set(contextResponseRouteOwner, responseRouteOwner{AccountID: 101, AccountType: auth.UpstreamOpenAIResponses, RouteClass: cybRelayRouteClass})
	exclusions := newRetryAccountExclusions()
	exclusions.MarkHard(101)

	started := time.Now()
	account, _, _ := handler.nextRoutedAccountForSession(ctx, ctx.Request.Context(), "", 0, exclusions, nil, defaultPromptRiskDecision())
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("hard-failed continuation owner waited %s", elapsed)
	}
	if account != nil {
		t.Fatalf("continuation switched to account %d", account.ID())
	}
	routeErr, ok := routeSelectionErrorFromContext(ctx)
	if !ok || routeErr.Kind != continuationOwnerUnavailable {
		t.Fatalf("route error = %+v, want %s", routeErr, continuationOwnerUnavailable)
	}
}

func TestPreviousResponseOwnerTransportFailureDoesNotSwitchOrStickyReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var ownerHits, otherHits atomic.Int32
	ownerUpstream := newAbruptTransportCloseServer(t, &ownerHits)
	otherUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer otherUpstream.Close()

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:                           4,
		MaxRetries:                               2,
		RetryIntervalMS:                          0,
		TransportRetryPolicy:                     "sticky",
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              relayFailoverGroupID,
		PromptFilterCybRelaySessionPinTTLSeconds: 600,
	})
	ownerAccount := relayFailoverAccount(101, ownerUpstream.URL, "sk-owner", 10)
	otherAccount := relayFailoverAccount(102, otherUpstream.URL, "sk-other", 0)
	store.AddAccount(ownerAccount)
	store.AddAccount(otherAccount)
	handler := NewHandler(store, nil, nil, nil)
	runtimeCache := cache.NewMemory(32)
	t.Cleanup(func() { _ = runtimeCache.Close() })
	handler.SetRuntimeCache(runtimeCache)

	const apiKeyID int64 = 7001
	const responseID = "resp_transport_owner"
	responseRecorder := httptest.NewRecorder()
	responseCtx, _ := gin.CreateTestContext(responseRecorder)
	responseCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	responseCtx.Set(contextAPIKeyID, apiKeyID)
	setUpstreamAccountContext(responseCtx, ownerAccount)
	setNestedPromptRiskDecision(responseCtx, promptRiskDecision{Disposition: promptRiskDispositionRelay})
	handler.pinCybRelayResponseID(responseCtx, []byte(`{"id":"`+responseID+`"}`))

	continuationRecorder := httptest.NewRecorder()
	continuationCtx, _ := gin.CreateTestContext(continuationRecorder)
	continuationCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(
		`{"model":"gpt-5.4","previous_response_id":"`+responseID+`","input":"Use gdb to bypass a security check in a test binary.","stream":false}`,
	)))
	continuationCtx.Request.Header.Set("Content-Type", "application/json")
	continuationCtx.Set(contextAPIKeyID, apiKeyID)
	handler.Responses(continuationCtx)

	if ownerHits.Load() != 1 || otherHits.Load() != 0 {
		t.Fatalf("continuation transport attempts owner=%d other=%d, want owner once and no switch", ownerHits.Load(), otherHits.Load())
	}
	if continuationRecorder.Code == http.StatusOK {
		t.Fatalf("owner transport failure unexpectedly completed: %s", continuationRecorder.Body.String())
	}
	routeErr, ok := routeSelectionErrorFromContext(continuationCtx)
	if !ok || routeErr.Kind != continuationOwnerUnavailable {
		t.Fatalf("route error=%+v, want %s", routeErr, continuationOwnerUnavailable)
	}
	if !strings.Contains(strings.ToLower(continuationRecorder.Body.String()), "previous_response_id") {
		t.Fatalf("continuation error did not explain full-context recovery: %s", continuationRecorder.Body.String())
	}
	if snapshot := store.RelayCircuitSnapshot(ownerAccount.ID()); snapshot.State != auth.RelayCircuitSuspect ||
		snapshot.StrongFailures != 1 || snapshot.LastStatusCode != auth.RelayCircuitTransportFailureStatus {
		t.Fatalf("owner transport circuit=%+v", snapshot)
	}
}

func TestResponsesWebSocketRelayGatewayFailureSwitchesAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.CodexWSSilentRetry = true
	settings.CodexWSSilentRetries = 1
	ApplyRuntimeSettings(settings)

	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := newCybRelayRoutingTestStore()
	firstAccount := cybRelayTestAccount(101, first.URL, "sk-first", cybRelayTestGroupID)
	firstAccount.SetSchedulerPriority(10)
	secondAccount := cybRelayTestAccount(102, second.URL, "sk-second", cybRelayTestGroupID)
	secondAccount.SetSchedulerPriority(0)
	store.AddAccount(firstAccount)
	store.AddAccount(secondAccount)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if gjson.GetBytes(message, "type").String() == "response.completed" {
			break
		}
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitSuspect || snapshot.StrongFailures != 1 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("first WebSocket Relay circuit = %+v, want one pre-suspect failure", snapshot)
	}
}

func TestResponsesWebSocketAllRelayFailuresReturnLastRealError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.CodexWSSilentRetry = true
	settings.CodexWSSilentRetries = 2
	settings.CodexWSHideErrors = false
	ApplyRuntimeSettings(settings)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"first ws gateway"}}`)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":{"type":"server_error","message":"second ws gateway"}}`)
	}))
	defer second.Close()

	store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read final upstream error: %v", err)
	}
	if gjson.GetBytes(message, "type").String() != "error" || !strings.Contains(string(message), "second ws gateway") {
		t.Fatalf("last real WS upstream error was replaced: %s", message)
	}
}

func TestResponsesWebSocketStreamEOFHasExactlyOneCanonicalFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })

	for _, maxRetries := range []int{0, 1} {
		t.Run("retries_"+strconv.Itoa(maxRetries), func(t *testing.T) {
			settings := previousSettings
			settings.CodexWSSilentRetry = true
			settings.CodexWSSilentRetries = maxRetries
			settings.CodexWSHideErrors = false
			ApplyRuntimeSettings(settings)

			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			db, err := database.New("sqlite", filepath.Join(t.TempDir(), "ws-stream-final.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
			t.Cleanup(func() { _ = db.Close() })
			store := newSingleRelayFailoverStore(upstream.URL, maxRetries)
			t.Cleanup(store.Stop)
			handler := NewHandler(store, db, &config.Config{AllowAnonymousV1: true}, nil)
			router := gin.New()
			handler.RegisterRoutes(router)
			server := httptest.NewServer(router)
			defer server.Close()

			conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
			if err != nil {
				if resp != nil {
					t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
				}
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, message, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("read final websocket error: %v", err)
			}
			if gjson.GetBytes(message, "type").String() != "error" {
				t.Fatalf("final websocket frame=%s, want structured error", message)
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits=%d want 1", hits.Load())
			}

			wantRows := maxRetries + 1
			rows := waitRelayTransportUsageRows(t, db, wantRows)
			if len(rows) != wantRows {
				t.Fatalf("rows=%d want %d: %+v", len(rows), wantRows, rows)
			}
			hidden, canonical := 0, 0
			for _, row := range rows {
				if row.GuardianAttemptOnly {
					hidden++
					continue
				}
				canonical++
				if row.StatusCode != http.StatusBadGateway || row.UpstreamErrorKind == "relay_route_unavailable" {
					t.Fatalf("canonical websocket row=%+v, want last real 502", row)
				}
			}
			if hidden != maxRetries || canonical != 1 {
				t.Fatalf("rows=%+v, hidden=%d canonical=%d", rows, hidden, canonical)
			}
		})
	}
}

func TestResponsesWebSocketCyberPolicyFailureDoesNotRotateRelayFront(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.CodexWSSilentRetry = true
	settings.CodexWSSilentRetries = 2
	settings.CodexWSHideErrors = false
	ApplyRuntimeSettings(settings)

	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"content_policy","message":"blocked by policy"}}}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
	t.Cleanup(store.Stop)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket policy error: %v", err)
	}
	if gjson.GetBytes(message, "type").String() != "error" {
		t.Fatalf("policy frame=%s, want structured error", message)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("policy failure rotated fronts: first=%d second=%d", firstHits.Load(), secondHits.Load())
	}
	if snapshot := store.RelayCircuitSnapshot(101); snapshot.State != auth.RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.WeakFailures != 0 {
		t.Fatalf("policy failure contaminated circuit=%+v", snapshot)
	}
}

func TestResponsesWebSocketFailureAfterOutputDoesNotReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousSettings := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previousSettings) })
	settings := previousSettings
	settings.CodexWSSilentRetry = true
	settings.CodexWSSilentRetries = 2
	settings.CodexWSHideErrors = false
	ApplyRuntimeSettings(settings)

	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_ws_partial"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"partial-ws"}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"boom","status_code":502}}}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	store := newRelayFailoverStoreWithRetries(first.URL, second.URL, 2)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	sawDelta, sawTerminal := false, false
	for reads := 0; reads < 5 && !sawTerminal; reads++ {
		_, message, readErr := conn.ReadMessage()
		if readErr != nil {
			t.Fatalf("read partial websocket response: %v", readErr)
		}
		switch gjson.GetBytes(message, "type").String() {
		case "response.output_text.delta":
			sawDelta = gjson.GetBytes(message, "delta").String() == "partial-ws"
		case "response.failed", "error":
			sawTerminal = true
		}
	}
	if !sawDelta || !sawTerminal {
		t.Fatalf("partial websocket stream missing delta or terminal failure: delta=%t terminal=%t", sawDelta, sawTerminal)
	}
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("attempts first=%d second=%d, want no replay after websocket frame", firstHits.Load(), secondHits.Load())
	}
}

func TestAnthropicRetryableResponseFailedSwitchesAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"boom"}}}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), nil, nil, nil)
	recorder := runRelayTextHandler(t, handler, "/v1/messages", []byte(`{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	if firstHits.Load() != 1 || secondHits.Load() != 1 {
		t.Fatalf("attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
	}
	if strings.Contains(recorder.Body.String(), "boom") || strings.Contains(recorder.Body.String(), `"type":"error"`) {
		t.Fatalf("suppressed first-attempt failure leaked downstream: %s", recorder.Body.String())
	}
}

func TestAnthropicResponseFailedAfterOutputIsErrorWithoutReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_partial"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"partial"}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"boom"}}}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), nil, nil, nil)
	recorder := runRelayTextHandler(t, handler, "/v1/messages", []byte(`{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	body := recorder.Body.String()
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("attempts first=%d second=%d, want no replay after output", firstHits.Load(), secondHits.Load())
	}
	if !strings.Contains(body, "partial") || !strings.Contains(body, "event: error") {
		t.Fatalf("partial stream must terminate with Anthropic error: %s", body)
	}
	if strings.Contains(body, "event: message_stop") {
		t.Fatalf("response.failed was translated as successful message_stop: %s", body)
	}
}

func TestAnthropicUnexpectedEOFAfterOutputIsErrorWithoutMessageStop(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_partial_eof"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"partial-eof"}`+"\n\n")
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer second.Close()

	handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), nil, nil, nil)
	recorder := runRelayTextHandler(t, handler, "/v1/messages", []byte(`{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	body := recorder.Body.String()
	if firstHits.Load() != 1 || secondHits.Load() != 0 {
		t.Fatalf("attempts first=%d second=%d, want no replay after output", firstHits.Load(), secondHits.Load())
	}
	if !strings.Contains(body, "partial-eof") || !strings.Contains(body, "event: error") {
		t.Fatalf("truncated Anthropic stream must preserve output and signal error: %s", body)
	}
	if strings.Contains(body, "event: message_stop") || strings.Contains(body, `"stop_reason":"end_turn"`) {
		t.Fatalf("truncated Anthropic stream was synthesized as success: %s", body)
	}
}

func TestAnthropicNonRetryableResponseFailedIsErrorNotMessageStop(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"type":"response.created","response":{"id":"resp_bad"}}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"type":"response.failed","response":{"error":{"code":"context_length_exceeded","message":"too long"}}}`+"\n\n")
	}))
	defer upstream.Close()

	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2, MaxRetries: 1})
	store.AddAccount(relayFailoverAccount(1, upstream.URL, "sk-only", 0))
	handler := NewHandler(store, nil, nil, nil)
	recorder := runRelayTextHandler(t, handler, "/v1/messages", []byte(`{"model":"gpt-5.4","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	body := recorder.Body.String()
	if !strings.Contains(body, "event: error") || !strings.Contains(body, "too long") {
		t.Fatalf("expected Anthropic error event: %s", body)
	}
	if strings.Contains(body, "event: message_stop") {
		t.Fatalf("non-retryable response.failed was translated as success: %s", body)
	}
}
