package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const encryptedOwnerSoftTimeoutAPIKeyID int64 = 8101

func seedEncryptedOwnerForSoftTimeoutTest(t *testing.T, handler *Handler, owner *auth.Account) {
	t.Helper()
	capture := newEncryptedContextCapture(encryptedOwnerSoftTimeoutAPIKeyID)
	capture.Observe([]byte(`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"owner-soft-timeout-cipher"}}`))
	if capture == nil || len(capture.keys) != 1 {
		t.Fatalf("encrypted capture=%+v, want one owner key", capture)
	}
	handler.commitEncryptedContextCapture(owner, capture)
}

func encryptedOwnerSoftTimeoutRequestBody() []byte {
	return []byte(`{
		"model":"gpt-5.4",
		"stream":true,
		"input":[
			{"type":"reasoning","encrypted_content":"owner-soft-timeout-cipher"},
			{"role":"user","content":"continue without replay"}
		]
	}`)
}

func newAcceptedButSilentUpstream(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
}

func newEncryptedOwnerSoftTimeoutHandler(t *testing.T, ownerURL, peerURL string, db *database.DB) (*Handler, *auth.Store, *auth.Account) {
	t.Helper()
	store := newRelayFailoverStoreWithRetries(ownerURL, peerURL, 1)
	t.Cleanup(store.Stop)
	owner := store.FindByID(101)
	if owner == nil {
		t.Fatal("missing encrypted owner account")
	}
	handler := NewHandler(store, db, nil, nil)
	runtimeCache := cache.NewMemory(32)
	t.Cleanup(func() { _ = runtimeCache.Close() })
	handler.SetRuntimeCache(runtimeCache)
	seedEncryptedOwnerForSoftTimeoutTest(t, handler, owner)
	return handler, store, owner
}

func setOneSecondFirstTokenTimeout(t *testing.T, websocketRetry bool) {
	t.Helper()
	previous := CurrentRuntimeSettings()
	t.Cleanup(func() { ApplyRuntimeSettings(previous) })
	settings := previous
	settings.FirstTokenTimeoutSec = 1
	if websocketRetry {
		settings.CodexWSSilentRetry = true
		settings.CodexWSSilentRetries = 1
		settings.CodexWSHideErrors = false
	}
	ApplyRuntimeSettings(settings)
}

func assertEncryptedOwnerSoftTimeoutUsage(t *testing.T, db *database.DB, ownerID int64, viaWebsocket bool) {
	t.Helper()
	rows := waitForRetryUsageLogs(t, db, 2)
	if len(rows) != 2 {
		t.Fatalf("usage rows=%d want exactly two (one hidden attempt and one canonical result): %+v", len(rows), rows)
	}
	var hidden, canonical *database.UsageLog
	for _, row := range rows {
		if row.AccountID == ownerID {
			hidden = row
		} else if row.AccountID == 0 {
			canonical = row
		}
	}
	if hidden == nil || hidden.AccountID != ownerID || hidden.StatusCode != auth.RelayCircuitTransportFailureStatus {
		t.Fatalf("hidden owner attempt=%+v, want account %d internal transport %d", hidden, ownerID, auth.RelayCircuitTransportFailureStatus)
	}
	if canonical == nil || canonical.AccountID != 0 || canonical.StatusCode != http.StatusGatewayTimeout ||
		canonical.UpstreamErrorKind != encryptedOwnerAttemptUncertain || canonical.ViaWebsocket != viaWebsocket ||
		canonical.UpstreamAccountType != auth.UpstreamOpenAIResponses {
		t.Fatalf("canonical result=%+v, want account-neutral encrypted-owner 504", canonical)
	}
	if canonical.PinKind != encryptedContextPinKind || !canonical.RoutePinned ||
		canonical.RouteSource != cybRelayRouteSourcePin ||
		!strings.Contains(canonical.RouteSignals, encryptedOwnerHitSignal) ||
		strings.Contains(canonical.RouteSignals, encryptedOwnerUnavailableSignal) ||
		strings.Contains(canonical.RouteSignals, encryptedContextDowngradeSignal) {
		t.Fatalf("canonical owner pin was lost or downgraded: %+v", canonical)
	}
	if hidden.LogicalRequestID == "" || hidden.LogicalRequestID != canonical.LogicalRequestID {
		t.Fatalf("logical request mismatch hidden=%q canonical=%q", hidden.LogicalRequestID, canonical.LogicalRequestID)
	}
	report, err := db.BuildCodexAuditReport(context.Background(), database.CodexAuditQuery{
		Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Minute), BucketMinutes: 5, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.EncryptedOwnerViolations != 0 || report.Summary.RouteInvariantViolations != 0 || report.Summary.RouteMetadataConflicts != 0 {
		t.Fatalf("soft timeout canonical result triggered an audit violation: %+v", report.Summary)
	}
}

func TestEncryptedOwnerSoftExclusionFailsWithoutDowngradeOrAccountSwitch(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:     []string{"opaque-owner-key"},
		Owner:    encryptedContextOwnerForAccount(relay),
		HasOwner: true,
		Signals:  []string{encryptedOwnerHitSignal},
	})
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(relay.ID())

	started := time.Now()
	account, _, decision := handler.nextRoutedAccountForSession(
		ctx, ctx.Request.Context(), "", 101, exclusions, nil, defaultPromptRiskDecision(),
	)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("soft-timed-out encrypted owner waited %s", elapsed)
	}
	if account != nil {
		handler.store.Release(account)
		t.Fatalf("encrypted owner request switched to account %d", account.ID())
	}
	if encryptedContextNeedsDowngrade(ctx) {
		t.Fatal("soft timeout marked encrypted context for downgrade")
	}
	state, ok := encryptedContextStateFromContext(ctx)
	if !ok || !state.HasOwner || state.Owner.AccountID != relay.ID() {
		t.Fatalf("encrypted owner state changed: %+v present=%v", state, ok)
	}
	if decision.PinKind != encryptedContextPinKind || !decision.RoutePinned || decision.RouteSource != cybRelayRouteSourcePin {
		t.Fatalf("owner route decision lost pin: %+v", decision)
	}
	routeErr, ok := routeSelectionErrorFromContext(ctx)
	if !ok || routeErr.Kind != encryptedOwnerAttemptUncertain {
		t.Fatalf("route error=%+v present=%v, want %s", routeErr, ok, encryptedOwnerAttemptUncertain)
	}
	if got := atomic.LoadInt64(&oauth.ActiveRequests) + atomic.LoadInt64(&relay.ActiveRequests); got != 0 {
		t.Fatalf("selection leaked active requests=%d", got)
	}
}

func TestOrdinarySoftExclusionStillRotatesToAnotherAccount(t *testing.T) {
	handler, oauth, relay := newRelayOverflowTestHandler()
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(oauth.ID())
	ctx := newRouteTestContext()
	account, _, decision := handler.nextRoutedAccountForSession(
		ctx, ctx.Request.Context(), "", 0, exclusions, nil, defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		if account != nil {
			handler.store.Release(account)
		}
		t.Fatalf("ordinary soft exclusion selected account=%v, want peer Relay %d", account, relay.ID())
	}
	if !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceOverflow {
		handler.store.Release(account)
		t.Fatalf("ordinary retry decision=%+v, want normal overflow rotation", decision)
	}
	handler.store.Release(account)
}

func TestPreviousResponseOwnerSoftExclusionKeepsExistingExactOwnerSemantics(t *testing.T) {
	handler, _, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	ctx.Set(contextResponseRouteOwner, encryptedContextOwnerForAccount(relay))
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(relay.ID())
	requestContext, cancel := context.WithCancel(context.Background())
	cancel()

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx, requestContext, "", 101, exclusions, nil, defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		if account != nil {
			handler.store.Release(account)
		}
		t.Fatalf("previous_response_id owner=%v, want exact owner %d", account, relay.ID())
	}
	if decision.RouteSource != cybRelayRouteSourceContinuation {
		handler.store.Release(account)
		t.Fatalf("previous_response_id decision changed: %+v", decision)
	}
	handler.store.Release(account)
}

func TestCombinedPreviousResponseAndEncryptedOwnerSoftTimeoutIsNotReplayed(t *testing.T) {
	enableEncryptedContextAffinity(t)
	handler, oauth, relay := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	owner := encryptedContextOwnerForAccount(relay)
	ctx.Set(contextResponseRouteOwner, owner)
	setEncryptedContextState(ctx, encryptedContextAffinityState{
		Keys:     []string{"combined-owner-key"},
		Owner:    owner,
		HasOwner: true,
		Signals:  []string{encryptedOwnerHitSignal},
	})
	exclusions := newRetryAccountExclusions()
	exclusions.MarkSoftFirstTokenTimeout(owner.AccountID)

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx, ctx.Request.Context(), "", 101, exclusions, nil, defaultPromptRiskDecision(),
	)
	if account != nil {
		handler.store.Release(account)
		t.Fatalf("combined owner request was replayed to account %d", account.ID())
	}
	if encryptedContextNeedsDowngrade(ctx) {
		t.Fatal("combined owner soft timeout marked encrypted context for downgrade")
	}
	if decision.PinKind != encryptedContextPinKind || !decision.RoutePinned ||
		!containsEncryptedContextSignal(decision.Signals, encryptedOwnerHitSignal) ||
		!containsEncryptedContextSignal(decision.Signals, responseOwnerRouteSignal) {
		t.Fatalf("combined owner decision lost authority signals: %+v", decision)
	}
	routeErr, ok := routeSelectionErrorFromContext(ctx)
	if !ok || routeErr.Kind != encryptedOwnerAttemptUncertain {
		t.Fatalf("combined owner route error=%+v present=%v", routeErr, ok)
	}
	if got := atomic.LoadInt64(&oauth.ActiveRequests) + atomic.LoadInt64(&relay.ActiveRequests); got != 0 {
		t.Fatalf("combined owner selection leaked active requests=%d", got)
	}
}

func TestEncryptedOwnerAttemptUncertainFailureSpec(t *testing.T) {
	spec := routeSelectionFailureSpecFor(routeSelectionError{Kind: encryptedOwnerAttemptUncertain})
	if spec.HTTPStatusCode != http.StatusGatewayTimeout || spec.OpenAIErrorType != api.ErrorTypeUpstream ||
		spec.AnthropicErrorType != "overloaded_error" || spec.WebSocketCloseCode != websocket.CloseTryAgainLater {
		t.Fatalf("failure spec=%+v", spec)
	}
}

func TestResponsesSSEEncryptedOwnerFirstTokenTimeoutDoesNotReplayOrSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	enableEncryptedContextAffinity(t)
	setOneSecondFirstTokenTimeout(t, false)

	var ownerHits, peerHits atomic.Int32
	ownerUpstream := newAcceptedButSilentUpstream(t, &ownerHits)
	defer ownerUpstream.Close()
	peerUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer peerUpstream.Close()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "encrypted-owner-soft-http.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	handler, _, owner := newEncryptedOwnerSoftTimeoutHandler(t, ownerUpstream.URL, peerUpstream.URL, db)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set(contextAPIKeyID, encryptedOwnerSoftTimeoutAPIKeyID)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(encryptedOwnerSoftTimeoutRequestBody()))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.Responses(ctx)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status=%d want 504; body=%s", recorder.Code, recorder.Body.String())
	}
	if code := gjson.GetBytes(recorder.Body.Bytes(), "error.code").String(); code != encryptedOwnerAttemptUncertain {
		t.Fatalf("error code=%q want %q; body=%s", code, encryptedOwnerAttemptUncertain, recorder.Body.String())
	}
	if ownerHits.Load() != 1 || peerHits.Load() != 0 {
		t.Fatalf("upstream executions owner=%d peer=%d, want exactly one owner attempt and no switch", ownerHits.Load(), peerHits.Load())
	}
	if encryptedContextNeedsDowngrade(ctx) {
		t.Fatal("HTTP/SSE timeout downgraded encrypted context")
	}
	assertEncryptedOwnerSoftTimeoutUsage(t, db, owner.ID(), false)
}

func TestResponsesWebSocketEncryptedOwnerFirstTokenTimeoutDoesNotReplayOrSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	enableEncryptedContextAffinity(t)
	setOneSecondFirstTokenTimeout(t, true)

	var ownerHits, peerHits atomic.Int32
	ownerUpstream := newAcceptedButSilentUpstream(t, &ownerHits)
	defer ownerUpstream.Close()
	peerUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHits.Add(1)
		writeRelayTestSuccess(w, r)
	}))
	defer peerUpstream.Close()

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "encrypted-owner-soft-ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetUsageLogConfig(database.UsageLogModeFull, 1, 1)
	t.Cleanup(func() { _ = db.Close() })
	handler, _, owner := newEncryptedOwnerSoftTimeoutHandler(t, ownerUpstream.URL, peerUpstream.URL, db)

	router := gin.New()
	router.GET("/v1/responses", func(c *gin.Context) {
		c.Set(contextAPIKeyID, encryptedOwnerSoftTimeoutAPIKeyID)
		handler.ResponsesWebSocket(c)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
	if err != nil {
		if response != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, response.StatusCode)
		}
		t.Fatal(err)
	}
	defer conn.Close()
	request := encryptedOwnerSoftTimeoutRequestBody()
	request = bytes.Replace(request, []byte(`"stream":true`), []byte(`"type":"response.create","stream":true`), 1)
	if err := conn.WriteMessage(websocket.TextMessage, request); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read structured timeout error: %v", err)
	}
	if gjson.GetBytes(message, "type").String() != "error" ||
		gjson.GetBytes(message, "error.code").String() != encryptedOwnerAttemptUncertain {
		t.Fatalf("websocket error frame=%s", message)
	}
	_, _, closeErr := conn.ReadMessage()
	if !websocket.IsCloseError(closeErr, websocket.CloseTryAgainLater) {
		t.Fatalf("websocket close=%v, want %d", closeErr, websocket.CloseTryAgainLater)
	}
	if ownerHits.Load() != 1 || peerHits.Load() != 0 {
		t.Fatalf("websocket upstream executions owner=%d peer=%d, want exactly one owner attempt and no switch", ownerHits.Load(), peerHits.Load())
	}
	assertEncryptedOwnerSoftTimeoutUsage(t, db, owner.ID(), true)
}
