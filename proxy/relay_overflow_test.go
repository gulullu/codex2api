package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func int64Pointer(value int64) *int64 {
	return &value
}

func newRelayOverflowTestHandler() (*Handler, *auth.Account, *auth.Account) {
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1})
	store.SetCybRelayConfig(auth.CybRelayConfig{Enabled: true, GroupID: 7})
	oauth := &auth.Account{
		DBID:                    1,
		AccessToken:             "oauth",
		PlanType:                "pro",
		Status:                  auth.StatusReady,
		BaseConcurrencyOverride: int64Pointer(1),
	}
	relay := &auth.Account{
		DBID:                    2,
		UpstreamType:            auth.UpstreamOpenAIResponses,
		BaseURL:                 "https://relay.example/v1",
		APIKey:                  "relay-key",
		Status:                  auth.StatusReady,
		GroupIDs:                []int64{7},
		BaseConcurrencyOverride: int64Pointer(1),
	}
	store.AddAccount(oauth)
	store.AddAccount(relay)
	return NewHandler(store, nil, nil, nil), oauth, relay
}

func newRouteTestContext() *gin.Context {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	return ctx
}

func TestNextRoutedAccountPrefersOAuthWhenCapacityExists(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, oauth, _ := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		0,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != oauth.ID() {
		t.Fatalf("account = %#v, want OAuth %d", account, oauth.ID())
	}
	if decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceDefault {
		t.Fatalf("decision = %+v, want default OAuth route", decision)
	}
	handler.store.Release(account)
}

func TestNextRoutedAccountOverflowsToRelayWhenOAuthIsFull(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, oauth, relay := newRelayOverflowTestHandler()
	atomic.StoreInt64(&oauth.ActiveRequests, 1)
	ctx := newRouteTestContext()

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		0,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		t.Fatalf("account = %#v, want Relay %d", account, relay.ID())
	}
	if !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceOverflow {
		t.Fatalf("decision = %+v, want overflow Relay route", decision)
	}
	if len(decision.Signals) != 1 || decision.Signals[0] != relayOverflowSignal {
		t.Fatalf("signals = %#v, want %q", decision.Signals, relayOverflowSignal)
	}
	handler.store.Release(account)
	atomic.StoreInt64(&oauth.ActiveRequests, 0)
}

func TestDirectRelayRouteNeverFallsBackToOAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, oauth, relay := newRelayOverflowTestHandler()
	atomic.StoreInt32(&relay.Disabled, 1)
	ctx := newRouteTestContext()
	required := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		RouteSource: cybRelayRouteSourceProbe,
		Signals:     []string{probeRouteSignal},
	}

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		0,
		newRetryAccountExclusions(),
		nil,
		required,
	)
	if account != nil {
		handler.store.Release(account)
		t.Fatalf("account = %#v, want nil when dedicated Relay is unavailable", account)
	}
	if !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceProbe {
		t.Fatalf("decision = %+v, want original Relay-only decision", decision)
	}
	if got := atomic.LoadInt64(&oauth.ActiveRequests); got != 0 {
		t.Fatalf("OAuth active requests = %d, direct Relay route must not touch OAuth", got)
	}
}

func TestRelayCircuitHeldNeverEscapesToOAuthAcrossProtocols(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name         string
		path         string
		websocket    bool
		continuation bool
	}{
		{name: "responses_http", path: "/v1/responses"},
		{name: "chat_completions", path: "/v1/chat/completions"},
		{name: "anthropic_messages", path: "/v1/messages"},
		{name: "responses_inbound_ws", path: "/v1/responses", websocket: true},
		{name: "responses_continuation", path: "/v1/responses", continuation: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, oauth, relay := newRelayOverflowTestHandler()
			permit, ok := handler.store.BeginRelayCircuitRequest(relay)
			if !ok || !permit.Active {
				t.Fatalf("Relay circuit permit=%+v ok=%v", permit, ok)
			}
			if !handler.store.ReportRelayCircuitFailure(permit, http.StatusBadGateway) {
				t.Fatal("failed to open Relay circuit")
			}
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, test.path, nil)
			if test.websocket {
				ctx.Request.Header.Set("Connection", "Upgrade")
				ctx.Request.Header.Set("Upgrade", "websocket")
			}
			if test.continuation {
				ctx.Set(contextResponseRouteOwner, responseRouteOwner{AccountID: relay.ID(), AccountType: auth.UpstreamOpenAIResponses, RouteClass: cybRelayRouteClass})
			}
			required := promptRiskDecision{Disposition: promptRiskDispositionRelay, RouteSource: cybRelayRouteSourceProbe, Signals: []string{probeRouteSignal}}
			account, _, decision := handler.nextRoutedAccountForSession(ctx, ctx.Request.Context(), "", 0, newRetryAccountExclusions(), nil, required)
			if account != nil {
				handler.store.Release(account)
				t.Fatalf("held Relay escaped to account=%d", account.ID())
			}
			if !decision.routesToCybRelay() {
				t.Fatalf("Relay-only decision lost: %+v", decision)
			}
			if got := atomic.LoadInt64(&oauth.ActiveRequests); got != 0 {
				t.Fatalf("OAuth touched under Relay-only %s: active=%d", test.name, got)
			}
		})
	}
}

func TestProbeRequestRoutesDirectlyToRelayEvenWithLegacyShortCircuitDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_PROBE_SHORT_CIRCUIT_ENABLED", "false")
	handler, _, _ := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	body := []byte(`{"model":"gpt-5.4","input":"hello"}`)

	if blocked := handler.inspectPromptFilterOpenAI(ctx, body, "/v1/responses", "gpt-5.4"); blocked {
		t.Fatal("probe must route, not block")
	}
	decision, ok := promptRiskDecisionFromContext(ctx)
	if !ok || !decision.routesToCybRelay() {
		t.Fatalf("decision = %+v, present=%v; want Relay route", decision, ok)
	}
	if decision.RouteSource != cybRelayRouteSourceProbe {
		t.Fatalf("route source = %q, want %q", decision.RouteSource, cybRelayRouteSourceProbe)
	}
	if len(decision.Signals) != 1 || decision.Signals[0] != probeRouteSignal {
		t.Fatalf("signals = %#v, want probe signal", decision.Signals)
	}
}

func TestPreviousResponseOwnerKeepsOverflowContinuationOnExactRelayAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, relay := newRelayOverflowTestHandler()
	handler.SetRuntimeCache(cache.NewMemory(32))

	responseCtx := newRouteTestContext()
	responseCtx.Set(contextAPIKeyID, int64(101))
	setUpstreamAccountContext(responseCtx, relay)
	handler.setSelectedRouteDecision(responseCtx, overflowPromptRiskDecision())
	handler.pinCybRelayResponseID(responseCtx, []byte(`{"id":"resp_overflow_1"}`))

	continueCtx := newRouteTestContext()
	continueCtx.Set(contextAPIKeyID, int64(101))
	continueBody := []byte(`{"model":"gpt-5.4","previous_response_id":"resp_overflow_1","input":"continue"}`)
	handler.loadResponseRouteOwner(continueCtx, continueBody)

	owner, ok := responseRouteOwnerFromContext(continueCtx)
	if !ok || owner.AccountID != relay.ID() {
		t.Fatalf("owner = %+v, present=%v; want Relay %d", owner, ok, relay.ID())
	}
	account, _, decision := handler.nextRoutedAccountForSession(
		continueCtx,
		context.Background(),
		"",
		101,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account == nil || account.ID() != relay.ID() {
		t.Fatalf("account = %#v, want exact Relay owner %d", account, relay.ID())
	}
	if decision.RouteSource != cybRelayRouteSourceContinuation || !decision.routesToCybRelay() {
		t.Fatalf("decision = %+v, want Relay continuation", decision)
	}
	handler.store.Release(account)

	otherKeyCtx := newRouteTestContext()
	otherKeyCtx.Set(contextAPIKeyID, int64(202))
	handler.loadResponseRouteOwner(otherKeyCtx, continueBody)
	if owner, ok := responseRouteOwnerFromContext(otherKeyCtx); ok {
		t.Fatalf("cross-key owner leaked: %+v", owner)
	}
}

func TestLoadResponseRouteOwnerClearsPriorWebSocketTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _, relay := newRelayOverflowTestHandler()
	handler.SetRuntimeCache(cache.NewMemory(32))

	ctx := newRouteTestContext()
	ctx.Set(contextAPIKeyID, int64(101))
	setUpstreamAccountContext(ctx, relay)
	handler.setSelectedRouteDecision(ctx, overflowPromptRiskDecision())
	handler.pinCybRelayResponseID(ctx, []byte(`{"id":"resp_ws_turn_1"}`))

	handler.loadResponseRouteOwner(ctx, []byte(`{"previous_response_id":"resp_ws_turn_1"}`))
	if owner, ok := responseRouteOwnerFromContext(ctx); !ok || owner.AccountID != relay.ID() {
		t.Fatalf("owner = %+v, present=%v; want Relay %d", owner, ok, relay.ID())
	}

	// A Responses WebSocket reuses the Gin context. A new independent turn must
	// not inherit the previous turn's exact-account owner.
	handler.loadResponseRouteOwner(ctx, []byte(`{"input":"independent turn"}`))
	if owner, ok := responseRouteOwnerFromContext(ctx); ok {
		t.Fatalf("stale WebSocket owner retained: %+v", owner)
	}
}

func TestContinuationRelayOwnerMustRemainInConfiguredRelayGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, oauth, relay := newRelayOverflowTestHandler()
	relay.GroupIDs = []int64{8}
	ctx := newRouteTestContext()
	ctx.Set(contextResponseRouteOwner, responseRouteOwner{
		AccountID:   relay.ID(),
		AccountType: auth.UpstreamOpenAIResponses,
		RouteClass:  cybRelayRouteClass,
	})

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		0,
		newRetryAccountExclusions(),
		nil,
		defaultPromptRiskDecision(),
	)
	if account != nil {
		handler.store.Release(account)
		t.Fatalf("account = %#v, want nil after Relay owner leaves configured group", account)
	}
	if decision.RouteSource != cybRelayRouteSourceContinuation {
		t.Fatalf("decision = %+v, want continuation route", decision)
	}
	routeErr, ok := routeSelectionErrorFromContext(ctx)
	if !ok || routeErr.Kind != continuationOwnerUnavailable {
		t.Fatalf("route error = %+v, present=%v; want %q", routeErr, ok, continuationOwnerUnavailable)
	}
	if got := atomic.LoadInt64(&oauth.ActiveRequests); got != 0 {
		t.Fatalf("OAuth active requests = %d, exact Relay continuation must not fall back", got)
	}
}

func TestRelayRequiredContinuationRejectsOAuthOwnerWithReplayError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, oauth, _ := newRelayOverflowTestHandler()
	ctx := newRouteTestContext()
	ctx.Set(contextResponseRouteOwner, responseRouteOwner{
		AccountID:   oauth.ID(),
		AccountType: "oauth",
		RouteClass:  "",
	})
	required := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		RouteSource: cybRelayRouteSourceProbe,
		Signals:     []string{probeRouteSignal},
	}

	account, _, decision := handler.nextRoutedAccountForSession(
		ctx,
		context.Background(),
		"",
		0,
		newRetryAccountExclusions(),
		nil,
		required,
	)
	if account != nil {
		handler.store.Release(account)
		t.Fatalf("account = %#v, want explicit replay-required failure", account)
	}
	if decision.RouteSource != cybRelayRouteSourceContinuation || !decision.routesToCybRelay() {
		t.Fatalf("decision = %+v, want Relay continuation conflict", decision)
	}
	routeErr, ok := routeSelectionErrorFromContext(ctx)
	if !ok || routeErr.Kind != routeSwitchRequiresReplay {
		t.Fatalf("route error = %+v, present=%v; want %q", routeErr, ok, routeSwitchRequiresReplay)
	}
	if got := atomic.LoadInt64(&oauth.ActiveRequests); got != 0 {
		t.Fatalf("OAuth active requests = %d, conflicting owner must not be acquired", got)
	}
}

func TestRouteSelectionFailureSpec(t *testing.T) {
	tests := []struct {
		name              string
		routeErr          routeSelectionError
		wantStatus        int
		wantOpenAIType    api.ErrorType
		wantAnthropicType string
		wantWSClose       int
	}{
		{
			name:              "replay required",
			routeErr:          routeSelectionError{Kind: routeSwitchRequiresReplay, Message: "resend full context"},
			wantStatus:        http.StatusConflict,
			wantOpenAIType:    api.ErrorTypeInvalidRequest,
			wantAnthropicType: "invalid_request_error",
			wantWSClose:       websocket.ClosePolicyViolation,
		},
		{
			name:              "owner unavailable",
			routeErr:          routeSelectionError{Kind: continuationOwnerUnavailable, Message: "retry later"},
			wantStatus:        http.StatusServiceUnavailable,
			wantOpenAIType:    api.ErrorTypeServer,
			wantAnthropicType: "overloaded_error",
			wantWSClose:       websocket.CloseTryAgainLater,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := routeSelectionFailureSpecFor(tt.routeErr)
			if spec.HTTPStatusCode != tt.wantStatus || spec.OpenAIErrorType != tt.wantOpenAIType || spec.AnthropicErrorType != tt.wantAnthropicType || spec.WebSocketCloseCode != tt.wantWSClose {
				t.Fatalf("spec = %+v, want status=%d openai=%q anthropic=%q ws=%d", spec, tt.wantStatus, tt.wantOpenAIType, tt.wantAnthropicType, tt.wantWSClose)
			}
			apiErr := routeSelectionAPIError(tt.routeErr, spec)
			if apiErr.Code != api.ErrorCode(tt.routeErr.Kind) || apiErr.Message != tt.routeErr.Message || apiErr.Type != tt.wantOpenAIType {
				t.Fatalf("api error = %+v", apiErr)
			}
		})
	}
}

func TestLogRouteSelectionErrorInitializesLogicalRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &Handler{}
	ctx := newRouteTestContext()
	ctx.Set(contextUpstreamAccountID, int64(99))
	ctx.Set(contextUpstreamAccountType, "oauth")
	routeErr := routeSelectionError{Kind: continuationOwnerUnavailable, Message: "retry later"}
	spec := routeSelectionFailureSpecFor(routeErr)

	before := time.Now()
	handler.logRouteSelectionError(ctx, "/v1/responses", "gpt-5.4", "gpt-5.4", false, false, 0, routeErr, spec)
	after := time.Now()

	if requestID := logicalRequestID(ctx); requestID == "" {
		t.Fatal("logical request ID was not initialized")
	}
	startedValue, ok := ctx.Get(contextLogicalRequestStart)
	started, typeOK := startedValue.(time.Time)
	if !ok || !typeOK || started.Before(before) || started.After(after) {
		t.Fatalf("logical request start = %#v, want within [%s, %s]", startedValue, before, after)
	}
	if accountID, _ := ctx.Get(contextUpstreamAccountID); accountID != int64(0) {
		t.Fatalf("upstream account ID = %#v, want cleared", accountID)
	}
	if accountType := ctx.GetString(contextUpstreamAccountType); accountType != "" {
		t.Fatalf("upstream account type = %q, want cleared", accountType)
	}
}
