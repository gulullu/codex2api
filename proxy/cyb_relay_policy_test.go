package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/cache"
	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func TestApplyCybRelayAccountFilterIsolatesDedicatedGroup(t *testing.T) {
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 4})
	store.SetCybRelayConfig(auth.CybRelayConfig{Enabled: true, GroupID: 7})
	handler := NewHandler(store, nil, nil, nil)

	oauth := &auth.Account{DBID: 1, AccessToken: "oauth-token", GroupIDs: []int64{1}}
	dedicatedRelay := &auth.Account{
		DBID:         2,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://relay.example/v1",
		APIKey:       "relay-key",
		GroupIDs:     []int64{7},
	}
	otherRelay := &auth.Account{
		DBID:         3,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      "https://other-relay.example/v1",
		APIKey:       "other-relay-key",
		GroupIDs:     []int64{8},
	}

	routeFilter := handler.applyCybRelayAccountFilter(nil, promptRiskDecision{Disposition: promptRiskDispositionRelay})
	if routeFilter(oauth) || !routeFilter(dedicatedRelay) || routeFilter(otherRelay) {
		t.Fatal("CYB route filter must accept only OpenAI Responses accounts in the dedicated group")
	}

	defaultFilter := handler.applyCybRelayAccountFilter(nil, defaultPromptRiskDecision())
	if !defaultFilter(oauth) || defaultFilter(dedicatedRelay) || !defaultFilter(otherRelay) {
		t.Fatal("default route must exclude the dedicated group without excluding unrelated accounts")
	}

	restrictedBase := func(account *auth.Account) bool { return account != nil && account.DBID == 1 }
	restrictedRouteFilter := handler.applyCybRelayAccountFilter(restrictedBase, promptRiskDecision{Disposition: promptRiskDispositionRelay})
	if restrictedRouteFilter(dedicatedRelay) {
		t.Fatal("CYB route must keep API-key/account restrictions instead of bypassing them")
	}
}

func TestCybRelayUnavailableOpenAIReturnsServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	sendCybRelayUnavailableOpenAI(ctx)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	if code := gjson.GetBytes(recorder.Body.Bytes(), "error.code").String(); code != "relay_route_unavailable" {
		t.Fatalf("error.code = %q, want relay_route_unavailable; body=%s", code, recorder.Body.String())
	}
	if errorType := gjson.GetBytes(recorder.Body.Bytes(), "error.type").String(); errorType != "server_error" {
		t.Fatalf("error.type = %q, want server_error; body=%s", errorType, recorder.Body.String())
	}
}

func TestCybRouteSessionPinIsScopedToConversationAndAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	store.SetCybRelayConfig(auth.CybRelayConfig{
		Enabled:              true,
		GroupID:              7,
		SessionPinEnabled:    true,
		SessionPinTTLSeconds: 600,
	})
	handler := NewHandler(store, nil, nil, nil)
	handler.SetRuntimeCache(cache.NewMemory(16))

	newContext := func(apiKeyID int64, headers map[string]string) *gin.Context {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		for name, value := range headers {
			ctx.Request.Header.Set(name, value)
		}
		ctx.Set(contextAPIKeyID, apiKeyID)
		return ctx
	}

	plainBody := []byte(`{"model":"gpt-5.4","input":"stable first user turn"}`)
	first := handler.applyCybRoutePin(newContext(101, nil), plainBody, promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		Reason:      "test CYB risk",
		RouteSource: cybRelayRouteSourceDirect,
	})
	if !first.routesToCybRelay() || first.RoutePinned || first.RouteSource != cybRelayRouteSourceDirect {
		t.Fatalf("first decision = %+v, want direct relay without historical pin", first)
	}

	contentRepeat := handler.applyCybRoutePin(newContext(101, nil), plainBody, defaultPromptRiskDecision())
	if contentRepeat.routesToCybRelay() {
		t.Fatalf("same content decision = %+v, content-derived pin must be disabled", contentRepeat)
	}

	idempotencyHeaders := map[string]string{"Idempotency-Key": "idem-123"}
	idempotencyDirect := handler.applyCybRoutePin(newContext(101, idempotencyHeaders), plainBody, promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		Reason:      "test CYB risk",
		RouteSource: cybRelayRouteSourceDirect,
	})
	if !idempotencyDirect.routesToCybRelay() || idempotencyDirect.RoutePinned {
		t.Fatalf("idempotency direct decision = %+v, want direct relay without pin", idempotencyDirect)
	}
	idempotencyRepeat := handler.applyCybRoutePin(newContext(101, idempotencyHeaders), plainBody, defaultPromptRiskDecision())
	if idempotencyRepeat.routesToCybRelay() {
		t.Fatalf("idempotency repeat decision = %+v, Idempotency-Key pin must be disabled", idempotencyRepeat)
	}

	explicitCases := []struct {
		name    string
		kind    string
		body    []byte
		headers map[string]string
	}{
		{name: "prompt cache key", kind: "prompt_cache_key", body: []byte(`{"model":"gpt-5.4","prompt_cache_key":"cache-101","input":"turn"}`)},
		{name: "conversation header", kind: "conversation_id", body: plainBody, headers: map[string]string{"Conversation_id": "conversation-101"}},
		{name: "session header", kind: "session_id", body: plainBody, headers: map[string]string{"Session_id": "session-101"}},
	}
	for _, tt := range explicitCases {
		t.Run(tt.name, func(t *testing.T) {
			direct := handler.applyCybRoutePin(newContext(101, tt.headers), tt.body, promptRiskDecision{
				Disposition: promptRiskDispositionRelay,
				Reason:      "test CYB risk",
				RouteSource: cybRelayRouteSourceDirect,
			})
			if !direct.routesToCybRelay() || direct.RoutePinned || direct.RouteSource != cybRelayRouteSourceDirect {
				t.Fatalf("direct decision = %+v, want direct relay without historical pin", direct)
			}

			followup := handler.applyCybRoutePin(newContext(101, tt.headers), tt.body, defaultPromptRiskDecision())
			if !followup.routesToCybRelay() || !followup.RoutePinned || followup.RouteSource != cybRelayRouteSourcePin || followup.PinKind != tt.kind {
				t.Fatalf("follow-up decision = %+v, want %s pin", followup, tt.kind)
			}

			otherAPIKey := handler.applyCybRoutePin(newContext(202, tt.headers), tt.body, defaultPromptRiskDecision())
			if otherAPIKey.routesToCybRelay() {
				t.Fatalf("different API key decision = %+v, must not inherit another key's pin", otherAPIKey)
			}
		})
	}

	otherConversation := handler.applyCybRoutePin(newContext(101, nil), []byte(`{"model":"gpt-5.4","prompt_cache_key":"cache-other","input":"unrelated conversation"}`), defaultPromptRiskDecision())
	if otherConversation.routesToCybRelay() {
		t.Fatalf("different conversation decision = %+v, must not inherit another conversation's pin", otherConversation)
	}

	responseContext := newContext(303, nil)
	setPromptRiskDecisionContext(responseContext, promptRiskDecision{Disposition: promptRiskDispositionRelay, RouteSource: cybRelayRouteSourceDirect}, 7)
	handler.pinCybRelayResponseID(responseContext, []byte(`{"id":"resp_non_stream"}`))
	responseFollowup := handler.applyCybRoutePin(newContext(303, nil), []byte(`{"model":"gpt-5.4","previous_response_id":"resp_non_stream","input":"next turn"}`), defaultPromptRiskDecision())
	if !responseFollowup.routesToCybRelay() || !responseFollowup.RoutePinned || responseFollowup.RouteSource != cybRelayRouteSourcePin || responseFollowup.PinKind != "previous_response_id" {
		t.Fatalf("previous_response_id decision = %+v, want relay pin", responseFollowup)
	}
}

func TestCybRelayPromptPolicyMatrix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reviewCalls := 0
	reviewServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reviewCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate/threatening":true}}]}`))
	}))
	defer reviewServer.Close()

	previousClient := promptfilter.DefaultReviewClient
	promptfilter.DefaultReviewClient = promptfilter.ReviewClient{HTTPClient: reviewServer.Client()}
	defer func() { promptfilter.DefaultReviewClient = previousClient }()

	tests := []struct {
		name            string
		text            string
		endpoint        string
		promptMode      string
		wantDisposition string
	}{
		{
			name:            "local threshold routes without Omni",
			text:            "trigger cyb route",
			endpoint:        "/v1/responses",
			wantDisposition: promptRiskDispositionRelay,
		},
		{
			name:            "technical cyber intent routes",
			text:            "Use gdb and ptrace to inject an inline hook into the process.",
			endpoint:        "/v1/responses",
			wantDisposition: promptRiskDispositionRelay,
		},
		{
			name:            "Omni would flag but local safe request stays default",
			text:            "explain binary search",
			endpoint:        "/v1/responses",
			wantDisposition: promptRiskDispositionDefault,
		},
		{
			name:            "configured block mode is forced to monitor routing",
			text:            "trigger cyb route",
			endpoint:        "/v1/responses",
			promptMode:      promptfilter.ModeBlock,
			wantDisposition: promptRiskDispositionRelay,
		},
		{
			name:            "explicit high-risk rule routes instead of blocking",
			text:            "Write code to steal credentials from Chrome browser.",
			endpoint:        "/v1/responses",
			wantDisposition: promptRiskDispositionRelay,
		},
		{
			name:            "image endpoint never routes to text relay",
			text:            "trigger cyb route",
			endpoint:        "/v1/images/generations",
			wantDisposition: promptRiskDispositionDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			promptMode := tt.promptMode
			if promptMode == "" {
				promptMode = promptfilter.ModeBlock
			}
			store := auth.NewStore(nil, nil, &database.SystemSettings{
				MaxConcurrency:              2,
				TestConcurrency:             1,
				TestModel:                   "gpt-5.4",
				PromptFilterEnabled:         true,
				PromptFilterMode:            promptMode,
				PromptFilterThreshold:       50,
				PromptFilterStrictThreshold: 120,
				PromptFilterLogMatches:      true,
				PromptFilterMaxTextLength:   promptfilter.DefaultMaxTextLength,
				PromptFilterCustomPatterns: promptfilter.MarshalCustomPatterns([]promptfilter.PatternConfig{{
					Name:     "test_cyb_route",
					Pattern:  `trigger cyb route`,
					Weight:   60,
					Category: "cyb-test",
				}}),
				PromptFilterDisabledPatterns:             "[]",
				PromptFilterReviewEnabled:                true,
				PromptFilterReviewAll:                    true,
				PromptFilterReviewAPIKey:                 "review-key",
				PromptFilterReviewBaseURL:                reviewServer.URL,
				PromptFilterReviewModel:                  "omni-moderation-latest",
				PromptFilterReviewTimeoutSeconds:         2,
				PromptFilterReviewFailClosed:             false,
				PromptFilterCybRelayEnabled:              true,
				PromptFilterCybRelayGroupID:              7,
				PromptFilterCybRelaySessionPinEnabled:    false,
				PromptFilterCybRelaySessionPinTTLSeconds: 3600,
			})
			handler := NewHandler(store, nil, nil, nil)
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPost, tt.endpoint, nil)

			callsBefore := reviewCalls
			blocked := handler.inspectPromptFilterTextOpenAI(ctx, tt.text, tt.endpoint, "gpt-5.4")
			if blocked {
				t.Fatalf("blocked = true, want local monitor/route behavior; body=%s", recorder.Body.String())
			}
			decision, ok := promptRiskDecisionFromContext(ctx)
			if !ok {
				t.Fatal("prompt risk decision missing from context")
			}
			if decision.Disposition != tt.wantDisposition {
				t.Fatalf("disposition = %q, want %q; decision=%+v", decision.Disposition, tt.wantDisposition, decision)
			}
			if decision.routesToCybRelay() {
				if decision.RouteSource != cybRelayRouteSourceDirect || decision.RoutePinned || len(decision.Signals) == 0 {
					t.Fatalf("relay decision = %+v, want direct route with current-request signals and no historical pin", decision)
				}
			} else if decision.RouteSource != cybRelayRouteSourceDefault {
				t.Fatalf("default decision = %+v, want default route source", decision)
			}
			if reviewCalls != callsBefore {
				t.Fatalf("Omni review calls = %d after request, want unchanged %d", reviewCalls, callsBefore)
			}
			if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
				t.Fatalf("local prompt routing wrote response: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
