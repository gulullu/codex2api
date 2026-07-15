package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
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

func newTestUpstreamCybFeedbackHandler(t *testing.T, ttl time.Duration, maxEntries int, sessionPin bool) *Handler {
	t.Helper()
	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 4})
	store.SetCybRelayConfig(auth.CybRelayConfig{
		Enabled:              true,
		GroupID:              7,
		SessionPinEnabled:    sessionPin,
		SessionPinTTLSeconds: 600,
	})
	handler := NewHandler(store, nil, nil, nil)
	var key [sha256.Size]byte
	for index := range key {
		key[index] = byte(index + 1)
	}
	handler.upstreamCybFeedback = newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled:    true,
		TTL:        ttl,
		MaxEntries: maxEntries,
	}, key, time.Now)
	return handler
}

func newUpstreamCybFeedbackTestContext(endpoint string) *gin.Context {
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, endpoint, nil)
	return ctx
}

func TestUpstreamCybFeedbackDigestIsExactAndKeyed(t *testing.T) {
	var firstKey [sha256.Size]byte
	var secondKey [sha256.Size]byte
	firstKey[0] = 1
	secondKey[0] = 2
	cfg := upstreamCybFeedbackConfig{Enabled: true, TTL: time.Hour, MaxEntries: 8}
	first := newUpstreamCybFeedbackCacheForTest(cfg, firstKey, time.Now)
	second := newUpstreamCybFeedbackCacheForTest(cfg, secondKey, time.Now)
	body := []byte(`{"model":"gpt-5.6-sol","input":"same exact bytes"}`)

	digest, ok := first.digest("/v1/responses", body)
	if !ok {
		t.Fatal("eligible request did not produce a digest")
	}
	same, _ := first.digest("/v1/responses", append([]byte(nil), body...))
	if digest != same {
		t.Fatal("same endpoint and exact body produced different digests")
	}
	differentBody, _ := first.digest("/v1/responses", append(body, ' '))
	if digest == differentBody {
		t.Fatal("one-byte body change must miss")
	}
	differentEndpoint, _ := first.digest("/v1/chat/completions", body)
	if digest == differentEndpoint {
		t.Fatal("different endpoint must miss")
	}
	differentKey, _ := second.digest("/v1/responses", body)
	if digest == differentKey {
		t.Fatal("different process HMAC keys must isolate digests")
	}
	if _, ok := first.digest("/v1/images/generations", body); ok {
		t.Fatal("non-text endpoint must not be captured")
	}
}

func TestUpstreamCybFeedbackTTLDoesNotSlideOnLookup(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	var key [sha256.Size]byte
	cache := newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled: true, TTL: 10 * time.Minute, MaxEntries: 4,
	}, key, clock)
	digest, _ := cache.digest("/v1/responses", []byte(`{"input":"ttl"}`))
	cache.learnDigest(digest)
	now = now.Add(9 * time.Minute)
	if !cache.lookupDigest(digest) {
		t.Fatal("entry expired before TTL")
	}
	now = now.Add(2 * time.Minute)
	if cache.lookupDigest(digest) {
		t.Fatal("lookup incorrectly extended TTL")
	}
}

func TestUpstreamCybFeedbackLRUEviction(t *testing.T) {
	var key [sha256.Size]byte
	cache := newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled: true, TTL: time.Hour, MaxEntries: 2,
	}, key, time.Now)
	digestA, _ := cache.digest("/v1/responses", []byte(`{"input":"a"}`))
	digestB, _ := cache.digest("/v1/responses", []byte(`{"input":"b"}`))
	digestC, _ := cache.digest("/v1/responses", []byte(`{"input":"c"}`))
	cache.learnDigest(digestA)
	cache.learnDigest(digestB)
	if !cache.lookupDigest(digestA) {
		t.Fatal("expected A before eviction")
	}
	cache.learnDigest(digestC)
	if cache.lookupDigest(digestB) {
		t.Fatal("least-recently-used B was not evicted")
	}
	if !cache.lookupDigest(digestA) || !cache.lookupDigest(digestC) {
		t.Fatal("recent entries were evicted")
	}
}

func TestUpstreamCybFeedbackHitDoesNotCreateSessionOrWebSocketPin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, true)
	handler.SetRuntimeCache(cache.NewMemory(32))
	body := []byte(`{"model":"gpt-5.6-sol","input":"feedback exact body"}`)
	digest, _ := handler.upstreamCybFeedback.digest("/v1/responses", body)
	handler.upstreamCybFeedback.learnDigest(digest)

	ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
	ctx.Request.Header.Set("Session_id", "feedback-session")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Connection", "Upgrade")
	ctx.Set(contextAPIKeyID, int64(101))
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", body, false)
	decision := handler.applyUpstreamCybFeedbackRoute(ctx, body, "/v1/responses", defaultPromptRiskDecision())
	decision = handler.applyCybRoutePin(ctx, body, decision)
	if !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceDirect || decision.RoutePinned || decision.PinKind != "" || !decision.SkipPinPersistence {
		t.Fatalf("feedback decision = %+v, want direct non-pin relay route", decision)
	}
	if pinned, _ := ctx.Get(contextCybWSRoutePinned); pinned == true {
		t.Fatal("feedback-only hit pinned the WebSocket connection")
	}

	sessionKey := cybRelayPinCacheKey("session_id", responseCacheOwner(101), "feedback-session")
	if handler.hasCybRoutePin(ctx.Request.Context(), sessionKey) {
		t.Fatal("feedback-only hit persisted a session pin")
	}
	handler.pinCybRelayResponseID(ctx, []byte(`{"response":{"id":"resp_feedback"}}`))
	responseKey := cybRelayPinCacheKey("previous_response_id", responseCacheOwner(101), "resp_feedback")
	if handler.hasCybRoutePin(ctx.Request.Context(), responseKey) {
		t.Fatal("feedback-only hit persisted a response-id pin")
	}

	followup := newUpstreamCybFeedbackTestContext("/v1/responses")
	followup.Request.Header.Set("Session_id", "feedback-session")
	followup.Set(contextAPIKeyID, int64(101))
	differentBody := []byte(`{"model":"gpt-5.6-sol","input":"different follow-up"}`)
	got := handler.applyCybRoutePin(followup, differentBody, defaultPromptRiskDecision())
	if got.routesToCybRelay() {
		t.Fatalf("feedback expanded into session pin: %+v", got)
	}
}

func TestUpstreamCybFeedbackAppendsToExistingLocalRouteWithoutChangingPinSemantics(t *testing.T) {
	handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, true)
	body := []byte(`{"input":"locally routed and known"}`)
	digest, _ := handler.upstreamCybFeedback.digest("/v1/responses", body)
	handler.upstreamCybFeedback.learnDigest(digest)
	ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", body, false)
	base := promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		Reason:      "local rule",
		Signals:     []string{"local_threshold"},
		RouteSource: cybRelayRouteSourceDirect,
	}
	got := handler.applyUpstreamCybFeedbackRoute(ctx, body, "/v1/responses", base)
	if got.Reason != base.Reason || got.RouteSource != base.RouteSource || got.SkipPinPersistence {
		t.Fatalf("feedback changed existing local route semantics: %+v", got)
	}
	if len(got.Signals) != 2 || got.Signals[1] != upstreamCybFeedbackSignal {
		t.Fatalf("feedback signal not appended once: %v", got.Signals)
	}
}

func TestUpstreamCybFeedbackLearnsOnlyCanonicalDefaultOAuthCyberPolicy(t *testing.T) {
	validInput := func() database.UsageLogInput {
		return database.UsageLogInput{
			AccountID:           54,
			StatusCode:          http.StatusBadRequest,
			LogicalRequestID:    "logical-cyber",
			UpstreamErrorKind:   "cyber_policy",
			UpstreamAccountType: "oauth",
			RouteClass:          promptRiskDispositionDefault,
			RouteSource:         cybRelayRouteSourceDefault,
		}
	}
	negativeCases := []struct {
		name   string
		mutate func(*database.UsageLogInput, *Handler)
	}{
		{name: "guardian_or_hidden", mutate: func(input *database.UsageLogInput, _ *Handler) { input.GuardianAttemptOnly = true }},
		{name: "relay_account", mutate: func(input *database.UsageLogInput, _ *Handler) {
			input.UpstreamAccountType = auth.UpstreamOpenAIResponses
		}},
		{name: "relay_route", mutate: func(input *database.UsageLogInput, _ *Handler) { input.RouteClass = cybRelayRouteClass }},
		{name: "pin_source", mutate: func(input *database.UsageLogInput, _ *Handler) { input.RouteSource = cybRelayRouteSourcePin }},
		{name: "route_pinned", mutate: func(input *database.UsageLogInput, _ *Handler) { input.RoutePinned = true }},
		{name: "pin_kind", mutate: func(input *database.UsageLogInput, _ *Handler) { input.PinKind = "previous_response_id" }},
		{name: "no_logical_request", mutate: func(input *database.UsageLogInput, _ *Handler) { input.LogicalRequestID = "" }},
		{name: "no_account_owner", mutate: func(input *database.UsageLogInput, _ *Handler) { input.AccountID = 0 }},
		{name: "other_error", mutate: func(input *database.UsageLogInput, _ *Handler) { input.UpstreamErrorKind = "content_policy" }},
		{name: "relay_disabled", mutate: func(_ *database.UsageLogInput, handler *Handler) {
			handler.store.SetCybRelayConfig(auth.CybRelayConfig{})
		}},
	}

	body := []byte(`{"model":"gpt-5.6-sol","input":"learn only the real canonical miss"}`)
	for _, testCase := range negativeCases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, false)
			ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
			handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", body, false)
			input := validInput()
			testCase.mutate(&input, handler)
			handler.maybeLearnUpstreamCybFeedback(ctx, &input)
			digest, _ := upstreamCybFeedbackDigestFromContext(ctx)
			if handler.upstreamCybFeedback.lookupDigest(digest) {
				t.Fatalf("negative case %q trained feedback cache", testCase.name)
			}
		})
	}

	handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, false)
	ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", body, false)
	input := validInput()
	handler.maybeLearnUpstreamCybFeedback(ctx, &input)
	digest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	if !handler.upstreamCybFeedback.lookupDigest(digest) {
		t.Fatal("canonical default OAuth cyber_policy was not learned")
	}
}

func TestLogUsageForRequestMarksAndLearnsCanonicalCyberPolicy(t *testing.T) {
	handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, false)
	body := []byte(`{"input":"central usage lifecycle"}`)
	ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", body, false)
	setPromptRiskDecisionContext(ctx, defaultPromptRiskDecision(), 7)
	ctx.Set(contextUpstreamAccountType, "oauth")
	handler.logUsageForRequest(ctx, &database.UsageLogInput{
		AccountID:    54,
		StatusCode:   http.StatusOK,
		ErrorMessage: "upstream response.failed: cyber_policy",
	})
	digest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	if !handler.upstreamCybFeedback.lookupDigest(digest) {
		t.Fatal("canonical usage lifecycle did not learn marked cyber_policy")
	}
}

func TestUpstreamCybFeedbackHTTPFlowRoutesOnlyExactRepeatAfterCanonicalOAuthCyberPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_TRANSPORT_MODE", "standard")
	previousWebsocketExecute := WebsocketExecuteFunc
	t.Cleanup(func() { WebsocketExecuteFunc = previousWebsocketExecute })

	var oauthCalls atomic.Int32
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		oauthCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(bytes.NewBufferString(
				`{"error":{"code":"cyber_policy","type":"invalid_request_error","message":"This content was flagged for possible cybersecurity risk."}}`,
			)),
		}, nil
	}

	var relayCalls atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayCalls.Add(1)
		if r.URL.Path != "/v1/responses" {
			t.Errorf("relay path = %q, want /v1/responses", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_feedback_ok","object":"response","status":"completed","model":"gpt-5.4","output":[],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}`)
	}))
	t.Cleanup(relay.Close)

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      4,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	store.SetCybRelayConfig(auth.CybRelayConfig{Enabled: true, GroupID: 7})
	store.AddAccount(&auth.Account{
		DBID:        54,
		AccessToken: "oauth-token",
		PlanType:    "pro",
		Status:      auth.StatusReady,
	})
	store.AddAccount(&auth.Account{
		DBID:         51,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      relay.URL,
		APIKey:       "relay-key",
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     []int64{7},
	})
	handler := NewHandler(store, nil, &config.Config{
		AllowAnonymousV1:       true,
		CodexUpstreamTransport: "ws",
	}, nil)
	var key [sha256.Size]byte
	handler.upstreamCybFeedback = newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled: true, TTL: time.Hour, MaxEntries: 8,
	}, key, time.Now)

	run := func(body []byte) (*httptest.ResponseRecorder, *gin.Context) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		request := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		ctx.Request = request
		handler.Responses(ctx)
		return recorder, ctx
	}

	body := []byte(`{"model":"gpt-5.4","input":"benign exact feedback lifecycle","stream":false}`)
	first, _ := run(body)
	if first.Code != http.StatusBadRequest || oauthCalls.Load() != 1 || relayCalls.Load() != 0 {
		t.Fatalf("first request status=%d oauth=%d relay=%d body=%s", first.Code, oauthCalls.Load(), relayCalls.Load(), first.Body.String())
	}

	second, secondContext := run(append([]byte(nil), body...))
	if second.Code != http.StatusOK || oauthCalls.Load() != 1 || relayCalls.Load() != 1 {
		t.Fatalf("exact repeat status=%d oauth=%d relay=%d body=%s", second.Code, oauthCalls.Load(), relayCalls.Load(), second.Body.String())
	}
	decision, ok := promptRiskDecisionFromContext(secondContext)
	if !ok || !decision.routesToCybRelay() || decision.RouteSource != cybRelayRouteSourceDirect || decision.RoutePinned || decision.PinKind != "" || !decision.SkipPinPersistence || len(decision.Signals) != 1 || decision.Signals[0] != upstreamCybFeedbackSignal {
		t.Fatalf("exact repeat decision = %+v present=%v", decision, ok)
	}

	changed, _ := run(append(body, ' '))
	if changed.Code != http.StatusBadRequest || oauthCalls.Load() != 2 || relayCalls.Load() != 1 {
		t.Fatalf("one-byte change status=%d oauth=%d relay=%d body=%s", changed.Code, oauthCalls.Load(), relayCalls.Load(), changed.Body.String())
	}
}

func TestUpstreamCybFeedbackWebSocketTurnDoesNotLeakDigestOrPinIntoNextTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("CODEX_TRANSPORT_MODE", "standard")
	previousWebsocketExecute := WebsocketExecuteFunc
	t.Cleanup(func() { WebsocketExecuteFunc = previousWebsocketExecute })

	var oauthCalls atomic.Int32
	WebsocketExecuteFunc = func(_ context.Context, account *auth.Account, _ []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		if account.ID() != 54 {
			t.Errorf("OAuth hook account = %d, want 54", account.ID())
		}
		oauthCalls.Add(1)
		sse := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"oauth\"}\n\n" +
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_oauth\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2,\"total_tokens\":5}}}\n\n"
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(bytes.NewBufferString(sse)),
		}, nil
	}

	var relayCalls atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayCalls.Add(1)
		if r.URL.Path != "/v1/responses" {
			t.Errorf("relay path = %q, want /v1/responses", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"relay\"}\n\n"+
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_relay\",\"usage\":{\"input_tokens\":3,\"output_tokens\":2,\"total_tokens\":5}}}\n\n")
	}))
	t.Cleanup(relay.Close)

	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      4,
		MaxRetries:          0,
		MaxRateLimitRetries: 0,
	})
	store.SetCybRelayConfig(auth.CybRelayConfig{
		Enabled:              true,
		GroupID:              7,
		SessionPinEnabled:    true,
		SessionPinTTLSeconds: 600,
	})
	store.AddAccount(&auth.Account{
		DBID:        54,
		AccessToken: "oauth-token",
		PlanType:    "pro",
		Status:      auth.StatusReady,
	})
	store.AddAccount(&auth.Account{
		DBID:         51,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      relay.URL,
		APIKey:       "relay-key",
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     []int64{7},
	})
	handler := NewHandler(store, nil, &config.Config{
		AllowAnonymousV1:       true,
		CodexUpstreamTransport: "ws",
	}, nil)
	handler.SetRuntimeCache(cache.NewMemory(64))
	var key [sha256.Size]byte
	handler.upstreamCybFeedback = newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled: true, TTL: time.Hour, MaxEntries: 8,
	}, key, time.Now)

	firstPayload := []byte(`{"type":"response.create","model":"gpt-5.4","input":"benign exact feedback lifecycle"}`)
	firstDigest, _ := handler.upstreamCybFeedback.digest("/v1/responses", firstPayload)
	handler.upstreamCybFeedback.learnDigest(firstDigest)
	secondPayload := []byte(`{"type":"response.create","model":"gpt-5.4","input":"benign different feedback lifecycle"}`)

	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	connection, response, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):]+"/v1/responses", nil)
	if err != nil {
		if response != nil {
			t.Fatalf("dial websocket: %v status=%d", err, response.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	readCompleted := func(label string) {
		t.Helper()
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		for eventIndex := 0; eventIndex < 8; eventIndex++ {
			_, event, readErr := connection.ReadMessage()
			if readErr != nil {
				t.Fatalf("%s read event: %v", label, readErr)
			}
			switch eventType := gjson.GetBytes(event, "type").String(); eventType {
			case "response.completed":
				return
			case "error":
				t.Fatalf("%s returned error event: %s", label, event)
			}
		}
		t.Fatalf("%s did not complete", label)
	}

	if err := connection.WriteMessage(websocket.TextMessage, firstPayload); err != nil {
		t.Fatalf("write first turn: %v", err)
	}
	readCompleted("feedback turn")
	if relayCalls.Load() != 1 || oauthCalls.Load() != 0 {
		t.Fatalf("feedback turn relay=%d oauth=%d, want relay only", relayCalls.Load(), oauthCalls.Load())
	}

	if err := connection.WriteMessage(websocket.TextMessage, secondPayload); err != nil {
		t.Fatalf("write second turn: %v", err)
	}
	readCompleted("different turn")
	if relayCalls.Load() != 1 || oauthCalls.Load() != 1 {
		t.Fatalf("different turn relay=%d oauth=%d, stale digest or pin leaked across turns", relayCalls.Load(), oauthCalls.Load())
	}
}

func TestUpstreamCybFeedbackCaptureKeepsHTTPIngressAndOverwritesWebSocketTurns(t *testing.T) {
	handler := newTestUpstreamCybFeedbackHandler(t, time.Hour, 8, false)
	ctx := newUpstreamCybFeedbackTestContext("/v1/responses")
	original := []byte(`{"model":"client-alias","input":"original"}`)
	mapped := []byte(`{"model":"gpt-5.6-sol","input":"original"}`)
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", original, false)
	originalDigest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses/compact", mapped, false)
	keptDigest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	if originalDigest != keptDigest {
		t.Fatal("internal HTTP hand-off overwrote original ingress digest")
	}
	wantOriginal, _ := handler.upstreamCybFeedback.digest("/v1/responses", original)
	if keptDigest != wantOriginal {
		t.Fatal("captured digest did not bind original endpoint and bytes")
	}

	firstTurn := []byte(`{"type":"response.create","model":"gpt-5.6-sol","input":"one"}`)
	secondTurn := []byte(`{"type":"response.create","model":"gpt-5.6-sol","input":"two"}`)
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", firstTurn, true)
	firstDigest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	handler.captureUpstreamCybFeedbackRequest(ctx, "/v1/responses", secondTurn, true)
	secondDigest, _ := upstreamCybFeedbackDigestFromContext(ctx)
	if firstDigest == secondDigest {
		t.Fatal("WebSocket turn did not overwrite prior turn digest")
	}
}

func TestUpstreamCybFeedbackCacheConcurrentAccess(t *testing.T) {
	var key [sha256.Size]byte
	cache := newUpstreamCybFeedbackCacheForTest(upstreamCybFeedbackConfig{
		Enabled: true, TTL: time.Hour, MaxEntries: 1024,
	}, key, time.Now)
	const goroutines = 100
	var waitGroup sync.WaitGroup
	waitGroup.Add(goroutines)
	for index := 0; index < goroutines; index++ {
		index := index
		go func() {
			defer waitGroup.Done()
			body := []byte{byte(index), byte(index >> 8), byte(index >> 16)}
			digest, ok := cache.digest("/v1/responses", body)
			if !ok {
				t.Errorf("digest %d unavailable", index)
				return
			}
			cache.learnDigest(digest)
			if !cache.lookupDigest(digest) {
				t.Errorf("digest %d missing after learn", index)
			}
		}()
	}
	waitGroup.Wait()
}

func TestUpstreamCybFeedbackConfigFromEnv(t *testing.T) {
	t.Setenv("CODEX_UPSTREAM_CYB_FEEDBACK_ENABLED", "false")
	t.Setenv("CODEX_UPSTREAM_CYB_FEEDBACK_TTL", "30m")
	t.Setenv("CODEX_UPSTREAM_CYB_FEEDBACK_MAX_ENTRIES", "77")
	cfg := upstreamCybFeedbackConfigFromEnv()
	if cfg.Enabled || cfg.TTL != 30*time.Minute || cfg.MaxEntries != 77 {
		t.Fatalf("env config = %+v", cfg)
	}
}
