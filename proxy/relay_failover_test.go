package proxy

import (
	"bytes"
	"context"
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

func relayFailoverAccount(id int64, baseURL, key string, priority int64) *auth.Account {
	account := &auth.Account{
		DBID:         id,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      baseURL,
		APIKey:       key,
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
	}
	account.SetSchedulerPriority(priority)
	return account
}

func newRelayFailoverStore(firstURL, secondURL string) *auth.Store {
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:      4,
		MaxRetries:          1,
		MaxRateLimitRetries: 1,
		RetryIntervalMS:     0,
	})
	store.AddAccount(relayFailoverAccount(101, firstURL, "sk-first", 10))
	store.AddAccount(relayFailoverAccount(102, secondURL, "sk-second", 0))
	return store
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

			handler := NewHandler(newRelayFailoverStore(first.URL, second.URL), nil, nil, nil)
			recorder := runRelayTextHandler(t, handler, test.path, []byte(test.body))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			if firstHits.Load() != 1 || secondHits.Load() != 1 {
				t.Fatalf("attempts first=%d second=%d, want 1 then 1", firstHits.Load(), secondHits.Load())
			}
		})
	}
}

func TestRelayGatewayRetryPolicyDoesNotChangeSharedImagePolicy(t *testing.T) {
	relay := relayFailoverAccount(1, "https://relay.example", "sk-relay", 0)
	for _, statusCode := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
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
