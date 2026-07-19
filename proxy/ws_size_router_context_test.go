package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/config"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestWebsocketSizeRouterAdvisoryAllowedOnlyForUnboundRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name      string
		headers   http.Header
		body      string
		encrypted bool
		want      bool
	}{
		{name: "plain unbound", body: `{"input":"fresh"}`, want: true},
		{name: "previous response", body: `{"previous_response_id":"resp_123"}`},
		{name: "session header", headers: http.Header{"Session_id": []string{"session-123"}}, body: `{}`},
		{name: "conversation header", headers: http.Header{"Conversation_id": []string{"conversation-123"}}, body: `{}`},
		{name: "idempotency header", headers: http.Header{"Idempotency-Key": []string{"request-123"}}, body: `{}`},
		{name: "prompt cache key", body: `{"prompt_cache_key":"cache-123"}`},
		{name: "encrypted context owner", body: `{}`, encrypted: true},
		{name: "local affinity header", headers: http.Header{downstreamAffinityHeader: []string{"user-123"}}, body: `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			if tt.encrypted {
				setEncryptedContextState(ctx, encryptedContextAffinityState{Keys: []string{"encrypted-key"}})
			}
			headers := make(http.Header)
			for key, values := range tt.headers {
				for _, value := range values {
					headers.Add(key, value)
				}
			}
			if got := websocketSizeRouterAdvisoryAllowed(ctx, headers, []byte(tt.body)); got != tt.want {
				t.Fatalf("websocketSizeRouterAdvisoryAllowed() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestResponsesLearnedSizeRouterKeepsExplicitSessionOnWebsocket(t *testing.T) {
	gin.SetMode(gin.TestMode)

	previousExec := WebsocketExecuteFunc
	previousSettings := CurrentRuntimeSettings()
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousExec
		ApplyRuntimeSettings(previousSettings)
		resinCfg.Store(previousResin)
		globalWSSizeRouter = websocketSizeRouter{}
	})

	nextSettings := previousSettings
	nextSettings.CodexForceWebsocket = true
	nextSettings.CodexWSSizeRouter = true
	ApplyRuntimeSettings(nextSettings)

	wsCalls := 0
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		wsCalls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader(
				`data: {"type":"response.output_text.delta","delta":"ws-bound"}` + "\n\n" +
					`data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"service_tier":"default"}}` + "\n\n",
			)),
		}, nil
	}

	httpCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls++
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(
			`data: {"type":"response.output_text.delta","delta":"unexpected-http"}` + "\n\n" +
				`data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}` + "\n\n",
		))
	}))
	defer upstream.Close()
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	store := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 1, TestConcurrency: 1, TestModel: "gpt-5.4"})
	account := &auth.Account{DBID: 1, AccessToken: "at-1", PlanType: "pro", AccountID: "acct-1"}
	account.SetDispatchCountLimit(1)
	store.AddAccount(account)
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)

	globalWSSizeRouter = websocketSizeRouter{minTooBig: 1, learnedAt: time.Now()}

	body := []byte(`{"model":"gpt-5.4","input":"hello","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Session_id", "session-bound")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req

	handler.Responses(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ws-bound") {
		t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
	}
	if wsCalls != 1 {
		t.Fatalf("wsCalls = %d, want 1", wsCalls)
	}
	if httpCalls != 0 {
		t.Fatalf("httpCalls = %d, want 0 for context-bound size advisory", httpCalls)
	}
}
