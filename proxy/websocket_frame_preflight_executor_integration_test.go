package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

func TestExecuteRequestLargeUnboundWebsocketFrameUsesNativeHTTPBodyOnce(t *testing.T) {
	const appendMarker = "rb23-preflight-append-once"
	withPayloadRules(t, `{"append":[{"params":{"instructions":"`+appendMarker+`"}}]}`)
	previousWS := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousWS
		resinCfg.Store(previousResin)
	})

	var mu sync.Mutex
	var httpBodies [][]byte
	var httpAccounts []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		httpBodies = append(httpBodies, append([]byte(nil), body...))
		httpAccounts = append(httpAccounts, r.Header.Get("X-Resin-Account"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_http"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	account := &auth.Account{DBID: 73, AccessToken: "oauth-token", AccountID: "acct-73", PlanType: "pro", Status: auth.StatusReady}
	ruleStore := auth.NewStore(nil, nil, &database.SystemSettings{MaxConcurrency: 2})
	t.Cleanup(ruleStore.Stop)
	ruleStore.AddAccount(account)
	ruleHandler := &Handler{store: ruleStore}
	ruleRecorder := httptest.NewRecorder()
	ruleContext, _ := gin.CreateTestContext(ruleRecorder)
	ruleContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	originalBody := []byte(`{"model":"gpt-5.4","instructions":"base instructions","tools":[{"type":"image_generation"},{"type":"function","name":"keep_me","parameters":{"type":"object"}}],"input":[{"type":"reasoning","id":"reasoning-1","encrypted_content":"opaque-ciphertext"}],"stream":true}`)
	preparedBody, frozen := ruleHandler.prepareCodexPayloadRules(ruleContext, originalBody, "gpt-5.4", accountFilterForModel("gpt-5.4"))
	if !frozen {
		t.Fatal("expected OAuth payload-rule snapshot to be frozen")
	}
	upstreamCtx := withPayloadRuleSnapshot(context.Background(), freezePayloadRuleSnapshot(ruleContext))
	upstreamCtx = withPayloadRulesPreApplied(upstreamCtx)
	wsBody := stripResponsesImageGenerationTool(preparedBody)
	if strings.Contains(string(wsBody), `"image_generation"`) {
		t.Fatalf("test setup did not strip the websocket-only image tool: %s", wsBody)
	}

	wsCalls := 0
	var capturedWSBody []byte
	WebsocketExecuteFunc = func(_ context.Context, gotAccount *auth.Account, body []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		wsCalls++
		if gotAccount != account {
			t.Fatalf("websocket account changed: got=%p want=%p", gotAccount, account)
		}
		capturedWSBody = append([]byte(nil), body...)
		return nil, &WebsocketFramePreflightError{FrameBytes: 17 * 1024 * 1024, LimitBytes: 16 * 1024 * 1024}
	}

	resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
		upstreamCtx, account, wsBody, preparedBody, "", "stable-http-session",
		"", "sk-local", nil, http.Header{}, websocketFramePreflightAllowSameAccountHTTP, true,
	)
	if err != nil {
		t.Fatalf("preflight HTTP fallback error = %v", err)
	}
	if resp == nil {
		t.Fatal("preflight HTTP fallback response = nil")
	}
	_ = resp.Body.Close()
	if actualWebsocket || wsCalls != 1 {
		t.Fatalf("actualWebsocket=%t wsCalls=%d, want false/1", actualWebsocket, wsCalls)
	}

	// Compare against the ordinary HTTP executor fed the same original body and
	// session. Equality proves the fallback did not reuse the WS-stripped body or
	// apply HTTP payload rules twice.
	resp, err = ExecuteRequest(upstreamCtx, account, preparedBody, "stable-http-session", "", "sk-local", nil, http.Header{}, false)
	if err != nil {
		t.Fatalf("native HTTP request error = %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	gotBodies := append([][]byte(nil), httpBodies...)
	gotAccounts := append([]string(nil), httpAccounts...)
	mu.Unlock()
	if len(gotBodies) != 2 {
		t.Fatalf("HTTP upstream calls = %d, want fallback + native comparison", len(gotBodies))
	}
	if string(gotBodies[0]) != string(gotBodies[1]) {
		t.Fatalf("fallback HTTP body differs from native HTTP\nfallback=%s\nnative=%s", gotBodies[0], gotBodies[1])
	}
	if len(gotAccounts) != 2 || gotAccounts[0] != "73" || gotAccounts[1] != "73" {
		t.Fatalf("HTTP upstream accounts = %#v, want same selected account 73", gotAccounts)
	}
	if !strings.Contains(string(gotBodies[0]), `"image_generation"`) {
		t.Fatalf("HTTP fallback did not restore image_generation tool: %s", gotBodies[0])
	}
	if got := gjson.GetBytes(gotBodies[0], "input.0.encrypted_content").String(); got != "opaque-ciphertext" {
		t.Fatalf("HTTP fallback encrypted_content = %q", got)
	}
	if got := gjson.GetBytes(gotBodies[0], "prompt_cache_key").String(); got != "stable-http-session" {
		t.Fatalf("HTTP fallback prompt_cache_key = %q, want native HTTP session", got)
	}
	if instructions := gjson.GetBytes(gotBodies[0], "instructions").String(); strings.Count(instructions, appendMarker) != 1 {
		t.Fatalf("HTTP fallback instructions=%q, append marker count want exactly 1", instructions)
	}
	if strings.Contains(string(capturedWSBody), `"image_generation"`) {
		t.Fatalf("websocket candidate regained stripped image tool: %s", capturedWSBody)
	}
	if got := gjson.GetBytes(capturedWSBody, "input.0.encrypted_content").String(); got != "opaque-ciphertext" {
		t.Fatalf("websocket candidate encrypted_content = %q", got)
	}
	if instructions := gjson.GetBytes(capturedWSBody, "instructions").String(); strings.Count(instructions, appendMarker) != 1 {
		t.Fatalf("websocket candidate instructions=%q, append marker count want exactly 1", instructions)
	}
}

func TestExecuteRequestLargeContextBoundFrameAllowedUsesSameAccountHTTPOnce(t *testing.T) {
	t.Setenv(websocketContextBoundHTTPPreflightEnv, "")
	previousWS := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousWS
		resinCfg.Store(previousResin)
	})

	account := &auth.Account{DBID: 74, AccessToken: "oauth-token", AccountID: "acct-74", PlanType: "pro", Status: auth.StatusReady}
	var wsCalls int
	WebsocketExecuteFunc = func(_ context.Context, gotAccount *auth.Account, body []byte, sessionID, proxyOverride, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
		wsCalls++
		if gotAccount != account {
			t.Fatalf("WS preflight account changed: got=%p want=%p", gotAccount, account)
		}
		if sessionID != "explicit-ws-session" || proxyOverride != "sticky-proxy" {
			t.Fatalf("WS preflight identity session=%q proxy=%q", sessionID, proxyOverride)
		}
		if got := gjson.GetBytes(body, "input").String(); got != "large screenshot" {
			t.Fatalf("WS preflight body input=%q", got)
		}
		return nil, &WebsocketFramePreflightError{
			FrameBytes:   17 * 1024 * 1024,
			LimitBytes:   16 * 1024 * 1024,
			ContextBound: true,
		}
	}

	var httpCalls int
	var httpAccount string
	var httpBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls++
		httpAccount = r.Header.Get("X-Resin-Account")
		httpBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_same_account"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	ctx, observation := withUpstreamTransportObservation(context.Background())
	wsBody := []byte(`{"model":"gpt-5.4","input":"large screenshot"}`)
	httpBodyCandidate := append([]byte(nil), wsBody...)
	resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
		ctx, account, wsBody, httpBodyCandidate,
		"explicit-ws-session", "explicit-http-session", "sticky-proxy", "sk-local", nil, http.Header{},
		websocketFramePreflightAllowSameAccountHTTP, true,
	)
	if err != nil {
		t.Fatalf("same-account HTTP preflight error = %v", err)
	}
	if resp == nil {
		t.Fatal("same-account HTTP preflight response = nil")
	}
	_ = resp.Body.Close()
	if actualWebsocket || wsCalls != 1 || httpCalls != 1 {
		t.Fatalf("actualWebsocket=%t wsCalls=%d httpCalls=%d, want false/1/1", actualWebsocket, wsCalls, httpCalls)
	}
	if httpAccount != "74" {
		t.Fatalf("HTTP account=%q want selected account 74", httpAccount)
	}
	if got := gjson.GetBytes(httpBody, "prompt_cache_key").String(); got != "explicit-http-session" {
		t.Fatalf("HTTP prompt_cache_key=%q want explicit-http-session body=%s", got, httpBody)
	}
	if got := gjson.GetBytes(httpBody, "input").String(); got != "large screenshot" {
		t.Fatalf("HTTP body input=%q body=%s", got, httpBody)
	}
	reason, frameBytes, limitBytes := observation.Snapshot()
	if reason != websocketLargeFrameSameAccountHTTPReason || frameBytes != 17*1024*1024 || limitBytes != 16*1024*1024 {
		t.Fatalf("observation=(%q,%d,%d), want same-account HTTP reason and exact limits", reason, frameBytes, limitBytes)
	}
}

func TestExecuteRequestLargeContextBoundFrameEnvOffRestoresStrict(t *testing.T) {
	t.Setenv(websocketContextBoundHTTPPreflightEnv, "off")
	previousWS := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousWS
		resinCfg.Store(previousResin)
	})

	var wsCalls int
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		wsCalls++
		return nil, &WebsocketFramePreflightError{FrameBytes: 17 * 1024 * 1024, LimitBytes: 16 * 1024 * 1024, ContextBound: true}
	}
	var httpCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	ctx, observation := withUpstreamTransportObservation(context.Background())
	body := []byte(`{"model":"gpt-5.4","input":"large"}`)
	resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
		ctx, &auth.Account{DBID: 75, AccessToken: "must-not-be-used"}, body, body,
		"explicit-session", "explicit-session", "", "sk-local", nil, http.Header{},
		websocketFramePreflightAllowSameAccountHTTP, true,
	)
	frameErr, ok := websocketContextBoundFrameError(err)
	if !ok || frameErr == nil {
		t.Fatalf("env-off error=%v, want context-bound typed error", err)
	}
	if resp != nil || actualWebsocket || wsCalls != 1 || httpCalls != 0 {
		t.Fatalf("resp=%v actualWS=%t wsCalls=%d httpCalls=%d, want nil/false/1/0", resp, actualWebsocket, wsCalls, httpCalls)
	}
	reason, _, _ := observation.Snapshot()
	if reason != websocketLargeFrameContextBoundKind {
		t.Fatalf("env-off reason=%q want=%q", reason, websocketLargeFrameContextBoundKind)
	}
}

func TestExecuteRequestLargeUnboundWebsocketFrameSharedBodyFallbackDoesNotMutateCompatibilityPayload(t *testing.T) {
	tests := []struct {
		name   string
		marker string
		body   string
	}{
		{
			name:   "chat canonical body",
			marker: "chat-body-marker",
			body:   `{"model":"gpt-5.4","instructions":"chat-body-marker","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`,
		},
		{
			name:   "anthropic canonical body",
			marker: "anthropic-body-marker",
			body:   `{"model":"gpt-5.4","instructions":"anthropic-body-marker","input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`,
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previousWS := WebsocketExecuteFunc
			previousResin := resinCfg.Load()
			t.Cleanup(func() {
				WebsocketExecuteFunc = previousWS
				resinCfg.Store(previousResin)
			})

			var capturedHTTPBody []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHTTPBody, _ = io.ReadAll(r.Body)
				_ = r.Body.Close()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"resp_http"}`)
			}))
			t.Cleanup(upstream.Close)
			SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

			account := &auth.Account{DBID: int64(80 + index), AccessToken: "oauth-token"}
			sharedBody := []byte(test.body)
			before := append([]byte(nil), sharedBody...)
			WebsocketExecuteFunc = func(_ context.Context, _ *auth.Account, body []byte, _ string, _ string, _ string, _ *DeviceProfileConfig, _ http.Header, _ string) (*http.Response, error) {
				if !strings.Contains(string(body), test.marker) {
					t.Fatalf("WS compatibility body lost marker: %s", body)
				}
				return nil, &WebsocketFramePreflightError{FrameBytes: 17 * 1024 * 1024, LimitBytes: 16 * 1024 * 1024}
			}

			resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
				withPayloadRulesPreApplied(context.Background()), account,
				sharedBody, sharedBody, "", "compat-http-session", "", "sk-local", nil, http.Header{}, websocketFramePreflightAllowSameAccountHTTP, true,
			)
			if err != nil {
				t.Fatalf("compatibility fallback error = %v", err)
			}
			if resp == nil {
				t.Fatal("compatibility fallback response = nil")
			}
			_ = resp.Body.Close()
			if actualWebsocket {
				t.Fatal("compatibility fallback remained websocket")
			}
			if string(sharedBody) != string(before) {
				t.Fatalf("shared WS/HTTP caller body mutated\nbefore=%s\nafter=%s", before, sharedBody)
			}
			if !strings.Contains(string(capturedHTTPBody), test.marker) {
				t.Fatalf("HTTP compatibility body lost marker: %s", capturedHTTPBody)
			}
			if got := gjson.GetBytes(capturedHTTPBody, "prompt_cache_key").String(); got != "compat-http-session" {
				t.Fatalf("HTTP compatibility prompt_cache_key=%q", got)
			}
		})
	}
}
