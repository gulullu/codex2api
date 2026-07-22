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

func TestWebsocketStructuredOutputFormatPathOnlyMatchesAPIFields(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantPath     string
		wantName     string
		wantEncoding string
	}{
		{
			name:         "responses text format",
			body:         `{"model":"gpt-5.6-sol","text":{"format":{"type":"json_schema","name":"ExternalCallReviewResult","schema":{"type":"object"}}}}`,
			wantPath:     "text.format",
			wantName:     "ExternalCallReviewResult",
			wantEncoding: "object",
		},
		{
			name:         "legacy response format",
			body:         `{"model":"gpt-5.6-sol","response_format":{"type":"json_schema","json_schema":{"name":"result","schema":{"type":"object"}}}}`,
			wantPath:     "response_format",
			wantName:     "result",
			wantEncoding: "object",
		},
		{
			name:         "legacy wrapper encoded as JSON string",
			body:         `{"model":"gpt-5.6-sol","response_format":{"type":"json_schema","json_schema":"{\"name\":\"result\",\"schema\":{\"type\":\"object\"}}"}}`,
			wantPath:     "response_format",
			wantName:     "result",
			wantEncoding: "json_string",
		},
		{
			name:         "top level format encoded as JSON string",
			body:         `{"model":"gpt-5.6-sol","response_format":"{\"type\":\"json_schema\",\"name\":\"result\",\"schema\":{\"type\":\"object\"}}"}`,
			wantPath:     "response_format",
			wantName:     "result",
			wantEncoding: "json_string",
		},
		{
			name: "nested input is data",
			body: `{"model":"gpt-5.6-sol","input":{"text":{"format":{"type":"json_schema"}}}}`,
		},
		{
			name: "function tool schema is not response format",
			body: `{"model":"gpt-5.6-sol","tools":[{"type":"function","name":"review","parameters":{"type":"object","properties":{"type":{"const":"json_schema"}}}}]}`,
		},
		{
			name: "json object remains websocket compatible",
			body: `{"model":"gpt-5.6-sol","text":{"format":{"type":"json_object"}}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			format := findWebsocketStructuredOutputFormat([]byte(test.body))
			if format.path != test.wantPath || format.name != test.wantName || format.schemaEncoding != test.wantEncoding {
				t.Fatalf("format=%+v want path=%q name=%q encoding=%q", format, test.wantPath, test.wantName, test.wantEncoding)
			}
		})
	}
}

func TestWebsocketStructuredOutputSafeSummaryDoesNotLogSchemaContent(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","text":{"format":{"type":"json_schema","name":"ExternalCallReviewResult","strict":true,"schema":{"type":"object","description":"DO_NOT_LOG_ME","properties":{"private_field":{"type":"string","enum":["PRIVATE_ENUM_VALUE"]},"calculation":{"type":"number"}},"required":["private_field","calculation"]}}}}`)
	format := findWebsocketStructuredOutputFormat(body)
	summary := websocketStructuredOutputSafeSummary(body, format)
	for _, forbidden := range []string{"ExternalCallReviewResult", "DO_NOT_LOG_ME", "private_field", "PRIVATE_ENUM_VALUE"} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("safe summary leaked %q: %s", forbidden, summary)
		}
	}
	for _, required := range []string{"name_hash=", "schema_hash=", "schema_encoding=object", "properties=2", "required=2", "calculation_property=true", "calculation_required=true"} {
		if !strings.Contains(summary, required) {
			t.Fatalf("safe summary missing %q: %s", required, summary)
		}
	}
}

func TestWebsocketStructuredOutputSafeSummaryMissingSchemaDoesNotHashRequest(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","input":"DO_NOT_LOG_OR_HASH_THIS_PROMPT","text":{"format":{"type":"json_schema","name":"ExternalCallReviewResult"}}}`)
	format := findWebsocketStructuredOutputFormat(body)
	summary := websocketStructuredOutputSafeSummary(body, format)
	for _, forbidden := range []string{"ExternalCallReviewResult", "DO_NOT_LOG_OR_HASH_THIS_PROMPT"} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("safe summary leaked %q: %s", forbidden, summary)
		}
	}
	for _, required := range []string{"schema_hash=none", "schema_encoding=missing", "schema_kind=missing"} {
		if !strings.Contains(summary, required) {
			t.Fatalf("safe summary missing %q: %s", required, summary)
		}
	}
}

func TestExecuteRequestStructuredOutputUsesSameAccountHTTPBeforeWebsocketWrite(t *testing.T) {
	t.Setenv(websocketStructuredOutputHTTPEnv, "")
	t.Setenv(websocketStructuredOutputHTTPNamesEnv, "ExternalCallReviewResult")
	previousWS := WebsocketExecuteFunc
	previousResin := resinCfg.Load()
	t.Cleanup(func() {
		WebsocketExecuteFunc = previousWS
		resinCfg.Store(previousResin)
	})

	var wsCalls int
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		wsCalls++
		return nil, nil
	}

	var httpCalls int
	var httpAccount string
	var capturedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls++
		httpAccount = r.Header.Get("X-Resin-Account")
		capturedBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_structured_http"}`)
	}))
	t.Cleanup(upstream.Close)
	SetResinConfig(&ResinConfig{BaseURL: upstream.URL, PlatformName: "test"})

	account := &auth.Account{DBID: 91, AccessToken: "oauth-token", AccountID: "acct-91", PlanType: "pro", Status: auth.StatusReady}
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"reasoning","id":"reasoning-1","encrypted_content":"opaque-ciphertext"}],"text":{"format":{"type":"json_schema","name":"ExternalCallReviewResult","strict":true,"schema":{"type":"object","properties":{"verdict":{"type":"string"}},"required":["verdict"],"additionalProperties":false}}},"stream":false}`)
	ctx, observation := withUpstreamTransportObservation(context.Background())
	resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
		ctx, account, body, append([]byte(nil), body...), "stateless-ws", "stable-http-session",
		"", "sk-local", nil, http.Header{}, websocketFramePreflightAllowSameAccountHTTP, true,
	)
	if err != nil {
		t.Fatalf("structured-output HTTP preflight error=%v", err)
	}
	if resp == nil {
		t.Fatal("structured-output HTTP response=nil")
	}
	_ = resp.Body.Close()
	if actualWebsocket || wsCalls != 0 || httpCalls != 1 {
		t.Fatalf("actualWebsocket=%t wsCalls=%d httpCalls=%d, want false/0/1", actualWebsocket, wsCalls, httpCalls)
	}
	if httpAccount != "91" {
		t.Fatalf("HTTP account=%q want selected account 91", httpAccount)
	}
	if got := gjson.GetBytes(capturedBody, "prompt_cache_key").String(); got != "stable-http-session" {
		t.Fatalf("HTTP prompt_cache_key=%q body=%s", got, capturedBody)
	}
	if got := gjson.GetBytes(capturedBody, "text.format.name").String(); got != "ExternalCallReviewResult" {
		t.Fatalf("HTTP structured format name=%q body=%s", got, capturedBody)
	}
	if got := gjson.GetBytes(capturedBody, "input.0.encrypted_content").String(); got != "opaque-ciphertext" {
		t.Fatalf("HTTP encrypted_content=%q body=%s", got, capturedBody)
	}
	reason, frameBytes, limitBytes := observation.Snapshot()
	if reason != websocketStructuredOutputHTTPReason || frameBytes != 0 || limitBytes != 0 {
		t.Fatalf("observation=(%q,%d,%d), want structured-output HTTP reason", reason, frameBytes, limitBytes)
	}
}

func TestExecuteRequestStructuredOutputPreflightHonorsKillSwitchAndStrictPolicy(t *testing.T) {
	previousWS := WebsocketExecuteFunc
	t.Cleanup(func() { WebsocketExecuteFunc = previousWS })

	tests := []struct {
		name             string
		env              string
		names            string
		previousResponse bool
		inboundWS        bool
	}{
		{name: "kill switch off", env: "off", names: "result"},
		{name: "empty allowlist is inert"},
		{name: "previous response derives strict policy", names: "result", previousResponse: true},
		{name: "inbound websocket strict policy", names: "result", inboundWS: true},
		{name: "unlisted schema name", names: "different-result"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(websocketStructuredOutputHTTPEnv, test.env)
			t.Setenv(websocketStructuredOutputHTTPNamesEnv, test.names)
			wsCalls := 0
			WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
				wsCalls++
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"id":"resp_ws"}`)),
				}, nil
			}
			body := []byte(`{"model":"gpt-5.6-sol","text":{"format":{"type":"json_schema","name":"result","schema":{"type":"object"}}}}`)
			if test.previousResponse {
				body = []byte(`{"model":"gpt-5.6-sol","previous_response_id":"resp_owner","text":{"format":{"type":"json_schema","name":"result","schema":{"type":"object"}}}}`)
			}
			policy := websocketFramePreflightPolicyForHTTP(body)
			if test.inboundWS {
				policy = websocketFramePreflightStrict
			}
			resp, err, actualWebsocket := executeRequestWithWebsocketFramePreflight(
				context.Background(), &auth.Account{DBID: 92, AccessToken: "oauth-token"}, body, body,
				"ws-session", "http-session", "", "sk-local", nil, http.Header{}, policy, true,
			)
			if err != nil {
				t.Fatalf("websocket request error=%v", err)
			}
			if resp == nil {
				t.Fatal("websocket response=nil")
			}
			_ = resp.Body.Close()
			if !actualWebsocket || wsCalls != 1 {
				t.Fatalf("actualWebsocket=%t wsCalls=%d, want true/1", actualWebsocket, wsCalls)
			}
		})
	}
}

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
