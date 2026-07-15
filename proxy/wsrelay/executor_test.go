package wsrelay

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

func TestPrepareWebsocketHeadersUsesConfiguredDefaultsAndBetaFeatures(t *testing.T) {
	t.Setenv("CODEX_WS_SEND_USER_AGENT", "true")
	exec := NewExecutor()
	cfg := &proxy.DeviceProfileConfig{
		UserAgent:              "codex_cli_rs/0.120.0 (Mac OS 15.5.0; arm64) Apple_Terminal/464",
		PackageVersion:         "0.120.0",
		RuntimeVersion:         "0.120.0",
		OS:                     "MacOS",
		Arch:                   "arm64",
		StabilizeDeviceProfile: true,
		BetaFeatures:           "multi_agent",
	}
	ginHeaders := http.Header{
		"Originator": []string{"custom-originator"},
	}

	headers := exec.prepareWebsocketHeaders("token-123", &auth.Account{DBID: 42, AccountID: "42"}, "42", "session-123", "api-key-1", cfg, ginHeaders)

	if got := headers.Get("Authorization"); got != "Bearer token-123" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := headers.Get("OpenAI-Beta"); got != responsesWebsocketBetaHeader {
		t.Fatalf("OpenAI-Beta = %q", got)
	}
	if got := headers.Get("X-Codex-Beta-Features"); got != "multi_agent" {
		t.Fatalf("X-Codex-Beta-Features = %q", got)
	}
	if got := headers.Get("User-Agent"); got != cfg.UserAgent {
		t.Fatalf("User-Agent = %q", got)
	}
	if got := headers.Get("Version"); got != "0.120.0" {
		t.Fatalf("Version = %q", got)
	}
	if got := headers.Get("Originator"); got != proxy.Originator {
		t.Fatalf("Originator = %q", got)
	}
	if got := headers.Get("Chatgpt-Account-Id"); got != "42" {
		t.Fatalf("Chatgpt-Account-Id = %q", got)
	}
	if got := headers.Get("Conversation_id"); got != "session-123" {
		t.Fatalf("Conversation_id = %q", got)
	}
	if got := headers.Get("Session_id"); got != "session-123" {
		t.Fatalf("Session_id = %q", got)
	}
}

func TestPrepareSafePoolFrameMetadataMovesTurnScopedValuesIntoFrame(t *testing.T) {
	original := []byte(`{"model":"gpt-5.6","client_metadata":{"session_id":"session-A","thread_id":"thread-A","keep":"yes"}}`)
	headers := http.Header{
		"X-Codex-Turn-State":    {"turn-state-A"},
		"X-Codex-Turn-Metadata": {`{"session_id":"session-A","thread_id":"thread-A","turn_id":"turn-A"}`},
		"Traceparent":           {"00-trace-parent-01"},
		"Tracestate":            {"vendor=value"},
	}
	prepared, ok := prepareSafePoolFrameMetadata(original, headers)
	if !ok {
		t.Fatal("consistent official metadata was rejected")
	}
	for path, want := range map[string]string{
		"client_metadata.session_id":                    "session-A",
		"client_metadata.thread_id":                     "thread-A",
		"client_metadata.keep":                          "yes",
		"client_metadata.x-codex-turn-state":            "turn-state-A",
		"client_metadata.x-codex-turn-metadata":         `{"session_id":"session-A","thread_id":"thread-A","turn_id":"turn-A"}`,
		"client_metadata.ws_request_header_traceparent": "00-trace-parent-01",
		"client_metadata.ws_request_header_tracestate":  "vendor=value",
	} {
		if got := gjson.GetBytes(prepared, path).String(); got != want {
			t.Fatalf("%s = %q, want %q; body=%s", path, got, want, prepared)
		}
	}
	if gjson.GetBytes(original, "client_metadata.x-codex-turn-state").Exists() {
		t.Fatal("prepareSafePoolFrameMetadata mutated the caller's request body")
	}
}

func TestPrepareSafePoolFrameMetadataRejectsCanonicalIdentityConflicts(t *testing.T) {
	base := []byte(`{"model":"gpt-5.6","client_metadata":{"session_id":"session-A","thread_id":"thread-A"}}`)
	for _, tt := range []struct {
		name    string
		body    []byte
		headers http.Header
	}{
		{
			name: "nested thread conflicts with flat owner",
			body: []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-metadata":"{\"session_id\":\"session-A\",\"thread_id\":\"thread-B\"}"}}`),
		},
		{
			name:    "compatibility header conflicts with canonical body",
			body:    []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-metadata":"{\"session_id\":\"session-A\",\"thread_id\":\"thread-A\",\"turn_id\":\"turn-A\"}"}}`),
			headers: http.Header{"X-Codex-Turn-Metadata": {`{"session_id":"session-A","thread_id":"thread-A","turn_id":"turn-B"}`}},
		},
		{
			name:    "header thread conflicts with flat owner",
			body:    base,
			headers: http.Header{"X-Codex-Turn-Metadata": {`{"session_id":"session-A","thread_id":"thread-B"}`}},
		},
		{
			name:    "turn state header conflicts with canonical frame value",
			body:    []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-state":"state-A"}}`),
			headers: http.Header{"X-Codex-Turn-State": {"state-B"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := prepareSafePoolFrameMetadata(tt.body, tt.headers); ok {
				t.Fatal("conflicting metadata was admitted to safe pool")
			}
		})
	}
}

func TestPrepareSafePoolFrameMetadataAcceptsSemanticProjectionAndMemoryShape(t *testing.T) {
	body := []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-metadata":"{\"thread_id\":\"thread-A\",\"session_id\":\"session-A\",\"turn_id\":\"turn-A\"}"}}`)
	headers := http.Header{"X-Codex-Turn-Metadata": {`{ "turn_id":"turn-A", "session_id":"session-A", "thread_id":"thread-A" }`}}
	if _, ok := prepareSafePoolFrameMetadata(body, headers); !ok {
		t.Fatal("semantically equal compatibility projection was rejected")
	}

	memoryBody := []byte(`{"client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-metadata":"{\"request_kind\":\"memory\"}"}}`)
	if _, ok := prepareSafePoolFrameMetadata(memoryBody, nil); !ok {
		t.Fatal("memory metadata that legally omits session/thread was rejected")
	}
}

// TestPrepareWebsocketHeadersForwardsAttestationOnlyWhenPresent 验证 WS 路径同样
// 只在下游携带 DeviceCheck token（openai/codex#20619）时透传，缺失不伪造。
func TestPrepareWebsocketHeadersForwardsAttestationOnlyWhenPresent(t *testing.T) {
	exec := NewExecutor()
	acc := &auth.Account{DBID: 42, AccountID: "42"}

	withToken := exec.prepareWebsocketHeaders("token-123", acc, "42", "session-123", "api-key-1", nil, http.Header{
		"X-Oai-Attestation": []string{"v1.real-devicecheck-token"},
	})
	if got := withToken.Get("X-Oai-Attestation"); got != "v1.real-devicecheck-token" {
		t.Fatalf("X-Oai-Attestation = %q, want passthrough of downstream token", got)
	}

	without := exec.prepareWebsocketHeaders("token-123", acc, "42", "session-123", "api-key-1", nil, http.Header{})
	if got := without.Get("X-Oai-Attestation"); got != "" {
		t.Fatalf("X-Oai-Attestation = %q, want empty (never fabricate)", got)
	}
}

func TestPrepareWebsocketHeadersAppliesAccountCustomHeadersLast(t *testing.T) {
	exec := NewExecutor()
	account := &auth.Account{
		DBID:      42,
		AccountID: "42",
		CustomHeaders: map[string]string{
			"Authorization":      "Bearer websocket-override",
			"Chatgpt-Account-Id": "acct-override",
			"X-Custom-Header":    "custom-value",
		},
	}

	headers := exec.prepareWebsocketHeaders("token-123", account, "42", "session-123", "api-key-1", nil, http.Header{})

	if got := headers.Get("Authorization"); got != "Bearer websocket-override" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := headers.Get("Chatgpt-Account-Id"); got != "acct-override" {
		t.Fatalf("Chatgpt-Account-Id = %q", got)
	}
	if got := headers.Get("X-Custom-Header"); got != "custom-value" {
		t.Fatalf("X-Custom-Header = %q", got)
	}
}

func TestPrepareWebsocketHeadersSendsUserAgentByDefault(t *testing.T) {
	t.Setenv("CODEX_WS_SEND_USER_AGENT", "")
	exec := NewExecutor()
	ginHeaders := http.Header{
		"X-Codex-Turn-State":                    []string{"turn-state"},
		"X-Codex-Turn-Metadata":                 []string{"turn-metadata"},
		"X-Client-Request-Id":                   []string{"req-123"},
		"X-Responsesapi-Include-Timing-Metrics": []string{"true"},
	}

	headers := exec.prepareWebsocketHeaders("token-123", &auth.Account{DBID: 42, AccountID: "42"}, "42", "session-123", "api-key-1", nil, ginHeaders)

	if got := headers.Get("User-Agent"); got != proxy.MinimalCodexCLIUserAgentForHeaders() {
		t.Fatalf("User-Agent = %q, want %q", got, proxy.MinimalCodexCLIUserAgentForHeaders())
	}
	if got := headers.Get("Version"); got != proxy.LatestCodexCLIVersionForHeaders() {
		t.Fatalf("Version = %q, want %q", got, proxy.LatestCodexCLIVersionForHeaders())
	}
	if got := headers.Get("OpenAI-Beta"); got != responsesWebsocketBetaHeader {
		t.Fatalf("OpenAI-Beta = %q", got)
	}
	for _, name := range []string{"X-Codex-Turn-State", "X-Codex-Turn-Metadata", "X-Client-Request-Id", "X-Responsesapi-Include-Timing-Metrics"} {
		if got := headers.Get(name); got != ginHeaders.Get(name) {
			t.Fatalf("%s = %q, want %q", name, got, ginHeaders.Get(name))
		}
	}
	if got := headers.Get("Session_id"); got != "session-123" {
		t.Fatalf("Session_id = %q", got)
	}
	if got := headers.Get("Conversation_id"); got != "session-123" {
		t.Fatalf("Conversation_id = %q", got)
	}
}

func TestPrepareWebsocketHeadersCanOptOutOfUserAgent(t *testing.T) {
	t.Setenv("CODEX_WS_SEND_USER_AGENT", "false")
	exec := NewExecutor()

	headers := exec.prepareWebsocketHeaders("token-123", &auth.Account{DBID: 42, AccountID: "42"}, "42", "session-123", "api-key-1", nil, http.Header{})

	if got := headers.Get("User-Agent"); got != "" {
		t.Fatalf("User-Agent = %q, want empty", got)
	}
	if got := headers.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
}

func TestPrepareWebsocketHeadersHonorsForcedGeneratedUserAgent(t *testing.T) {
	t.Setenv("CODEX_WS_SEND_USER_AGENT", "true")
	prev := proxy.CurrentRuntimeSettings()
	proxy.ApplyRuntimeSettings(proxy.RuntimeSettings{ClientCompatMode: proxy.ClientCompatModeForce})
	t.Cleanup(func() { proxy.ApplyRuntimeSettings(prev) })
	exec := NewExecutor()
	account := &auth.Account{DBID: 43, AccountID: "42"}
	ginHeaders := http.Header{
		"User-Agent": []string{"codex_vscode/1.2.3"},
		"Originator": []string{"codex_vscode"},
		"Version":    []string{"1.2.3"},
	}

	headers := exec.prepareWebsocketHeaders("token-123", account, "42", "session-123", "api-key-1", nil, ginHeaders)

	got := headers.Get("User-Agent")
	if got == ginHeaders.Get("User-Agent") {
		t.Fatalf("User-Agent preserved client UA %q in forced mode", got)
	}
	if got != proxy.ProfileForAccount(account.DBID).UserAgent {
		t.Fatalf("User-Agent = %q, want real account profile %q", got, proxy.ProfileForAccount(account.DBID).UserAgent)
	}
	if !strings.HasPrefix(got, "codex-tui/") || !strings.Contains(got, " (") {
		t.Fatalf("User-Agent = %q, want generated full codex-tui profile", got)
	}
	if version := headers.Get("Version"); version != proxy.LatestCodexCLIVersionForHeaders() {
		t.Fatalf("Version = %q, want %q", version, proxy.LatestCodexCLIVersionForHeaders())
	}
	if originator := headers.Get("Originator"); originator != proxy.Originator {
		t.Fatalf("Originator = %q, want %q", originator, proxy.Originator)
	}
}

func TestPrepareWebsocketBodyPreservesPreviousResponseID(t *testing.T) {
	exec := NewExecutor()

	got := exec.prepareWebsocketBody([]byte(`{"model":"gpt-5.4","previous_response_id":"resp_123","input":[{"role":"user","content":"continue"}]}`), "session-123")

	if prev := gjson.GetBytes(got, "previous_response_id").String(); prev != "resp_123" {
		t.Fatalf("previous_response_id = %q, want resp_123; body=%s", prev, got)
	}
	if cacheKey := gjson.GetBytes(got, "prompt_cache_key").String(); cacheKey != "session-123" {
		t.Fatalf("prompt_cache_key = %q, want session-123; body=%s", cacheKey, got)
	}
	if typ := gjson.GetBytes(got, "type").String(); typ != "response.create" {
		t.Fatalf("type = %q, want response.create; body=%s", typ, got)
	}
	if !gjson.GetBytes(got, "stream").Bool() {
		t.Fatalf("stream should be true; body=%s", got)
	}
}

func TestOfficialPromptCacheRequestEntersSafeOwnerPool(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	t.Setenv(safePoolFenceMillisEnv, "10")
	var handshakes atomic.Int32
	var turns atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Session-Id") != "official-session" || req.Header.Get("Thread-Id") != "official-thread" {
			t.Errorf("canonical owner headers missing: %v", req.Header)
		}
		if req.Header.Get("Session_id") != "" || req.Header.Get("Conversation_id") != "" {
			t.Errorf("legacy prompt-cache session headers leaked into safe handshake: %v", req.Header)
		}
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		handshakes.Add(1)
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			turn := turns.Add(1)
			responseID := fmt.Sprintf("resp_official_%d", turn)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, responseID)))
			_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"status":"completed"}}`, responseID)))
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	exec := NewExecutorWithManager(manager)
	exec.wsURLOverrideTest = "ws" + strings.TrimPrefix(server.URL, "http")
	account := &auth.Account{DBID: 4601, AccountID: "acct-official", AccessToken: "token", DynamicConcurrencyLimit: 8}
	body := []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","client_metadata":{"session_id":"official-session","thread_id":"official-thread","turn_id":"turn-1"},"input":"hello"}`)
	for turn := 0; turn < 2; turn++ {
		response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, body, "official-cache", "", "key-A", nil, http.Header{}, "")
		if err != nil {
			t.Fatalf("turn %d execute: %v", turn+1, err)
		}
		if !response.safePool || response.oneShot || !response.conn.safeReusable.Load() {
			t.Fatalf("official request routing: safe=%v oneshot=%v reusable=%v", response.safePool, response.oneShot, response.conn.safeReusable.Load())
		}
		if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
			t.Fatalf("turn %d read: %v", turn+1, err)
		}
		if err := response.Close(); err != nil {
			t.Fatalf("turn %d close: %v", turn+1, err)
		}
	}
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("official safe turns used %d physical handshakes, want 1", got)
	}
	if got := manager.SafePoolMetricsSnapshot().ReuseHits; got != 1 {
		t.Fatalf("safe reuse hits = %d, want 1", got)
	}
}

func TestOfficialPromptCacheRequestHonorsHardOneShotKillSwitch(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		turn := handshakes.Add(1)
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		responseID := fmt.Sprintf("resp_oneshot_%d", turn)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, responseID)))
		_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"status":"completed"}}`, responseID)))
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	exec := NewExecutorWithManager(manager)
	exec.wsURLOverrideTest = "ws" + strings.TrimPrefix(server.URL, "http")
	account := &auth.Account{DBID: 4602, AccountID: "acct-oneshot", AccessToken: "token", DynamicConcurrencyLimit: 8}
	body := []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","client_metadata":{"session_id":"official-session","thread_id":"official-thread"},"input":"hello"}`)
	for turn := 0; turn < 2; turn++ {
		response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, body, "official-cache", "", "key-A", nil, http.Header{}, "")
		if err != nil {
			t.Fatalf("turn %d execute: %v", turn+1, err)
		}
		if response.safePool || !response.oneShot {
			t.Fatalf("hard-kill routing: safe=%v oneshot=%v", response.safePool, response.oneShot)
		}
		if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
			t.Fatalf("turn %d read: %v", turn+1, err)
		}
		if err := response.Close(); err != nil {
			t.Fatalf("turn %d close: %v", turn+1, err)
		}
		if manager.ConnectionCount() != 0 {
			t.Fatalf("turn %d left a one-shot socket pooled", turn+1)
		}
	}
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("hard kill used %d physical handshakes, want 2", got)
	}
}

func TestOfficialPromptCacheUnenrolledAccountsKeepBaselineSessionReuse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
	}{
		{name: "tagged but account not enrolled", scope: "tagged"},
		{name: "safe pool disabled", scope: "disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
			t.Setenv(safePoolScopeEnv, tc.scope)
			var handshakes atomic.Int32
			var turns atomic.Int32
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				conn, err := upgrader.Upgrade(w, req, nil)
				if err != nil {
					return
				}
				handshakes.Add(1)
				defer conn.Close()
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
					turn := turns.Add(1)
					responseID := fmt.Sprintf("resp_baseline_%d", turn)
					_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":%q}}`, responseID)))
					_ = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"status":"completed"}}`, responseID)))
				}
			}))
			t.Cleanup(server.Close)

			manager := NewManager()
			t.Cleanup(manager.Stop)
			exec := NewExecutorWithManager(manager)
			exec.wsURLOverrideTest = "ws" + strings.TrimPrefix(server.URL, "http")
			account := &auth.Account{DBID: 4610, AccountID: "acct-baseline", AccessToken: "token", DynamicConcurrencyLimit: 8}
			body := []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","client_metadata":{"session_id":"official-session","thread_id":"official-thread"},"input":"hello"}`)
			for turn := 0; turn < 2; turn++ {
				response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, body, "official-cache", "", "key-A", nil, http.Header{}, "")
				if err != nil {
					t.Fatalf("turn %d execute: %v", turn+1, err)
				}
				if response.safePool || response.oneShot || response.conn.safeReusable.Load() {
					t.Fatalf("unenrolled routing safe=%v oneshot=%v reusable=%v, want unchanged explicit-session path", response.safePool, response.oneShot, response.conn.safeReusable.Load())
				}
				if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
					t.Fatalf("turn %d read: %v", turn+1, err)
				}
				if err := response.Close(); err != nil {
					t.Fatalf("turn %d close: %v", turn+1, err)
				}
			}
			if got := handshakes.Load(); got != 1 {
				t.Fatalf("unenrolled baseline used %d handshakes, want 1", got)
			}
		})
	}
}

func TestOfficialPromptCacheFuseFallsBackBeforeDialInsteadOfHandshakeStorm(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handshakes.Add(1)
		conn, err := upgrader.Upgrade(w, req, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	exec := NewExecutorWithManager(manager)
	exec.wsURLOverrideTest = "ws" + strings.TrimPrefix(server.URL, "http")
	account := &auth.Account{DBID: 4603, AccountID: "acct-fused", AccessToken: "token", DynamicConcurrencyLimit: 100}
	manager.TripSafePoolCompatibilityFuse(account.ID(), errors.New("unknown legal control frame"))
	body := []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","client_metadata":{"session_id":"official-session","thread_id":"official-thread"},"input":"hello"}`)
	for request := 0; request < 5; request++ {
		response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, body, "official-cache", "", "key-A", nil, http.Header{}, "")
		if response != nil || !errors.Is(err, proxy.ErrWebsocketSafePoolFallback) {
			t.Fatalf("request %d response=%v err=%v, want pre-write same-account HTTP fallback", request+1, response, err)
		}
	}
	if got := handshakes.Load(); got != 0 {
		t.Fatalf("process-fused account opened %d websocket handshakes, want 0", got)
	}

	continuation := []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","previous_response_id":"resp_fused","client_metadata":{"session_id":"official-session","thread_id":"official-thread"},"input":"continue"}`)
	response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, continuation, "official-cache", "", "key-A", nil, http.Header{}, "")
	if response != nil || !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("fused continuation response=%v err=%v, want fail-closed continuation", response, err)
	}
	if got := handshakes.Load(); got != 0 {
		t.Fatalf("fused continuation opened %d websocket handshakes, want 0", got)
	}
}

func TestSafeScopeUnprovableOwnerFallsBackToHTTPBeforeDial(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "0")
	t.Setenv(safePoolScopeEnv, "all")
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		handshakes.Add(1)
		conn, err := upgrader.Upgrade(w, req, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	exec := NewExecutorWithManager(manager)
	exec.wsURLOverrideTest = "ws" + strings.TrimPrefix(server.URL, "http")
	account := &auth.Account{DBID: 4604, AccountID: "acct-owner-missing", AccessToken: "token", DynamicConcurrencyLimit: 8}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "missing owner", body: []byte(`{"model":"gpt-5.6","prompt_cache_key":"official-cache","input":"hello"}`)},
		{name: "conflicting owner", body: []byte(`{"model":"gpt-5.6","client_metadata":{"session_id":"session-A","thread_id":"thread-A","x-codex-turn-metadata":"{\"session_id\":\"session-A\",\"thread_id\":\"thread-B\"}"},"input":"hello"}`)},
		{name: "audio ineligible", body: []byte(`{"model":"gpt-5.6","modalities":["text","audio"],"client_metadata":{"session_id":"session-A","thread_id":"thread-A"},"input":"hello"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := exec.ExecuteRequestViaWebsocket(context.Background(), account, tc.body, "official-cache", "", "key-A", nil, http.Header{}, "")
			if response != nil || !errors.Is(err, proxy.ErrWebsocketSafePoolFallback) {
				t.Fatalf("response=%v err=%v, want pre-write same-account HTTP fallback", response, err)
			}
		})
	}
	if got := handshakes.Load(); got != 0 {
		t.Fatalf("owner-missing request opened %d websocket handshakes, want 0", got)
	}
}

func TestExecuteRequestViaWebsocketPreviousResponseBusyDoesNotCrossConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{
		DBID:                    42,
		AccessToken:             "token-123",
		AccountID:               "acct-42",
		DynamicConcurrencyLimit: 2,
	}
	wsURL, err := buildWebsocketURL(proxy.CodexBaseURL + CodexWsEndpoint)
	if err != nil {
		t.Fatalf("buildWebsocketURL: %v", err)
	}
	bound, session := newTestSlotConnection(manager, account, wsURL, "previous-bound#0")
	const (
		responseID = "resp_previous_busy"
		apiKey     = "key-A"
	)
	manager.BindResponseConn(responseID, bound, "previous-bound#0", account.ID(), apiKey)
	blocking := session.AddPendingRequest("previous-bound#0")
	t.Cleanup(func() { session.RemovePendingRequest(blocking.RequestID) })
	connectionCount := manager.ConnectionCount()

	exec := NewExecutorWithManager(manager)
	response, err := exec.ExecuteRequestViaWebsocket(
		context.Background(),
		account,
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_previous_busy","input":"continue"}`),
		"stateless-next-turn",
		"",
		apiKey,
		nil,
		http.Header{},
		"route-key",
	)
	if response != nil {
		t.Fatal("busy previous-response request unexpectedly acquired another connection")
	}
	if !errors.Is(err, proxy.ErrWebsocketSessionBusy) {
		t.Fatalf("previous-response busy error = %v, want ErrWebsocketSessionBusy", err)
	}
	if got := manager.ConnectionCount(); got != connectionCount {
		t.Fatalf("connection count = %d, want unchanged %d (no cross-slot fallback)", got, connectionCount)
	}
	if got := session.PendingCount(); got != 1 {
		t.Fatalf("bound connection pending count = %d, want original request only", got)
	}
	if got, _ := manager.lookupResponseConn(responseID, account.ID(), apiKey); got != bound {
		t.Fatal("busy previous-response binding was lost or replaced")
	}
}

func TestExecuteRequestViaWebsocketPreviousResponseMissingDoesNotAcquireOrdinaryConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{
		DBID:                    42,
		AccessToken:             "token-123",
		AccountID:               "acct-42",
		DynamicConcurrencyLimit: 2,
	}
	exec := NewExecutorWithManager(manager)
	started := time.Now()
	response, err := exec.ExecuteRequestViaWebsocket(
		context.Background(),
		account,
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_missing","input":"continue"}`),
		"stateless-next-turn",
		"",
		"key-A",
		nil,
		http.Header{},
		"route-key",
	)
	if response != nil {
		t.Fatal("missing previous-response binding unexpectedly acquired an ordinary connection")
	}
	if !errors.Is(err, proxy.ErrWebsocketContinuationUnavailable) {
		t.Fatalf("missing previous-response error = %v, want ErrWebsocketContinuationUnavailable", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("missing previous-response lookup took %v, suggesting an ordinary dial was attempted", elapsed)
	}
	if got := manager.ConnectionCount(); got != 0 {
		t.Fatalf("connection count = %d, want 0 (no ordinary-slot fallback)", got)
	}
}

func TestPrepareWebsocketBodyKeepsCacheKeyForStatelessSession(t *testing.T) {
	exec := NewExecutor()

	got := exec.prepareWebsocketBody([]byte(`{"model":"gpt-5.4","prompt_cache_key":"deterministic-key","input":[]}`), "stateless-abc123")

	if cacheKey := gjson.GetBytes(got, "prompt_cache_key").String(); cacheKey != "deterministic-key" {
		t.Fatalf("prompt_cache_key = %q, want deterministic-key (stateless sessionID must not overwrite); body=%s", cacheKey, got)
	}
}

func TestPrepareWebsocketBodyStatelessSessionWithoutCacheKey(t *testing.T) {
	exec := NewExecutor()

	got := exec.prepareWebsocketBody([]byte(`{"model":"gpt-5.4","input":[]}`), "stateless-abc123")

	if cacheKey := gjson.GetBytes(got, "prompt_cache_key").String(); cacheKey != "" {
		t.Fatalf("prompt_cache_key = %q, want empty (stateless sessionID must not be injected); body=%s", cacheKey, got)
	}
}

func TestNormalizeWebsocketHandshakeResponse(t *testing.T) {
	t.Run("switching protocols is successful websocket handshake", func(t *testing.T) {
		statusCode, _, failed := normalizeWebsocketHandshakeResponse(&http.Response{
			StatusCode: http.StatusSwitchingProtocols,
		})
		if failed {
			t.Fatal("failed = true, want false")
		}
		if statusCode != http.StatusOK {
			t.Fatalf("statusCode = %d, want %d", statusCode, http.StatusOK)
		}
	})

	t.Run("http 2xx is normalized for downstream handler", func(t *testing.T) {
		statusCode, _, failed := normalizeWebsocketHandshakeResponse(&http.Response{
			StatusCode: http.StatusNoContent,
		})
		if failed {
			t.Fatal("failed = true, want false")
		}
		if statusCode != http.StatusOK {
			t.Fatalf("statusCode = %d, want %d", statusCode, http.StatusOK)
		}
	})

	t.Run("non success status remains a handshake failure", func(t *testing.T) {
		statusCode, _, failed := normalizeWebsocketHandshakeResponse(&http.Response{
			StatusCode: http.StatusUnauthorized,
		})
		if !failed {
			t.Fatal("failed = false, want true")
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatalf("statusCode = %d, want %d", statusCode, http.StatusUnauthorized)
		}
	})
}

func TestWebsocketResponseToHTTPClosesBodyOnContextCancel(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
		time.Sleep(5 * time.Second)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	session := NewSession(1, nil)
	pr := session.AddPendingRequest("session-1")
	wc := NewWsConnection(conn, session, wsURL)
	manager := NewManager()
	defer manager.Stop()
	wsResp := &WsResponse{
		conn:        wc,
		pendingReq:  pr,
		sessionID:   "session-1",
		manager:     manager,
		readErrChan: make(chan error, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	resp := websocketResponseToHTTP(ctx, wsResp, http.StatusOK, http.Header{})
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := resp.Body.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Body.Read returned nil error after context cancellation")
		}
		if err != context.Canceled && err != io.ErrClosedPipe && !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("Body.Read error = %v, want context cancellation or closed pipe", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Body.Read stayed blocked after context cancellation")
	}
}

func newClosedTestWebsocketConn(t *testing.T) *websocket.Conn {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	handshakeDone := make(chan struct{})
	go func() {
		defer close(handshakeDone)
		defer serverConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(serverConn))
		if err != nil {
			return
		}
		acceptHash := sha1.Sum([]byte(req.Header.Get("Sec-Websocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = fmt.Fprintf(serverConn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(acceptHash[:]))
	}()

	wsURL, err := url.Parse("ws://example.test/responses")
	if err != nil {
		t.Fatalf("parse websocket URL: %v", err)
	}
	conn, _, err := websocket.NewClient(clientConn, wsURL, nil, 1024, 1024)
	if err != nil {
		t.Fatalf("create test websocket client: %v", err)
	}
	<-handshakeDone
	return conn
}

func TestExecuteRequestViaWebsocketSendFailureRemovesEffectiveProxyConnection(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{
		DBID:        42,
		AccessToken: "token-123",
		ProxyURL:    "http://account-proxy.test:8080",
	}
	sessionID := "session-1"
	wsURL, err := buildWebsocketURL(proxy.CodexBaseURL + CodexWsEndpoint)
	if err != nil {
		t.Fatalf("buildWebsocketURL: %v", err)
	}
	effectiveProxy := effectiveProxyURL(account, "")
	key := manager.poolKey(account.ID(), wsURL, sessionID, effectiveProxy)
	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{
		conn:    newClosedTestWebsocketConn(t),
		session: session,
		URL:     wsURL,
		PoolKey: key,
	}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)
	manager.probeFunc = func(wc *WsConnection) bool { return true }

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	exec := NewExecutorWithManager(manager)
	_, err = exec.ExecuteRequestViaWebsocket(ctx, account, []byte(`{"model":"gpt-5.4","input":"hi"}`), sessionID, "", "", nil, http.Header{}, "")
	if err == nil {
		t.Fatal("expected final send failure")
	}
	if _, ok := manager.connections.Load(key); ok {
		t.Fatal("expected failed connection keyed by effective account proxy to be removed")
	}
	if _, ok := manager.sessions.Load(key); ok {
		t.Fatal("expected failed session keyed by effective account proxy to be removed")
	}
	if conn.IsConnected() {
		t.Fatal("expected failed connection to be closed")
	}
}

func TestExecuteRequestViaWebsocketPreviousResponseSendFailureDoesNotResend(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)

	account := &auth.Account{
		DBID:                    42,
		AccessToken:             "token-123",
		AccountID:               "acct-42",
		DynamicConcurrencyLimit: 2,
	}
	const (
		responseID = "resp_bound_send_failure"
		apiKey     = "key-A"
	)
	wsURL, err := buildWebsocketURL(proxy.CodexBaseURL + CodexWsEndpoint)
	if err != nil {
		t.Fatalf("buildWebsocketURL: %v", err)
	}
	key := manager.poolKey(account.ID(), wsURL, "previous-bound#0", "")
	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{
		account:  account,
		conn:     newClosedTestWebsocketConn(t),
		session:  session,
		URL:      wsURL,
		PoolKey:  key,
		httpResp: &http.Response{StatusCode: http.StatusSwitchingProtocols},
	}
	conn.SetState(StateConnected)
	conn.Touch()
	manager.connections.Store(key, conn)
	manager.sessions.Store(key, session)
	manager.BindResponseConn(responseID, conn, "previous-bound#0", account.ID(), apiKey)
	manager.probeFunc = func(*WsConnection) bool { return true }

	exec := NewExecutorWithManager(manager)
	started := time.Now()
	response, err := exec.ExecuteRequestViaWebsocket(
		context.Background(),
		account,
		[]byte(`{"model":"gpt-5.4","previous_response_id":"resp_bound_send_failure","input":"continue"}`),
		"stateless-next-turn",
		"",
		apiKey,
		nil,
		http.Header{},
		"route-key",
	)
	if response != nil {
		t.Fatal("failed response-bound send unexpectedly returned a response")
	}
	if !errors.Is(err, proxy.ErrWebsocketWriteUncertain) {
		t.Fatalf("response-bound send error = %v, want ErrWebsocketWriteUncertain", err)
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("response-bound send failure took %v, suggesting a retry or ordinary dial was attempted", elapsed)
	}
	if got := manager.ConnectionCount(); got != 0 {
		t.Fatalf("connection count = %d, want 0 after discarding failed bound connection", got)
	}
	if got, _ := manager.lookupResponseConn(responseID, account.ID(), apiKey); got != nil {
		t.Fatal("failed response-bound connection remained available for continuation")
	}
}

func TestSendRequestWritesResponseCreatePayloadDirectly(t *testing.T) {
	received := make(chan []byte, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("read websocket message: %v", err)
			return
		}
		received <- payload
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	exec := NewExecutor()
	wc := NewWsConnection(conn, NewSession(1, nil), wsURL)
	body := []byte(`{"type":"response.create","model":"gpt-5.4","input":"hi","stream":true}`)
	if err := exec.sendRequest(wc, body, "request-1"); err != nil {
		t.Fatalf("sendRequest: %v", err)
	}

	got := <-received
	if string(got) != string(body) {
		t.Fatalf("sent payload = %s, want %s", got, body)
	}
	if eventType := gjson.GetBytes(got, "type").String(); eventType != "response.create" {
		t.Fatalf("sent type = %q, want response.create; payload=%s", eventType, got)
	}
	if gjson.GetBytes(got, "request_id").Exists() {
		t.Fatalf("payload should not contain internal request_id wrapper: %s", got)
	}
}

// TestResolveHandshakeSessionID 验证握手头 Session_id/Conversation_id 的取值策略。
// 该头逐连接冻结、复用连接时永不更新，因此 stateless 复用连接绝不能携带任何
// 单个请求的身份，否则第一个请求的会话身份会泄漏给后续复用该连接的所有用户
// （跨用户上下文污染，"用户2串到用户1的上下文"）。
func TestResolveHandshakeSessionID(t *testing.T) {
	t.Run("explicit session keeps original behavior", func(t *testing.T) {
		got := resolveHandshakeSessionID("session-123", "route-key", []byte(`{"prompt_cache_key":"whatever"}`))
		if got != "session-123" {
			t.Fatalf("headerSessionID = %q, want session-123", got)
		}
	})

	t.Run("stateless isolated mode must not send any session identity", func(t *testing.T) {
		// 默认隔离模式：帧体是每请求随机 prompt_cache_key，poolRouteKey 非空。
		// 若把随机 key 冻结进握手头，复用连接的后续用户都会顶着第一个请求的身份。
		got := resolveHandshakeSessionID("stateless-abc", "route-key", []byte(`{"prompt_cache_key":"per-request-random-uuid"}`))
		if got != "" {
			t.Fatalf("headerSessionID = %q, want empty (no connection-level session identity)", got)
		}
	})

	t.Run("stateless per-api-key mode keeps deterministic cache key", func(t *testing.T) {
		got := resolveHandshakeSessionID("stateless-abc", "", []byte(`{"prompt_cache_key":"deterministic-key"}`))
		if got != "deterministic-key" {
			t.Fatalf("headerSessionID = %q, want deterministic-key", got)
		}
	})

	t.Run("stateless without cache key falls back to stateless id", func(t *testing.T) {
		got := resolveHandshakeSessionID("stateless-abc", "", []byte(`{}`))
		if got != "stateless-abc" {
			t.Fatalf("headerSessionID = %q, want stateless-abc", got)
		}
	})
}

// TestPrepareWebsocketHeadersOmitsSessionHeadersWhenEmpty 验证 headerSessionID 为空时
// 不发送 Session_id/Conversation_id 握手头（隔离模式的 stateless 复用连接）。
func TestPrepareWebsocketHeadersOmitsSessionHeadersWhenEmpty(t *testing.T) {
	exec := NewExecutor()

	headers := exec.prepareWebsocketHeaders("token-123", &auth.Account{DBID: 42, AccountID: "42"}, "42", "", "api-key-1", nil, http.Header{})

	if got := headers.Get("Session_id"); got != "" {
		t.Fatalf("Session_id = %q, want unset", got)
	}
	if got := headers.Get("Conversation_id"); got != "" {
		t.Fatalf("Conversation_id = %q, want unset", got)
	}
}

func TestStatelessOneShotEnabled(t *testing.T) {
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "")
	if statelessOneShotEnabled() {
		t.Fatal("default must be false (slot reuse on)")
	}
	t.Setenv("CODEX_WS_STATELESS_ONESHOT", "1")
	if !statelessOneShotEnabled() {
		t.Fatal("CODEX_WS_STATELESS_ONESHOT=1 must disable slot reuse")
	}
}

func TestShouldRetryWebsocketSendError(t *testing.T) {
	messageTooBig := fmt.Errorf("send interrupted: %w", &websocket.CloseError{
		Code: websocket.CloseMessageTooBig,
		Text: "message too big",
	})
	if shouldRetryWebsocketSendError(messageTooBig) {
		t.Fatal("close 1009 must return to the handler for HTTP fallback without rebuilding WebSocket connections")
	}

	if shouldRetryWebsocketSendError(errors.New("temporary write failure")) {
		t.Fatal("unclassified write failures must not replay a possibly committed turn")
	}
	if shouldRetryWebsocketSendError(fmt.Errorf("send interrupted: %w", &websocket.CloseError{
		Code: websocket.CloseInternalServerErr,
		Text: "temporary upstream failure",
	})) {
		t.Fatal("peer close after a write attempt must not replay the turn")
	}
	if !shouldRetryWebsocketSendError(fmt.Errorf("reserve: %w", errWebsocketWriteNotStarted)) {
		t.Fatal("a proven pre-write failure should retain bounded reconnect retry")
	}
	if shouldRetryWebsocketSendError(nil) {
		t.Fatal("nil is not a retryable send error")
	}
}

func TestWriteMessagePostAttemptFailureIsUncertainAndNeverRetried(t *testing.T) {
	session := NewSession(42, nil)
	session.SetConnected(true)
	wc := &WsConnection{session: session}
	wc.SetState(StateConnected)
	if err := wc.BeginReadLease("request-1"); err != nil {
		t.Fatalf("begin lease: %v", err)
	}
	writes := 0
	wc.writeMessageFunc = func(messageType int, data []byte) error {
		writes++
		if messageType != websocket.TextMessage || string(data) != `{"type":"response.create"}` {
			t.Fatalf("unexpected attempted frame type=%d data=%s", messageType, data)
		}
		// Simulate Gorilla returning an error after the peer/kernel may already
		// have accepted the complete business frame.
		return errors.New("post-write socket failure")
	}
	err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`))
	if !errors.Is(err, proxy.ErrWebsocketWriteUncertain) {
		t.Fatalf("write error = %v, want ErrWebsocketWriteUncertain", err)
	}
	if shouldRetryWebsocketSendError(err) {
		t.Fatal("uncertain committed write was classified as replayable")
	}
	if writes != 1 {
		t.Fatalf("business write attempts = %d, want exactly 1", writes)
	}
}

func TestWsResponseIncompleteTerminatesAndBindsContinuation(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, AccountID: "acct-42"}
	session := NewSession(account.ID(), manager)
	session.SetConnected(true)
	conn := &WsConnection{account: account, session: session, PoolKey: "incomplete-connection"}
	conn.SetState(StateConnected)
	manager.connections.Store(conn.PoolKey, conn)

	response := &WsResponse{conn: conn, sessionID: "session-incomplete", manager: manager, apiKey: "key-A"}
	payload := []byte(`{"type":"response.incomplete","response":{"id":"resp_incomplete","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"}}}`)
	callbackCount := 0
	err := response.handleMessage(payload, func(got []byte) bool {
		callbackCount++
		if string(got) != string(payload) {
			t.Fatalf("callback payload = %s, want %s", got, payload)
		}
		return true
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("handleMessage error = %v, want io.EOF terminal", err)
	}
	if callbackCount != 1 {
		t.Fatalf("callback count = %d, want 1", callbackCount)
	}
	manager.respConnMu.Lock()
	binding, ok := manager.respConnBindings["resp_incomplete"]
	manager.respConnMu.Unlock()
	if !ok || binding.conn != conn || binding.sessionKey != "session-incomplete" || binding.accountID != account.ID() || binding.apiKey != "key-A" {
		t.Fatalf("incomplete response binding = %+v, present=%v", binding, ok)
	}
}
