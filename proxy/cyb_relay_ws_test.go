package proxy

import (
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
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const cybRelayTestGroupID int64 = 42

func newCybRelayRoutingTestStore() *auth.Store {
	return auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:                           4,
		TestConcurrency:                          1,
		TestModel:                                "gpt-5.4",
		PromptFilterEnabled:                      true,
		PromptFilterMode:                         "monitor",
		PromptFilterThreshold:                    80,
		PromptFilterStrictThreshold:              120,
		PromptFilterMaxTextLength:                80 * 1024,
		PromptFilterCybRelayEnabled:              true,
		PromptFilterCybRelayGroupID:              cybRelayTestGroupID,
		PromptFilterCybRelaySessionPinEnabled:    false,
		PromptFilterCybRelaySessionPinTTLSeconds: 3600,
	})
}

func cybRelayTestAccount(id int64, baseURL, apiKey string, groupIDs ...int64) *auth.Account {
	return &auth.Account{
		DBID:         id,
		UpstreamType: auth.UpstreamOpenAIResponses,
		BaseURL:      baseURL,
		APIKey:       apiKey,
		Models:       []string{"gpt-5.4"},
		PlanType:     "api",
		Status:       auth.StatusReady,
		GroupIDs:     groupIDs,
	}
}

func TestCybRelayAccountFilterIsolatesDedicatedResponsesAccounts(t *testing.T) {
	store := newCybRelayRoutingTestStore()
	handler := NewHandler(store, nil, nil, nil)

	dedicatedRelay := cybRelayTestAccount(1, "https://relay.example", "sk-relay", cybRelayTestGroupID)
	otherRelay := cybRelayTestAccount(2, "https://other.example", "sk-other", 7)
	dedicatedOAuth := &auth.Account{DBID: 3, AccessToken: "oauth", GroupIDs: []int64{cybRelayTestGroupID}}
	normalOAuth := &auth.Account{DBID: 4, AccessToken: "oauth", GroupIDs: []int64{7}}

	routeFilter := handler.applyCybRelayAccountFilter(nil, promptRiskDecision{Disposition: promptRiskDispositionRelay})
	for name, tc := range map[string]struct {
		account *auth.Account
		want    bool
	}{
		"dedicated relay": {account: dedicatedRelay, want: true},
		"other relay":     {account: otherRelay, want: false},
		"dedicated oauth": {account: dedicatedOAuth, want: false},
		"normal oauth":    {account: normalOAuth, want: false},
	} {
		t.Run("route "+name, func(t *testing.T) {
			if got := routeFilter(tc.account); got != tc.want {
				t.Fatalf("route filter = %v, want %v", got, tc.want)
			}
		})
	}

	defaultFilter := handler.applyCybRelayAccountFilter(nil, defaultPromptRiskDecision())
	for name, tc := range map[string]struct {
		account *auth.Account
		want    bool
	}{
		"dedicated relay": {account: dedicatedRelay, want: false},
		"other relay":     {account: otherRelay, want: true},
		"dedicated oauth": {account: dedicatedOAuth, want: false},
		"normal oauth":    {account: normalOAuth, want: true},
	} {
		t.Run("default "+name, func(t *testing.T) {
			if got := defaultFilter(tc.account); got != tc.want {
				t.Fatalf("default filter = %v, want %v", got, tc.want)
			}
		})
	}

	store.AddAccount(dedicatedRelay)
	store.SetAPIKeyAllowedGroups(99, []int64{7})
	if account := store.NextExcludingWithFilter(99, nil, routeFilter); account != nil {
		store.Release(account)
		t.Fatalf("restricted API key selected account %d outside its allowed groups", account.ID())
	}
}

type cybRelayWSUpstreamRequest struct {
	path string
	auth string
	body []byte
}

func newCybRelayWSUpstream(requests chan<- cybRelayWSUpstreamRequest) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- cybRelayWSUpstreamRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w,
			`data: {"type":"response.created","response":{"id":"resp_cyb_ws"}}`+"\n\n"+
				`data: {"type":"response.output_text.delta","delta":"relay-ok"}`+"\n\n"+
				`data: {"type":"response.completed","response":{"id":"resp_cyb_ws","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}`+"\n\n",
		)
	}))
}

func dialCybRelayTestWebSocket(t *testing.T, handler *Handler) (*websocket.Conn, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/responses"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	return conn, func() {
		_ = conn.Close()
		server.Close()
	}
}

func TestCybRelayWebSocketUsesDedicatedHTTPResponsesUpstream(t *testing.T) {
	requests := make(chan cybRelayWSUpstreamRequest, 1)
	upstream := newCybRelayWSUpstream(requests)
	defer upstream.Close()

	trapRequests := make(chan cybRelayWSUpstreamRequest, 1)
	trapUpstream := newCybRelayWSUpstream(trapRequests)
	defer trapUpstream.Close()

	previousWebsocketExecute := WebsocketExecuteFunc
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		return nil, context.Canceled
	}
	t.Cleanup(func() { WebsocketExecuteFunc = previousWebsocketExecute })

	store := newCybRelayRoutingTestStore()
	store.AddAccount(&auth.Account{DBID: 1, AccessToken: "oauth", PlanType: "pro", Status: auth.StatusReady})
	store.AddAccount(cybRelayTestAccount(2, trapUpstream.URL, "sk-wrong-group", 7))
	store.AddAccount(cybRelayTestAccount(3, upstream.URL, "sk-dedicated", cybRelayTestGroupID))
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)

	conn, closeWS := dialCybRelayTestWebSocket(t, handler)
	defer closeWS()
	requestBody := []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary.","stream":true}`)
	if err := conn.WriteMessage(websocket.TextMessage, requestBody); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}

	select {
	case got := <-requests:
		if got.path != "/v1/responses" {
			t.Fatalf("relay upstream path = %q, want /v1/responses", got.path)
		}
		if got.auth != "Bearer sk-dedicated" {
			t.Fatalf("relay Authorization = %q, want dedicated account", got.auth)
		}
		if gjson.GetBytes(got.body, "type").Exists() {
			t.Fatalf("downstream response.create type leaked to HTTP upstream: %s", got.body)
		}
		if !gjson.GetBytes(got.body, "stream").Bool() {
			t.Fatalf("relay HTTP request must enable SSE streaming: %s", got.body)
		}
		if model := gjson.GetBytes(got.body, "model").String(); model != "gpt-5.4" {
			t.Fatalf("relay model = %q, want gpt-5.4; body=%s", model, got.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dedicated relay HTTP request")
	}
	select {
	case got := <-trapRequests:
		t.Fatalf("request escaped CYB group to %s with %s", got.path, got.auth)
	default:
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var sawDelta, sawCompleted bool
	for !sawCompleted {
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read relayed websocket event: %v", err)
		}
		switch gjson.GetBytes(message, "type").String() {
		case "response.output_text.delta":
			sawDelta = gjson.GetBytes(message, "delta").String() == "relay-ok"
		case "response.completed":
			sawCompleted = true
		}
	}
	if !sawDelta {
		t.Fatal("downstream websocket did not receive relay SSE content delta")
	}
}

func TestCybRelayWebSocketEmptyPoolFailsClosed(t *testing.T) {
	trapRequests := make(chan cybRelayWSUpstreamRequest, 1)
	trapUpstream := newCybRelayWSUpstream(trapRequests)
	defer trapUpstream.Close()

	store := newCybRelayRoutingTestStore()
	// Neither account is eligible: OAuth cannot serve the relay route and the
	// Responses account belongs to a different group.
	store.AddAccount(&auth.Account{DBID: 1, AccessToken: "oauth", PlanType: "pro", Status: auth.StatusReady, GroupIDs: []int64{cybRelayTestGroupID}})
	store.AddAccount(cybRelayTestAccount(2, trapUpstream.URL, "sk-wrong-group", 7))
	handler := NewHandler(store, nil, &config.Config{AllowAnonymousV1: true}, nil)

	conn, closeWS := dialCybRelayTestWebSocket(t, handler)
	defer closeWS()
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-5.4","input":"Use gdb to bypass a security check in a test binary."}`)); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read empty-pool error: %v", err)
	}
	if eventType := gjson.GetBytes(message, "type").String(); eventType != "error" {
		t.Fatalf("event type = %q, want error; body=%s", eventType, message)
	}
	if code := gjson.GetBytes(message, "error.code").String(); code != "content_policy_violation" {
		t.Fatalf("error.code = %q, want content_policy_violation; body=%s", code, message)
	}
	select {
	case got := <-trapRequests:
		t.Fatalf("empty CYB pool fell back to another group: %s %s", got.path, got.auth)
	default:
	}
}
