package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestResponsesWebSocketGrokChannelUsesRelayStyleHTTPUpstream(t *testing.T) {
	requests := make(chan cybRelayWSUpstreamRequest, 1)
	upstream := newCybRelayWSUpstream(requests)
	defer upstream.Close()

	previousWebsocketExecute := WebsocketExecuteFunc
	var codexWebsocketCalls atomic.Int32
	WebsocketExecuteFunc = func(context.Context, *auth.Account, []byte, string, string, string, *DeviceProfileConfig, http.Header, string) (*http.Response, error) {
		codexWebsocketCalls.Add(1)
		return nil, errors.New("Grok must not enter the Codex OAuth websocket executor")
	}
	t.Cleanup(func() { WebsocketExecuteFunc = previousWebsocketExecute })

	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "codex2api.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()

	const apiKey = "sk-grok-ws-channel-test"
	if _, err := db.InsertAPIKeyWithOptions(context.Background(), database.APIKeyInput{
		Name: "grok-ws-channel",
		Key:  apiKey,
		Limits: database.APIKeyLimits{
			UpstreamChannel: database.UpstreamChannelGrok,
		},
	}); err != nil {
		t.Fatalf("InsertAPIKeyWithOptions: %v", err)
	}

	store := auth.NewStore(db, nil, &database.SystemSettings{
		MaxConcurrency:  2,
		TestConcurrency: 1,
		TestModel:       "gpt-5.4",
	})
	store.AddAccount(&auth.Account{
		DBID:         71,
		UpstreamType: auth.UpstreamGrok,
		BaseURL:      upstream.URL,
		APIKey:       "xai-test-key",
		PlanType:     "api",
		Status:       auth.StatusReady,
	})
	handler := NewHandler(store, db, &config.Config{}, nil)

	conn, closeWS := dialCybRelayTestWebSocketWithHeaders(t, handler, http.Header{
		"Authorization": []string{"Bearer " + apiKey},
	})
	defer closeWS()
	requestBody := []byte(`{"type":"response.create","model":"gpt-5.4","input":"hello from Grok channel","stream":true}`)
	if err := conn.WriteMessage(websocket.TextMessage, requestBody); err != nil {
		t.Fatalf("write websocket request: %v", err)
	}

	select {
	case got := <-requests:
		if got.path != "/v1/responses" {
			t.Fatalf("Grok upstream path = %q, want /v1/responses", got.path)
		}
		if got.auth != "Bearer xai-test-key" {
			t.Fatalf("Grok Authorization = %q, want Grok API key", got.auth)
		}
		if gjson.GetBytes(got.body, "type").Exists() {
			t.Fatalf("downstream response.create type leaked to Grok HTTP upstream: %s", got.body)
		}
		if !gjson.GetBytes(got.body, "stream").Bool() {
			t.Fatalf("Grok HTTP request must enable SSE streaming: %s", got.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Grok RelayStyle HTTP request")
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read Grok websocket event: %v", err)
		}
		if gjson.GetBytes(message, "type").String() == "response.completed" {
			break
		}
	}
	if got := codexWebsocketCalls.Load(); got != 0 {
		t.Fatalf("Grok request entered Codex OAuth websocket executor %d time(s)", got)
	}
}

func dialCybRelayTestWebSocketWithHeaders(t *testing.T, handler *Handler, headers http.Header) (*websocket.Conn, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)
	server := httptest.NewServer(router)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/responses"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
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
