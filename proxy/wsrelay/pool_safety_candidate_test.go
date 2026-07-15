package wsrelay

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/auth"
	"github.com/gorilla/websocket"
)

// A reused physical socket must never forward a second response identity into
// the current logical request. The current implementation forwards the frame
// before noticing anything because it has no response identity guard.
func TestCandidateRejectsResponseIdentityMismatchBeforeForwarding(t *testing.T) {
	r := &WsResponse{}
	forwarded := 0
	callback := func([]byte) bool {
		forwarded++
		return true
	}

	if err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":0,"response":{"id":"resp_A"}}`), callback); err != nil {
		t.Fatalf("first response.created: %v", err)
	}
	err := r.handleMessage([]byte(`{"type":"response.created","sequence_number":0,"response":{"id":"resp_B"}}`), callback)
	if err == nil {
		t.Fatal("mismatched response identity was accepted")
	}
	if forwarded != 1 {
		t.Fatalf("forwarded frames = %d, want only the first identity", forwarded)
	}
	r.mu.Lock()
	broken := r.connBroken
	r.mu.Unlock()
	if !broken {
		t.Fatal("response identity mismatch did not poison the connection")
	}
}

// WebSocket request headers are frozen at the HTTP upgrade. Reusing a socket
// after a per-request/per-turn header changes silently represents request B as
// request A upstream. Until those fields can be carried per response.create,
// a changed handshake identity must force a fresh physical connection.
func TestCandidateHandshakeIdentityChangeForcesFreshConnection(t *testing.T) {
	var handshakes atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		connectionNumber := handshakes.Add(1)
		requestNumber := 0
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			requestNumber++
			responseID := fmt.Sprintf("resp_%d_%d", connectionNumber, requestNumber)
			frames := [][]byte{
				[]byte(fmt.Sprintf(`{"type":"response.created","sequence_number":0,"response":{"id":%q}}`, responseID)),
				[]byte(fmt.Sprintf(`{"type":"response.completed","sequence_number":1,"response":{"id":%q}}`, responseID)),
			}
			for _, frame := range frames {
				if err := conn.WriteMessage(websocket.TextMessage, frame); err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := NewManager()
	t.Cleanup(manager.Stop)
	account := &auth.Account{DBID: 42, DynamicConcurrencyLimit: 4}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	runTurn := func(requestID string) {
		t.Helper()
		headers := http.Header{
			"X-Client-Request-Id": {requestID},
			"X-Codex-Turn-State":  {"turn-" + requestID},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wc, pending, slot, err := manager.AcquireReusableConnection(
			ctx,
			account,
			wsURL,
			"shared-api-key",
			"stateless-"+requestID,
			1,
			headers,
			"",
		)
		if err != nil {
			t.Fatalf("AcquireReusableConnection(%s): %v", requestID, err)
		}
		if err := wc.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create"}`)); err != nil {
			t.Fatalf("WriteMessage(%s): %v", requestID, err)
		}
		response := &WsResponse{
			conn:        wc,
			pendingReq:  pending,
			sessionID:   slot,
			manager:     manager,
			apiKey:      "api-key-A",
			readErrChan: make(chan error, 1),
		}
		if err := response.ReadStream(func([]byte) bool { return true }); err != nil {
			t.Fatalf("ReadStream(%s): %v", requestID, err)
		}
		if err := response.Close(); err != nil {
			t.Fatalf("Close(%s): %v", requestID, err)
		}
	}

	runTurn("request-A")
	runTurn("request-B")
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("physical handshakes = %d, want 2 when per-request/per-turn identity changes", got)
	}
}
