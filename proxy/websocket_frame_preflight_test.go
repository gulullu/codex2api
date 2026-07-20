package proxy

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func TestUpstreamTransportObservationClearsPriorInboundWSTurnReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	firstCtx, first := withUpstreamTransportObservation(context.Background())
	observeUpstreamTransport(firstCtx, false, websocketLargeFrameHTTPPreflightReason, 17, 16)
	if got := applyUpstreamTransportObservation(c, first, true); got {
		t.Fatal("first turn actual transport = websocket, want HTTP")
	}
	if value, _ := c.Get(contextWebsocketTransportReason); value != websocketLargeFrameHTTPPreflightReason {
		t.Fatalf("first turn reason = %#v", value)
	}

	secondCtx, second := withUpstreamTransportObservation(context.Background())
	observeUpstreamTransport(secondCtx, true, "", 0, 0)
	if got := applyUpstreamTransportObservation(c, second, true); !got {
		t.Fatal("second turn actual transport = HTTP, want websocket")
	}
	if value, _ := c.Get(contextWebsocketTransportReason); value != "" {
		t.Fatalf("second turn inherited prior reason = %#v", value)
	}
}

func TestAppendWebsocketTransportAuditSignalPreservesAndDeduplicates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(contextWebsocketTransportReason, websocketLargeFrameHTTPPreflightReason)
	input := &database.UsageLogInput{RouteSignals: `["local_threshold"]`}

	appendWebsocketTransportAuditSignal(c, input)
	appendWebsocketTransportAuditSignal(c, input)
	if got, want := input.RouteSignals, `["local_threshold","ws_large_payload_http_preflight"]`; got != want {
		t.Fatalf("route signals = %s, want %s", got, want)
	}

	c.Set(contextWebsocketTransportReason, websocketLargeFrameSameAccountHTTPReason)
	sameAccountInput := &database.UsageLogInput{RouteSignals: `["encrypted_owner_hit"]`}
	appendWebsocketTransportAuditSignal(c, sameAccountInput)
	appendWebsocketTransportAuditSignal(c, sameAccountInput)
	if got, want := sameAccountInput.RouteSignals, `["encrypted_owner_hit","ws_large_context_same_account_http_preflight"]`; got != want {
		t.Fatalf("same-account route signals = %s, want %s", got, want)
	}

	malformed := &database.UsageLogInput{RouteSignals: `legacy-not-json`}
	appendWebsocketTransportAuditSignal(c, malformed)
	if malformed.RouteSignals != `legacy-not-json` {
		t.Fatalf("malformed route signals replaced: %q", malformed.RouteSignals)
	}
}

func TestWebsocketFramePreflightPolicyForHTTPKeepsPreviousResponseStrict(t *testing.T) {
	if got := websocketFramePreflightPolicyForHTTP([]byte(`{"model":"gpt-5.4","previous_response_id":"resp_owner","input":"continue"}`)); got != websocketFramePreflightStrict {
		t.Fatalf("previous_response_id policy = %v, want strict", got)
	}
	if got := websocketFramePreflightPolicyForHTTP([]byte(`{"model":"gpt-5.4","input":"full context"}`)); got != websocketFramePreflightAllowSameAccountHTTP {
		t.Fatalf("full-context HTTP policy = %v, want same-account HTTP", got)
	}
}
