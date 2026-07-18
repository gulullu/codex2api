package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

const (
	websocketLargeFrameHTTPPreflightReason = "ws_large_payload_http_preflight"
	websocketLargeFrameContextBoundKind    = "websocket_large_frame_context_bound"
)

// WebsocketFramePreflightError is returned by the registered WS executor only
// after it has built the final response.create frame, but before it acquires a
// connection, a pool slot or writes any bytes. ExecuteRequest may therefore
// switch an unbound request to HTTP without replaying an upstream operation.
type WebsocketFramePreflightError struct {
	FrameBytes   int
	LimitBytes   int
	ContextBound bool
}

func (e *WebsocketFramePreflightError) Error() string {
	if e == nil {
		return "websocket request frame exceeds the configured safe limit"
	}
	return fmt.Sprintf("websocket request frame is %d bytes and exceeds the configured %d byte safe limit", e.FrameBytes, e.LimitBytes)
}

// upstreamTransportObservation lets the request handler persist the transport
// that was actually used rather than the initially requested transport.
type upstreamTransportObservation struct {
	mu           sync.RWMutex
	observed     bool
	viaWebsocket bool
	reason       string
	frameBytes   int
	limitBytes   int
}

type upstreamTransportObservationContextKey struct{}

const contextWebsocketTransportReason = "websocketTransportReason"

func withUpstreamTransportObservation(ctx context.Context) (context.Context, *upstreamTransportObservation) {
	if ctx == nil {
		ctx = context.Background()
	}
	observation := &upstreamTransportObservation{}
	return context.WithValue(ctx, upstreamTransportObservationContextKey{}, observation), observation
}

func observeUpstreamTransport(ctx context.Context, viaWebsocket bool, reason string, frameBytes, limitBytes int) {
	if ctx == nil {
		return
	}
	observation, _ := ctx.Value(upstreamTransportObservationContextKey{}).(*upstreamTransportObservation)
	if observation == nil {
		return
	}
	observation.mu.Lock()
	observation.observed = true
	observation.viaWebsocket = viaWebsocket
	observation.reason = strings.TrimSpace(reason)
	observation.frameBytes = frameBytes
	observation.limitBytes = limitBytes
	observation.mu.Unlock()
}

func observeDefaultUpstreamTransport(ctx context.Context, viaWebsocket bool) {
	if ctx == nil {
		return
	}
	observation, _ := ctx.Value(upstreamTransportObservationContextKey{}).(*upstreamTransportObservation)
	if observation == nil {
		return
	}
	observation.mu.Lock()
	if !observation.observed {
		observation.observed = true
		observation.viaWebsocket = viaWebsocket
	}
	observation.mu.Unlock()
}

func (o *upstreamTransportObservation) ViaWebsocket(fallback bool) bool {
	if o == nil {
		return fallback
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.observed {
		return fallback
	}
	return o.viaWebsocket
}

func (o *upstreamTransportObservation) Snapshot() (reason string, frameBytes, limitBytes int) {
	if o == nil {
		return "", 0, 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.reason, o.frameBytes, o.limitBytes
}

func applyUpstreamTransportObservation(c *gin.Context, observation *upstreamTransportObservation, fallback bool) bool {
	actual := observation.ViaWebsocket(fallback)
	reason, _, _ := observation.Snapshot()
	if c != nil {
		// A Gin context is reused for every turn of the inbound Responses WS.
		// Always replace the prior turn's reason, including with an empty value,
		// so one large-frame decision cannot leak into later canonical rows.
		c.Set(contextWebsocketTransportReason, strings.TrimSpace(reason))
	}
	return actual
}

func appendWebsocketTransportAuditSignal(c *gin.Context, input *database.UsageLogInput) {
	if c == nil || input == nil {
		return
	}
	value, exists := c.Get(contextWebsocketTransportReason)
	if !exists {
		return
	}
	reason, _ := value.(string)
	if reason != websocketLargeFrameHTTPPreflightReason && reason != websocketLargeFrameContextBoundKind {
		return
	}
	signals := make([]string, 0, 4)
	if raw := strings.TrimSpace(input.RouteSignals); raw != "" {
		if err := json.Unmarshal([]byte(raw), &signals); err != nil {
			// RouteSignals is authoritative routing evidence. Preserve malformed
			// legacy content rather than silently replacing it with a transport-only
			// array; the structured log makes the data-quality issue discoverable.
			log.Printf("[WS Preflight] unable to append transport audit signal without replacing invalid route_signals: %v", err)
			return
		}
	}
	for _, signal := range signals {
		if signal == reason {
			return
		}
	}
	signals = append(signals, reason)
	encoded, err := json.Marshal(signals)
	if err == nil {
		input.RouteSignals = string(encoded)
	}
}

func websocketLargeFrameContextBoundMessage(frameErr *WebsocketFramePreflightError) string {
	frameBytes, limitBytes := 0, 0
	if frameErr != nil {
		frameBytes, limitBytes = frameErr.FrameBytes, frameErr.LimitBytes
	}
	return fmt.Sprintf("WebSocket request frame (%d bytes) exceeds the configured safe limit (%d bytes). This request is bound to an existing upstream context and cannot be switched to HTTP safely. Shorten the request or start a new conversation.", frameBytes, limitBytes)
}

func websocketLargeFrameContextBoundAPIError(frameErr *WebsocketFramePreflightError) *api.APIError {
	return api.NewAPIError(
		api.ErrorCode(websocketLargeFrameContextBoundKind),
		websocketLargeFrameContextBoundMessage(frameErr),
		api.ErrorTypeInvalidRequest,
	)
}

func websocketContextBoundFrameError(err error) (*WebsocketFramePreflightError, bool) {
	var frameErr *WebsocketFramePreflightError
	if !errors.As(err, &frameErr) || frameErr == nil || !frameErr.ContextBound {
		return nil, false
	}
	return frameErr, true
}

// executeRequestWithWebsocketFramePreflight keeps the initially selected
// account and caller-owned scheduler lease while choosing the transport. The
// WS executor returns its typed decision before any connection/slot/write. An
// unbound request then uses the caller-provided normal HTTP body and HTTP
// session identity in this same handler attempt. Context-bound requests remain
// local errors for the handler to publish without account/circuit penalties.
func executeRequestWithWebsocketFramePreflight(
	ctx context.Context,
	account *auth.Account,
	websocketBody, httpBody []byte,
	websocketSessionID, httpSessionID, proxyURL, apiKey string,
	deviceCfg *DeviceProfileConfig,
	headers http.Header,
	useWebsocket bool,
) (*http.Response, error, bool) {
	if !useWebsocket {
		resp, err := ExecuteRequest(ctx, account, httpBody, httpSessionID, proxyURL, apiKey, deviceCfg, headers, false)
		return resp, err, false
	}

	resp, err := ExecuteRequest(ctx, account, websocketBody, websocketSessionID, proxyURL, apiKey, deviceCfg, headers, true)
	var frameErr *WebsocketFramePreflightError
	if !errors.As(err, &frameErr) {
		return resp, err, true
	}
	if frameErr.ContextBound {
		observeUpstreamTransport(ctx, false, websocketLargeFrameContextBoundKind, frameErr.FrameBytes, frameErr.LimitBytes)
		log.Printf("[WS Preflight] transport=none reason=%s account=%d frame_bytes=%d limit_bytes=%d context_bound=true", websocketLargeFrameContextBoundKind, account.ID(), frameErr.FrameBytes, frameErr.LimitBytes)
		return nil, frameErr, false
	}

	observeUpstreamTransport(ctx, false, websocketLargeFrameHTTPPreflightReason, frameErr.FrameBytes, frameErr.LimitBytes)
	log.Printf("[WS Preflight] transport=http reason=%s account=%d frame_bytes=%d limit_bytes=%d context_bound=false", websocketLargeFrameHTTPPreflightReason, account.ID(), frameErr.FrameBytes, frameErr.LimitBytes)
	resp, err = ExecuteRequest(ctx, account, httpBody, httpSessionID, proxyURL, apiKey, deviceCfg, headers, false)
	return resp, err, false
}
