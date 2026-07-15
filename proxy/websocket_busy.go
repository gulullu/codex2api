package proxy

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// ErrWebsocketSessionBusy marks an upstream WebSocket session whose single
// in-flight request slot did not become available before the acquire timeout.
// It is not an account-health or gateway failure and must not be handled by
// the generic sticky transport retry policy.
var ErrWebsocketSessionBusy = errors.New("upstream websocket session busy")

// ErrWebsocketLocalCapacity marks local WebSocket connection capacity that
// stayed full until the acquire timeout. Like a busy session, it is local
// transport contention rather than evidence that the upstream account failed.
var ErrWebsocketLocalCapacity = errors.New("local websocket connection capacity exhausted")

// ErrWebsocketSafePoolFallback means automatic safe reuse was disabled for the
// selected account before any request bytes were written (for example by a
// process-local compatibility/isolation fuse). Context-independent requests may
// retain the same account lease and use HTTP; connection-local continuations
// must fail closed instead of opening one WS per request.
var ErrWebsocketSafePoolFallback = errors.New("safe websocket reuse unavailable; use same-account HTTP")

// ErrWebsocketContinuationUnavailable means a previous_response_id can no
// longer be resumed on the exact WS connection that owns its upstream state.
// Retrying on an ordinary slot could lose context or duplicate a turn, so this
// is a terminal local-continuity error rather than an account-health failure.
var ErrWebsocketContinuationUnavailable = errors.New("upstream websocket continuation unavailable")

// ErrWebsocketWriteUncertain means response.create was handed to the socket but
// the client could not prove whether the upstream accepted it. Replaying on the
// same or another account could duplicate a turn.
var ErrWebsocketWriteUncertain = errors.New("upstream websocket write outcome uncertain")

// ErrWebsocketReadUncertain means the request was committed but the transport
// failed before a validated terminal response. It is terminal for this logical
// request and is not evidence that the account itself is unhealthy.
var ErrWebsocketReadUncertain = errors.New("upstream websocket response outcome uncertain")

// ErrWebsocketIsolationViolation marks a safe-pool frame that crossed or could
// not be proven to belong to the active owner/lease. The connection is poisoned
// and account-local WS reuse is fused, but the account must not be penalized.
var ErrWebsocketIsolationViolation = errors.New("upstream websocket isolation violation")

const upstreamErrorKindWebsocketBusy = "websocket_busy_session"
const upstreamErrorKindWebsocketCapacity = "websocket_local_capacity"
const upstreamErrorKindWebsocketSafePoolFallback = "websocket_safe_pool_fallback"
const upstreamErrorKindWebsocketContinuation = "websocket_continuation_unavailable"
const upstreamErrorKindWebsocketWriteUncertain = "websocket_write_uncertain"
const upstreamErrorKindWebsocketReadUncertain = "websocket_read_uncertain"
const upstreamErrorKindWebsocketIsolation = "websocket_isolation_violation"

func isWebsocketNoReplayError(err error) bool {
	return errors.Is(err, ErrWebsocketWriteUncertain) ||
		errors.Is(err, ErrWebsocketReadUncertain) ||
		errors.Is(err, ErrWebsocketIsolationViolation)
}

func websocketNoReplayKind(err error) string {
	switch {
	case errors.Is(err, ErrWebsocketIsolationViolation):
		return upstreamErrorKindWebsocketIsolation
	case errors.Is(err, ErrWebsocketWriteUncertain):
		return upstreamErrorKindWebsocketWriteUncertain
	case errors.Is(err, ErrWebsocketReadUncertain):
		return upstreamErrorKindWebsocketReadUncertain
	default:
		return ""
	}
}

func isWebsocketSessionBusyError(err error) bool {
	return errors.Is(err, ErrWebsocketSessionBusy)
}

func isWebsocketLocalCapacityError(err error) bool {
	return errors.Is(err, ErrWebsocketLocalCapacity)
}

func isWebsocketLocalContentionError(err error) bool {
	return isWebsocketSessionBusyError(err) || isWebsocketLocalCapacityError(err) || errors.Is(err, ErrWebsocketSafePoolFallback) || errors.Is(err, ErrWebsocketContinuationUnavailable)
}

func websocketLocalContentionKind(err error) string {
	if isWebsocketLocalCapacityError(err) {
		return upstreamErrorKindWebsocketCapacity
	}
	if isWebsocketSessionBusyError(err) {
		return upstreamErrorKindWebsocketBusy
	}
	if errors.Is(err, ErrWebsocketSafePoolFallback) {
		return upstreamErrorKindWebsocketSafePoolFallback
	}
	if errors.Is(err, ErrWebsocketContinuationUnavailable) {
		return upstreamErrorKindWebsocketContinuation
	}
	return ""
}

func websocketLocalContentionSource(err error) string {
	if errors.Is(err, ErrWebsocketLocalCapacity) {
		return "local_capacity"
	}
	if errors.Is(err, ErrWebsocketContinuationUnavailable) {
		return "continuation_unavailable"
	}
	if errors.Is(err, ErrWebsocketSafePoolFallback) {
		return "safe_pool_fallback"
	}
	return "busy_session"
}

// shouldFallbackWebsocketLocalContentionToHTTP allows a one-time, same-account
// HTTP downgrade for local WS contention only when the request does not depend
// on an explicitly serialized upstream conversation. The account lease and
// routing decision are retained by websocketHTTPFallbackState, so encrypted-
// content ownership and account affinity are preserved without redispatch.
func shouldFallbackWebsocketLocalContentionToHTTP(err error, useWebsocket bool, rawBody []byte, sessionIdentity requestSessionIdentity) bool {
	if !useWebsocket || !isWebsocketLocalContentionError(err) {
		return false
	}
	if errors.Is(err, ErrWebsocketContinuationUnavailable) {
		return false
	}
	if errors.Is(err, ErrWebsocketSafePoolFallback) {
		return strings.TrimSpace(gjson.GetBytes(rawBody, "previous_response_id").String()) == ""
	}
	if strings.TrimSpace(sessionIdentity.explicitUpstreamID) != "" {
		return false
	}
	return strings.TrimSpace(gjson.GetBytes(rawBody, "previous_response_id").String()) == ""
}

func sendCanonicalRequestFailure(c *gin.Context, err error) {
	var structured *Error
	if errors.As(err, &structured) && structured != nil && structured.HTTPStatus >= 400 && structured.HTTPStatus <= 599 {
		c.JSON(structured.HTTPStatus, structured.ToGinH())
		return
	}

	statusCode, _, message := canonicalRequestFailure(err)
	c.JSON(statusCode, gin.H{
		"error": gin.H{
			"type":    "upstream_error",
			"message": message,
		},
	})
}
