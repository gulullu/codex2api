package proxy

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
)

func relayTransparentFailureStatusBody(outcome streamOutcome, terminalFailurePayload []byte) (int, []byte) {
	if len(terminalFailurePayload) > 0 {
		return outcome.logStatusCode, responseFailedErrorBody(terminalFailurePayload)
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    "upstream_error",
			"message": outcome.failureMessage,
		},
	})
	// A pre-first-byte transport/stream break has no upstream HTTP status.
	// Expose it as 502 instead of the internal audit-only 598 code.
	return 502, body
}

// relayCircuitAttempt owns the breaker permit for exactly one upstream
// attempt. The once guard is deliberate: stream and HTTP paths have several
// layers of cleanup, and a duplicate 500/503 report must not count twice
// toward the rolling failure threshold.
type relayCircuitAttempt struct {
	store  *auth.Store
	permit auth.RelayCircuitPermit
	once   sync.Once
}

func inactiveRelayCircuitAttempt() *relayCircuitAttempt {
	return &relayCircuitAttempt{}
}

func newRelayCircuitAttempt(store *auth.Store, permit auth.RelayCircuitPermit) *relayCircuitAttempt {
	return &relayCircuitAttempt{store: store, permit: permit}
}

func (a *relayCircuitAttempt) finish(fn func(*auth.Store, auth.RelayCircuitPermit)) {
	if a == nil {
		return
	}
	a.once.Do(func() {
		if a.store == nil || !a.permit.Active {
			return
		}
		fn(a.store, a.permit)
	})
}

// Failure reports only statuses owned by the Relay breaker. Other outcomes
// release the bounded permit without changing the breaker state.
func (a *relayCircuitAttempt) Failure(statusCode int) {
	// 598 is an internal marker shared by stream/audit code, not an upstream
	// HTTP response. It is only breaker evidence when the caller has proved
	// that the failure came from the upstream transport via the explicit
	// helpers below. This prevents client cancellation, downstream write
	// failure, first-token guards, and WS frame fallback from opening a front.
	if statusCode == auth.RelayCircuitTransportFailureStatus {
		a.Abandon()
		return
	}
	a.finish(func(store *auth.Store, permit auth.RelayCircuitPermit) {
		if auth.IsRelayCircuitFailureStatus(statusCode) {
			store.ReportRelayCircuitFailure(permit, statusCode)
		} else {
			store.ReportRelayGuardianFailure(permit.Guardian, statusCode)
			store.AbandonRelayCircuitRequest(permit)
		}
	})
}

// UpstreamTransportFailure records a Relay-only failure that produced no HTTP
// response. It deliberately rejects soft first-token timeouts, WebSocket frame
// size fallback, and any error observed after the downstream request context
// was canceled. The return value tells retry policy to hard-exclude this front
// door even when the global transport policy is sticky.
func (a *relayCircuitAttempt) UpstreamTransportFailure(ctx context.Context, kind string, softFirstTokenTimeout bool) bool {
	if a == nil || !a.permit.Active || softFirstTokenTimeout {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if kind != "transport" && kind != "timeout" {
		return false
	}
	a.finish(func(store *auth.Store, permit auth.RelayCircuitPermit) {
		store.ReportRelayCircuitFailure(permit, auth.RelayCircuitTransportFailureStatus)
	})
	return true
}

// FinishStreamOutcome centralizes the distinction between a real upstream
// stream break and an internal 598 marker produced for a non-upstream cause.
// Callers may use the return value to hard-exclude the failed Relay front.
func (a *relayCircuitAttempt) FinishStreamOutcome(ctx context.Context, outcome streamOutcome, softFirstTokenTimeout bool) bool {
	if outcome.logStatusCode != auth.RelayCircuitTransportFailureStatus {
		a.Failure(outcome.logStatusCode)
		return false
	}
	if a.UpstreamTransportFailure(ctx, outcome.failureKind, softFirstTokenTimeout) {
		return true
	}
	a.Abandon()
	return false
}

func (a *relayCircuitAttempt) Success() {
	a.finish(func(store *auth.Store, permit auth.RelayCircuitPermit) {
		store.ReportRelayCircuitSuccess(permit)
	})
}

func (a *relayCircuitAttempt) Abandon() {
	a.finish(func(store *auth.Store, permit auth.RelayCircuitPermit) {
		store.AbandonRelayCircuitRequest(permit)
	})
}

// Release finalizes an otherwise-unreported attempt before returning the
// account to the scheduler. Calling Failure or Success first makes Abandon a
// no-op through the once guard.
func (a *relayCircuitAttempt) Release(store *auth.Store, account *auth.Account) {
	a.Abandon()
	if store != nil && account != nil {
		store.Release(account)
	}
}

// nextCircuitPermittedRoutedAccountForSession keeps a scheduler/Begin race out
// of the logical attempt count. If suspect/probation capacity changes between
// selection and permit acquisition, release the account and reselect here. No
// upstream attempt or audit attempt has started yet.
func (h *Handler) nextCircuitPermittedRoutedAccountForSession(
	c *gin.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	baseFilter auth.AccountFilter,
	required promptRiskDecision,
) (*auth.Account, string, promptRiskDecision, *relayCircuitAttempt) {
	return h.nextCircuitPermittedRoutedAccountForSessionWithMode(c, affinityKey, apiKeyID, exclusions, baseFilter, baseFilter, required, true)
}

func (h *Handler) nextCircuitPermittedRoutedAccountForSessionWithMode(
	c *gin.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	selectionFilter auth.AccountFilter,
	permitPoolFilter auth.AccountFilter,
	required promptRiskDecision,
	waitForCapacity bool,
) (*auth.Account, string, promptRiskDecision, *relayCircuitAttempt) {
	for {
		account, proxyURL, selected := h.nextRoutedAccountForSessionWithMode(
			c,
			c.Request.Context(),
			affinityKey,
			apiKeyID,
			exclusions,
			selectionFilter,
			required,
			waitForCapacity,
		)
		if account == nil {
			return nil, "", selected, inactiveRelayCircuitAttempt()
		}
		if !selected.routesToCybRelay() || !account.IsOpenAIResponsesAPI() {
			return account, proxyURL, selected, inactiveRelayCircuitAttempt()
		}

		// Last-resort/open decisions must use the same request eligibility as the
		// scheduler. A healthy peer that this API key cannot use is not real
		// fallback capacity for the current logical request.
		poolFilter := func(candidate *auth.Account) bool {
			if candidate == nil || !candidate.AllowsAPIKey(apiKeyID) || !h.store.APIKeyAllowsAccount(apiKeyID, candidate) {
				return false
			}
			return permitPoolFilter == nil || permitPoolFilter(candidate)
		}
		permit, ok := h.store.BeginRelayCircuitRequestForLogicalRequestWithFilter(account, logicalRequestID(c), poolFilter)
		if ok {
			return account, proxyURL, selected, newRelayCircuitAttempt(h.store, permit)
		}

		// Selection increments ActiveRequests and dispatch counters. Release the
		// account immediately; hard exclusion prevents this logical request from
		// spinning on the same bounded account.
		h.store.Release(account)
		if exclusions == nil {
			return nil, "", selected, inactiveRelayCircuitAttempt()
		}
		exclusions.MarkHard(account.ID())
	}
}

// nextCircuitPermittedRoutedAccountForSessionWithStickyFallback gives the
// retained account one immediate, fully policy-checked chance. If it cannot be
// acquired, ordinary requests resume with the original filter and the full
// OAuth/Relay scheduler. Explicit route-owner errors remain fail-closed.
func (h *Handler) nextCircuitPermittedRoutedAccountForSessionWithStickyFallback(
	c *gin.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	baseFilter auth.AccountFilter,
	required promptRiskDecision,
	sticky *requestStickyRetryState,
) (*auth.Account, string, promptRiskDecision, *relayCircuitAttempt) {
	if preferenceFilter, retainedProxyURL, ok := sticky.TakeAccountFilter(baseFilter); ok {
		account, _, selected, attempt := h.nextCircuitPermittedRoutedAccountForSessionWithMode(
			c, affinityKey, apiKeyID, exclusions, preferenceFilter, baseFilter, required, false,
		)
		if account != nil {
			return account, retainedProxyURL, selected, attempt
		}
		if c.Request.Context().Err() != nil {
			return nil, "", selected, attempt
		}
		if _, routeBoundFailure := routeSelectionErrorFromContext(c); routeBoundFailure {
			return nil, "", selected, attempt
		}
	}
	return h.nextCircuitPermittedRoutedAccountForSession(c, affinityKey, apiKeyID, exclusions, baseFilter, required)
}
