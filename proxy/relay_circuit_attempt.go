package proxy

import (
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
// abandon a half-open lease without changing the breaker state.
func (a *relayCircuitAttempt) Failure(statusCode int) {
	a.finish(func(store *auth.Store, permit auth.RelayCircuitPermit) {
		if auth.IsRelayCircuitFailureStatus(statusCode) {
			store.ReportRelayCircuitFailure(permit, statusCode)
		} else {
			store.AbandonRelayCircuitRequest(permit)
		}
	})
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
// of the logical attempt count. When an expired half-open account was selected
// concurrently but another request won its single probe lease, release it and
// reselect inside this function. No upstream attempt or audit attempt has
// started yet.
func (h *Handler) nextCircuitPermittedRoutedAccountForSession(
	c *gin.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	baseFilter auth.AccountFilter,
	required promptRiskDecision,
) (*auth.Account, string, promptRiskDecision, *relayCircuitAttempt) {
	for {
		account, proxyURL, selected := h.nextRoutedAccountForSession(
			c,
			c.Request.Context(),
			affinityKey,
			apiKeyID,
			exclusions,
			baseFilter,
			required,
		)
		if account == nil {
			return nil, "", selected, inactiveRelayCircuitAttempt()
		}
		if !selected.routesToCybRelay() || !account.IsOpenAIResponsesAPI() {
			return account, proxyURL, selected, inactiveRelayCircuitAttempt()
		}

		permit, ok := h.store.BeginRelayCircuitRequest(account)
		if ok {
			return account, proxyURL, selected, newRelayCircuitAttempt(h.store, permit)
		}

		// Selection increments ActiveRequests and dispatch counters. Release the
		// account immediately; hard exclusion prevents this logical request from
		// spinning on the same half-open account.
		h.store.Release(account)
		if exclusions == nil {
			return nil, "", selected, inactiveRelayCircuitAttempt()
		}
		exclusions.MarkHard(account.ID())
	}
}
