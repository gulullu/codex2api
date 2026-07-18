package proxy

import (
	"context"
	"log"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

const (
	relayOverflowSignal = "oauth_no_dispatch_slot"
)

func accountFilterAnd(left, right auth.AccountFilter) auth.AccountFilter {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return func(account *auth.Account) bool {
		return left(account) && right(account)
	}
}

func accountFilterOr(left, right auth.AccountFilter) auth.AccountFilter {
	return func(account *auth.Account) bool {
		return (left != nil && left(account)) || (right != nil && right(account))
	}
}

func oauthOnlyAccountFilter(base auth.AccountFilter) auth.AccountFilter {
	return accountFilterAnd(base, func(account *auth.Account) bool {
		return account != nil && !account.IsOpenAIResponsesAPI()
	})
}

func overflowPromptRiskDecision() promptRiskDecision {
	return promptRiskDecision{
		Disposition: promptRiskDispositionRelay,
		Reason:      "OAuth capacity unavailable; overflowed to relay pool",
		Signals:     []string{relayOverflowSignal},
		RouteSource: cybRelayRouteSourceOverflow,
	}
}

func (h *Handler) relayCircuitRequestPoolFilter(apiKeyID int64, relayFilter auth.AccountFilter) auth.AccountFilter {
	return accountFilterAnd(relayFilter, func(account *auth.Account) bool {
		return h != nil && h.store != nil && account != nil &&
			account.AllowsAPIKey(apiKeyID) && h.store.APIKeyAllowsAccount(apiKeyID, account)
	})
}

// nextRelayAccountForSessionWithInvariant gives the request-scoped Relay pool
// one availability repair pass after the ordinary scheduler has no candidate.
// The Store owns the atomic last-resort decision; this layer supplies the same
// model, routing, API-key and exclusion authority used by real selection.
func (h *Handler) nextRelayAccountForSessionWithInvariant(
	affinityKey string,
	apiKeyID int64,
	exclude map[int64]bool,
	relayFilter auth.AccountFilter,
) (*auth.Account, string) {
	account, proxyURL := h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, relayFilter)
	if account != nil || h == nil || h.store == nil {
		return account, proxyURL
	}
	requestPoolFilter := h.relayCircuitRequestPoolFilter(apiKeyID, relayFilter)
	if !h.store.EnsureRelayCircuitRequestPoolInvariant(requestPoolFilter, exclude) {
		return nil, ""
	}
	return h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, relayFilter)
}

func (h *Handler) nextRetryRelayAccountForSession(
	ctx context.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	relayFilter auth.AccountFilter,
) (*auth.Account, string) {
	if h == nil || h.store == nil {
		return nil, ""
	}
	for {
		exclude := exclusions.ForSelection()
		account, proxyURL := h.nextRelayAccountForSessionWithInvariant(affinityKey, apiKeyID, exclude, relayFilter)
		if account != nil {
			return account, proxyURL
		}
		account, proxyURL = h.store.WaitForSessionAvailableWithFilter(
			ctx,
			affinityKey,
			30*time.Second,
			apiKeyID,
			exclude,
			relayFilter,
		)
		if account != nil {
			return account, proxyURL
		}
		if exclusions == nil || !exclusions.ResetSoft() {
			return nil, ""
		}
		log.Printf("first-token soft exclusions exhausted; retrying Relay routing")
	}
}

func (h *Handler) setSelectedRouteDecision(c *gin.Context, decision promptRiskDecision) promptRiskDecision {
	for _, signal := range encryptedContextSignalsFromContext(c) {
		decision.Signals = appendUniqueRouteSignal(decision.Signals, signal)
	}
	setPromptRiskDecisionContext(c, decision, h.cybRelayConfig().GroupID)
	return decision
}

func (h *Handler) failUncertainEncryptedOwner(
	c *gin.Context,
	owner responseRouteOwner,
	required promptRiskDecision,
	extraSignal string,
) promptRiskDecision {
	decision := encryptedContextPromptRiskDecision(owner)
	if required.routesToCybRelay() {
		decision = required
		decision.RouteSource = cybRelayRouteSourcePin
		decision.PinKind = encryptedContextPinKind
		decision.RoutePinned = true
		decision.Signals = appendUniqueRouteSignal(decision.Signals, encryptedOwnerHitSignal)
	}
	decision.Signals = appendUniqueRouteSignal(decision.Signals, extraSignal)
	decision.Reason = "encrypted context owner timed out before first token; request was not replayed or switched"
	setRouteSelectionError(c, encryptedOwnerAttemptUncertain, "The account that owns encrypted_content timed out before first token; the request was not replayed or switched because upstream completion is uncertain")
	return h.setSelectedRouteDecision(c, decision)
}

// nextRoutedAccountForSession keeps policy-triggered traffic Relay-only, while
// allowing ordinary traffic to spill into the configured Relay group when no
// OAuth account can be acquired immediately. Account acquisition remains
// atomic because both paths reuse Store's existing CAS-based selectors.
func (h *Handler) nextRoutedAccountForSession(
	c *gin.Context,
	ctx context.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	baseFilter auth.AccountFilter,
	required promptRiskDecision,
) (*auth.Account, string, promptRiskDecision) {
	return h.nextRoutedAccountForSessionWithMode(c, ctx, affinityKey, apiKeyID, exclusions, baseFilter, required, true)
}

// nextRoutedAccountForSessionWithMode keeps all route-owner and Relay-only
// invariants shared between ordinary selection and the request-local sticky
// preference probe. The probe uses waitForCapacity=false: it gets one atomic
// immediate chance at the retained account, then the caller falls back to the
// full official scheduler instead of waiting behind that one account.
func (h *Handler) nextRoutedAccountForSessionWithMode(
	c *gin.Context,
	ctx context.Context,
	affinityKey string,
	apiKeyID int64,
	exclusions *retryAccountExclusions,
	baseFilter auth.AccountFilter,
	required promptRiskDecision,
	waitForCapacity bool,
) (*auth.Account, string, promptRiskDecision) {
	clearRouteSelectionError(c)
	if owner, ok := responseRouteOwnerFromContext(c); ok {
		if encryptedOwner, encryptedOK := encryptedContextOwnerFromContext(c); encryptedOK {
			if encryptedOwner.AccountID != owner.AccountID {
				markEncryptedContextDowngrade(c, encryptedOwnerConflictSignal)
			} else if exclusions != nil && exclusions.IsSoft(owner.AccountID) {
				// previous_response_id still owns exact routing for ordinary requests.
				// When the same request also carries owner-bound encrypted_content,
				// however, its uncertain first attempt must not be replayed even to that
				// exact owner.
				decision := h.failUncertainEncryptedOwner(c, encryptedOwner, required, responseOwnerRouteSignal)
				return nil, "", decision
			}
		}
		ownerIsRelay := owner.AccountType == auth.UpstreamOpenAIResponses || owner.RouteClass == cybRelayRouteClass
		if required.routesToCybRelay() && !ownerIsRelay {
			conflict := required
			conflict.RouteSource = cybRelayRouteSourceContinuation
			conflict.Reason = "previous_response_id belongs to OAuth; resend full context without previous_response_id to use Relay"
			conflict.Signals = appendUniqueRouteSignal(conflict.Signals, responseOwnerRouteSignal)
			setRouteSelectionError(c, routeSwitchRequiresReplay, conflict.Reason)
			conflict = h.setSelectedRouteDecision(c, conflict)
			return nil, "", conflict
		}
		decision := continuationPromptRiskDecision(owner)
		if required.routesToCybRelay() {
			decision = required
			decision.RouteSource = cybRelayRouteSourceContinuation
			decision.Reason = "continued on the Relay account that owns previous_response_id"
			decision.Signals = appendUniqueRouteSignal(decision.Signals, responseOwnerRouteSignal)
		}
		// A continuation cannot move to another account because the upstream
		// owns previous_response_id state. Once that exact owner has failed in
		// this logical request, fail explicitly instead of waiting 30 seconds
		// for an account that the hard-exclusion set makes impossible to select.
		if exclusions != nil && exclusions.IsHard(owner.AccountID) {
			setRouteSelectionError(c, continuationOwnerUnavailable, "The account that owns previous_response_id is unavailable; retry later or resend full context")
			decision = h.setSelectedRouteDecision(c, decision)
			return nil, "", decision
		}
		ownerBaseFilter := oauthOnlyAccountFilter(baseFilter)
		if ownerIsRelay {
			ownerBaseFilter = h.applyCybRelayAccountFilter(baseFilter, promptRiskDecision{Disposition: promptRiskDispositionRelay})
		}
		ownerFilter := responseOwnerAccountFilter(ownerBaseFilter, owner)
		var account *auth.Account
		var proxyURL string
		if waitForCapacity {
			account, proxyURL = h.nextRetryAccountForSession(ctx, affinityKey, apiKeyID, exclusions, ownerFilter)
		} else {
			account, proxyURL = h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclusions.ForSelection(), ownerFilter)
		}
		if account == nil && waitForCapacity {
			setRouteSelectionError(c, continuationOwnerUnavailable, "The account that owns previous_response_id is unavailable; retry later or resend full context")
		}
		decision = h.setSelectedRouteDecision(c, decision)
		return account, proxyURL, decision
	}

	if owner, ok := encryptedContextOwnerFromContext(c); ok {
		ownerIsRelay := owner.AccountType == auth.UpstreamOpenAIResponses || owner.RouteClass == cybRelayRouteClass
		switch {
		case required.routesToCybRelay() && !ownerIsRelay:
			// Local full-payload routing rules always win over an OAuth owner.
			// The caller will downgrade opaque history before sending to Relay.
			markEncryptedContextDowngrade(c, encryptedOwnerConflictSignal)
		case exclusions != nil && exclusions.IsHard(owner.AccountID):
			markEncryptedContextDowngrade(c, encryptedOwnerUnavailableSignal)
		case exclusions != nil && exclusions.IsSoft(owner.AccountID):
			// A first-token timeout is deliberately only a soft health signal: the
			// upstream may already be executing even though no response token reached
			// us. Opaque encrypted_content is account-owned, so neither replaying the
			// request nor switching/downgrading to another account is safe here. Keep
			// the owner/pin intact and fail this logical request explicitly.
			decision := h.failUncertainEncryptedOwner(c, owner, required, "")
			return nil, "", decision
		default:
			ownerFilter := oauthOnlyAccountFilter(baseFilter)
			if ownerIsRelay {
				ownerFilter = h.applyCybRelayAccountFilter(baseFilter, promptRiskDecision{Disposition: promptRiskDispositionRelay})
			}
			var exclude map[int64]bool
			if exclusions != nil {
				exclude = exclusions.ForSelection()
			}
			account, proxyURL := h.nextAccountForSessionWithFilter(
				affinityKey,
				apiKeyID,
				exclude,
				responseOwnerAccountFilter(ownerFilter, owner),
			)
			if account != nil {
				decision := encryptedContextPromptRiskDecision(owner)
				if required.routesToCybRelay() {
					decision = required
					decision.PinKind = encryptedContextPinKind
					decision.RoutePinned = true
					decision.Signals = appendUniqueRouteSignal(decision.Signals, encryptedOwnerHitSignal)
				}
				decision = h.setSelectedRouteDecision(c, decision)
				return account, proxyURL, decision
			}
			// The request-local sticky probe is only an immediate preference.
			// A capacity miss here must not erase the encrypted owner before the
			// ordinary selector gets its normal chance to reacquire that owner.
			if !waitForCapacity {
				return nil, "", required
			}
			markEncryptedContextDowngrade(c, encryptedOwnerUnavailableSignal)
		}
	}

	if required.routesToCybRelay() {
		relayFilter := h.applyCybRelayAccountFilter(baseFilter, required)
		var account *auth.Account
		var proxyURL string
		if waitForCapacity {
			account, proxyURL = h.nextRetryRelayAccountForSession(ctx, affinityKey, apiKeyID, exclusions, relayFilter)
		} else {
			account, proxyURL = h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclusions.ForSelection(), relayFilter)
		}
		required = h.setSelectedRouteDecision(c, required)
		return account, proxyURL, required
	}

	oauthFilter := oauthOnlyAccountFilter(baseFilter)
	overflowDecision := overflowPromptRiskDecision()
	cfg := h.cybRelayConfig()
	if !cfg.Enabled || cfg.GroupID <= 0 {
		var account *auth.Account
		var proxyURL string
		if waitForCapacity {
			account, proxyURL = h.nextRetryAccountForSession(ctx, affinityKey, apiKeyID, exclusions, baseFilter)
		} else {
			account, proxyURL = h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclusions.ForSelection(), baseFilter)
		}
		decision := defaultPromptRiskDecision()
		decision = h.setSelectedRouteDecision(c, decision)
		return account, proxyURL, decision
	}

	relayFilter := h.applyCybRelayAccountFilter(baseFilter, overflowDecision)
	combinedFilter := accountFilterOr(oauthFilter, relayFilter)

	for {
		exclude := exclusions.ForSelection()
		if account, proxyURL := h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, oauthFilter); account != nil {
			decision := defaultPromptRiskDecision()
			decision = h.setSelectedRouteDecision(c, decision)
			return account, proxyURL, decision
		}
		var relayAccount *auth.Account
		var relayProxyURL string
		if waitForCapacity {
			relayAccount, relayProxyURL = h.nextRelayAccountForSessionWithInvariant(affinityKey, apiKeyID, exclude, relayFilter)
		} else {
			relayAccount, relayProxyURL = h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, relayFilter)
		}
		if relayAccount != nil {
			overflowDecision = h.setSelectedRouteDecision(c, overflowDecision)
			return relayAccount, relayProxyURL, overflowDecision
		}
		if !waitForCapacity {
			decision := defaultPromptRiskDecision()
			decision = h.setSelectedRouteDecision(c, decision)
			return nil, "", decision
		}

		account, proxyURL := h.store.WaitForSessionAvailableWithFilter(
			ctx,
			affinityKey,
			30*time.Second,
			apiKeyID,
			exclude,
			combinedFilter,
		)
		if account != nil {
			if account.IsOpenAIResponsesAPI() {
				overflowDecision = h.setSelectedRouteDecision(c, overflowDecision)
				return account, proxyURL, overflowDecision
			}
			decision := defaultPromptRiskDecision()
			decision = h.setSelectedRouteDecision(c, decision)
			return account, proxyURL, decision
		}
		if exclusions == nil || !exclusions.ResetSoft() {
			decision := defaultPromptRiskDecision()
			decision = h.setSelectedRouteDecision(c, decision)
			return nil, "", decision
		}
		log.Printf("first-token soft exclusions exhausted; retrying OAuth/Relay routing")
	}
}

func (h *Handler) logRouteSelectionError(c *gin.Context, endpoint, model, effectiveModel string, stream, viaWebsocket bool, attempt int, routeErr routeSelectionError, spec routeSelectionFailureSpec) {
	_ = logicalRequestID(c)
	durationMs := logicalRequestDurationMs(c)
	clearUpstreamAccountContext(c)
	if routeErr.Kind == encryptedOwnerAttemptUncertain {
		if owner, ok := encryptedContextOwnerFromContext(c); ok {
			// The canonical row is intentionally account-neutral because no second
			// attempt started, but the route shape still needs the owner's upstream
			// class so audit can validate the retained encrypted pin.
			c.Set(contextUpstreamAccountType, owner.AccountType)
		}
	}
	h.logUsageForRequest(c, &database.UsageLogInput{
		AccountID:         0,
		Endpoint:          endpoint,
		Model:             model,
		EffectiveModel:    effectiveModel,
		StatusCode:        spec.HTTPStatusCode,
		DurationMs:        durationMs,
		InboundEndpoint:   endpoint,
		Stream:            stream,
		ViaWebsocket:      viaWebsocket,
		IsRetryAttempt:    attempt > 0,
		AttemptIndex:      attempt + 1,
		UpstreamErrorKind: routeErr.Kind,
		ErrorMessage:      routeErr.Message,
	})
}
