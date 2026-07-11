package proxy

import (
	"context"
	"log"
	"net/http"
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

func (h *Handler) setSelectedRouteDecision(c *gin.Context, decision promptRiskDecision) {
	setPromptRiskDecisionContext(c, decision, h.cybRelayConfig().GroupID)
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
	clearRouteSelectionError(c)
	if owner, ok := responseRouteOwnerFromContext(c); ok {
		ownerIsRelay := owner.AccountType == auth.UpstreamOpenAIResponses || owner.RouteClass == cybRelayRouteClass
		if required.routesToCybRelay() && !ownerIsRelay {
			conflict := required
			conflict.RouteSource = cybRelayRouteSourceContinuation
			conflict.Reason = "previous_response_id belongs to OAuth; resend full context without previous_response_id to use Relay"
			conflict.Signals = appendUniqueRouteSignal(conflict.Signals, responseOwnerRouteSignal)
			setRouteSelectionError(c, routeSwitchRequiresReplay, conflict.Reason)
			h.setSelectedRouteDecision(c, conflict)
			return nil, "", conflict
		}
		decision := continuationPromptRiskDecision(owner)
		if required.routesToCybRelay() {
			decision = required
			decision.RouteSource = cybRelayRouteSourceContinuation
			decision.Reason = "continued on the Relay account that owns previous_response_id"
			decision.Signals = appendUniqueRouteSignal(decision.Signals, responseOwnerRouteSignal)
		}
		ownerBaseFilter := oauthOnlyAccountFilter(baseFilter)
		if ownerIsRelay {
			ownerBaseFilter = h.applyCybRelayAccountFilter(baseFilter, promptRiskDecision{Disposition: promptRiskDispositionRelay})
		}
		account, proxyURL := h.nextRetryAccountForSession(
			ctx,
			affinityKey,
			apiKeyID,
			exclusions,
			responseOwnerAccountFilter(ownerBaseFilter, owner),
		)
		if account == nil {
			setRouteSelectionError(c, continuationOwnerUnavailable, "The account that owns previous_response_id is unavailable; retry later or resend full context")
		}
		h.setSelectedRouteDecision(c, decision)
		return account, proxyURL, decision
	}

	if required.routesToCybRelay() {
		relayFilter := h.applyCybRelayAccountFilter(baseFilter, required)
		account, proxyURL := h.nextRetryAccountForSession(ctx, affinityKey, apiKeyID, exclusions, relayFilter)
		h.setSelectedRouteDecision(c, required)
		return account, proxyURL, required
	}

	oauthFilter := oauthOnlyAccountFilter(baseFilter)
	overflowDecision := overflowPromptRiskDecision()
	cfg := h.cybRelayConfig()
	if !cfg.Enabled || cfg.GroupID <= 0 {
		account, proxyURL := h.nextRetryAccountForSession(ctx, affinityKey, apiKeyID, exclusions, baseFilter)
		decision := defaultPromptRiskDecision()
		h.setSelectedRouteDecision(c, decision)
		return account, proxyURL, decision
	}

	relayFilter := h.applyCybRelayAccountFilter(baseFilter, overflowDecision)
	combinedFilter := accountFilterOr(oauthFilter, relayFilter)

	for {
		exclude := exclusions.ForSelection()
		if account, proxyURL := h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, oauthFilter); account != nil {
			decision := defaultPromptRiskDecision()
			h.setSelectedRouteDecision(c, decision)
			return account, proxyURL, decision
		}
		if account, proxyURL := h.nextAccountForSessionWithFilter(affinityKey, apiKeyID, exclude, relayFilter); account != nil {
			h.setSelectedRouteDecision(c, overflowDecision)
			return account, proxyURL, overflowDecision
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
				h.setSelectedRouteDecision(c, overflowDecision)
				return account, proxyURL, overflowDecision
			}
			decision := defaultPromptRiskDecision()
			h.setSelectedRouteDecision(c, decision)
			return account, proxyURL, decision
		}
		if exclusions == nil || !exclusions.ResetSoft() {
			decision := defaultPromptRiskDecision()
			h.setSelectedRouteDecision(c, decision)
			return nil, "", decision
		}
		log.Printf("first-token soft exclusions exhausted; retrying OAuth/Relay routing")
	}
}

func (h *Handler) logRouteSelectionError(c *gin.Context, endpoint, model, effectiveModel string, stream, viaWebsocket bool, attempt int, routeErr routeSelectionError) {
	clearUpstreamAccountContext(c)
	h.logUsageForRequest(c, &database.UsageLogInput{
		AccountID:         0,
		Endpoint:          endpoint,
		Model:             model,
		EffectiveModel:    effectiveModel,
		StatusCode:        http.StatusServiceUnavailable,
		DurationMs:        logicalRequestDurationMs(c),
		InboundEndpoint:   endpoint,
		Stream:            stream,
		ViaWebsocket:      viaWebsocket,
		IsRetryAttempt:    attempt > 0,
		AttemptIndex:      attempt + 1,
		UpstreamErrorKind: routeErr.Kind,
		ErrorMessage:      routeErr.Message,
	})
}
