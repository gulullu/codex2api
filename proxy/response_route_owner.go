package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	responseRouteOwnerNamespace     = "response-route-owner-v1"
	responseRouteOwnerTTL           = 10 * time.Minute
	responseOwnerRouteSignal        = "previous_response_owner"
	cybRelayRouteSourceContinuation = "continuation"
	contextResponseRouteOwner       = "responseRouteOwner"
	contextRouteSelectionError      = "routeSelectionError"
	routeSwitchRequiresReplay       = "route_switch_requires_replay"
	continuationOwnerUnavailable    = "continuation_owner_unavailable"
)

type responseRouteOwner struct {
	AccountID   int64  `json:"account_id"`
	AccountType string `json:"account_type"`
	RouteClass  string `json:"route_class"`
}

type routeSelectionError struct {
	Kind    string
	Message string
}

func clearRouteSelectionError(c *gin.Context) {
	if c != nil {
		c.Set(contextRouteSelectionError, routeSelectionError{})
	}
}

func setRouteSelectionError(c *gin.Context, kind, message string) {
	if c != nil {
		c.Set(contextRouteSelectionError, routeSelectionError{
			Kind:    strings.TrimSpace(kind),
			Message: strings.TrimSpace(message),
		})
	}
}

func routeSelectionErrorFromContext(c *gin.Context) (routeSelectionError, bool) {
	if c == nil {
		return routeSelectionError{}, false
	}
	value, ok := c.Get(contextRouteSelectionError)
	if !ok {
		return routeSelectionError{}, false
	}
	routeErr, ok := value.(routeSelectionError)
	return routeErr, ok && routeErr.Kind != ""
}

func responseRouteOwnerCacheKey(c *gin.Context, responseID string) string {
	return cybRelayPinCacheKey(
		"response_owner",
		responseCacheOwner(requestAPIKeyID(c)),
		responseID,
	)
}

func responseRouteOwnerFromContext(c *gin.Context) (responseRouteOwner, bool) {
	if c == nil {
		return responseRouteOwner{}, false
	}
	value, ok := c.Get(contextResponseRouteOwner)
	if !ok {
		return responseRouteOwner{}, false
	}
	owner, ok := value.(responseRouteOwner)
	return owner, ok && owner.AccountID > 0
}

func (h *Handler) loadResponseRouteOwner(c *gin.Context, rawBody []byte) {
	if c == nil {
		return
	}
	// Responses WebSocket reuses one Gin context for multiple turns.
	// Clear any owner from the prior turn before resolving this request.
	c.Set(contextResponseRouteOwner, responseRouteOwner{})
	if h == nil || h.cache == nil {
		return
	}
	responseID := strings.TrimSpace(gjson.GetBytes(rawBody, "previous_response_id").String())
	key := responseRouteOwnerCacheKey(c, responseID)
	if key == "" {
		return
	}
	ctx := context.Background()
	if c.Request != nil {
		ctx = c.Request.Context()
	}
	cacheCtx, cancel := context.WithTimeout(ctx, cybRelayCacheTimeout)
	defer cancel()
	payload, ok, err := h.cache.GetRuntime(cacheCtx, responseRouteOwnerNamespace, key)
	if err != nil || !ok {
		return
	}
	var owner responseRouteOwner
	if json.Unmarshal(payload, &owner) != nil || owner.AccountID <= 0 {
		return
	}
	c.Set(contextResponseRouteOwner, owner)
}

func (h *Handler) recordResponseRouteOwner(c *gin.Context, responseID string) {
	if h == nil || h.cache == nil || c == nil || strings.TrimSpace(responseID) == "" {
		return
	}
	accountIDValue, ok := c.Get(contextUpstreamAccountID)
	if !ok {
		return
	}
	accountID, ok := accountIDValue.(int64)
	if !ok || accountID <= 0 {
		return
	}
	accountType := c.GetString(contextUpstreamAccountType)
	routeClass := c.GetString("routeClass")
	payload, _ := json.Marshal(responseRouteOwner{
		AccountID:   accountID,
		AccountType: strings.TrimSpace(accountType),
		RouteClass:  strings.TrimSpace(routeClass),
	})
	key := responseRouteOwnerCacheKey(c, responseID)
	if key == "" {
		return
	}
	cacheCtx, cancel := context.WithTimeout(context.Background(), cybRelayCacheTimeout)
	defer cancel()
	_ = h.cache.SetRuntime(cacheCtx, responseRouteOwnerNamespace, key, payload, responseRouteOwnerTTL)
}

func responseOwnerAccountFilter(base auth.AccountFilter, owner responseRouteOwner) auth.AccountFilter {
	return accountFilterAnd(base, func(account *auth.Account) bool {
		return account != nil && account.ID() == owner.AccountID
	})
}

func continuationPromptRiskDecision(owner responseRouteOwner) promptRiskDecision {
	decision := defaultPromptRiskDecision()
	decision.RouteSource = cybRelayRouteSourceContinuation
	decision.Signals = []string{responseOwnerRouteSignal}
	decision.Reason = "continued on the account that owns previous_response_id"
	if owner.AccountType == auth.UpstreamOpenAIResponses {
		decision.Disposition = promptRiskDispositionRelay
	}
	return decision
}
