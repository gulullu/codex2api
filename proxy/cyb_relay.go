package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const (
	promptRiskDispositionDefault = "default"
	promptRiskDispositionBlock   = "block_policy"
	promptRiskDispositionRelay   = "route_cyb"

	cybRelayRouteClass        = "cyb_relay"
	cybRelayPinCacheNamespace = "cyb-route-pin"
	cybRelayCacheTimeout      = 500 * time.Millisecond

	contextPromptRiskDecision   = "promptRiskDecision"
	contextCybWSRoutePinned     = "cybWSRoutePinned"
	contextUpstreamAccountID    = "upstreamAccountID"
	contextUpstreamAccountType  = "upstreamAccountType"
	contextNestedPromptDecision = "nestedPromptRiskDecision"
)

type promptRiskDecision struct {
	Disposition string
	Reason      string
	Signals     []string
	RoutePinned bool
}

func defaultPromptRiskDecision() promptRiskDecision {
	return promptRiskDecision{Disposition: promptRiskDispositionDefault}
}

func (d promptRiskDecision) blocks() bool {
	return d.Disposition == promptRiskDispositionBlock
}

func (d promptRiskDecision) routesToCybRelay() bool {
	return d.Disposition == promptRiskDispositionRelay
}

func (d promptRiskDecision) routeReason() string {
	if reason := strings.TrimSpace(d.Reason); reason != "" {
		return reason
	}
	return strings.Join(d.Signals, ",")
}

func (h *Handler) cybRelayConfig() auth.CybRelayConfig {
	if h == nil || h.store == nil {
		return auth.CybRelayConfig{}
	}
	return h.store.GetCybRelayConfig()
}

func (h *Handler) applyCybRelayAccountFilter(base auth.AccountFilter, decision promptRiskDecision) auth.AccountFilter {
	cfg := h.cybRelayConfig()
	if decision.routesToCybRelay() {
		return func(account *auth.Account) bool {
			if !cfg.Enabled || cfg.GroupID <= 0 || account == nil || !account.IsOpenAIResponsesAPI() || !account.HasGroupID(cfg.GroupID) {
				return false
			}
			return base == nil || base(account)
		}
	}
	if !cfg.Enabled || cfg.GroupID <= 0 {
		return base
	}
	return func(account *auth.Account) bool {
		if account == nil || account.HasGroupID(cfg.GroupID) {
			return false
		}
		return base == nil || base(account)
	}
}

func setPromptRiskDecisionContext(c *gin.Context, decision promptRiskDecision, groupID int64) {
	if c == nil {
		return
	}
	c.Set(contextPromptRiskDecision, decision)
	if decision.routesToCybRelay() {
		c.Set("routeClass", cybRelayRouteClass)
		c.Set("routeReason", decision.routeReason())
		c.Set("routeGroupID", groupID)
		c.Set("routePinned", decision.RoutePinned)
	} else {
		c.Set("routeClass", promptRiskDispositionDefault)
		c.Set("routeReason", decision.routeReason())
		c.Set("routeGroupID", int64(0))
		c.Set("routePinned", false)
	}
}

func promptRiskDecisionFromContext(c *gin.Context) (promptRiskDecision, bool) {
	if c == nil {
		return promptRiskDecision{}, false
	}
	value, ok := c.Get(contextPromptRiskDecision)
	if !ok {
		return promptRiskDecision{}, false
	}
	decision, ok := value.(promptRiskDecision)
	return decision, ok
}

func setNestedPromptRiskDecision(c *gin.Context, decision promptRiskDecision) {
	if c != nil {
		c.Set(contextNestedPromptDecision, decision)
	}
}

func takeNestedPromptRiskDecision(c *gin.Context) (promptRiskDecision, bool) {
	if c == nil {
		return promptRiskDecision{}, false
	}
	value, ok := c.Get(contextNestedPromptDecision)
	if !ok {
		return promptRiskDecision{}, false
	}
	c.Set(contextNestedPromptDecision, nil)
	decision, ok := value.(promptRiskDecision)
	return decision, ok
}

func cybRelayPinCacheKey(kind, owner, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(owner) + "|" + strings.TrimSpace(kind) + "|" + value))
	return strings.TrimSpace(kind) + ":" + hex.EncodeToString(sum[:])
}

func reliableCybSessionPinKey(c *gin.Context, rawBody []byte) string {
	if c == nil {
		return ""
	}
	apiKeyID := requestAPIKeyID(c)
	owner := responseCacheOwner(apiKeyID)
	var headers http.Header
	if c.Request != nil {
		headers = c.Request.Header
	}
	if explicit := ResolveExplicitSessionID(headers, rawBody); explicit != "" {
		return cybRelayPinCacheKey("session", owner, explicit)
	}
	if seed := deriveContentSessionSeed(rawBody); strings.HasPrefix(seed, "content-") {
		return cybRelayPinCacheKey("content", owner, seed)
	}
	return ""
}

func previousResponseCybPinKey(c *gin.Context, rawBody []byte) string {
	if c == nil {
		return ""
	}
	previousID := strings.TrimSpace(gjson.GetBytes(rawBody, "previous_response_id").String())
	if previousID == "" {
		return ""
	}
	return cybRelayPinCacheKey("response", responseCacheOwner(requestAPIKeyID(c)), previousID)
}

func (h *Handler) hasCybRoutePin(ctx context.Context, key string) bool {
	if h == nil || h.cache == nil || key == "" {
		return false
	}
	cacheCtx, cancel := context.WithTimeout(ctx, cybRelayCacheTimeout)
	defer cancel()
	_, ok, err := h.cache.GetRuntime(cacheCtx, cybRelayPinCacheNamespace, key)
	if err != nil {
		log.Printf("读取 CYB relay 会话固定失败: %v", err)
		return false
	}
	return ok
}

func (h *Handler) writeCybRoutePin(key string, ttl time.Duration) bool {
	if h == nil || h.cache == nil || key == "" || ttl <= 0 {
		return false
	}
	payload, _ := json.Marshal(map[string]string{"route": cybRelayRouteClass})
	ctx, cancel := context.WithTimeout(context.Background(), cybRelayCacheTimeout)
	defer cancel()
	if err := h.cache.SetRuntime(ctx, cybRelayPinCacheNamespace, key, payload, ttl); err != nil {
		log.Printf("写入 CYB relay 会话固定失败: %v", err)
		return false
	}
	return true
}

func (h *Handler) applyCybRoutePin(c *gin.Context, rawBody []byte, decision promptRiskDecision) promptRiskDecision {
	cfg := h.cybRelayConfig()
	if c == nil || !cfg.Enabled || !cfg.SessionPinEnabled || decision.blocks() {
		setPromptRiskDecisionContext(c, decision, cfg.GroupID)
		return decision
	}

	if pinned, _ := c.Get(contextCybWSRoutePinned); pinned == true && !decision.routesToCybRelay() {
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "websocket session pinned to CYB relay",
			Signals:     []string{"websocket_session_pin"},
			RoutePinned: true,
		}
	}

	sessionKey := reliableCybSessionPinKey(c, rawBody)
	previousKey := previousResponseCybPinKey(c, rawBody)
	requestCtx := context.Background()
	if c.Request != nil {
		requestCtx = c.Request.Context()
	}
	if !decision.routesToCybRelay() && (h.hasCybRoutePin(requestCtx, sessionKey) || h.hasCybRoutePin(requestCtx, previousKey)) {
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "conversation pinned to CYB relay",
			Signals:     []string{"conversation_pin"},
			RoutePinned: true,
		}
	}

	if decision.routesToCybRelay() {
		pinTTL := time.Duration(cfg.SessionPinTTLSeconds) * time.Second
		if sessionKey != "" {
			decision.RoutePinned = h.writeCybRoutePin(sessionKey, pinTTL) || decision.RoutePinned
		}
		if previousKey != "" {
			decision.RoutePinned = h.writeCybRoutePin(previousKey, pinTTL) || decision.RoutePinned
		}
		if c.Request != nil && isResponsesWebSocketUpgradeRequest(c.Request) {
			c.Set(contextCybWSRoutePinned, true)
			decision.RoutePinned = true
		}
	}

	setPromptRiskDecisionContext(c, decision, cfg.GroupID)
	return decision
}

func (h *Handler) pinCybRelayResponseID(c *gin.Context, event []byte) {
	decision, ok := promptRiskDecisionFromContext(c)
	if !ok || !decision.routesToCybRelay() {
		return
	}
	cfg := h.cybRelayConfig()
	if !cfg.Enabled || !cfg.SessionPinEnabled {
		return
	}
	responseID := strings.TrimSpace(gjson.GetBytes(event, "response.id").String())
	if responseID == "" {
		responseID = strings.TrimSpace(gjson.GetBytes(event, "id").String())
	}
	if responseID == "" {
		return
	}
	key := cybRelayPinCacheKey("response", responseCacheOwner(requestAPIKeyID(c)), responseID)
	_ = h.writeCybRoutePin(key, time.Duration(cfg.SessionPinTTLSeconds)*time.Second)
}

func setUpstreamAccountContext(c *gin.Context, account *auth.Account) {
	if c == nil || account == nil {
		return
	}
	c.Set(contextUpstreamAccountID, account.ID())
	accountType := "oauth"
	if account.IsOpenAIResponsesAPI() {
		accountType = auth.UpstreamOpenAIResponses
	}
	c.Set(contextUpstreamAccountType, accountType)
}

func populateCybUsageRouteMeta(h *Handler, c *gin.Context, input *database.UsageLogInput) {
	if input == nil {
		return
	}
	if c != nil {
		if value, ok := c.Get("routeClass"); ok {
			input.RouteClass, _ = value.(string)
		}
		if value, ok := c.Get("routeReason"); ok {
			input.RouteReason, _ = value.(string)
		}
		if value, ok := c.Get("routeGroupID"); ok {
			input.RouteGroupID, _ = value.(int64)
		}
		if value, ok := c.Get("routePinned"); ok {
			input.RoutePinned, _ = value.(bool)
		}
		if value, ok := c.Get(contextUpstreamAccountType); ok {
			input.UpstreamAccountType, _ = value.(string)
		}
	}
	if input.UpstreamAccountType == "" && h != nil && h.store != nil && input.AccountID != 0 {
		if account := h.store.FindByID(input.AccountID); account != nil {
			input.UpstreamAccountType = "oauth"
			if account.IsOpenAIResponsesAPI() {
				input.UpstreamAccountType = auth.UpstreamOpenAIResponses
			}
		}
	}
}

func populateCybPromptFilterRouteMeta(c *gin.Context, input *database.PromptFilterLogInput) {
	if c == nil || input == nil {
		return
	}
	if value, ok := c.Get("routeClass"); ok {
		input.RouteClass, _ = value.(string)
	}
	if value, ok := c.Get("routeReason"); ok {
		input.RouteReason, _ = value.(string)
	}
	if value, ok := c.Get("routeGroupID"); ok {
		input.RouteGroupID, _ = value.(int64)
	}
	if value, ok := c.Get("routePinned"); ok {
		input.RoutePinned, _ = value.(bool)
	}
	if value, ok := c.Get(contextUpstreamAccountType); ok {
		input.UpstreamAccountType, _ = value.(string)
	}
	if value, ok := c.Get(contextUpstreamAccountID); ok {
		input.AccountID, _ = value.(int64)
	}
}

func sendCybRelayUnavailableOpenAI(c *gin.Context) {
	api.SendErrorWithStatus(c, api.NewAPIError(
		api.ErrorCode("content_policy_violation"),
		"This request could not be routed to the isolated safety pool. Please try again later.",
		api.ErrorTypeInvalidRequest,
	), http.StatusBadRequest)
}

func sendCybRelayUnavailableAnthropic(c *gin.Context) {
	sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "This request could not be routed to the isolated safety pool. Please try again later.")
}

func writeCybRelayUnavailableWebSocket(conn *websocket.Conn) error {
	return writeResponsesWSError(conn, api.NewAPIError(
		api.ErrorCode("content_policy_violation"),
		"This request could not be routed to the isolated safety pool. Please try again later.",
		api.ErrorTypeInvalidRequest,
	))
}
