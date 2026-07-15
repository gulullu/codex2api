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
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
)

const (
	promptRiskDispositionDefault = "default"
	promptRiskDispositionBlock   = "block_policy"
	promptRiskDispositionRelay   = "route_cyb"

	cybRelayRouteClass          = "cyb_relay"
	cybRelayRouteSourceDefault  = "default"
	cybRelayRouteSourceDirect   = "direct"
	cybRelayRouteSourceProbe    = "probe"
	cybRelayRouteSourceOverflow = "overflow"
	cybRelayRouteSourcePin      = "pin"
	cybRelayPinCacheNamespace   = "cyb-route-pin-v2"
	cybRelayCacheTimeout        = 500 * time.Millisecond

	contextPromptRiskDecision   = "promptRiskDecision"
	contextCybWSRoutePinned     = "cybWSRoutePinned"
	contextUpstreamAccountID    = "upstreamAccountID"
	contextUpstreamAccountType  = "upstreamAccountType"
	contextNestedPromptDecision = "nestedPromptRiskDecision"
	contextLogicalRequestID     = "logicalRequestID"
	contextLogicalRequestStart  = "logicalRequestStart"
)

type promptRiskDecision struct {
	Disposition string
	Reason      string
	Signals     []string
	RouteSource string
	PinKind     string
	RoutePinned bool
	// SkipPinPersistence is an internal routing guard. It is never persisted
	// to audit rows and is used when an exact feedback digest is the sole
	// reason for the current route, so one learned request cannot expand into
	// a whole conversation or WebSocket pin.
	SkipPinPersistence bool
}

func defaultPromptRiskDecision() promptRiskDecision {
	return promptRiskDecision{Disposition: promptRiskDispositionDefault, RouteSource: cybRelayRouteSourceDefault}
}

func logicalRequestID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if value, ok := c.Get(contextLogicalRequestID); ok {
		if requestID, ok := value.(string); ok && strings.TrimSpace(requestID) != "" {
			return strings.TrimSpace(requestID)
		}
	}
	return beginLogicalRequest(c)
}

// beginLogicalRequest creates an internal, server-controlled identity used only
// for audit de-duplication. It must never reuse the client supplied X-Request-ID.
// HTTP requests call this lazily once; Responses WebSocket calls it once per
// response.create turn so retries share an ID without merging separate turns.
func beginLogicalRequest(c *gin.Context) string {
	if c == nil {
		return ""
	}
	requestID := uuid.NewString()
	c.Set(contextLogicalRequestID, requestID)
	c.Set(contextLogicalRequestStart, time.Now())
	return requestID
}

func logicalRequestDurationMs(c *gin.Context) int {
	if c == nil {
		return 0
	}
	if value, ok := c.Get(contextLogicalRequestStart); ok {
		if startedAt, ok := value.(time.Time); ok && !startedAt.IsZero() {
			return int(time.Since(startedAt).Milliseconds())
		}
	}
	return 0
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
	if strings.TrimSpace(decision.RouteSource) == "" {
		decision.RouteSource = cybRelayRouteSourceDefault
	}
	c.Set(contextPromptRiskDecision, decision)
	c.Set("routeSource", decision.RouteSource)
	c.Set("routeSignals", append([]string(nil), decision.Signals...))
	c.Set("pinKind", decision.PinKind)
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

type cybRoutePinCandidate struct {
	Kind string
	Key  string
}

func cybRoutePinCandidates(c *gin.Context, rawBody []byte) []cybRoutePinCandidate {
	if c == nil {
		return nil
	}
	owner := responseCacheOwner(requestAPIKeyID(c))
	candidates := make([]cybRoutePinCandidate, 0, 4)
	seen := map[string]struct{}{}
	add := func(kind, value string) {
		key := cybRelayPinCacheKey(kind, owner, value)
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, cybRoutePinCandidate{Kind: kind, Key: key})
	}

	// Exact continuation identifiers take precedence over broader session
	// hints. Content hashes and Idempotency-Key are intentionally excluded.
	add("previous_response_id", gjson.GetBytes(rawBody, "previous_response_id").String())
	add("prompt_cache_key", gjson.GetBytes(rawBody, "prompt_cache_key").String())
	if c.Request != nil {
		add("conversation_id", c.Request.Header.Get("Conversation_id"))
		add("session_id", c.Request.Header.Get("Session_id"))
	}
	return candidates
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
	if decision.SkipPinPersistence {
		if strings.TrimSpace(decision.RouteSource) == "" || decision.RouteSource == cybRelayRouteSourceDefault {
			decision.RouteSource = cybRelayRouteSourceDirect
		}
		setPromptRiskDecisionContext(c, decision, cfg.GroupID)
		return decision
	}

	if pinned, _ := c.Get(contextCybWSRoutePinned); pinned == true && !decision.routesToCybRelay() {
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "websocket session pinned to CYB relay",
			Signals:     nil,
			RouteSource: cybRelayRouteSourcePin,
			PinKind:     "websocket",
			RoutePinned: true,
		}
	}

	candidates := cybRoutePinCandidates(c, rawBody)
	requestCtx := context.Background()
	if c.Request != nil {
		requestCtx = c.Request.Context()
	}
	if !decision.routesToCybRelay() {
		for _, candidate := range candidates {
			if h.hasCybRoutePin(requestCtx, candidate.Key) {
				decision = promptRiskDecision{
					Disposition: promptRiskDispositionRelay,
					Reason:      "conversation pinned to CYB relay",
					Signals:     nil,
					RouteSource: cybRelayRouteSourcePin,
					PinKind:     candidate.Kind,
					RoutePinned: true,
				}
				break
			}
		}
	}

	if decision.routesToCybRelay() {
		if strings.TrimSpace(decision.RouteSource) == "" || decision.RouteSource == cybRelayRouteSourceDefault {
			decision.RouteSource = cybRelayRouteSourceDirect
		}
		pinTTL := time.Duration(cfg.SessionPinTTLSeconds) * time.Second
		for _, candidate := range candidates {
			_ = h.writeCybRoutePin(candidate.Key, pinTTL)
		}
		if c.Request != nil && isResponsesWebSocketUpgradeRequest(c.Request) {
			c.Set(contextCybWSRoutePinned, true)
		}
	}

	setPromptRiskDecisionContext(c, decision, cfg.GroupID)
	return decision
}

func (h *Handler) pinCybRelayResponseID(c *gin.Context, event []byte) {
	responseID := strings.TrimSpace(gjson.GetBytes(event, "response.id").String())
	if responseID == "" {
		responseID = strings.TrimSpace(gjson.GetBytes(event, "id").String())
	}
	if responseID == "" {
		return
	}
	h.recordResponseRouteOwner(c, responseID)
	decision, ok := promptRiskDecisionFromContext(c)
	if !ok || !decision.routesToCybRelay() || decision.SkipPinPersistence {
		return
	}
	cfg := h.cybRelayConfig()
	if !cfg.Enabled || !cfg.SessionPinEnabled {
		return
	}
	key := cybRelayPinCacheKey("previous_response_id", responseCacheOwner(requestAPIKeyID(c)), responseID)
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

func clearUpstreamAccountContext(c *gin.Context) {
	if c == nil {
		return
	}
	c.Set(contextUpstreamAccountID, int64(0))
	c.Set(contextUpstreamAccountType, "")
}

func (h *Handler) logCybRelayUnavailable(c *gin.Context, endpoint, model, effectiveModel string, stream, viaWebsocket bool, attempt int) {
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
		UpstreamErrorKind: "relay_route_unavailable",
		ErrorMessage:      "isolated relay route unavailable; OAuth fallback prevented",
	})
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
		if value, ok := c.Get("routeSource"); ok {
			input.RouteSource, _ = value.(string)
		}
		if value, ok := c.Get("routeSignals"); ok {
			if signals, ok := value.([]string); ok {
				encoded, _ := json.Marshal(signals)
				input.RouteSignals = string(encoded)
			}
		}
		if value, ok := c.Get("pinKind"); ok {
			input.PinKind, _ = value.(string)
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
	if value, ok := c.Get("routeSource"); ok {
		input.RouteSource, _ = value.(string)
	}
	if value, ok := c.Get("routeSignals"); ok {
		if signals, ok := value.([]string); ok {
			encoded, _ := json.Marshal(signals)
			input.RouteSignals = string(encoded)
		}
	}
	if value, ok := c.Get("pinKind"); ok {
		input.PinKind, _ = value.(string)
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
		api.ErrorCode("relay_route_unavailable"),
		"The isolated relay route is temporarily unavailable. Please retry later.",
		api.ErrorTypeServer,
	), http.StatusServiceUnavailable)
}

func sendCybRelayUnavailableAnthropic(c *gin.Context) {
	sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", "The isolated relay route is temporarily unavailable. Please retry later.")
}

func writeCybRelayUnavailableWebSocket(conn *websocket.Conn) error {
	return writeResponsesWSError(conn, api.NewAPIError(
		api.ErrorCode("relay_route_unavailable"),
		"The isolated relay route is temporarily unavailable. Please retry later.",
		api.ErrorTypeServer,
	))
}
