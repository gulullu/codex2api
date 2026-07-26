package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/security/cybroute"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	relayRouteSourceDefault      = "official_default"
	relayRouteSourceRule         = "cyb_rule"
	relayRouteSourceProbe        = "probe"
	relayRouteSourceContinuation = "relay_continuation"
	relayRouteSourceOverflow     = "oauth_overflow"
	relayRouteSourceFeedback     = "cyb_feedback"

	relayRoutePinNamespace = "relay-group-pin-v1"
	relayRouteContextKey   = "relayRoutePlan"

	defaultRelayRoutePinTTL = 24 * time.Hour
	relayRouteCacheTimeout  = 500 * time.Millisecond
)

var errRelayRoutePinUnavailable = errors.New("relay route pin storage unavailable")

type relayRouteConfig struct {
	Enabled bool
	GroupID int64
	PinTTL  time.Duration
}

type relayRoutePinValue struct {
	GroupID int64  `json:"group_id"`
	Source  string `json:"source,omitempty"`
}

type relayRoutePinCandidate struct {
	Kind string
	Key  string
}

type relayRoutePlan struct {
	Config              relayRouteConfig
	Endpoint            string
	Model               string
	RequiredGroupID     int64
	Source              string
	Origin              string
	Reason              string
	Signals             []string
	PinCandidates       []relayRoutePinCandidate
	FeedbackDigest      relayCybFeedbackDigest
	FeedbackDigestValid bool
	SkipPinPersistence  bool
	Pinned              bool
	FirstAccountID      int64
	PreviousAccount     int64
	SelectionCount      int
}

func loadRelayRouteConfig() relayRouteConfig {
	groupID, _ := strconv.ParseInt(strings.TrimSpace(os.Getenv("CODEX_CYB_RELAY_GROUP_ID")), 10, 64)
	cfg := relayRouteConfig{
		Enabled: groupID > 0,
		GroupID: groupID,
		PinTTL:  defaultRelayRoutePinTTL,
	}
	if raw := strings.TrimSpace(os.Getenv("CODEX_CYB_RELAY_ENABLED")); raw != "" {
		if enabled, err := strconv.ParseBool(raw); err == nil {
			cfg.Enabled = enabled
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CODEX_CYB_RELAY_PIN_TTL_SECONDS")); raw != "" {
		if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds > 0 {
			cfg.PinTTL = time.Duration(seconds) * time.Second
		}
	}
	if cfg.GroupID <= 0 {
		cfg.Enabled = false
	}
	return cfg
}

func defaultRelayRoutePlan(cfg relayRouteConfig) relayRoutePlan {
	return relayRoutePlan{
		Config: cfg,
		Source: relayRouteSourceDefault,
		Origin: relayRouteSourceDefault,
	}
}

func (p *relayRoutePlan) Required() bool {
	return p != nil && p.Config.Enabled && p.RequiredGroupID > 0
}

func (p *relayRoutePlan) accountInTargetGroup(account *auth.Account) bool {
	if p == nil || account == nil || p.Config.GroupID <= 0 {
		return false
	}
	return account.InAnyGroup(map[int64]struct{}{p.Config.GroupID: {}})
}

func (p *relayRoutePlan) accountInRequiredGroup(account *auth.Account) bool {
	if p == nil || account == nil || p.RequiredGroupID <= 0 {
		return false
	}
	return account.InAnyGroup(map[int64]struct{}{p.RequiredGroupID: {}})
}

func (p *relayRoutePlan) composeFilter(base auth.AccountFilter) auth.AccountFilter {
	if !p.Required() {
		return base
	}
	return requireRelayGroupFilter(base, p.RequiredGroupID)
}

func requireRelayGroupFilter(base auth.AccountFilter, groupID int64) auth.AccountFilter {
	if groupID <= 0 {
		return base
	}
	groups := map[int64]struct{}{groupID: {}}
	return func(account *auth.Account) bool {
		return account != nil &&
			account.InAnyGroup(groups) &&
			(base == nil || base(account))
	}
}

func (h *Handler) prepareRelayRoutePlan(c *gin.Context, rawBody []byte, endpoint string) (*relayRoutePlan, error) {
	cfg := loadRelayRouteConfig()
	plan := defaultRelayRoutePlan(cfg)
	plan.Endpoint = strings.TrimSpace(endpoint)
	plan.Model = strings.TrimSpace(gjson.GetBytes(rawBody, "model").String())
	if !cfg.Enabled || c == nil {
		setRelayRoutePlanContext(c, &plan)
		return &plan, nil
	}

	apiKeyID := requestAPIKeyID(c)
	plan.PinCandidates = relayRoutePinCandidates(c, rawBody, apiKeyID)
	plan.FeedbackDigest, plan.FeedbackDigestValid = globalRelayCybFeedback.digest(endpoint, rawBody)

	probeSignature, probe := cybroute.DetectProbe(rawBody, endpoint)
	var result cybroute.Result
	if h != nil && h.store != nil {
		result = cybroute.Inspect(rawBody, endpoint, plan.Model, h.store.GetPromptFilterConfig())
	}

	switch {
	case probe:
		plan.RequiredGroupID = cfg.GroupID
		plan.Source = relayRouteSourceProbe
		plan.Origin = relayRouteSourceProbe
		plan.Reason = probeSignature
		plan.Signals = []string{"probe:" + probeSignature}
	case result.Route:
		plan.RequiredGroupID = cfg.GroupID
		plan.Source = relayRouteSourceRule
		plan.Origin = relayRouteSourceRule
		plan.Reason = firstRelayRouteSignal(result.Signals)
		plan.Signals = append([]string(nil), result.Signals...)
	case plan.FeedbackDigestValid && globalRelayCybFeedback.contains(plan.FeedbackDigest):
		plan.RequiredGroupID = cfg.GroupID
		plan.Source = relayRouteSourceFeedback
		plan.Origin = relayRouteSourceFeedback
		plan.Reason = "previous_oauth_cyber_policy"
		plan.Signals = []string{"upstream_cyber_policy_feedback"}
		// A learned body digest is scoped to this exact request only. It must not
		// turn one upstream cyber_policy response into a whole-conversation pin.
		plan.SkipPinPersistence = true
	default:
		if strings.TrimSpace(gjson.GetBytes(rawBody, "previous_response_id").String()) != "" &&
			len(plan.PinCandidates) == 0 {
			return &plan, fmt.Errorf("%w: continuation requires a stable conversation scope", errRelayRoutePinUnavailable)
		}
		pin, found, err := h.readRelayRoutePin(c.Request.Context(), plan.PinCandidates)
		if err != nil {
			return &plan, err
		}
		if found && pin.GroupID > 0 {
			plan.RequiredGroupID = pin.GroupID
			plan.Source = relayRouteSourceContinuation
			plan.Origin = strings.TrimSpace(pin.Source)
			if plan.Origin == "" {
				plan.Origin = relayRouteSourceContinuation
			}
			plan.Reason = "relay_group_pin"
			plan.Pinned = true
		}
	}

	setRelayRoutePlanContext(c, &plan)
	return &plan, nil
}

func (h *Handler) relayRoutePlanForRequest(c *gin.Context, rawBody []byte, endpoint string) (*relayRoutePlan, error) {
	if plan, ok := relayRoutePlanFromContext(c); ok {
		return plan, nil
	}
	return h.prepareRelayRoutePlan(c, rawBody, endpoint)
}

func (h *Handler) prepareRelayRoutePlanAndReply(c *gin.Context, rawBody []byte, endpoint string) (*relayRoutePlan, bool) {
	plan, err := h.prepareRelayRoutePlan(c, rawBody, endpoint)
	if err != nil {
		h.replyRelayRouteUnavailable(c, err)
		return nil, false
	}
	return plan, true
}

func (h *Handler) relayRoutePlanForRequestAndReply(c *gin.Context, rawBody []byte, endpoint string) (*relayRoutePlan, bool) {
	plan, err := h.relayRoutePlanForRequest(c, rawBody, endpoint)
	if err != nil {
		h.replyRelayRouteUnavailable(c, err)
		return nil, false
	}
	return plan, true
}

func (h *Handler) upgradeRelayRoutePlanFromPayloadRules(plan *relayRoutePlan, body []byte, endpoint string, model string) {
	if plan == nil || plan.Required() || !plan.Config.Enabled || h == nil || h.store == nil {
		return
	}
	result := cybroute.Inspect(body, endpoint, model, h.store.GetPromptFilterConfig())
	if !result.Route {
		return
	}
	plan.RequiredGroupID = plan.Config.GroupID
	plan.Source = relayRouteSourceRule
	plan.Origin = relayRouteSourceRule
	plan.Reason = firstRelayRouteSignal(result.Signals)
	plan.Signals = append([]string{"payload_rules_oauth_preview"}, result.Signals...)
}

func firstRelayRouteSignal(signals []string) string {
	for _, signal := range signals {
		if signal = strings.TrimSpace(signal); signal != "" {
			return signal
		}
	}
	return "deterministic_rule"
}

func setRelayRoutePlanContext(c *gin.Context, plan *relayRoutePlan) {
	if c != nil && plan != nil {
		c.Set(relayRouteContextKey, plan)
	}
}

func relayRoutePlanFromContext(c *gin.Context) (*relayRoutePlan, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Get(relayRouteContextKey)
	if !ok {
		return nil, false
	}
	plan, ok := value.(*relayRoutePlan)
	return plan, ok && plan != nil
}

func relayRoutePinCandidates(c *gin.Context, rawBody []byte, apiKeyID int64) []relayRoutePinCandidate {
	if c == nil {
		return nil
	}
	candidates := make([]relayRoutePinCandidate, 0, 5)
	seen := make(map[string]struct{}, 5)
	add := func(kind, value string) {
		key := relayRoutePinCacheKey(apiKeyID, kind, value)
		if key == "" {
			return
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, relayRoutePinCandidate{Kind: kind, Key: key})
	}

	if c.Request != nil {
		if affinityID := resolveDownstreamAffinityID(c.Request.Header); affinityID != "" {
			add("trusted_affinity", affinityID)
			// The gateway-owned affinity is the authoritative shared-key scope.
			// Do not also persist client-controlled session or response IDs,
			// which would widen the pin beyond the trusted user+conversation.
			return candidates
		}
		for _, header := range []struct {
			kind string
			name string
		}{
			{kind: "session_id", name: "Session-Id"},
			{kind: "session_id", name: "Session_id"},
			{kind: "conversation_id", name: "Conversation-Id"},
			{kind: "conversation_id", name: "Conversation_id"},
		} {
			add(header.kind, c.Request.Header.Get(header.name))
		}
	}
	add("prompt_cache_key", gjson.GetBytes(rawBody, "prompt_cache_key").String())
	return candidates
}

func relayRoutePinCacheKey(apiKeyID int64, kind string, value string) string {
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if apiKeyID <= 0 || kind == "" || value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", apiKeyID, kind, value)))
	return kind + ":" + hex.EncodeToString(sum[:])
}

func (h *Handler) readRelayRoutePin(ctx context.Context, candidates []relayRoutePinCandidate) (relayRoutePinValue, bool, error) {
	if len(candidates) == 0 {
		return relayRoutePinValue{}, false, nil
	}
	if h == nil || h.cache == nil {
		return relayRoutePinValue{}, false, errRelayRoutePinUnavailable
	}
	cacheCtx, cancel := context.WithTimeout(ctx, relayRouteCacheTimeout)
	defer cancel()
	for _, candidate := range candidates {
		raw, found, err := h.cache.GetRuntime(cacheCtx, relayRoutePinNamespace, candidate.Key)
		if err != nil {
			return relayRoutePinValue{}, false, fmt.Errorf("%w: %v", errRelayRoutePinUnavailable, err)
		}
		if !found {
			continue
		}
		var pin relayRoutePinValue
		if err := json.Unmarshal(raw, &pin); err != nil || pin.GroupID <= 0 {
			return relayRoutePinValue{}, false, fmt.Errorf("%w: invalid pin value", errRelayRoutePinUnavailable)
		}
		return pin, true, nil
	}
	return relayRoutePinValue{}, false, nil
}

func (h *Handler) writeRelayRoutePins(ctx context.Context, plan *relayRoutePlan) error {
	if plan == nil || !plan.Required() || plan.SkipPinPersistence {
		return nil
	}
	if len(plan.PinCandidates) == 0 {
		return fmt.Errorf("%w: stable conversation scope missing", errRelayRoutePinUnavailable)
	}
	if h == nil || h.cache == nil {
		return errRelayRoutePinUnavailable
	}
	raw, err := json.Marshal(relayRoutePinValue{GroupID: plan.RequiredGroupID, Source: plan.Origin})
	if err != nil {
		return err
	}
	cacheCtx, cancel := context.WithTimeout(ctx, relayRouteCacheTimeout)
	defer cancel()
	for _, candidate := range plan.PinCandidates {
		if err := h.cache.SetRuntime(cacheCtx, relayRoutePinNamespace, candidate.Key, raw, plan.Config.PinTTL); err != nil {
			return fmt.Errorf("%w: %v", errRelayRoutePinUnavailable, err)
		}
	}
	return nil
}

func (h *Handler) observeRelayRouteSelection(c *gin.Context, plan *relayRoutePlan, account *auth.Account) (becameOverflow bool, err error) {
	if plan == nil || !plan.Config.Enabled || account == nil {
		return false, nil
	}
	inTargetGroup := plan.accountInTargetGroup(account)
	if plan.Required() && !plan.accountInRequiredGroup(account) {
		h.logRelayGroupEscapeViolation(c, plan)
		return false, fmt.Errorf("relay route invariant violated: selected account outside group %d", plan.RequiredGroupID)
	}
	if !plan.Required() && inTargetGroup {
		plan.RequiredGroupID = plan.Config.GroupID
		plan.Source = relayRouteSourceOverflow
		plan.Origin = relayRouteSourceOverflow
		plan.Reason = "official_priority_fallback"
		becameOverflow = true
	}
	if !plan.Required() {
		return false, nil
	}
	if err := h.writeRelayRoutePins(c.Request.Context(), plan); err != nil {
		return becameOverflow, err
	}

	plan.SelectionCount++
	if plan.FirstAccountID == 0 {
		plan.FirstAccountID = account.ID()
	}
	switched := plan.PreviousAccount != 0 && plan.PreviousAccount != account.ID()
	plan.PreviousAccount = account.ID()
	h.logRelayRouteSelection(c, plan, account, switched)
	return becameOverflow, nil
}

func (h *Handler) applyRelayRouteSelection(
	c *gin.Context,
	plan *relayRoutePlan,
	account *auth.Account,
	filter auth.AccountFilter,
	retainedHTTPFallback bool,
) (auth.AccountFilter, bool) {
	if retainedHTTPFallback {
		return filter, true
	}
	becameOverflow, err := h.observeRelayRouteSelection(c, plan, account)
	if err != nil {
		h.store.Release(account)
		h.replyRelayRouteUnavailable(c, err)
		return filter, false
	}
	if becameOverflow {
		filter = plan.composeFilter(filter)
	}
	return filter, true
}

func (h *Handler) replyRelayRouteUnavailable(c *gin.Context, err error) {
	if c == nil {
		return
	}
	endpoint := ""
	if c.Request != nil && c.Request.URL != nil {
		endpoint = c.Request.URL.Path
	}
	log.Printf("Relay route state unavailable (endpoint=%s): %v", endpoint, err)
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": gin.H{"message": "Relay route state is temporarily unavailable", "type": "server_error"},
	})
}
