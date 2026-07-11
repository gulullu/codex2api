package proxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// promptFilterFullTextMaxRunes limits the persisted redacted blocked-request text preview.
const promptFilterFullTextMaxRunes = 32000
const codexAmbientSuggestionClassifierPrefix = "Classify Codex ambient suggestion candidates for policy safety."
const codex55UnrestrictedInstructionsPatternName = "codex55_unrestricted_instructions"
const promptCyberPolicyMessage = "This request was blocked by the content policy. Please rephrase and try again."

func promptCyberPolicyError() *api.APIError {
	return api.NewAPIError(
		api.ErrorCode("content_policy_violation"),
		promptCyberPolicyMessage,
		api.ErrorTypeInvalidRequest,
	)
}

func sendPromptCyberPolicyBlockedOpenAI(c *gin.Context) {
	api.SendErrorWithStatus(c, promptCyberPolicyError(), http.StatusBadRequest)
}

func routingPromptFilterConfig(cfg promptfilter.Config) promptfilter.Config {
	// codex2api only uses local rules as routing signals. Moderation and
	// user-visible policy blocking are owned by the upstream sub2 layer.
	cfg.Mode = promptfilter.ModeMonitor
	cfg.Review.Enabled = false
	cfg.Review.All = false
	return cfg
}

func (h *Handler) inspectPromptFilterOpenAI(c *gin.Context, rawBody []byte, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	text := promptfilter.ExtractText(rawBody, endpoint, cfg.MaxTextLength)
	c.Set(contextPromptFilterText, text)
	if nested, ok := takeNestedPromptRiskDecision(c); ok {
		setPromptRiskDecisionContext(c, nested, h.cybRelayConfig().GroupID)
		return false
	}
	verdict := promptfilter.Inspect(rawBody, endpoint, cfg)
	return h.inspectCybRelayPrompt(c, rawBody, verdict, text, endpoint, model)
}

func (h *Handler) inspectPromptFilterTextOpenAI(c *gin.Context, text string, endpoint string, model string) bool {
	c.Set(contextPromptFilterText, text)
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	verdict := promptfilter.InspectText(text, cfg)
	return h.inspectCybRelayPrompt(c, nil, verdict, text, endpoint, model)
}

func (h *Handler) inspectPromptFilterAnthropic(c *gin.Context, rawBody []byte, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	text := promptfilter.ExtractText(rawBody, endpoint, cfg.MaxTextLength)
	c.Set(contextPromptFilterText, text)
	verdict := promptfilter.Inspect(rawBody, endpoint, cfg)
	return h.inspectCybRelayPrompt(c, rawBody, verdict, text, endpoint, model)
}

var promptFilterExplicitHighRiskPatterns = map[string]struct{}{
	codex55UnrestrictedInstructionsPatternName: {},
	"credential_theft":                         {},
	"malware_authoring":                        {},
	"ransomware_deployment":                    {},
	"phishing_generation":                      {},
	"mfa_bypass":                               {},
	"fraud_carding":                            {},
}

func promptFilterExplicitHighRiskVerdict(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if _, ok := promptFilterExplicitHighRiskPatterns[match.Name]; ok {
			return true
		}
	}
	return false
}

func cybRelayTextEndpoint(endpoint string) bool {
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "/v1/responses", "/v1/responses/compact", "/v1/chat/completions", "/v1/messages":
		return true
	default:
		return false
	}
}

func promptFilterCYBSignal(verdict promptfilter.Verdict, text string, cfg promptfilter.Config, endpoint string) (bool, []string) {
	if !verdict.Enabled || !cybRelayTextEndpoint(endpoint) {
		return false, nil
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = promptfilter.DefaultThreshold
	}
	signals := make([]string, 0, 4)
	if verdict.Score >= threshold {
		signals = append(signals, "local_threshold")
	}
	if promptfilter.IsHighRiskReviewVerdict(verdict) {
		signals = append(signals, "local_high_risk")
	}
	if promptFilterExplicitHighRiskVerdict(verdict) {
		signals = append(signals, "explicit_high_risk_rule")
	}
	if promptfilter.LooksLikeTechnicalCyberIntent(text) {
		signals = append(signals, "technical_cyber_intent")
	}
	return len(signals) > 0, signals
}

// PromptFilterRouteSignal exposes the same monitor-only routing decision used
// by the live proxy so the admin route tester cannot drift back to legacy
// moderation or blocking semantics.
func PromptFilterRouteSignal(verdict promptfilter.Verdict, text string, cfg promptfilter.Config, endpoint string) (bool, []string) {
	cfg = routingPromptFilterConfig(cfg)
	return promptFilterCYBSignal(verdict, text, cfg, endpoint)
}

func omniOutcomeRequiresPolicyBlock(outcome promptfilter.ReviewOutcome, cybSignal bool) bool {
	if !outcome.Flagged {
		return false
	}
	trueCategories := 0
	for category, flagged := range outcome.Categories {
		if !flagged {
			continue
		}
		trueCategories++
		if strings.EqualFold(strings.TrimSpace(category), "illicit") && cybSignal {
			continue
		}
		// Every category except plain illicit is a non-CYB hard policy category.
		// Unknown future categories also fail safe here.
		return true
	}
	// A raw flag without category evidence is non-standard and must not be
	// reclassified as CYB merely because the local detector also fired.
	return trueCategories == 0 || !cybSignal
}

func (h *Handler) reviewPromptFilterVerdictDetailed(ctx context.Context, text string, verdict promptfilter.Verdict, cfg promptfilter.Config, endpoint string) (promptfilter.Verdict, promptfilter.ReviewOutcome, error) {
	outcome, reviewErr := promptfilter.DefaultReviewClient.ReviewTextDetailed(ctx, text, cfg.Review)
	flagged := outcome.FlaggedForEndpoint(endpoint)
	verdict = promptfilter.ApplyReviewResult(verdict, flagged, outcome.Model, reviewErr, cfg.Review)
	if reviewErr == nil && !flagged && len(verdict.Matched) == 0 {
		verdict.Reason = "prompt review cleared request"
	}
	if reviewErr == nil && flagged {
		switch promptfilter.NormalizeConfig(cfg).Mode {
		case promptfilter.ModeBlock:
			verdict.Action = promptfilter.ActionBlock
		case promptfilter.ModeWarn:
			verdict.Action = promptfilter.ActionWarn
		}
		verdict.Reason = "prompt review flagged request"
	}
	return verdict, outcome, reviewErr
}

func (h *Handler) inspectCybRelayPrompt(c *gin.Context, rawBody []byte, localVerdict promptfilter.Verdict, text string, endpoint string, model string) bool {
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	cybSignal, signals := promptFilterCYBSignal(localVerdict, text, cfg, endpoint)
	relayCfg := h.cybRelayConfig()
	probeRoute := relayCfg.Enabled && relayCfg.GroupID > 0 && cybRelayTextEndpoint(endpoint) && detectProbeRoute(rawBody, endpoint, text)
	decision := defaultPromptRiskDecision()
	if probeRoute {
		signals = appendUniqueRouteSignal(signals, probeRouteSignal)
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "Probe isolated to relay pool",
			Signals:     signals,
			RouteSource: cybRelayRouteSourceProbe,
		}
	} else if cybSignal {
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "CYB risk isolated to relay pool",
			Signals:     signals,
			RouteSource: cybRelayRouteSourceDirect,
		}
	}

	// Keep local rule matches for diagnostics, but never turn them into a
	// user-visible moderation decision in codex2api.
	localVerdict.Action = promptfilter.ActionAllow
	if !cybRelayTextEndpoint(endpoint) {
		setPromptRiskDecisionContext(c, defaultPromptRiskDecision(), h.cybRelayConfig().GroupID)
		h.logPromptFilterVerdict(c, endpoint, model, "local_filter", "", localVerdict)
		return false
	}
	decision = h.applyCybRoutePin(c, rawBody, decision)
	h.logPromptFilterVerdict(c, endpoint, model, "local_filter", "", localVerdict)
	h.logCybRelayDecision(c, endpoint, model, text, localVerdict, decision)
	return false
}

func (h *Handler) logCybRelayDecision(c *gin.Context, endpoint string, model string, text string, baseVerdict promptfilter.Verdict, decision promptRiskDecision) {
	if !decision.routesToCybRelay() {
		return
	}
	verdict := baseVerdict
	verdict.Enabled = true
	verdict.Action = promptfilter.ActionRoute
	verdict.Reason = decision.routeReason()
	verdict.TextPreview = text
	verdict.FullText = text
	h.logPromptFilterVerdict(c, endpoint, model, "cyb_relay_routed", "", verdict)
}

func (h *Handler) logPromptFilterVerdict(c *gin.Context, endpoint string, model string, source string, errorCode string, verdict promptfilter.Verdict) {
	if h == nil || h.db == nil || !verdict.Enabled {
		return
	}
	if source == "local_filter" && len(verdict.Matched) == 0 && !verdict.Reviewed {
		return
	}
	if h.store != nil {
		cfg := h.store.GetPromptFilterConfig()
		if source == "local_filter" && !cfg.LogMatches {
			return
		}
	}
	input := &database.PromptFilterLogInput{
		Source:          source,
		Endpoint:        endpoint,
		Model:           model,
		Action:          verdict.Action,
		Mode:            verdict.Mode,
		Score:           verdict.Score,
		Threshold:       verdict.Threshold,
		MatchedPatterns: promptfilter.MatchesJSON(verdict.Matched),
		TextPreview:     promptfilter.RedactedPreview(verdict.TextPreview, 500),
		ClientIP:        c.ClientIP(),
		ErrorCode:       errorCode,
		ReviewModel:     verdict.ReviewModel,
		ReviewFlagged:   verdict.ReviewFlagged,
		ReviewError:     verdict.ReviewError,
	}
	// 被拦截（block）的请求仅记录脱敏后的检查文本预览，便于排查触发原因，
	// 同时避免把 Authorization/API Key/token 等敏感值持久化到日志。
	if verdict.Action == promptfilter.ActionBlock || verdict.Action == promptfilter.ActionRoute {
		input.FullText = promptfilter.RedactedPreview(verdict.FullText, promptFilterFullTextMaxRunes)
	}
	populatePromptFilterAPIKeyMeta(c, input)
	populateCybPromptFilterRouteMeta(c, input)
	input.ClientRequestID = strings.TrimSpace(c.GetHeader("X-Client-Request-Id"))
	input.LogicalRequestID = logicalRequestID(c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.db.InsertPromptFilterLog(ctx, input)
}

func (h *Handler) logUpstreamCyberPolicy(c *gin.Context, endpoint string, model string, body []byte) {
	if h == nil || h.store == nil {
		return
	}
	errorCode := upstreamCyberPolicyCode(body)
	if errorCode == "" {
		return
	}
	cfg := h.store.GetPromptFilterConfig()
	reqText := ""
	if v, ok := c.Get(contextPromptFilterText); ok {
		if s, ok2 := v.(string); ok2 {
			reqText = strings.TrimSpace(s)
		}
	}
	upstreamReason := promptfilter.RedactSensitive(string(body))
	fullText := upstreamReason
	if reqText != "" {
		fullText = `【上游拦截原因】
` + upstreamReason + `

【请求内容】
` + reqText
	}
	verdict := promptfilter.Verdict{
		Enabled:     true,
		Mode:        cfg.Mode,
		Action:      promptfilter.ActionBlock,
		Score:       0,
		Threshold:   cfg.Threshold,
		Reason:      "upstream returned cyber policy",
		TextPreview: reqText,
		FullText:    fullText,
	}
	h.logPromptFilterVerdict(c, endpoint, model, "upstream_cyber_policy", errorCode, verdict)
}

func upstreamCyberPolicyCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	raw := string(body)
	for _, path := range []string{"codex_error_info", "error.codex_error_info", "error.code", "code"} {
		if value := strings.TrimSpace(gjson.GetBytes(body, path).String()); strings.EqualFold(value, "cyber_policy") {
			return "cyber_policy"
		}
	}
	if strings.Contains(strings.ToLower(raw), "cyber_policy") || strings.Contains(strings.ToLower(raw), "cyber security risk") {
		return "cyber_policy"
	}
	return ""
}

func populatePromptFilterAPIKeyMeta(c *gin.Context, input *database.PromptFilterLogInput) {
	if c == nil || input == nil {
		return
	}
	if v, exists := c.Get(contextAPIKeyID); exists && v != nil {
		switch typed := v.(type) {
		case int64:
			input.APIKeyID = typed
		case int:
			input.APIKeyID = int64(typed)
		}
	}
	if v, exists := c.Get(contextAPIKeyName); exists && v != nil {
		if name, ok := v.(string); ok {
			input.APIKeyName = name
		}
	}
	if v, exists := c.Get(contextAPIKeyMasked); exists && v != nil {
		if masked, ok := v.(string); ok {
			input.APIKeyMasked = masked
		}
	}
}

func shouldReviewPromptFilterVerdict(verdict promptfilter.Verdict, cfg promptfilter.Config) bool {
	if promptFilterVerdictIsFinal(verdict) {
		return false
	}
	review := promptfilter.NormalizeReviewConfig(cfg.Review)
	if !review.Ready() {
		return false
	}
	if verdict.Action == promptfilter.ActionWarn || verdict.Action == promptfilter.ActionBlock {
		return true
	}
	return review.All && verdict.Action == promptfilter.ActionAllow
}

func promptFilterVerdictIsFinal(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if match.Name == codex55UnrestrictedInstructionsPatternName {
			return true
		}
	}
	return false
}

func promptFilterAllowedHighRisk(verdict promptfilter.Verdict, text string) bool {
	if promptFilterVerdictIsFinal(verdict) {
		return false
	}
	if verdict.Action != promptfilter.ActionAllow {
		return false
	}
	// 本地已判高危 → 送判官复核(原逻辑)；
	// 或本地漏判(score 低)但命中"纯技术化网络攻击"高召回特征 → 强制送判官二审。
	// 后者专治"汇编/GDB 改内存劫持 DNS"这类本地正则 score=0、omni 也打不出 flag 的漏放。
	return promptfilter.IsHighRiskReviewVerdict(verdict) ||
		promptfilter.LooksLikeTechnicalCyberIntent(text)
}

func promptFilterBlockedByLocalHighRisk(verdict promptfilter.Verdict) bool {
	if promptFilterVerdictIsFinal(verdict) {
		return false
	}
	if verdict.Action != promptfilter.ActionBlock {
		return false
	}
	if promptfilter.IsHighRiskReviewVerdict(verdict) {
		return true
	}
	threshold := verdict.Threshold
	if threshold <= 0 {
		threshold = promptfilter.DefaultThreshold
	}
	return verdict.Score >= threshold || verdict.RawScore >= threshold
}

func (h *Handler) inspectHighRiskReviewDisagreement(c *gin.Context, verdict promptfilter.Verdict, text string, endpoint string, model string, writeBlock func()) (bool, bool) {
	if !promptFilterAllowedHighRisk(verdict, text) && !promptFilterBlockedByLocalHighRisk(verdict) {
		return false, false
	}
	blocked := h.inspectSemanticReviewDisagreementText(c, text, endpoint, model, writeBlock)
	return true, blocked
}

func codexAmbientSuggestionClassifierBypass(text string, cfg promptfilter.Config) (promptfilter.Verdict, bool) {
	if !isCodexAmbientSuggestionClassifier(text) {
		return promptfilter.Verdict{}, false
	}
	cfg = promptfilter.NormalizeConfig(cfg)
	return promptfilter.Verdict{
		Enabled:   cfg.Enabled,
		Mode:      cfg.Mode,
		Action:    promptfilter.ActionAllow,
		Score:     0,
		Threshold: cfg.Threshold,
		Matched: []promptfilter.Match{{
			Name:     "internal_policy_classifier_bypass",
			Weight:   0,
			Category: "meta_safety",
		}},
		Reason:      "allowed internal Codex ambient suggestion policy classifier",
		TextPreview: text,
		FullText:    text,
	}, true
}

func isCodexAmbientSuggestionClassifier(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || !strings.HasPrefix(trimmed, codexAmbientSuggestionClassifierPrefix) {
		return false
	}
	lower := strings.ToLower(trimmed)
	required := []string{
		"ambient suggestion candidates",
		"suggestion_id:",
		"return a json object",
		"\"exclude\"",
		"only output the json object",
	}
	for _, needle := range required {
		if !strings.Contains(lower, needle) {
			return false
		}
	}
	return true
}

func (h *Handler) reviewPromptFilterVerdict(ctx context.Context, text string, verdict promptfilter.Verdict, cfg promptfilter.Config, endpoint string) promptfilter.Verdict {
	flagged, model, err := promptfilter.DefaultReviewClient.ReviewText(ctx, text, cfg.Review, endpoint)
	verdict = promptfilter.ApplyReviewResult(verdict, flagged, model, err, cfg.Review)
	if err == nil && !flagged && len(verdict.Matched) == 0 {
		verdict.Reason = "prompt review cleared request"
	}
	if err == nil && flagged {
		switch promptfilter.NormalizeConfig(cfg).Mode {
		case promptfilter.ModeBlock:
			verdict.Action = promptfilter.ActionBlock
		case promptfilter.ModeWarn:
			verdict.Action = promptfilter.ActionWarn
		}
		verdict.Reason = "prompt review flagged request"
	}
	return verdict
}
