package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
const promptFilterUserTextRescueSignal = "user_text_rescue"
const promptFilterSQLCredentialExfiltrationSignal = "local_sql_credential_exfiltration"
const contextPromptFilterScanMeta = "promptFilterScanMeta"

type promptFilterRouteScan struct {
	Verdict       promptfilter.Verdict
	FullText      string
	AuditText     string
	CYBSignal     bool
	Signals       []string
	PayloadBytes  int64
	ScannedBytes  int64
	ScanTruncated bool
	ScanDetails   string
}

type promptFilterAuditScanMeta struct {
	PayloadBytes  int64
	ScannedBytes  int64
	ScanTruncated bool
	ScanDetails   string
}

type promptFilterPartitionScanDetails struct {
	Version       int                               `json:"version"`
	PayloadBytes  int                               `json:"payload_bytes"`
	ScannedBytes  int                               `json:"scanned_bytes"`
	ScanTruncated bool                              `json:"scan_truncated"`
	OpaqueBytes   int                               `json:"opaque_bytes"`
	Partitions    []promptFilterPartitionScanDetail `json:"partitions"`
}

type promptFilterPartitionScanDetail struct {
	Name         string               `json:"name"`
	BudgetBytes  int                  `json:"budget_bytes"`
	SourceBytes  int                  `json:"source_bytes"`
	ScannedBytes int                  `json:"scanned_bytes"`
	Truncated    bool                 `json:"truncated"`
	Score        int                  `json:"score"`
	RawScore     int                  `json:"raw_score"`
	Matched      []promptfilter.Match `json:"matched,omitempty"`
	RouteSignals []string             `json:"route_signals,omitempty"`
}

var promptFilterSQLCredentialExtractionPattern = regexp.MustCompile(`(?i)\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b[^.!?\n]{0,160}\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b|\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b[^.!?\n]{0,100}\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b|(?:提取|导出|转储|窃取|获取|读取|泄露|外传)[^。！？\n]{0,100}(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)|(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)[^。！？\n]{0,80}(?:提取|导出|转储|窃取|获取|读取|泄露|外传)`)

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
	scan := inspectPromptFilterPayload(rawBody, endpoint, cfg, h.cybRelayConfig().UserTextRescanEnabled())
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	if nested, ok := takeNestedPromptRiskDecision(c); ok {
		setPromptRiskDecisionContext(c, nested, h.cybRelayConfig().GroupID)
		return false
	}
	return h.inspectCybRelayPrompt(c, rawBody, scan, endpoint, model)
}

func (h *Handler) inspectPromptFilterTextOpenAI(c *gin.Context, text string, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterText(text, endpoint, cfg)
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	return h.inspectCybRelayPrompt(c, nil, scan, endpoint, model)
}

func (h *Handler) inspectPromptFilterAnthropic(c *gin.Context, rawBody []byte, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterPayload(rawBody, endpoint, cfg, h.cybRelayConfig().UserTextRescanEnabled())
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	return h.inspectCybRelayPrompt(c, rawBody, scan, endpoint, model)
}

func setPromptFilterScanContext(c *gin.Context, scan promptFilterRouteScan) {
	if c == nil {
		return
	}
	c.Set(contextPromptFilterScanMeta, promptFilterAuditScanMeta{
		PayloadBytes:  scan.PayloadBytes,
		ScannedBytes:  scan.ScannedBytes,
		ScanTruncated: scan.ScanTruncated,
		ScanDetails:   scan.ScanDetails,
	})
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

const promptFilterMultiVectorWebAttackMinScore = 80

// promptFilterMultiVectorWebAttackVerdict is intentionally narrower than a
// generic "two risky rules" heuristic. Production evidence showed that the
// path_traversal + xss_attack combination was missed at the normal threshold,
// while command_injection + path_traversal frequently appears in benign
// security-scanner instructions. Keep this exact pair until shadow evidence
// justifies expanding it.
func promptFilterMultiVectorWebAttackVerdict(verdict promptfilter.Verdict) bool {
	if verdict.Score < promptFilterMultiVectorWebAttackMinScore {
		return false
	}
	hasPathTraversal := false
	hasXSSAttack := false
	for _, match := range verdict.Matched {
		switch match.Name {
		case "path_traversal":
			hasPathTraversal = true
		case "xss_attack":
			hasXSSAttack = true
		}
	}
	return hasPathTraversal && hasXSSAttack
}

func promptFilterExplicitHighRiskVerdict(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if _, ok := promptFilterExplicitHighRiskPatterns[match.Name]; ok {
			return true
		}
	}
	return false
}

// promptFilterSQLCredentialExfiltrationVerdict fills one narrow, observed
// routing gap. All three facts must coexist in the same independently scanned
// partition; signals from system/tools/user are never combined to satisfy it.
func promptFilterSQLCredentialExfiltrationVerdict(verdict promptfilter.Verdict, text string) bool {
	hasSQLInjection := false
	hasOperationalExploit := false
	for _, match := range verdict.Matched {
		switch match.Name {
		case "sql_injection_attack":
			hasSQLInjection = true
		case "operational_exploit_request":
			hasOperationalExploit = true
		}
	}
	return hasSQLInjection && hasOperationalExploit && promptFilterSQLCredentialExtractionPattern.MatchString(text)
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
	if promptFilterSQLCredentialExfiltrationVerdict(verdict, text) {
		signals = append(signals, promptFilterSQLCredentialExfiltrationSignal)
	}
	// Only fill the evidence-backed gap below the normal routing threshold.
	// Existing stronger signals retain their original, more specific reason.
	if len(signals) == 0 && promptFilterMultiVectorWebAttackVerdict(verdict) {
		signals = append(signals, "local_multi_vector_web_attack")
	}
	return len(signals) > 0, signals
}

func inspectPromptFilterText(text string, endpoint string, cfg promptfilter.Config) promptFilterRouteScan {
	verdict := promptfilter.InspectText(text, cfg)
	cybSignal, signals := promptFilterCYBSignal(verdict, text, cfg, endpoint)
	details := promptFilterPartitionScanDetails{
		Version:      promptfilter.RoutingPartitionScanVersion,
		PayloadBytes: len(text),
		ScannedBytes: len(text),
		Partitions: []promptFilterPartitionScanDetail{{
			Name:         "text",
			BudgetBytes:  len(text),
			SourceBytes:  len(text),
			ScannedBytes: len(text),
			Score:        verdict.Score,
			RawScore:     verdict.RawScore,
			Matched:      verdict.Matched,
			RouteSignals: signals,
		}},
	}
	return promptFilterRouteScan{
		Verdict:      verdict,
		FullText:     text,
		AuditText:    text,
		CYBSignal:    cybSignal,
		Signals:      signals,
		PayloadBytes: int64(len(text)),
		ScannedBytes: int64(len(text)),
		ScanDetails:  marshalPromptFilterScanDetails(details),
	}
}

// inspectPromptFilterPayload scans four independently budgeted compartments.
// Every supported full-payload field remains covered, but scores and composite
// routing rules are never assembled across compartments.
func inspectPromptFilterPayload(rawBody []byte, endpoint string, cfg promptfilter.Config, userTextRescanEnabled bool) promptFilterRouteScan {
	if !userTextRescanEnabled || !cybRelayTextEndpoint(endpoint) {
		fullText := promptfilter.ExtractText(rawBody, endpoint, cfg.MaxTextLength)
		fullScan := inspectPromptFilterText(fullText, endpoint, cfg)
		legacyBudget := cfg.MaxTextLength
		if legacyBudget <= 0 {
			legacyBudget = promptfilter.DefaultMaxTextLength
		}
		fullScan.PayloadBytes = int64(len(rawBody))
		fullScan.ScanTruncated = len(fullText) >= legacyBudget
		fullScan.ScanDetails = marshalPromptFilterScanDetails(promptFilterPartitionScanDetails{
			Version:       promptfilter.RoutingPartitionScanVersion,
			PayloadBytes:  len(rawBody),
			ScannedBytes:  len(fullText),
			ScanTruncated: fullScan.ScanTruncated,
			Partitions: []promptFilterPartitionScanDetail{{
				Name:         "legacy_full",
				BudgetBytes:  legacyBudget,
				SourceBytes:  len(fullText),
				ScannedBytes: len(fullText),
				Truncated:    fullScan.ScanTruncated,
				Score:        fullScan.Verdict.Score,
				RawScore:     fullScan.Verdict.RawScore,
				Matched:      fullScan.Verdict.Matched,
				RouteSignals: fullScan.Signals,
			}},
		})
		return fullScan
	}

	partitioned := promptfilter.ExtractRoutingPartitions(rawBody, endpoint)
	details := promptFilterPartitionScanDetails{
		Version:       partitioned.Version,
		PayloadBytes:  partitioned.PayloadBytes,
		ScannedBytes:  partitioned.ScannedBytes,
		ScanTruncated: partitioned.ScanTruncated,
		OpaqueBytes:   partitioned.OpaqueBytes,
		Partitions:    make([]promptFilterPartitionScanDetail, 0, len(partitioned.Partitions)),
	}

	var merged promptFilterRouteScan
	firstVerdict := true
	userRouted := false
	userText := ""
	userPreview := ""
	combinedParts := make([]string, 0, len(partitioned.Partitions))
	partitionScans := make([]promptFilterRouteScan, len(partitioned.Partitions))
	scanPartition := func(index int) {
		partition := partitioned.Partitions[index]
		partitionCfg := cfg
		partitionCfg.MaxTextLength = partition.BudgetBytes
		partitionVerdict := promptfilter.InspectText(partition.Text, partitionCfg)
		partitionSignal, partitionSignals := promptFilterCYBSignal(partitionVerdict, partition.Text, partitionCfg, endpoint)
		partitionScans[index] = promptFilterRouteScan{
			Verdict:   partitionVerdict,
			FullText:  partition.Text,
			AuditText: partition.Text,
			CYBSignal: partitionSignal,
			Signals:   partitionSignals,
		}
	}
	if partitioned.ScannedBytes >= 64*1024 {
		var wait sync.WaitGroup
		for index, partition := range partitioned.Partitions {
			if strings.TrimSpace(partition.Text) == "" {
				scanPartition(index)
				continue
			}
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				scanPartition(index)
			}(index)
		}
		wait.Wait()
	} else {
		for index := range partitioned.Partitions {
			scanPartition(index)
		}
	}
	for index, partition := range partitioned.Partitions {
		partitionScan := partitionScans[index]
		if firstVerdict {
			merged.Verdict = partitionScan.Verdict
			firstVerdict = false
		} else {
			merged.Verdict = mergePromptFilterVerdicts(merged.Verdict, partitionScan.Verdict)
		}
		merged.CYBSignal = merged.CYBSignal || partitionScan.CYBSignal
		for _, signal := range partitionScan.Signals {
			merged.Signals = appendUniqueRouteSignal(merged.Signals, signal)
		}
		if partition.Name == promptfilter.RoutingPartitionUser {
			userRouted = partitionScan.CYBSignal
			userText = partition.Text
			userPreview = partitionScan.Verdict.TextPreview
		}
		if strings.TrimSpace(partition.Text) != "" {
			combinedParts = append(combinedParts, partition.Text)
		}
		details.Partitions = append(details.Partitions, promptFilterPartitionScanDetail{
			Name:         partition.Name,
			BudgetBytes:  partition.BudgetBytes,
			SourceBytes:  partition.SourceBytes,
			ScannedBytes: partition.ScannedBytes,
			Truncated:    partition.Truncated,
			Score:        partitionScan.Verdict.Score,
			RawScore:     partitionScan.Verdict.RawScore,
			Matched:      partitionScan.Verdict.Matched,
			RouteSignals: partitionScan.Signals,
		})
	}
	merged.FullText = strings.TrimSpace(strings.Join(combinedParts, "\n"))
	merged.AuditText = merged.FullText
	merged.PayloadBytes = int64(partitioned.PayloadBytes)
	merged.ScannedBytes = int64(partitioned.ScannedBytes)
	merged.ScanTruncated = partitioned.ScanTruncated
	merged.ScanDetails = marshalPromptFilterScanDetails(details)

	// Preserve the existing rescue marker without running a fifth rule scan:
	// only mark the user signal as rescued when its bounded witness was absent
	// from the legacy full-text window.
	if userRouted {
		legacyFullText := promptfilter.ExtractText(rawBody, endpoint, cfg.MaxTextLength)
		if routingTextOutsideLegacyWindow(legacyFullText, userText) {
			merged.Signals = appendUniqueRouteSignal(merged.Signals, promptFilterUserTextRescueSignal)
			merged.AuditText = strings.TrimSpace(userText + "\n--- partitioned payload scan ---\n" + merged.FullText)
			merged.Verdict.TextPreview = userPreview
		}
	}
	return merged
}

func routingTextOutsideLegacyWindow(legacyFullText string, userText string) bool {
	userText = strings.TrimSpace(userText)
	if userText == "" {
		return false
	}
	for _, witness := range routingTextWitnesses(userText) {
		if witness != "" && strings.Contains(legacyFullText, witness) {
			return false
		}
	}
	return true
}

func routingTextWitnesses(text string) []string {
	const witnessBytes = 128
	text = strings.TrimSpace(text)
	if len(text) <= witnessBytes {
		return []string{text}
	}
	head := text[:witnessBytes]
	for len(head) > 0 && !utf8.ValidString(head) {
		head = head[:len(head)-1]
	}
	tail := text[len(text)-witnessBytes:]
	for len(tail) > 0 && !utf8.ValidString(tail) {
		tail = tail[1:]
	}
	return []string{head, tail}
}

func marshalPromptFilterScanDetails(details promptFilterPartitionScanDetails) string {
	data, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func mergePromptFilterVerdicts(full promptfilter.Verdict, user promptfilter.Verdict) promptfilter.Verdict {
	merged := full
	if user.Score > merged.Score {
		merged.Score = user.Score
		merged.Reason = user.Reason
	}
	if user.RawScore > merged.RawScore {
		merged.RawScore = user.RawScore
	}
	if user.ExtractedChars > merged.ExtractedChars {
		merged.ExtractedChars = user.ExtractedChars
	}
	if user.StrictHit && !merged.StrictHit {
		merged.StrictHit = true
		merged.Reason = user.Reason
	}
	merged.Enabled = merged.Enabled || user.Enabled

	seen := make(map[promptfilter.Match]struct{}, len(full.Matched)+len(user.Matched))
	merged.Matched = make([]promptfilter.Match, 0, len(full.Matched)+len(user.Matched))
	for _, verdict := range []promptfilter.Verdict{full, user} {
		for _, match := range verdict.Matched {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			merged.Matched = append(merged.Matched, match)
		}
	}
	return merged
}

// PromptFilterRouteSignal exposes the per-text monitor-only routing decision.
// The raw live path applies this decision independently to the full payload
// and input/messages compartments, while single-text testers use it once.
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

func (h *Handler) inspectCybRelayPrompt(c *gin.Context, rawBody []byte, scan promptFilterRouteScan, endpoint string, model string) bool {
	localVerdict := scan.Verdict
	text := scan.AuditText
	cybSignal := scan.CYBSignal
	signals := append([]string(nil), scan.Signals...)
	relayCfg := h.cybRelayConfig()
	probeRoute := relayCfg.Enabled && relayCfg.GroupID > 0 && cybRelayTextEndpoint(endpoint) && detectProbeRoute(rawBody, endpoint, scan.FullText)
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
	populatePromptFilterScanMeta(c, input)
	input.ClientRequestID = strings.TrimSpace(c.GetHeader("X-Client-Request-Id"))
	input.LogicalRequestID = logicalRequestID(c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.db.InsertPromptFilterLog(ctx, input)
}

func populatePromptFilterScanMeta(c *gin.Context, input *database.PromptFilterLogInput) {
	if c == nil || input == nil {
		return
	}
	value, exists := c.Get(contextPromptFilterScanMeta)
	if !exists {
		return
	}
	meta, ok := value.(promptFilterAuditScanMeta)
	if !ok {
		return
	}
	input.PayloadBytes = meta.PayloadBytes
	input.ScannedBytes = meta.ScannedBytes
	input.ScanTruncated = meta.ScanTruncated
	input.ScanDetails = meta.ScanDetails
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
		value := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, path).String()))
		switch value {
		case "cyber_policy":
			return "cyber_policy"
		case "content_policy", "content_filter", "policy_violation", "safety":
			return value
		}
	}
	lowerRaw := strings.ToLower(raw)
	if strings.Contains(lowerRaw, "cyber_policy") || strings.Contains(lowerRaw, "cyber security risk") {
		return "cyber_policy"
	}
	if strings.Contains(lowerRaw, "blocked by the content policy") ||
		strings.Contains(lowerRaw, "content policy violation") ||
		strings.Contains(lowerRaw, "violates the content policy") {
		return "content_policy"
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
