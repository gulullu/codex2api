// Package cybroute turns deterministic prompt-filter evidence into an account
// group routing hint. It deliberately does not moderate requests, call an
// external reviewer, or select an upstream account.
package cybroute

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/cybtext"
	"github.com/codex2api/security/promptfilter"
)

const (
	boundedUserWindowBodyThreshold          = 128 * 1024
	oversizedScanChunkBytes                 = 64 * 1024
	oversizedScanOverlapBytes               = 8 * 1024
	SignalLocalThreshold                    = "local_threshold"
	SignalLocalHighRisk                     = "local_high_risk"
	SignalExplicitHighRiskRule              = "explicit_high_risk_rule"
	SignalTechnicalCyberIntent              = "technical_cyber_intent"
	SignalSQLCredentialExfiltration         = "local_sql_credential_exfiltration"
	SignalTargetedCovertSurveillance        = "local_targeted_covert_surveillance"
	SignalNonChineseEnglishLanguage         = "local_non_zh_en_language"
	SignalCTFFlagExploitation               = "local_ctf_flag_exploitation"
	SignalOperationalSecurityTesting        = "local_operational_security_testing_platform"
	SignalOperationalRansomwareAuthoring    = "local_operational_ransomware_authoring"
	SignalMLModelBackdoorTraining           = "local_ml_model_backdoor_training"
	SignalRemoteCommandControlPlatform      = "local_remote_command_control_platform"
	SignalSecurityCodeAudit                 = "local_security_code_audit"
	SignalLoginProtectionReverseEngineering = "local_login_protection_reverse_engineering"
	SignalPersonalMediaCacheDecode          = "local_personal_media_cache_decode"
	SignalMultiVectorWebAttack              = "local_multi_vector_web_attack"
)

// Result is a routing-only decision. Route never means block.
type Result struct {
	Route         bool
	Signals       []string
	Matches       []promptfilter.Match
	Score         int
	Threshold     int
	PrimaryOrigin promptfilter.SegmentOrigin
	Truncated     bool
	ScannedBytes  int64
	FullScan      bool
}

type provenancePartition struct {
	origin promptfilter.SegmentOrigin
	text   strings.Builder
}

type routeOriginEvidence struct {
	origin  promptfilter.SegmentOrigin
	matches map[string]promptfilter.Match
}

func (e *routeOriginEvidence) add(verdict promptfilter.Verdict) {
	if e == nil {
		return
	}
	if e.matches == nil {
		e.matches = make(map[string]promptfilter.Match, len(verdict.Matched))
	}
	for _, match := range verdict.Matched {
		key := strings.ToLower(strings.TrimSpace(match.Name)) + "\x00" +
			strings.ToLower(strings.TrimSpace(match.Category))
		if _, exists := e.matches[key]; exists {
			continue
		}
		e.matches[key] = match
	}
}

func (e *routeOriginEvidence) cumulativeVerdict(cfg promptfilter.Config) promptfilter.Verdict {
	verdict := promptfilter.Verdict{
		Enabled:   true,
		Mode:      cfg.Mode,
		Threshold: cfg.Threshold,
	}
	for _, match := range e.matches {
		verdict.Matched = append(verdict.Matched, match)
		verdict.RawScore += match.Weight
		if !match.SignalOnly || match.Strict {
			verdict.Score += match.Weight
		}
		if match.Strict {
			verdict.StrictHit = true
		}
	}
	return verdict
}

type routingEngineEntry struct {
	engine *promptfilter.Engine
	err    error
}

const maxRoutingEngineCacheEntries = 16

var routingEngineCache = struct {
	sync.Mutex
	entries map[string]routingEngineEntry
	order   []string
}{
	entries: make(map[string]routingEngineEntry),
}

func compiledRoutingEngine(cfg promptfilter.Config) (*promptfilter.Engine, error) {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	key := string(encoded)
	routingEngineCache.Lock()
	if entry, ok := routingEngineCache.entries[key]; ok {
		routingEngineCache.Unlock()
		return entry.engine, entry.err
	}
	routingEngineCache.Unlock()

	engine, compileErr := promptfilter.NewEngine(cfg)
	entry := routingEngineEntry{engine: engine, err: compileErr}
	routingEngineCache.Lock()
	defer routingEngineCache.Unlock()
	if actual, ok := routingEngineCache.entries[key]; ok {
		return actual.engine, actual.err
	}
	if len(routingEngineCache.entries) >= maxRoutingEngineCacheEntries && len(routingEngineCache.order) > 0 {
		oldest := routingEngineCache.order[0]
		delete(routingEngineCache.entries, oldest)
		routingEngineCache.order = routingEngineCache.order[1:]
	}
	routingEngineCache.entries[key] = entry
	routingEngineCache.order = append(routingEngineCache.order, key)
	return entry.engine, entry.err
}

// Inspect evaluates only user-authored provenance that can represent a routing
// request. Evidence is never joined across origins. Developer/system/assistant
// replay cannot initiate a route, while prior user turns may preserve the CYB
// route for a full-history conversation. The current routing-only learned rule
// snapshot is applied without involving Prompt Filter configuration.
func Inspect(body []byte, endpoint, model string, cfg promptfilter.Config) Result {
	return InspectWithLearnedPatterns(body, endpoint, model, cfg, currentLearnedRules())
}

// InspectWithLearnedPatterns evaluates an independent routing-only rule
// snapshot in addition to the stable local CYB rules. The supplied patterns
// are never written back to or exposed as Prompt Filter configuration.
func InspectWithLearnedPatterns(
	body []byte,
	endpoint, model string,
	cfg promptfilter.Config,
	learned []cyblearn.Rule,
) Result {
	cfg = routingConfig(cfg)
	if len(body) > boundedUserWindowBodyThreshold && supportsBoundedUserWindows(endpoint) {
		// The general Prompt Filter envelope intentionally serves many policy
		// features and materializes gjson string results. Routing only needs
		// user provenance, so oversized requests take the independent bounded
		// parser directly and never decode a multi-megabyte user scalar first.
		result := Result{Threshold: cfg.Threshold}
		if inspectOversizedRouteBody(body, endpoint, cfg, learned, &result) {
			result.ScannedBytes = int64(len(body))
			result.FullScan = true
		} else {
			result.Truncated = true
		}
		return result
	}
	envelope := promptfilter.BuildEnvelopeWithModelsAndConfig(
		body,
		endpoint,
		model,
		"",
		promptfilter.TransportHTTP,
		cfg,
	)
	result := inspectEnvelope(envelope, cfg)
	if result.Truncated {
		if !result.Route {
			partitions := boundedUserWindowPartitions(body, endpoint)
			inspectRoutePartitions(partitions, cfg, &result)
			applyLearnedRulesToPartitions(partitions, learned, &result)
		}
		return result
	}
	applyLearnedRules(envelope, learned, &result)
	result.ScannedBytes = int64(len(body))
	result.FullScan = true
	return result
}

func supportsBoundedUserWindows(endpoint string) bool {
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "/v1/responses", "/v1/responses/compact", "/v1/chat/completions", "/v1/messages":
		return true
	default:
		return false
	}
}

func applyLearnedRules(envelope promptfilter.RequestEnvelope, learned []cyblearn.Rule, result *Result) {
	if result == nil || len(learned) == 0 || envelope.AdapterUnclassified || len(envelope.Segments) == 0 {
		return
	}
	applyLearnedRulesToPartitions(partitionEnvelope(envelope), learned, result)
}

func boundedUserWindowPartitions(body []byte, endpoint string) []provenancePartition {
	current, history, tool := cybtext.ExtractRoutingWindows(body, endpoint, 128*1024)
	partitions := make([]provenancePartition, 0, len(current)+len(history)+len(tool))
	add := func(origin promptfilter.SegmentOrigin, windows []string) {
		for _, window := range windows {
			window = strings.TrimSpace(window)
			if window == "" {
				continue
			}
			var partition provenancePartition
			partition.origin = origin
			partition.text.WriteString(window)
			partitions = append(partitions, partition)
		}
	}
	add(promptfilter.OriginCurrentUser, current)
	add(promptfilter.OriginHistory, history)
	if len(current) == 0 {
		add(promptfilter.OriginToolOutput, tool)
	}
	return partitions
}

func inspectOversizedRouteBody(
	body []byte,
	endpoint string,
	cfg promptfilter.Config,
	learned []cyblearn.Rule,
	result *Result,
) bool {
	if result == nil {
		return false
	}
	// A user may configure the official prompt-filter scan budget below this
	// routing walker's chunk size. Do not let that setting create a fresh hole
	// inside each already bounded chunk; the override is local to this
	// routing-only pass and does not change the stored Prompt Filter config.
	chunkConfig := cfg
	if chunkConfig.MaxTextLength < oversizedScanChunkBytes {
		chunkConfig.MaxTextLength = oversizedScanChunkBytes
	}
	engine, _ := compiledRoutingEngine(chunkConfig)
	matchSeen := routeMatchSeen(result)
	learnedSeen := learnedMatchSeen(result, learned)
	evidence := make(map[promptfilter.SegmentOrigin]*routeOriginEvidence, 3)
	evidenceOrder := make([]*routeOriginEvidence, 0, 3)
	_, ok := cybtext.WalkRoutingTextChunks(
		body,
		endpoint,
		oversizedScanChunkBytes,
		oversizedScanOverlapBytes,
		func(origin cybtext.TextOrigin, text string) {
			mapped, mappedOK := routingTextOrigin(origin)
			if !mappedOK {
				return
			}
			originEvidence := evidence[mapped]
			if originEvidence == nil {
				originEvidence = &routeOriginEvidence{origin: mapped}
				evidence[mapped] = originEvidence
				evidenceOrder = append(evidenceOrder, originEvidence)
			}
			verdict := inspectRoutePartitionTextWithEngine(
				mapped,
				text,
				chunkConfig,
				engine,
				result,
				matchSeen,
			)
			originEvidence.add(verdict)
			applyLearnedRulesToText(mapped, text, learned, result, learnedSeen)
		},
	)
	if !ok {
		return false
	}
	for _, originEvidence := range evidenceOrder {
		applyRouteVerdict(
			originEvidence.origin,
			"",
			originEvidence.cumulativeVerdict(chunkConfig),
			chunkConfig,
			result,
			matchSeen,
		)
	}
	return true
}

func routingTextOrigin(origin cybtext.TextOrigin) (promptfilter.SegmentOrigin, bool) {
	switch origin {
	case cybtext.TextOriginCurrentUser:
		return promptfilter.OriginCurrentUser, true
	case cybtext.TextOriginHistory:
		return promptfilter.OriginHistory, true
	case cybtext.TextOriginToolOutput:
		return promptfilter.OriginToolOutput, true
	default:
		return "", false
	}
}

func applyLearnedRulesToPartitions(
	partitions []provenancePartition,
	learned []cyblearn.Rule,
	result *Result,
) {
	if result == nil || len(learned) == 0 || len(partitions) == 0 {
		return
	}
	seen := learnedMatchSeen(result, learned)
	for _, partition := range partitions {
		text := strings.TrimSpace(partition.text.String())
		if text == "" {
			continue
		}
		applyLearnedRulesToText(partition.origin, text, learned, result, seen)
	}
}

func learnedMatchSeen(result *Result, learned []cyblearn.Rule) map[string]struct{} {
	size := len(learned)
	if result != nil {
		size += len(result.Matches)
	}
	seen := make(map[string]struct{}, size)
	if result == nil {
		return seen
	}
	for _, match := range result.Matches {
		seen[strings.ToLower(strings.TrimSpace(match.Name))] = struct{}{}
	}
	return seen
}

func applyLearnedRulesToText(
	origin promptfilter.SegmentOrigin,
	text string,
	learned []cyblearn.Rule,
	result *Result,
	seen map[string]struct{},
) {
	text = strings.TrimSpace(text)
	if result == nil || text == "" || len(learned) == 0 {
		return
	}
	if seen == nil {
		seen = learnedMatchSeen(result, learned)
	}
	lowerText := strings.ToLower(text)
	nonASCII := containsNonASCII(text)
	for _, rule := range learned {
		if !nonASCII && !rule.MayMatchLowerText(lowerText) {
			continue
		}
		if !rule.MatchString(text) {
			continue
		}
		if !result.Route {
			result.PrimaryOrigin = origin
		}
		result.Route = true
		if result.Score < 250 {
			result.Score = 250
		}
		result.Signals = appendUnique(result.Signals, "learned_rule:"+strings.TrimSpace(rule.Name))
		key := strings.ToLower(strings.TrimSpace(rule.Name))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result.Matches = append(result.Matches, promptfilter.Match{
			Name:     rule.Name,
			Weight:   250,
			Category: "cyb_learned",
			Strict:   true,
		})
	}
}

func inspectEnvelope(envelope promptfilter.RequestEnvelope, cfg promptfilter.Config) Result {
	result := Result{
		Threshold: cfg.Threshold,
		Truncated: envelope.Truncated || envelope.CurrentUserTruncated || envelope.AuxiliaryTruncated,
	}
	if envelope.AdapterUnclassified || len(envelope.Segments) == 0 {
		return result
	}
	inspectRoutePartitions(partitionEnvelope(envelope), cfg, &result)
	return result
}

func inspectRoutePartitions(
	partitions []provenancePartition,
	cfg promptfilter.Config,
	result *Result,
) {
	if result == nil || len(partitions) == 0 {
		return
	}
	matchSeen := routeMatchSeen(result)
	for _, partition := range partitions {
		text := strings.TrimSpace(partition.text.String())
		if text == "" {
			continue
		}
		inspectRoutePartitionText(partition.origin, text, cfg, result, matchSeen)
	}
}

func routeMatchSeen(result *Result) map[string]struct{} {
	size := 0
	if result != nil {
		size = len(result.Matches)
	}
	seen := make(map[string]struct{}, size)
	if result == nil {
		return seen
	}
	for _, match := range result.Matches {
		seen[match.Name+"\x00"+match.Category] = struct{}{}
	}
	return seen
}

func inspectRoutePartitionText(
	origin promptfilter.SegmentOrigin,
	text string,
	cfg promptfilter.Config,
	result *Result,
	matchSeen map[string]struct{},
) promptfilter.Verdict {
	return inspectRoutePartitionTextWithEngine(origin, text, cfg, nil, result, matchSeen)
}

func inspectRoutePartitionTextWithEngine(
	origin promptfilter.SegmentOrigin,
	text string,
	cfg promptfilter.Config,
	engine *promptfilter.Engine,
	result *Result,
	matchSeen map[string]struct{},
) promptfilter.Verdict {
	text = strings.TrimSpace(text)
	if result == nil || text == "" {
		return promptfilter.Verdict{}
	}
	var verdict promptfilter.Verdict
	if engine != nil {
		// The hint gate may prove that no Prompt Filter regexp can match this
		// bounded chunk. Keep an enabled empty verdict so the independent raw
		// routing helpers below still inspect every chunk.
		verdict = promptfilter.Verdict{
			Enabled:   true,
			Mode:      cfg.Mode,
			Threshold: cfg.Threshold,
		}
		if engine.ExactPrecheckMayMatch(text) {
			verdict = engine.InspectTextWithExactPrecheck(
				text,
				cfg.Advanced.Guard.Performance,
			)
		}
	} else {
		verdict = promptfilter.InspectText(text, cfg)
	}
	applyRouteVerdict(origin, text, verdict, cfg, result, matchSeen)
	return verdict
}

func applyRouteVerdict(
	origin promptfilter.SegmentOrigin,
	text string,
	verdict promptfilter.Verdict,
	cfg promptfilter.Config,
	result *Result,
	matchSeen map[string]struct{},
) {
	if result == nil {
		return
	}
	signals := routeSignals(verdict, text, cfg)
	if len(signals) == 0 {
		return
	}
	if !result.Route || verdict.Score > result.Score {
		result.PrimaryOrigin = origin
		result.Score = verdict.Score
	}
	result.Route = true
	for _, signal := range signals {
		result.Signals = appendUnique(result.Signals, signal)
	}
	if matchSeen == nil {
		matchSeen = routeMatchSeen(result)
	}
	for _, match := range verdict.Matched {
		key := match.Name + "\x00" + match.Category
		if _, exists := matchSeen[key]; exists {
			continue
		}
		matchSeen[key] = struct{}{}
		result.Matches = append(result.Matches, match)
	}
}

func partitionEnvelope(envelope promptfilter.RequestEnvelope) []provenancePartition {
	partitions := partitionEnvelopeMatching(envelope, canInitiateRoute)
	if len(partitions) > 0 {
		// Full-history clients may not send a stable session identifier. Keep
		// prior user-authored turns as conversation evidence, but never let
		// developer/system/assistant replay or tool output override a new user
		// turn. Each origin remains a separate rule-engine partition.
		return append(partitions, partitionEnvelopeMatching(envelope, canContinueUserHistory)...)
	}
	// A tool continuation can legitimately have no new current-user segment.
	// In that case, retain only user-authored history and tool output as
	// continuation evidence. Assistant/developer/system replay never becomes
	// routing evidence on its own.
	return partitionEnvelopeMatching(envelope, canContinueRoute)
}

func partitionEnvelopeMatching(
	envelope promptfilter.RequestEnvelope,
	include func(promptfilter.Segment) bool,
) []provenancePartition {
	partitions := make([]provenancePartition, 0, 8)
	indexByOrigin := make(map[promptfilter.SegmentOrigin]int, 8)
	for _, segment := range envelope.Segments {
		if !include(segment) || strings.TrimSpace(segment.Text) == "" {
			continue
		}
		index, ok := indexByOrigin[segment.Origin]
		if !ok {
			index = len(partitions)
			indexByOrigin[segment.Origin] = index
			partitions = append(partitions, provenancePartition{origin: segment.Origin})
		}
		if partitions[index].text.Len() > 0 {
			partitions[index].text.WriteByte('\n')
		}
		partitions[index].text.WriteString(segment.Text)
	}
	return partitions
}

func canInitiateRoute(segment promptfilter.Segment) bool {
	return segment.Origin == promptfilter.OriginCurrentUser
}

func canContinueRoute(segment promptfilter.Segment) bool {
	switch segment.Origin {
	case promptfilter.OriginHistory:
		return strings.EqualFold(strings.TrimSpace(segment.Role), "user")
	case promptfilter.OriginToolOutput:
		return true
	default:
		return false
	}
}

func canContinueUserHistory(segment promptfilter.Segment) bool {
	return segment.Origin == promptfilter.OriginHistory &&
		strings.EqualFold(strings.TrimSpace(segment.Role), "user")
}

func routingConfig(cfg promptfilter.Config) promptfilter.Config {
	cfg.Enabled = true
	cfg.Mode = promptfilter.ModeMonitor
	cfg.Review.Enabled = false
	cfg.Review.APIKey = ""
	cfg.Advanced.Output.Enabled = false
	cfg.CustomPatterns = appendProductionPatterns(cfg.CustomPatterns)
	cfg.DisabledPatterns = appendPatternNames(cfg.DisabledPatterns, nonCYBRoutePatterns)
	return promptfilter.NormalizeConfig(cfg)
}

func appendProductionPatterns(configured []promptfilter.PatternConfig) []promptfilter.PatternConfig {
	seen := make(map[string]struct{}, len(configured))
	for _, pattern := range configured {
		seen[strings.ToLower(strings.TrimSpace(pattern.Name))] = struct{}{}
	}
	out := append([]promptfilter.PatternConfig(nil), configured...)
	for _, pattern := range productionPatternConfigs {
		if _, ok := seen[strings.ToLower(pattern.Name)]; ok {
			continue
		}
		out = append(out, pattern)
	}
	return out
}

func appendPatternNames(configured []string, required []string) []string {
	seen := make(map[string]struct{}, len(configured)+len(required))
	out := append([]string(nil), configured...)
	for _, name := range configured {
		seen[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for _, name := range required {
		key := strings.ToLower(strings.TrimSpace(name))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out
}

func routeSignals(verdict promptfilter.Verdict, text string, cfg promptfilter.Config) []string {
	if !verdict.Enabled {
		return nil
	}
	signals := make([]string, 0, 8)
	if verdict.Score >= cfg.Threshold {
		signals = append(signals, SignalLocalThreshold)
	}
	if highRiskVerdict(verdict) {
		signals = append(signals, SignalLocalHighRisk)
	}
	if explicitHighRiskVerdict(verdict) {
		signals = append(signals, SignalExplicitHighRiskRule)
	}
	if looksLikeTechnicalCyberIntent(text) {
		signals = append(signals, SignalTechnicalCyberIntent)
	}
	if sqlCredentialExfiltrationVerdict(verdict, text) {
		signals = append(signals, SignalSQLCredentialExfiltration)
	}
	if targetedCovertSurveillanceVerdict(text) {
		signals = append(signals, SignalTargetedCovertSurveillance)
	}
	if looksLikeNonChineseEnglishNaturalLanguage(text) {
		signals = append(signals, SignalNonChineseEnglishLanguage)
	}
	for _, signal := range observedGapSignals(text) {
		signals = appendUnique(signals, signal)
	}
	if len(signals) == 0 && multiVectorWebAttackVerdict(verdict) {
		signals = append(signals, SignalMultiVectorWebAttack)
	}
	return signals
}

func highRiskVerdict(verdict promptfilter.Verdict) bool {
	if verdict.Score >= 200 || verdict.RawScore >= 200 || verdict.StrictHit {
		return true
	}
	for _, match := range verdict.Matched {
		if match.Strict {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
