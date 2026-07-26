// Package cybroute turns deterministic prompt-filter evidence into an account
// group routing hint. It deliberately does not moderate requests, call an
// external reviewer, or select an upstream account.
package cybroute

import (
	"strings"

	"github.com/codex2api/security/promptfilter"
)

const (
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
}

type provenancePartition struct {
	origin promptfilter.SegmentOrigin
	text   strings.Builder
}

// Inspect evaluates each official envelope provenance partition independently.
// Evidence is never joined across origins, so a system/tool witness cannot
// complete a composite rule started by current-user text.
func Inspect(body []byte, endpoint, model string, cfg promptfilter.Config) Result {
	cfg = routingConfig(cfg)
	envelope := promptfilter.BuildEnvelopeWithModelsAndConfig(
		body,
		endpoint,
		model,
		"",
		promptfilter.TransportHTTP,
		cfg,
	)
	result := Result{
		Threshold: cfg.Threshold,
		Truncated: envelope.Truncated || envelope.CurrentUserTruncated || envelope.AuxiliaryTruncated,
	}
	if envelope.AdapterUnclassified || len(envelope.Segments) == 0 {
		return result
	}

	partitions := partitionEnvelope(envelope)
	matchSeen := make(map[string]struct{})
	for _, partition := range partitions {
		text := strings.TrimSpace(partition.text.String())
		if text == "" {
			continue
		}
		verdict := promptfilter.InspectText(text, cfg)
		signals := routeSignals(verdict, text, cfg)
		if len(signals) == 0 {
			continue
		}
		if !result.Route || verdict.Score > result.Score {
			result.PrimaryOrigin = partition.origin
			result.Score = verdict.Score
		}
		result.Route = true
		for _, signal := range signals {
			result.Signals = appendUnique(result.Signals, signal)
		}
		for _, match := range verdict.Matched {
			key := match.Name + "\x00" + match.Category
			if _, ok := matchSeen[key]; ok {
				continue
			}
			matchSeen[key] = struct{}{}
			result.Matches = append(result.Matches, match)
		}
	}
	return result
}

func partitionEnvelope(envelope promptfilter.RequestEnvelope) []provenancePartition {
	partitions := make([]provenancePartition, 0, 8)
	indexByOrigin := make(map[promptfilter.SegmentOrigin]int, 8)
	for _, segment := range envelope.Segments {
		if strings.TrimSpace(segment.Text) == "" {
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
