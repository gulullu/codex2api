package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/cybroute"
)

const (
	relayCYBMissRawMaxBytes               = 1024 * 1024
	relayCYBMissUserTextMaxRunes          = 128 * 1024
	relayCYBMissUserWindowMaxBytes        = relayCYBMissUserTextMaxRunes * utf8.UTFMax
	relayCYBMissUserTextHeadShare         = 1
	relayCYBMissUserTextAllShares         = 4
	relayCYBCurrentTerminalMinRunes       = 512
	relayCYBCurrentTerminalMaxRunes       = 4 * 1024
	relayCYBCurrentTerminalThresholdRunes = 1024
)

// BackfillLegacyRelayCYBMissSamples moves a single bounded batch of historical
// eligible cyber_policy misses into the existing learning queue. The audit body
// is already redacted; no Prompt Filter settings or Sub2 state are changed.
func (h *Handler) BackfillLegacyRelayCYBMissSamples(
	ctx context.Context,
	limit int,
) (database.RelayCYBMissBackfillResult, error) {
	return h.BackfillLegacyRelayCYBMissSamplesBefore(ctx, limit, time.Now().UTC())
}

// BackfillLegacyRelayCYBMissSamplesBefore uses one immutable startup cutoff so
// the historical drain cannot race a newer live audit row whose dedicated CYB
// sample writer has not committed yet.
func (h *Handler) BackfillLegacyRelayCYBMissSamplesBefore(
	ctx context.Context,
	limit int,
	cutoff time.Time,
) (database.RelayCYBMissBackfillResult, error) {
	return h.BackfillLegacyRelayCYBMissSamplesPage(
		ctx,
		limit,
		cutoff,
		time.Time{},
		"",
	)
}

// BackfillLegacyRelayCYBMissSamplesPage continues one startup phase after a
// stable audit key. It is exported only for the admin startup coordinator; the
// normal one-shot helper above retains its original behavior.
func (h *Handler) BackfillLegacyRelayCYBMissSamplesPage(
	ctx context.Context,
	limit int,
	cutoff time.Time,
	afterCreatedAt time.Time,
	afterRequestID string,
) (database.RelayCYBMissBackfillResult, error) {
	var result database.RelayCYBMissBackfillResult
	if h == nil || h.db == nil {
		return result, nil
	}
	relayGroupID := ConfiguredCYBRelayGroupID()
	candidates, err := h.db.ListRelayCYBMissBackfillCandidatesAfter(
		ctx,
		relayGroupID,
		cutoff,
		afterCreatedAt,
		afterRequestID,
		limit,
	)
	if err != nil {
		return result, err
	}
	result.Scanned = len(candidates)
	for _, candidate := range candidates {
		redactedRequest := strings.TrimSpace(
			redactRelayAuditSensitiveText(candidate.RedactedRequest),
		)
		userText, userTextTruncated, rejectionReason := relayCYBLegacyUserText(
			redactedRequest,
			candidate.Endpoint,
			candidate.RequestTruncated,
		)
		if candidate.RequestTruncated && rejectionReason == "" {
			rejectionReason = "历史审计正文已截断，无法确认最新用户语料，禁止自动学习"
		}
		if candidate.SampleSource == database.RelayCYBMissSourceRelay &&
			rejectionReason == "" {
			switch {
			case h.store != nil:
				result := cybroute.Inspect(
					[]byte(redactedRequest),
					candidate.Endpoint,
					"",
					h.store.GetPromptFilterConfig(),
				)
				if result.Route {
					rejectionReason = "历史 Relay CYB 请求已被当前本地规则覆盖，无需重复学习"
				}
			}
		}
		input := &database.RelayCYBMissSampleInput{
			RequestID:         candidate.RequestID,
			CreatedAt:         candidate.CreatedAt,
			SampleSource:      candidate.SampleSource,
			AccountID:         candidate.AccountID,
			AccountName:       candidate.AccountName,
			AccountType:       candidate.AccountType,
			RedactedRequest:   redactedRequest,
			UserText:          userText,
			UserTextTruncated: userTextTruncated,
			RequestTruncated:  candidate.RequestTruncated,
			ContentHash:       relayCYBMissContentHash(userText),
		}
		inserted, err := h.db.InsertRelayCYBMissBackfillSample(ctx, input, rejectionReason)
		if err != nil {
			return result, err
		}
		result.NextCreatedAt = candidate.CreatedAt
		result.NextRequestID = candidate.RequestID
		if !inserted {
			continue
		}
		if rejectionReason == "" {
			result.Queued++
		} else {
			result.Rejected++
		}
	}
	if err := h.db.RecordRelayCYBMissBackfillEvent(ctx, result); err != nil {
		return result, err
	}
	return result, nil
}

func (h *Handler) enqueueRelayCYBMissSample(
	plan *relayRoutePlan,
	account *auth.Account,
	sampleSource string,
) {
	if h == nil || h.db == nil || plan == nil || account == nil ||
		plan.AuditRequestID == "" || plan.LearningCaseCaptured || len(plan.AuditRawBody) == 0 {
		return
	}
	auditBody := plan.AuditRawBody
	// A reconstructed previous_response_id body is the actual standalone body
	// only for a Relay attempt. An OAuth attempt can hit the same group-0 replay
	// cache while still sending the official request path; learning replay
	// history there would misattribute an old turn to the current OAuth miss.
	learningBody := auditBody
	if sampleSource == database.RelayCYBMissSourceRelay {
		learningBody = plan.cybInspectionBody()
	}
	if !plan.relayCYBHasCurrentUserText() {
		return
	}
	redactedRequest, requestTruncated := relayCYBMissRedactedRequest(auditBody)
	userText, userTextTruncated := relayCYBMissUserTextWithTruncation(
		learningBody,
		plan.Endpoint,
	)
	if strings.TrimSpace(userText) == "" {
		return
	}
	contentHash := relayCYBMissContentHash(userText)
	accountID, accountType := relayAuditAccountSnapshot(account)
	if !h.db.EnqueueRelayCYBMissSample(&database.RelayCYBMissSampleInput{
		RequestID:         plan.AuditRequestID,
		CreatedAt:         time.Now(),
		SampleSource:      sampleSource,
		AccountID:         accountID,
		AccountType:       accountType,
		RedactedRequest:   redactedRequest,
		UserText:          userText,
		UserTextTruncated: userTextTruncated,
		RequestTruncated:  requestTruncated,
		ContentHash:       contentHash,
	}) {
		return
	}
	plan.LearningCaseCaptured = true
	plan.AuditRawBody = nil
	plan.CYBUpstreamBody = nil
}

func (plan *relayRoutePlan) relayCYBHasCurrentUserText() bool {
	if plan == nil || len(plan.AuditRawBody) == 0 {
		return false
	}
	if !plan.CurrentUserChecked || plan.CurrentUserBodyBytes != len(plan.AuditRawBody) {
		plan.HasCurrentUserText = relayCYBHasCurrentUserText(plan.AuditRawBody, plan.Endpoint)
		plan.CurrentUserChecked = true
		plan.CurrentUserBodyBytes = len(plan.AuditRawBody)
	}
	return plan.HasCurrentUserText
}

func relayCYBMissRedactedRequest(rawBody []byte) (string, bool) {
	if len(rawBody) == 0 {
		return "", false
	}
	bounded := rawBody
	truncated := false
	if len(bounded) > relayCYBMissRawMaxBytes {
		bounded = bounded[:relayCYBMissRawMaxBytes]
		truncated = true
	}
	text := redactRelayAuditSensitiveText(strings.ToValidUTF8(string(bounded), "\uFFFD"))
	return strings.TrimSpace(text), truncated
}

func relayCYBMissUserText(rawBody []byte, endpoint string) string {
	text, _ := relayCYBMissUserTextWithTruncation(rawBody, endpoint)
	return text
}

// relayCYBMissUserTextWithTruncation extracts only user-authored text. The
// current user turn is placed before replayed history, and an oversized current
// turn keeps substantially more tail than head because Codex-style callers
// often prepend a large fixed template before the actual user instruction.
func relayCYBMissUserTextWithTruncation(rawBody []byte, endpoint string) (string, bool) {
	if len(rawBody) == 0 || !relayCybFeedbackTextEndpoint(endpoint) {
		return "", false
	}
	current, history := relayCYBExtractUserWindows(
		rawBody,
		endpoint,
		relayCYBMissUserWindowMaxBytes,
	)
	parts := make([]string, 0, 3)
	truncated := false
	switch len(current) {
	case 0:
	case 1:
		parts = append(parts, markRelayCYBCurrentUserTerminal(current[0]))
	default:
		// Keep the current user's real beginning and actual tail as one
		// highest-priority segment. The explicit marker prevents candidate
		// validation from matching across the omitted middle.
		parts = append(parts,
			markRelayCYBCurrentUserTerminal(
				current[0]+"\n"+cyblearn.UserTextTruncationMarker+"\n"+current[len(current)-1],
			),
		)
		truncated = true
	}
	switch len(history) {
	case 0:
	case 1:
		parts = append(parts, history[0])
	default:
		// History is secondary to the current turn. When it is oversized,
		// prefer its most recent tail before the oldest head and keep the
		// windows as separate user segments.
		parts = append(parts, history[len(history)-1], history[0])
		truncated = true
	}
	return boundRelayCYBUserSegments(parts, relayCYBMissUserTextMaxRunes, truncated)
}

func markRelayCYBCurrentUserTerminal(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	runeCount := utf8.RuneCountInString(text)
	// A short current turn is often only a benign continuation such as
	// "continue". Requiring every learned rule to match it would suppress
	// useful evidence from an earlier user-authored turn. The terminal marker
	// exists only for a genuinely long current turn, where it prevents a rule
	// from learning the repeated template head instead of the actual tail.
	if runeCount <= relayCYBCurrentTerminalThresholdRunes {
		return text
	}
	terminalRunes := runeCount / 4
	if terminalRunes < relayCYBCurrentTerminalMinRunes {
		terminalRunes = relayCYBCurrentTerminalMinRunes
	}
	if terminalRunes > relayCYBCurrentTerminalMaxRunes {
		terminalRunes = relayCYBCurrentTerminalMaxRunes
	}
	start := relayCYBRuneSuffixStart(text, terminalRunes)
	return strings.TrimSpace(text[:start]) +
		"\n" + cyblearn.CurrentUserTerminalMarker + "\n" +
		strings.TrimSpace(text[start:])
}

func boundRelayCYBUserSegments(parts []string, maxRunes int, alreadyTruncated bool) (string, bool) {
	if maxRunes <= 0 {
		return "", len(parts) > 0 || alreadyTruncated
	}
	separatorRuneCount := utf8.RuneCountInString(cyblearn.UserSegmentSeparator)
	var out strings.Builder
	out.Grow(min(maxRunes, 256*1024))
	usedRunes := 0
	truncated := alreadyTruncated
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if out.Len() > 0 {
			if usedRunes+separatorRuneCount >= maxRunes {
				return strings.TrimSpace(out.String()), true
			}
			out.WriteString(cyblearn.UserSegmentSeparator)
			usedRunes += separatorRuneCount
		}
		remaining := maxRunes - usedRunes
		partRunes := utf8.RuneCountInString(part)
		if partRunes <= remaining {
			out.WriteString(redactRelayAuditSensitiveText(part))
			usedRunes += partRunes
			continue
		}
		bounded := truncateRelayCYBUserSegment(part, partRunes, remaining)
		out.WriteString(redactRelayAuditSensitiveText(bounded))
		truncated = true
		for next := index + 1; next < len(parts); next++ {
			if strings.TrimSpace(parts[next]) != "" {
				truncated = true
				break
			}
		}
		break
	}
	return strings.TrimSpace(out.String()), truncated
}

func truncateRelayCYBUserSegment(text string, runeCount, maxRunes int) string {
	if runeCount <= maxRunes {
		return text
	}
	if maxRunes <= 0 {
		return ""
	}
	marker := "\n" + cyblearn.UserTextTruncationMarker + "\n"
	markerRunes := utf8.RuneCountInString(marker)
	if maxRunes <= markerRunes+2 {
		return text[relayCYBRuneSuffixStart(text, maxRunes):]
	}
	payloadRunes := maxRunes - markerRunes
	headRunes := payloadRunes * relayCYBMissUserTextHeadShare / relayCYBMissUserTextAllShares
	tailRunes := payloadRunes - headRunes
	headEnd := relayCYBRunePrefixEnd(text, headRunes)
	tailStart := relayCYBRuneSuffixStart(text, tailRunes)
	return text[:headEnd] + marker + text[tailStart:]
}

func relayCYBRunePrefixEnd(text string, runes int) int {
	if runes <= 0 {
		return 0
	}
	count := 0
	for index := range text {
		if count == runes {
			return index
		}
		count++
	}
	return len(text)
}

func relayCYBRuneSuffixStart(text string, runes int) int {
	if runes <= 0 {
		return len(text)
	}
	index := len(text)
	for count := 0; count < runes && index > 0; count++ {
		_, size := utf8.DecodeLastRuneInString(text[:index])
		if size <= 0 {
			break
		}
		index -= size
	}
	return index
}

func relayCYBMissContentHash(userText string) string {
	normalized := normalizeRelayCybFeedbackText(userText)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func relayCYBLegacyUserText(
	redactedRequest string,
	endpoint string,
	requestTruncated bool,
) (string, bool, string) {
	if strings.TrimSpace(redactedRequest) == "" {
		return "", requestTruncated, "历史审计请求正文为空，无法恢复用户语料"
	}
	body := []byte(redactedRequest)
	if !json.Valid(body) {
		if !requestTruncated {
			return "", false, "历史审计请求正文不是有效 JSON，无法安全恢复用户语料"
		}
		repaired, ok := repairRelayCYBTruncatedJSONPrefix(body)
		if !ok {
			return "", true, "历史审计请求已截断，无法安全恢复用户语料"
		}
		body = repaired
	}
	current, _ := relayCYBExtractUserWindows(
		body,
		endpoint,
		relayCYBMissUserWindowMaxBytes,
	)
	if len(current) == 0 {
		return "", requestTruncated, "历史审计请求没有可确认的当前用户语料，禁止从旧历史或工具输出自动学习"
	}
	userText, extractedTruncated := relayCYBMissUserTextWithTruncation(body, endpoint)
	if strings.TrimSpace(userText) == "" {
		return "", requestTruncated || extractedTruncated, "历史审计请求未包含可恢复的当前用户或用户历史语料"
	}
	return userText, requestTruncated || extractedTruncated, ""
}

// repairRelayCYBTruncatedJSONPrefix only repairs a prefix that ends inside a
// complete JSON string value, immediately after a complete value, or directly
// after a complete key's colon (with neutral null). It never guesses missing
// keys, commas, literals or user roles. json.Valid is the final gate, so a
// truncated key or structural token is rejected.
func repairRelayCYBTruncatedJSONPrefix(prefix []byte) ([]byte, bool) {
	prefix = []byte(strings.TrimSpace(strings.ToValidUTF8(string(prefix), "\uFFFD")))
	if len(prefix) == 0 {
		return nil, false
	}
	if json.Valid(prefix) {
		return append([]byte(nil), prefix...), true
	}
	stack := make([]byte, 0, 16)
	inString := false
	escaped := false
	unicodeDigits := 0
	for _, value := range prefix {
		if inString {
			if unicodeDigits > 0 {
				if !isRelayCYBJSONHex(value) {
					return nil, false
				}
				unicodeDigits--
				continue
			}
			if escaped {
				switch value {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				case 'u':
					unicodeDigits = 4
				default:
					return nil, false
				}
				escaped = false
				continue
			}
			switch value {
			case '\\':
				escaped = true
			case '"':
				inString = false
			default:
				if value < 0x20 {
					return nil, false
				}
			}
			continue
		}
		switch value {
		case '"':
			inString = true
		case '{', '[':
			stack = append(stack, value)
		case '}':
			if len(stack) == 0 || stack[len(stack)-1] != '{' {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		case ']':
			if len(stack) == 0 || stack[len(stack)-1] != '[' {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		}
	}
	if escaped || unicodeDigits > 0 {
		return nil, false
	}
	repaired := append([]byte(nil), prefix...)
	if inString {
		repaired = append(repaired, '"')
	} else if len(stack) > 0 && prefix[len(prefix)-1] == ':' {
		// A cutoff immediately after a complete key has no user-controlled
		// value to guess. null is the only neutral completion and preserves
		// any complete user messages that appeared earlier in the prefix.
		repaired = append(repaired, "null"...)
	}
	for index := len(stack) - 1; index >= 0; index-- {
		if stack[index] == '{' {
			repaired = append(repaired, '}')
		} else {
			repaired = append(repaired, ']')
		}
	}
	if !json.Valid(repaired) {
		return nil, false
	}
	return repaired, true
}

func isRelayCYBJSONHex(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}
