package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/promptfilter"
)

const (
	relayCYBMissRawMaxBytes      = 1024 * 1024
	relayCYBMissEnvelopeMaxRunes = 128 * 1024
)

// BackfillLegacyRelayCYBMissSamples moves a single bounded batch of historical
// OAuth cyber_policy misses into the existing learning queue. The audit body is
// already redacted; no Prompt Filter settings or Sub2 state are read or changed.
func (h *Handler) BackfillLegacyRelayCYBMissSamples(
	ctx context.Context,
	limit int,
) (database.RelayCYBMissBackfillResult, error) {
	var result database.RelayCYBMissBackfillResult
	if h == nil || h.db == nil {
		return result, nil
	}
	candidates, err := h.db.ListRelayCYBMissBackfillCandidates(ctx, limit)
	if err != nil {
		return result, err
	}
	result.Scanned = len(candidates)
	for _, candidate := range candidates {
		redactedRequest := strings.TrimSpace(
			redactRelayAuditSensitiveText(candidate.RedactedRequest),
		)
		userText, rejectionReason := relayCYBLegacyUserText(
			redactedRequest,
			candidate.Endpoint,
			candidate.RequestTruncated,
		)
		input := &database.RelayCYBMissSampleInput{
			RequestID:        candidate.RequestID,
			CreatedAt:        candidate.CreatedAt,
			AccountID:        candidate.AccountID,
			AccountName:      candidate.AccountName,
			AccountType:      candidate.AccountType,
			RedactedRequest:  redactedRequest,
			UserText:         userText,
			RequestTruncated: candidate.RequestTruncated,
			ContentHash:      relayCYBMissContentHash(userText),
		}
		inserted, err := h.db.InsertRelayCYBMissBackfillSample(ctx, input, rejectionReason)
		if err != nil {
			return result, err
		}
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

func (h *Handler) enqueueRelayCYBMissSample(plan *relayRoutePlan, account *auth.Account) {
	if h == nil || h.db == nil || plan == nil || account == nil ||
		plan.AuditRequestID == "" || plan.LearningCaseCaptured || len(plan.AuditRawBody) == 0 {
		return
	}
	rawBody := plan.AuditRawBody
	redactedRequest, requestTruncated := relayCYBMissRedactedRequest(rawBody)
	userText := relayCYBMissUserText(rawBody, plan.Endpoint)
	contentHash := relayCYBMissContentHash(userText)
	accountID, accountType := relayAuditAccountSnapshot(account)
	if !h.db.EnqueueRelayCYBMissSample(&database.RelayCYBMissSampleInput{
		RequestID:        plan.AuditRequestID,
		CreatedAt:        time.Now(),
		AccountID:        accountID,
		AccountType:      accountType,
		RedactedRequest:  redactedRequest,
		UserText:         userText,
		RequestTruncated: requestTruncated,
		ContentHash:      contentHash,
	}) {
		return
	}
	plan.LearningCaseCaptured = true
	plan.AuditRawBody = nil
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
	if len(rawBody) == 0 || !relayCybFeedbackTextEndpoint(endpoint) {
		return ""
	}
	envelope := promptfilter.BuildEnvelope(
		rawBody,
		endpoint,
		"",
		promptfilter.TransportHTTP,
		relayCYBMissEnvelopeMaxRunes,
	)
	current := make([]string, 0, 4)
	history := make([]string, 0, 8)
	for _, segment := range envelope.Segments {
		text := strings.TrimSpace(segment.Text)
		if text == "" {
			continue
		}
		switch {
		case segment.Origin == promptfilter.OriginCurrentUser:
			current = append(current, text)
		case segment.Origin == promptfilter.OriginHistory &&
			strings.EqualFold(strings.TrimSpace(segment.Role), "user"):
			history = append(history, text)
		}
	}
	parts := append(current, history...)
	if len(parts) == 0 {
		return ""
	}
	for index := range parts {
		parts[index] = strings.TrimSpace(redactRelayAuditSensitiveText(parts[index]))
	}
	return strings.Join(parts, cyblearn.UserSegmentSeparator)
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
) (string, string) {
	if strings.TrimSpace(redactedRequest) == "" {
		return "", "历史审计请求正文为空，无法恢复用户语料"
	}
	body := []byte(redactedRequest)
	if !json.Valid(body) {
		if !requestTruncated {
			return "", "历史审计请求正文不是有效 JSON，无法安全恢复用户语料"
		}
		repaired, ok := repairRelayCYBTruncatedJSONPrefix(body)
		if !ok {
			return "", "历史审计请求已截断，无法安全恢复用户语料"
		}
		body = repaired
	}
	userText := relayCYBMissUserText(body, endpoint)
	if strings.TrimSpace(userText) == "" {
		return "", "历史审计请求未包含可恢复的当前用户或用户历史语料"
	}
	return userText, ""
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
