package proxy

import (
	"crypto/sha256"
	"encoding/hex"
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
