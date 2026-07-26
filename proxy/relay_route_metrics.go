package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cybroute"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
)

const relayAuditRequestPrefixMaxBytes = database.RelayAuditFullTextMaxRunes * 4

var relayAuditSensitiveJSONFieldPattern = regexp.MustCompile(
	`(?i)("(?:previous_response_id|prompt_cache_key|encrypted_content|authorization|api_key|access_token|refresh_token|password|secret)"\s*:\s*)"(?:\\.|[^"\\])*(?:"|$)`,
)

func relayRouteScanDetailsJSON(result cybroute.Result) string {
	type scanDetails struct {
		Score         int      `json:"score"`
		Threshold     int      `json:"threshold"`
		PrimaryOrigin string   `json:"primary_origin,omitempty"`
		Signals       []string `json:"signals,omitempty"`
		Truncated     bool     `json:"truncated"`
	}
	raw, err := json.Marshal(scanDetails{
		Score:         result.Score,
		Threshold:     result.Threshold,
		PrimaryOrigin: string(result.PrimaryOrigin),
		Signals:       append([]string(nil), result.Signals...),
		Truncated:     result.Truncated,
	})
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func relayAuditSignalsJSON(signals []string) string {
	cleaned := make([]string, 0, len(signals))
	seen := make(map[string]struct{}, len(signals))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		if _, exists := seen[signal]; exists {
			continue
		}
		seen[signal] = struct{}{}
		cleaned = append(cleaned, signal)
	}
	raw, err := json.Marshal(cleaned)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func populateRelayAuditAPIKeyMeta(c *gin.Context, input *database.RelayAuditRequestInput) {
	if c == nil || input == nil {
		return
	}
	input.APIKeyID = requestAPIKeyID(c)
	if value, exists := c.Get(contextAPIKeyName); exists {
		if name, ok := value.(string); ok {
			input.APIKeyName = strings.TrimSpace(name)
		}
	}
	if value, exists := c.Get(contextAPIKeyMasked); exists {
		if masked, ok := value.(string); ok {
			input.APIKeyMasked = strings.TrimSpace(masked)
		}
	}
}

func relayAuditRequestText(rawBody []byte) (string, bool) {
	if len(rawBody) == 0 {
		return "", false
	}
	prefix := rawBody
	truncated := false
	if len(prefix) > relayAuditRequestPrefixMaxBytes {
		prefix = prefix[:relayAuditRequestPrefixMaxBytes]
		truncated = true
	}
	text := promptfilter.RedactSensitive(string(prefix))
	text = relayAuditSensitiveJSONFieldPattern.ReplaceAllString(text, `${1}"[REDACTED]"`)
	_, bounded, runeTruncated := database.BoundRelayAuditText(text)
	return bounded, truncated || runeTruncated
}

func (h *Handler) beginRelayAudit(c *gin.Context, plan *relayRoutePlan, rawBody []byte) {
	if h == nil || h.db == nil || c == nil || plan == nil || plan.AuditRequestID == "" {
		return
	}
	fullText, auditTextTruncated := relayAuditRequestText(rawBody)
	scannedBytes := int64(len(rawBody))
	if plan.AuditScanTruncated {
		scannedBytes = 0
	}
	input := &database.RelayAuditRequestInput{
		RequestID:             plan.AuditRequestID,
		CreatedAt:             plan.AuditCreatedAt,
		Endpoint:              plan.Endpoint,
		Model:                 plan.Model,
		ClientIP:              c.ClientIP(),
		FullText:              fullText,
		PayloadBytes:          int64(len(rawBody)),
		ScannedBytes:          scannedBytes,
		ScanTruncated:         plan.AuditScanTruncated || auditTextTruncated,
		ScanDetails:           plan.AuditScanDetails,
		RouteSource:           plan.Source,
		RouteReason:           plan.Reason,
		RouteSignals:          relayAuditSignalsJSON(plan.Signals),
		RouteGroupID:          plan.RequiredGroupID,
		HasPreviousResponseID: plan.HasPreviousResponseID,
		ReplayStatus:          plan.AuditReplayStatus,
		ReplaySource:          plan.AuditReplaySource,
		StateFallbackReason:   plan.StateFallbackReason,
		DetectorMiss:          plan.DetectorMiss,
		RouteViolation:        plan.RouteViolation,
		GroupExhausted:        plan.GroupExhausted,
	}
	populateRelayAuditAPIKeyMeta(c, input)
	_ = h.db.EnqueueRelayAuditRequest(input)
}

func (h *Handler) recordRelayContinuationReplayAudit(
	plan *relayRoutePlan,
	replayed bool,
	source string,
	replayErr error,
) {
	if h == nil || h.db == nil || plan == nil || plan.AuditRequestID == "" || !plan.HasPreviousResponseID {
		return
	}
	status := ""
	if replayed {
		status = "hit"
	} else if replayErr != nil {
		status = "unavailable"
		var typed *RelayContinuationReplayError
		if errors.As(replayErr, &typed) && typed.Reason != "" {
			status = string(typed.Reason)
		}
	}
	if status == "" {
		return
	}
	plan.AuditReplayStatus = status
	plan.AuditReplaySource = strings.TrimSpace(source)
	h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{
		ReplayStatus: plan.AuditReplayStatus,
		ReplaySource: plan.AuditReplaySource,
	})
}

func relayAuditAccountSnapshot(account *auth.Account) (int64, string) {
	if account == nil {
		return 0, ""
	}
	account.Mu().RLock()
	accountType := strings.TrimSpace(account.UpstreamType)
	account.Mu().RUnlock()
	return account.ID(), accountType
}

func (h *Handler) logRelayRouteSelection(c *gin.Context, plan *relayRoutePlan, account *auth.Account, switched bool) {
	if h == nil || h.db == nil || c == nil || plan == nil || account == nil || plan.AuditRequestID == "" {
		return
	}
	mode := "initial"
	if switched {
		mode = "same_group_switch"
	} else if plan.SelectionCount > 1 {
		mode = "retry"
	}
	h.beginRelayAudit(c, plan, nil)
	accountID, accountType := relayAuditAccountSnapshot(account)
	_ = h.db.EnqueueRelayAuditAttempt(&database.RelayAuditAttemptInput{
		RequestID:        plan.AuditRequestID,
		AttemptIndex:     plan.SelectionCount,
		SelectionMode:    mode,
		AccountID:        accountID,
		AccountType:      accountType,
		UpstreamEndpoint: plan.Endpoint,
		SelectedAt:       time.Now(),
	})
}

func (h *Handler) logRelayGroupExhausted(c *gin.Context, plan *relayRoutePlan) {
	if plan == nil {
		return
	}
	plan.GroupExhausted = true
	h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{
		GroupExhausted: true,
		ErrorKind:      "relay_group_exhausted",
	})
}

func (h *Handler) logRelayGroupEscapeViolation(c *gin.Context, plan *relayRoutePlan) {
	if plan == nil {
		return
	}
	plan.RouteViolation = true
	h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{
		RouteViolation: true,
		ErrorKind:      "relay_group_escape_violation",
	})
}

func (h *Handler) logRelayRouteStateFallback(c *gin.Context, plan *relayRoutePlan, reason string) {
	if plan == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{
		StateFallbackReason: reason,
	})
}

func (h *Handler) logRelayCyberPolicyMetric(c *gin.Context, plan *relayRoutePlan, detectorMiss bool) {
	if plan == nil || !detectorMiss {
		return
	}
	plan.DetectorMiss = true
	h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{DetectorMiss: true})
}

func (h *Handler) enqueueRelayAuditState(plan *relayRoutePlan, state database.RelayAuditStateInput) {
	if h == nil || h.db == nil || plan == nil || plan.AuditRequestID == "" {
		return
	}
	state.RequestID = plan.AuditRequestID
	_ = h.db.EnqueueRelayAuditState(&state)
}

func (h *Handler) logRelayAuditUsage(c *gin.Context, input *database.UsageLogInput) {
	if h == nil || h.db == nil || input == nil {
		return
	}
	plan, ok := relayRoutePlanFromContext(c)
	if !ok || plan.AuditRequestID == "" {
		return
	}
	var account *auth.Account
	if h.store != nil && input.AccountID > 0 {
		account = h.store.FindByID(input.AccountID)
	}
	accountID, accountType := relayAuditAccountSnapshot(account)
	if accountID == 0 {
		accountID = input.AccountID
	}
	transport := "http"
	if input.ViaWebsocket {
		transport = "websocket"
	}
	upstreamEndpoint := strings.TrimSpace(input.UpstreamEndpoint)
	if upstreamEndpoint == "" {
		upstreamEndpoint = strings.TrimSpace(input.Endpoint)
	}
	final := !input.IsRetryAttempt
	plan.AuditLastTransport = transport
	plan.AuditLastStatusCode = input.StatusCode
	plan.AuditLastErrorKind = input.UpstreamErrorKind
	plan.AuditLastError = input.ErrorMessage
	// Official success usage rows intentionally leave AttemptIndex at zero.
	// Preserve that canonical usage behavior, but retain the final transport
	// and status so the deferred independent audit finalizer can complete the
	// already-recorded selection attempt accurately.
	if input.AttemptIndex <= 0 {
		return
	}
	if final {
		plan.AuditFinalized = h.db.EnqueueRelayAuditOutcome(&database.RelayAuditOutcomeInput{
			RequestID:        plan.AuditRequestID,
			AttemptIndex:     input.AttemptIndex,
			AccountID:        accountID,
			AccountType:      accountType,
			UpstreamEndpoint: upstreamEndpoint,
			Transport:        transport,
			ViaWebsocket:     input.ViaWebsocket,
			StatusCode:       input.StatusCode,
			ErrorKind:        input.UpstreamErrorKind,
			ErrorMessage:     input.ErrorMessage,
			CompletedAt:      time.Now(),
			Final:            true,
			DetectorMiss:     plan.DetectorMiss,
		})
		return
	}
	_ = h.db.EnqueueRelayAuditOutcome(&database.RelayAuditOutcomeInput{
		RequestID:        plan.AuditRequestID,
		AttemptIndex:     input.AttemptIndex,
		AccountID:        accountID,
		AccountType:      accountType,
		UpstreamEndpoint: upstreamEndpoint,
		Transport:        transport,
		ViaWebsocket:     input.ViaWebsocket,
		StatusCode:       input.StatusCode,
		ErrorKind:        input.UpstreamErrorKind,
		ErrorMessage:     input.ErrorMessage,
		CompletedAt:      time.Now(),
		Final:            false,
		DetectorMiss:     plan.DetectorMiss,
	})
}

func (h *Handler) finalizeRelayAuditRequest(c *gin.Context, plan *relayRoutePlan) {
	if h == nil || h.db == nil || plan == nil || plan.AuditRequestID == "" || plan.AuditFinalized {
		return
	}
	plan.AuditFinalized = true
	statusCode := plan.AuditLastStatusCode
	if statusCode <= 0 && c != nil && c.Writer != nil && c.Writer.Status() > 0 {
		statusCode = c.Writer.Status()
	}
	if statusCode <= 0 {
		statusCode = http.StatusOK
	}
	errorKind := plan.AuditLastErrorKind
	errorMessage := plan.AuditLastError
	if errorKind == "" && statusCode >= 400 {
		errorKind = relayAuditErrorKindForStatus(statusCode, plan)
	}
	if plan.SelectionCount <= 0 || plan.PreviousAccount <= 0 {
		h.enqueueRelayAuditState(plan, database.RelayAuditStateInput{
			DetectorMiss:   plan.DetectorMiss,
			RouteViolation: plan.RouteViolation,
			GroupExhausted: plan.GroupExhausted,
			StatusCode:     statusCode,
			ErrorKind:      errorKind,
			ErrorMessage:   errorMessage,
			CompletedAt:    time.Now(),
			Final:          true,
		})
		return
	}
	var account *auth.Account
	if h.store != nil {
		account = h.store.FindByID(plan.PreviousAccount)
	}
	accountID, accountType := relayAuditAccountSnapshot(account)
	if accountID == 0 {
		accountID = plan.PreviousAccount
	}
	transport := plan.AuditLastTransport
	if transport == "" {
		transport = "none"
	}
	_ = h.db.EnqueueRelayAuditOutcome(&database.RelayAuditOutcomeInput{
		RequestID:        plan.AuditRequestID,
		AttemptIndex:     plan.SelectionCount,
		AccountID:        accountID,
		AccountType:      accountType,
		UpstreamEndpoint: plan.Endpoint,
		Transport:        transport,
		ViaWebsocket:     transport == "websocket",
		StatusCode:       statusCode,
		ErrorKind:        errorKind,
		ErrorMessage:     errorMessage,
		CompletedAt:      time.Now(),
		Final:            true,
		DetectorMiss:     plan.DetectorMiss,
	})
}

func relayAuditErrorKindForStatus(statusCode int, plan *relayRoutePlan) string {
	switch {
	case plan != nil && plan.RouteViolation:
		return "relay_group_escape_violation"
	case plan != nil && plan.GroupExhausted:
		return "relay_group_exhausted"
	case statusCode == http.StatusConflict && plan != nil &&
		plan.HasPreviousResponseID && plan.AuditReplayStatus != "hit":
		return "continuation_replay_unavailable"
	case statusCode == http.StatusTooManyRequests:
		return "rate_limited"
	case statusCode == http.StatusServiceUnavailable:
		return "no_available_account"
	case statusCode >= 500:
		return "server_error"
	case statusCode >= 400:
		return "client_error"
	default:
		return ""
	}
}
