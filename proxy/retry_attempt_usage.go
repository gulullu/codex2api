package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// retryAttemptUsageSpec describes one failed upstream attempt that is about to
// be hidden by a transparent retry. The next attempt is logged separately with
// the same logical request ID.
type retryAttemptUsageSpec struct {
	AccountID            int64
	Endpoint             string
	Model                string
	EffectiveModel       string
	StatusCode           int
	DurationMs           int
	FirstTokenMs         int
	ReasoningEffort      string
	UpstreamEndpoint     string
	Stream               bool
	ViaWebsocket         bool
	RequestedServiceTier string
	ActualServiceTier    string
	Attempt              int
	UpstreamErrorKind    string
	ErrorMessage         string
	routeDecision        *promptRiskDecision
}

func rememberPendingFinalFailure(c *gin.Context, spec retryAttemptUsageSpec) *retryAttemptUsageSpec {
	if decision, ok := promptRiskDecisionFromContext(c); ok {
		decisionCopy := decision
		decisionCopy.Signals = append([]string(nil), decision.Signals...)
		spec.routeDecision = &decisionCopy
	}
	return &spec
}

func pendingFinalRouteDecision(c *gin.Context, decision promptRiskDecision) promptRiskDecision {
	if decision.PinKind != encryptedContextPinKind || !encryptedContextNeedsDowngrade(c) {
		return decision
	}

	// The real encrypted owner attempt is already persisted as attempt-only.
	// The account-neutral canonical row represents exhaustion after that owner
	// became unavailable, so it must not pretend account 0 still owns/pins the
	// ciphertext. Keep the Relay route, but express the terminal owner failure
	// as a continuation-style result with downgrade evidence.
	decision.RouteSource = cybRelayRouteSourceContinuation
	decision.PinKind = ""
	decision.RoutePinned = false
	decision.Reason = "encrypted context owner unavailable; Relay route exhausted"
	filtered := make([]string, 0, len(decision.Signals)+2)
	for _, signal := range decision.Signals {
		if signal != encryptedOwnerHitSignal {
			filtered = appendUniqueRouteSignal(filtered, signal)
		}
	}
	for _, signal := range encryptedContextSignalsFromContext(c) {
		if signal != encryptedOwnerHitSignal {
			filtered = appendUniqueRouteSignal(filtered, signal)
		}
	}
	decision.Signals = appendUniqueRouteSignal(filtered, encryptedOwnerUnavailableSignal)
	decision.Signals = appendUniqueRouteSignal(decision.Signals, encryptedContextDowngradeSignal)
	return decision
}

func buildRetryAttemptUsageLog(c *gin.Context, spec retryAttemptUsageSpec) *database.UsageLogInput {
	statusCode := spec.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadGateway
	}
	errorKind := strings.TrimSpace(spec.UpstreamErrorKind)
	if errorKind == "" {
		errorKind = classifyHTTPFailure(statusCode)
		if errorKind == "" {
			errorKind = "transport"
		}
	}
	errorMessage := strings.TrimSpace(spec.ErrorMessage)
	if errorMessage == "" {
		errorMessage = fmt.Sprintf("HTTP %d", statusCode)
	}
	tiers := resolveUsageServiceTiers(spec.ActualServiceTier, spec.RequestedServiceTier)

	return &database.UsageLogInput{
		AccountID:            spec.AccountID,
		Endpoint:             spec.Endpoint,
		Model:                spec.Model,
		EffectiveModel:       spec.EffectiveModel,
		StatusCode:           statusCode,
		DurationMs:           spec.DurationMs,
		FirstTokenMs:         spec.FirstTokenMs,
		ReasoningEffort:      spec.ReasoningEffort,
		InboundEndpoint:      spec.Endpoint,
		UpstreamEndpoint:     spec.UpstreamEndpoint,
		Stream:               spec.Stream,
		ViaWebsocket:         spec.ViaWebsocket,
		ServiceTier:          tiers.ServiceTier,
		RequestedServiceTier: tiers.RequestedServiceTier,
		ActualServiceTier:    tiers.ActualServiceTier,
		BillingServiceTier:   tiers.BillingServiceTier,
		IsRetryAttempt:       spec.Attempt > 0,
		AttemptIndex:         spec.Attempt + 1,
		UpstreamErrorKind:    errorKind,
		ErrorMessage:         errorMessage,
		GuardianAttemptOnly:  true,
		LogicalRequestID:     logicalRequestID(c),
	}
}

func (h *Handler) logRetryAttemptFailure(c *gin.Context, spec retryAttemptUsageSpec) {
	h.logUsageForRequest(c, buildRetryAttemptUsageLog(c, spec))
}

func (h *Handler) logRetryRequestErrorFailure(c *gin.Context, spec retryAttemptUsageSpec, err error, firstTokenTimeout bool) {
	spec.StatusCode, spec.UpstreamErrorKind, spec.ErrorMessage = retryRequestFailure(err, firstTokenTimeout)
	h.logRetryAttemptFailure(c, spec)
}

func canonicalRequestFailure(err error) (int, string, string) {
	statusCode := http.StatusBadGateway
	var structured *Error
	if errors.As(err, &structured) && structured.HTTPStatus >= 400 && structured.HTTPStatus <= 599 {
		statusCode = structured.HTTPStatus
	}
	kind := classifyTransportFailure(err)
	if kind == "" {
		kind = "transport"
	}
	message := "上游请求失败"
	if err != nil {
		message = err.Error()
	}
	return statusCode, kind, message
}

func canonicalRequestFailureSpec(spec retryAttemptUsageSpec, err error) retryAttemptUsageSpec {
	spec.StatusCode, spec.UpstreamErrorKind, spec.ErrorMessage = canonicalRequestFailure(err)
	return spec
}

func canonicalStreamStatus(outcome streamOutcome) int {
	if outcome.logStatusCode != logStatusUpstreamStreamBreak {
		return outcome.logStatusCode
	}
	if outcome.softFirstTokenTimeout {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func canonicalStreamFailureSpec(spec retryAttemptUsageSpec, outcome streamOutcome) retryAttemptUsageSpec {
	spec.StatusCode = canonicalStreamStatus(outcome)
	spec.UpstreamErrorKind = outcome.failureKind
	spec.ErrorMessage = outcome.failureMessage
	return spec
}

func upstreamFailureBody(message string) []byte {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "Upstream request failed"
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    "upstream_error",
			"message": message,
		},
	})
	return body
}

// logPendingFinalFailure turns the last hidden retry attempt into the one
// canonical logical result when account selection runs out before another
// upstream attempt can start. It is deliberately account-neutral: the hidden
// attempt already carries the failing front-door account, while this row
// represents route exhaustion after that real upstream failure.
func (h *Handler) logPendingFinalFailure(c *gin.Context, spec *retryAttemptUsageSpec) {
	if h == nil || spec == nil {
		return
	}
	if spec.routeDecision != nil {
		decision := pendingFinalRouteDecision(c, *spec.routeDecision)
		setPromptRiskDecisionContext(c, decision, h.cybRelayConfig().GroupID)
	}
	clearUpstreamAccountContext(c)
	// Route exhaustion is account-neutral, but it is still the final result of
	// an isolated Relay route. Keep that upstream class explicit so audit and
	// Guardian queries neither misclassify it as OAuth nor drop it entirely.
	if c != nil {
		c.Set(contextUpstreamAccountType, auth.UpstreamOpenAIResponses)
	}
	input := buildRetryAttemptUsageLog(c, *spec)
	input.AccountID = 0
	input.GuardianAttemptOnly = false
	h.logUsageForRequest(c, input)
}

// logFinalRequestErrorFailure writes the one canonical, user-visible logical
// result when the retry budget is exhausted by an upstream transport error.
// Hidden attempts remain GuardianAttemptOnly=true; the final row is what the
// audit page and sub2 failover controller must observe.
func (h *Handler) logFinalRequestErrorFailure(c *gin.Context, spec retryAttemptUsageSpec, err error) {
	spec = canonicalRequestFailureSpec(spec, err)
	input := buildRetryAttemptUsageLog(c, spec)
	input.GuardianAttemptOnly = false
	h.logUsageForRequest(c, input)
}

func (h *Handler) logTransparentStreamRetryFailure(c *gin.Context, spec retryAttemptUsageSpec, outcome streamOutcome) {
	spec.StatusCode = outcome.logStatusCode
	spec.UpstreamErrorKind = outcome.failureKind
	spec.ErrorMessage = outcome.failureMessage
	h.logRetryAttemptFailure(c, spec)
}

func retryRequestFailure(err error, firstTokenTimeout bool) (int, string, string) {
	statusCode := http.StatusBadGateway
	if firstTokenTimeout {
		statusCode = logStatusUpstreamStreamBreak
	}
	kind := classifyTransportFailure(err)
	if kind == "" {
		kind = "transport"
	}
	message := "上游请求失败"
	if err != nil {
		message = err.Error()
	}
	return statusCode, kind, message
}
