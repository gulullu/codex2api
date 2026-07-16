package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// httpFinalResponseWriter observes the synchronous net/http publication
// boundary used by Gin renderers. A nil Write result means the complete error
// body was accepted by the server-side response writer; a short/failed write
// must never be promoted to the canonical, user-visible logical result.
type httpFinalResponseWriter struct {
	gin.ResponseWriter
	wroteBody bool
	writeErr  error
}

func (w *httpFinalResponseWriter) rememberWrite(n, expected int, err error) {
	if n > 0 {
		w.wroteBody = true
	}
	if w.writeErr != nil {
		return
	}
	if err != nil {
		w.writeErr = err
		return
	}
	if n != expected {
		w.writeErr = io.ErrShortWrite
	}
}

func (w *httpFinalResponseWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.rememberWrite(n, len(data), err)
	return n, err
}

func (w *httpFinalResponseWriter) WriteString(data string) (int, error) {
	n, err := w.ResponseWriter.WriteString(data)
	w.rememberWrite(n, len(data), err)
	return n, err
}

// publishHTTPFinalResponse executes one terminal non-WebSocket response and
// reports whether it crossed the server-side publication boundary. Cancellation
// observed before the write prevents publication; once the complete body Write
// succeeds, that terminal is canonical even if context cancellation races after
// the write, matching the Responses WebSocket terminal-publication contract.
// Canonical audit rows may be written only when this returns true. The caller
// owns hidden-attempt logging when it returns false, because route-selection
// failures have no upstream attempt while transport/non-2xx failures do.
func publishHTTPFinalResponseErr(c *gin.Context, send func() error) bool {
	if c == nil || c.Writer == nil || send == nil || c.Request == nil || c.Request.Context().Err() != nil {
		return false
	}
	original := c.Writer
	tracked := &httpFinalResponseWriter{ResponseWriter: original}
	c.Writer = tracked
	defer func() { c.Writer = original }()

	sendErr := send()
	if sendErr != nil || tracked.writeErr != nil || !tracked.wroteBody {
		return false
	}
	return true
}

// publishHTTPFinalResponse keeps compatibility for Gin helpers whose API does
// not return their render error. The tracking writer still observes the actual
// Write/WriteString result.
func publishHTTPFinalResponse(c *gin.Context, send func()) bool {
	if send == nil {
		return false
	}
	return publishHTTPFinalResponseErr(c, func() error { send(); return nil })
}

// publishHTTPFinalWithAudit centralizes the response/audit ordering. Exactly
// one audit callback runs after the publication attempt: canonical only for a
// complete live write, hidden otherwise. Either callback may be nil when the
// terminal condition itself did not start an upstream attempt.
func publishHTTPFinalWithAudit(c *gin.Context, send, canonical, hidden func()) bool {
	delivered := publishHTTPFinalResponse(c, send)
	if delivered {
		if canonical != nil {
			canonical()
		}
	} else if hidden != nil {
		hidden()
	}
	return delivered
}

// publishHTTPFinalWithAuditErr is the error-aware form for callers that own a
// terminal writer returning an error. A send error, tracked write error, short
// write, missing body, or pre-write cancellation selects the hidden callback.
func publishHTTPFinalWithAuditErr(c *gin.Context, send func() error, canonical, hidden func()) bool {
	delivered := publishHTTPFinalResponseErr(c, send)
	if delivered {
		if canonical != nil {
			canonical()
		}
	} else if hidden != nil {
		hidden()
	}
	return delivered
}

// httpFinalUsageCopy prevents the canonical and hidden callbacks from mutating
// one shared usage input. In particular, a client-visible 503 mapping must not
// overwrite the raw 401/429/5xx status retained by a failed-publication attempt.
func httpFinalUsageCopy(input *database.UsageLogInput, statusCode int, hidden bool) *database.UsageLogInput {
	if input == nil {
		return nil
	}
	copy := *input
	copy.StatusCode = statusCode
	copy.GuardianAttemptOnly = hidden
	return &copy
}

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
	UpstreamAccountType  string
	routeDecision        *promptRiskDecision
}

func rememberPendingFinalFailure(c *gin.Context, spec retryAttemptUsageSpec) *retryAttemptUsageSpec {
	if c != nil {
		if value, ok := c.Get(contextUpstreamAccountType); ok {
			spec.UpstreamAccountType, _ = value.(string)
		}
	}
	if decision, ok := promptRiskDecisionFromContext(c); ok {
		decisionCopy := decision
		decisionCopy.Signals = append([]string(nil), decision.Signals...)
		spec.routeDecision = &decisionCopy
	}
	return &spec
}

func pendingFinalRouteDecision(c *gin.Context, decision promptRiskDecision) promptRiskDecision {
	encryptedDowngraded := encryptedContextNeedsDowngrade(c)
	if !encryptedDowngraded {
		for _, signal := range encryptedContextSignalsFromContext(c) {
			if signal == encryptedContextDowngradeSignal {
				encryptedDowngraded = true
				break
			}
		}
	}
	if decision.PinKind != encryptedContextPinKind || !encryptedDowngraded {
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
	statusCode, errorKind, errorMessage := retryRequestFailure(err, firstTokenTimeout)
	// Callers that have positively recorded a Relay transport failure may pass
	// the internal 598 audit status.  Keep the downstream-facing default at 502
	// for every other request error.
	if spec.StatusCode == 0 {
		spec.StatusCode = statusCode
	}
	if strings.TrimSpace(spec.UpstreamErrorKind) == "" {
		spec.UpstreamErrorKind = errorKind
	}
	spec.ErrorMessage = errorMessage
	h.logRetryAttemptFailure(c, spec)
}

func relayTransportFailureAuditStatus(recorded bool) int {
	if recorded {
		return logStatusUpstreamStreamBreak
	}
	return 0
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

func canonicalRequestFailureSpecWithKind(spec retryAttemptUsageSpec, err error, errorKind string) retryAttemptUsageSpec {
	spec = canonicalRequestFailureSpec(spec, err)
	if strings.TrimSpace(errorKind) != "" {
		spec.UpstreamErrorKind = errorKind
	}
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

// openAIFinalResponseStatus returns the status the OpenAI-compatible client
// actually observes after the final upstream response mapping is applied.
// Hidden attempts keep their real upstream status; only the one canonical row
// should use this client-visible status.
func openAIFinalResponseStatus(statusCode int, body []byte) int {
	if _, ok := parseUsageLimitDetails(body); ok {
		return http.StatusServiceUnavailable
	}
	if statusCode == http.StatusUnauthorized && !isMissingScopeUnauthorized(body) {
		return http.StatusServiceUnavailable
	}
	if statusCode < 400 || statusCode > 599 {
		return http.StatusBadGateway
	}
	return statusCode
}

// openAIFinalResponseStatusForContext mirrors sendFinalUpstreamError's
// account-ownership-aware 403 mapping. OAuth 403 is a pool-level failure after
// safe account switching is exhausted; Relay 403 remains the upstream
// client-visible status because it can be request-specific policy/WAF output.
func openAIFinalResponseStatusForContext(c *gin.Context, statusCode int, body []byte) int {
	if statusCode == http.StatusForbidden && c != nil &&
		!strings.EqualFold(c.GetString(contextUpstreamAccountType), auth.UpstreamOpenAIResponses) {
		return http.StatusServiceUnavailable
	}
	return openAIFinalResponseStatus(statusCode, body)
}

func openAIFailureUsageStatus(statusCode int, body []byte, guardianAttemptOnly bool) int {
	if guardianAttemptOnly {
		return statusCode
	}
	return openAIFinalResponseStatus(statusCode, body)
}

// anthropicFinalResponseStatus mirrors sendFinalAnthropicUpstreamError's
// client-visible status mapping. Missing-scope 401 responses remain 401;
// account credential failures become a pool-level 503.
func anthropicFinalResponseStatus(statusCode int, body []byte) int {
	if statusCode == http.StatusUnauthorized && !isMissingScopeUnauthorized(body) {
		return http.StatusServiceUnavailable
	}
	if statusCode < 400 || statusCode > 599 {
		return http.StatusBadGateway
	}
	return statusCode
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
	// Route exhaustion is account-neutral, but it still belongs to the class of
	// the last real upstream attempt. Preserve that class so OAuth exhaustion is
	// not mislabeled as Relay and Guardian continues to ignore OAuth failures.
	if c != nil {
		// Missing provenance stays unknown. Defaulting an absent snapshot to
		// Relay would allow a future caller bug to feed OAuth failures into Relay
		// audit/Guardian queries.
		c.Set(contextUpstreamAccountType, strings.TrimSpace(spec.UpstreamAccountType))
	}
	canonical := *spec
	canonical.AccountID = 0
	h.logCanonicalFailureSpec(c, canonical)
}

// logPendingFinalFailureAs records a pending hidden attempt using the status
// and error semantics of the response that is actually returned after account
// selection is exhausted. The original hidden attempt remains unchanged.
func (h *Handler) logPendingFinalFailureAs(c *gin.Context, spec *retryAttemptUsageSpec, statusCode int, errorKind, errorMessage string) {
	if spec == nil {
		return
	}
	canonical := *spec
	canonical.StatusCode = statusCode
	if strings.TrimSpace(errorKind) != "" {
		canonical.UpstreamErrorKind = errorKind
	}
	if strings.TrimSpace(errorMessage) != "" {
		canonical.ErrorMessage = errorMessage
	}
	h.logPendingFinalFailure(c, &canonical)
}

// logPendingOrSyntheticFinalFailureAs promotes the last hidden upstream
// attempt when one exists. If account selection/owner repair fails before any
// upstream attempt, it emits the missing account-neutral canonical row instead
// of silently dropping the client-visible 4xx/503 from logical-request audit.
// Callers must invoke this only after the HTTP terminal response is published.
func (h *Handler) logPendingOrSyntheticFinalFailureAs(c *gin.Context, pending *retryAttemptUsageSpec, synthetic retryAttemptUsageSpec, statusCode int, errorKind, errorMessage string) {
	if pending != nil {
		h.logPendingFinalFailureAs(c, pending, statusCode, errorKind, errorMessage)
		return
	}
	synthetic.AccountID = 0
	synthetic.StatusCode = statusCode
	if strings.TrimSpace(errorKind) != "" {
		synthetic.UpstreamErrorKind = errorKind
	}
	if strings.TrimSpace(errorMessage) != "" {
		synthetic.ErrorMessage = errorMessage
	}
	clearUpstreamAccountContext(c)
	h.logCanonicalFailureSpec(c, synthetic)
}

// logCanonicalFailureSpec writes exactly one user-visible logical result from
// an already normalized spec. Callers must set StatusCode to the status the
// client actually observes, while hidden upstream attempts remain separate.
func (h *Handler) logCanonicalFailureSpec(c *gin.Context, spec retryAttemptUsageSpec) {
	if h == nil {
		return
	}
	input := buildRetryAttemptUsageLog(c, spec)
	input.GuardianAttemptOnly = false
	h.logUsageForRequest(c, input)
}

// logFinalRequestErrorFailure writes the one canonical, user-visible logical
// result when the retry budget is exhausted by an upstream transport error.
// Hidden attempts remain GuardianAttemptOnly=true; the final row is what the
// audit page and sub2 failover controller must observe.
func (h *Handler) logFinalRequestErrorFailure(c *gin.Context, spec retryAttemptUsageSpec, err error) {
	spec = canonicalRequestFailureSpec(spec, err)
	h.logCanonicalFailureSpec(c, spec)
}

func (h *Handler) logFinalRequestErrorFailureWithKind(c *gin.Context, spec retryAttemptUsageSpec, err error, errorKind string) {
	spec = canonicalRequestFailureSpecWithKind(spec, err, errorKind)
	h.logCanonicalFailureSpec(c, spec)
}

func (h *Handler) logFinalRequestErrorFailureAs(c *gin.Context, spec retryAttemptUsageSpec, err error, statusCode int, errorKind string) {
	spec = canonicalRequestFailureSpecWithKind(spec, err, errorKind)
	spec.StatusCode = statusCode
	h.logCanonicalFailureSpec(c, spec)
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
