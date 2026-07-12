package proxy

import (
	"fmt"
	"net/http"
	"strings"

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
