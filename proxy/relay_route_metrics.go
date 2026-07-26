package proxy

import (
	"fmt"
	"strings"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
)

const relayRouteLogSourcePrefix = "relay_route_"

func (h *Handler) logRelayRouteSelection(c *gin.Context, plan *relayRoutePlan, account *auth.Account, switched bool) {
	if h == nil || h.db == nil || c == nil || plan == nil || account == nil {
		return
	}
	mode := "initial"
	if switched {
		mode = "same_group_switch"
	} else if plan.SelectionCount > 1 {
		mode = "retry"
	}
	matches := make([]promptfilter.Match, 0, len(plan.Signals))
	for _, signal := range plan.Signals {
		if signal = strings.TrimSpace(signal); signal != "" {
			matches = append(matches, promptfilter.Match{Name: signal, Category: "relay_route"})
		}
	}
	input := relayRouteMetricInput(c, plan, relayRouteLogSourcePrefix+plan.Source, mode)
	input.MatchedPatterns = promptfilter.MatchesJSON(matches)
	populatePromptFilterAPIKeyMeta(c, input)
	_ = h.db.EnqueuePromptFilterLog(input, database.PromptFilterLogPriorityLow)
}

func (h *Handler) logRelayGroupExhausted(c *gin.Context, plan *relayRoutePlan) {
	h.enqueueRelayRouteMetric(c, plan, relayRouteLogSourcePrefix+"group_exhausted", "error", database.PromptFilterLogPriorityHigh)
}

func (h *Handler) logRelayGroupEscapeViolation(c *gin.Context, plan *relayRoutePlan) {
	h.enqueueRelayRouteMetric(c, plan, relayRouteLogSourcePrefix+"group_escape_violation", "error", database.PromptFilterLogPriorityHigh)
}

func (h *Handler) logRelayCyberPolicyMetric(c *gin.Context, plan *relayRoutePlan, detectorMiss bool) {
	source := relayRouteLogSourcePrefix + "relay_cyber_policy"
	if detectorMiss {
		source = relayRouteLogSourcePrefix + "detector_miss"
	}
	h.enqueueRelayRouteMetric(c, plan, source, "cyber_policy", database.PromptFilterLogPriorityHigh)
}

func (h *Handler) enqueueRelayRouteMetric(c *gin.Context, plan *relayRoutePlan, source string, mode string, priority database.PromptFilterLogPriority) {
	if h == nil || h.db == nil || c == nil || plan == nil {
		return
	}
	input := relayRouteMetricInput(c, plan, source, mode)
	populatePromptFilterAPIKeyMeta(c, input)
	_ = h.db.EnqueuePromptFilterLog(input, priority)
}

func relayRouteMetricInput(c *gin.Context, plan *relayRoutePlan, source string, mode string) *database.PromptFilterLogInput {
	return &database.PromptFilterLogInput{
		Source:          source,
		Endpoint:        plan.Endpoint,
		Protocol:        string(promptfilter.ProtocolForEndpoint(plan.Endpoint)),
		Provider:        "relay_group",
		Model:           plan.Model,
		Action:          "route",
		Mode:            mode,
		PolicyProfile:   "relay_group",
		ReasonCode:      plan.Reason,
		PrimaryOrigin:   plan.Origin,
		MatchedPatterns: "[]",
		ErrorCode:       fmt.Sprintf("group:%d", plan.RequiredGroupID),
		ClientIP:        c.ClientIP(),
	}
}
