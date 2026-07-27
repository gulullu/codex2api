package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
)

const skipCYBLearningPipelineContextKey = "skipCYBLearningPipeline"

var ErrInternalRelayGroupUnavailable = errors.New("CYB Relay group is not configured")

// ExecuteInternalResponse performs one Responses request through the configured
// account pool. It is intended for bounded administrative jobs such as prompt
// intelligence analysis and bypasses only the inbound prompt filter to avoid
// the defensive analysis prompt blocking itself.
func (h *Handler) ExecuteInternalResponse(ctx context.Context, body []byte) (int, []byte) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Set("prompt_intelligence_internal", true)
	h.Responses(c)
	return recorder.Code, recorder.Body.Bytes()
}

// ExecuteInternalRelayResponse runs an administrative Responses call through
// the configured CYB Relay group. Account choice, priority, concurrency and
// retries remain owned by the normal Store/FastScheduler path. The request
// bypasses CYB inspection, pins, route audit and feedback capture so a learning
// prompt cannot recursively create another learning case.
func (h *Handler) ExecuteInternalRelayResponse(ctx context.Context, body []byte) (int, []byte, error) {
	cfg := loadRelayRouteConfig()
	if !cfg.Enabled || cfg.GroupID <= 0 {
		return 0, nil, ErrInternalRelayGroupUnavailable
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	c.Set("prompt_intelligence_internal", true)
	c.Set(skipCYBLearningPipelineContextKey, true)
	c.Set(internalRelayGroupContextKey, cfg.GroupID)
	h.Responses(c)
	return recorder.Code, recorder.Body.Bytes(), nil
}
