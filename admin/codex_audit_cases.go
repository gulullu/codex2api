package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

// GetCodexAuditCases serves paged audit case files. Historical case queries
// always receive an explicit window; realtime health/account snapshots remain
// on their existing endpoints and are deliberately not mixed into this API.
func (h *Handler) GetCodexAuditCases(c *gin.Context) {
	kind := strings.ToLower(strings.TrimSpace(c.DefaultQuery("kind", database.CodexAuditCaseRelayRoute)))
	switch kind {
	case database.CodexAuditCaseRelayRoute,
		database.CodexAuditCaseSessionBleed,
		database.CodexAuditCaseOAuthCyber,
		database.CodexAuditCaseRelayCyber:
	default:
		writeError(c, http.StatusBadRequest, "kind 参数无效")
		return
	}

	start, end, ok := codexAuditCasesWindow(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	page, err := h.db.ListCodexAuditCasesPage(ctx, database.CodexAuditCasesQuery{
		Kind:     kind,
		Start:    start,
		End:      end,
		Page:     positiveQueryInt(c, "page", 1),
		PageSize: positiveQueryInt(c, "page_size", 10),
	})
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

func codexAuditCasesWindow(c *gin.Context) (time.Time, time.Time, bool) {
	end := time.Now()
	if raw := strings.TrimSpace(c.Query("end")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(c, http.StatusBadRequest, "end 参数格式无效，需要 RFC3339")
			return time.Time{}, time.Time{}, false
		}
		end = parsed
	}
	start := time.Time{}
	if raw := strings.TrimSpace(c.Query("start")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(c, http.StatusBadRequest, "start 参数格式无效，需要 RFC3339")
			return time.Time{}, time.Time{}, false
		}
		start = parsed
	}
	if start.IsZero() {
		hours := 0.5
		if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
			if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 {
				hours = parsed
			}
		}
		if hours > 168 {
			hours = 168
		}
		start = end.Add(-time.Duration(hours * float64(time.Hour)))
	}
	if !start.Before(end) {
		writeError(c, http.StatusBadRequest, "start 必须早于 end")
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}
