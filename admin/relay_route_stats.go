package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func (h *Handler) GetRelayRouteStats(c *gin.Context) {
	hours := 24
	if raw := strings.TrimSpace(c.Query("window_hours")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(c, http.StatusBadRequest, "window_hours 参数无效")
			return
		}
		hours = parsed
	}
	window, err := database.ValidateRelayRouteStatsWindow(hours)
	if err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	stats, err := h.db.GetRelayRouteStats(ctx, window)
	if err != nil {
		if errors.Is(err, database.ErrRelayAuditReportTooLarge) {
			writeError(c, http.StatusUnprocessableEntity, "范围内审计数据过多，请缩短时间范围")
			return
		}
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, stats)
}
