package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

const (
	relayAuditDefaultHours = 0.5
	relayAuditMaxHours     = 7 * 24
)

// GetRelayAuditReport serves the standalone Relay routing audit dashboard.
// It is intentionally independent from Prompt Filter logs and settings.
func (h *Handler) GetRelayAuditReport(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "审计数据库不可用")
		return
	}
	start, end, err := relayAuditWindowFromQuery(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	bucketMinutes := 5
	if raw := strings.TrimSpace(c.Query("bucket_minutes")); raw != "" {
		bucketMinutes, err = strconv.Atoi(raw)
		if err != nil || bucketMinutes < 1 || bucketMinutes > 1440 {
			writeError(c, http.StatusBadRequest, "bucket_minutes 参数无效")
			return
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	report, err := h.db.BuildRelayAuditReport(ctx, database.RelayAuditQuery{
		Start: start, End: end, BucketMinutes: bucketMinutes,
	})
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, report)
}

// GetRelayAuditCases returns stable, server-side paged case files with the
// complete bounded request text and the corresponding upstream attempt chain.
func (h *Handler) GetRelayAuditCases(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "审计数据库不可用")
		return
	}
	start, end, err := relayAuditWindowFromQuery(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	page := 1
	if raw := strings.TrimSpace(c.Query("page")); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil || page < 1 {
			writeError(c, http.StatusBadRequest, "page 参数无效")
			return
		}
	}
	pageSize := 20
	if raw := strings.TrimSpace(c.Query("page_size")); raw != "" {
		pageSize, err = strconv.Atoi(raw)
		if err != nil || pageSize < 1 || pageSize > 100 {
			writeError(c, http.StatusBadRequest, "page_size 参数无效")
			return
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	result, err := h.db.ListRelayAuditCasesPage(ctx, database.RelayAuditCaseQuery{
		Kind:  strings.TrimSpace(c.DefaultQuery("kind", database.RelayAuditCaseRelayRoute)),
		Start: start, End: end, Page: page, PageSize: pageSize, SummaryOnly: true,
	})
	if err != nil {
		if strings.Contains(err.Error(), "unsupported relay audit case kind") {
			writeError(c, http.StatusBadRequest, err.Error())
			return
		}
		writeInternalError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

// GetRelayAuditCaseDetail fetches the large, already-redacted request sample
// and attempt chain only when an administrator expands a paged case.
func (h *Handler) GetRelayAuditCaseDetail(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "审计数据库不可用")
		return
	}
	requestID := strings.TrimSpace(c.Param("request_id"))
	if requestID == "" || len(requestID) > 128 {
		writeError(c, http.StatusBadRequest, "request_id 参数无效")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	detail, err := h.db.GetRelayAuditCaseDetail(ctx, requestID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(c, http.StatusNotFound, "审计案卷不存在")
			return
		}
		writeInternalError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, detail)
}

func relayAuditWindowFromQuery(c *gin.Context) (time.Time, time.Time, error) {
	end := time.Now()
	start := end.Add(-time.Duration(relayAuditDefaultHours * float64(time.Hour)))

	rawStart := strings.TrimSpace(c.Query("start"))
	rawEnd := strings.TrimSpace(c.Query("end"))
	if rawStart != "" || rawEnd != "" {
		if rawStart == "" || rawEnd == "" {
			return time.Time{}, time.Time{}, fmt.Errorf("start 和 end 必须同时提供")
		}
		parsedStart, err := time.Parse(time.RFC3339, rawStart)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("start 参数无效")
		}
		parsedEnd, err := time.Parse(time.RFC3339, rawEnd)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("end 参数无效")
		}
		start, end = parsedStart, parsedEnd
	} else if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
		hours, err := strconv.ParseFloat(raw, 64)
		if err != nil || hours <= 0 || hours > relayAuditMaxHours {
			return time.Time{}, time.Time{}, fmt.Errorf("hours 必须在 0 到 %d 之间", relayAuditMaxHours)
		}
		start = end.Add(-time.Duration(hours * float64(time.Hour)))
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("审计时间范围无效")
	}
	if end.Sub(start) > relayAuditMaxHours*time.Hour {
		return time.Time{}, time.Time{}, fmt.Errorf("审计时间范围不能超过 7 天")
	}
	return start, end, nil
}
