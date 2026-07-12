package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

func (h *Handler) GetRelayGuardianStatus(c *gin.Context) {
	if h.store == nil {
		writeError(c, http.StatusServiceUnavailable, "Relay Guardian 未初始化")
		return
	}
	c.JSON(http.StatusOK, h.store.RelayGuardianStatus())
}

func parseGuardianTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("empty time")
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("unsupported time format")
}

func parseGuardianTimeQuery(c *gin.Context, name string) (time.Time, error) {
	raw, provided := c.GetQuery(name)
	if !provided {
		return time.Time{}, nil
	}
	return parseGuardianTime(raw)
}

func guardianSafePage(page, pageSize int) int {
	if page <= 1 {
		return page
	}
	effectivePageSize := pageSize
	if effectivePageSize < 1 {
		effectivePageSize = 20
	} else if effectivePageSize > 200 {
		effectivePageSize = 200
	}
	maxInt := int(^uint(0) >> 1)
	if page-1 > maxInt/effectivePageSize {
		// Pass an invalid value through to the DB layer, which owns pagination
		// normalization. This prevents its OFFSET multiplication from overflowing.
		return 0
	}
	return page
}

func (h *Handler) ListRelayGuardianEvents(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "Relay Guardian 事件存储未初始化")
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	page = guardianSafePage(page, pageSize)
	start, err := parseGuardianTimeQuery(c, "start")
	if err != nil {
		writeError(c, http.StatusBadRequest, "start 时间格式无效")
		return
	}
	end, err := parseGuardianTimeQuery(c, "end")
	if err != nil {
		writeError(c, http.StatusBadRequest, "end 时间格式无效")
		return
	}
	if !start.IsZero() && !end.IsZero() && start.After(end) {
		writeError(c, http.StatusBadRequest, "start 不能晚于 end")
		return
	}
	result, err := h.db.ListRelayGuardianEvents(c.Request.Context(), page, pageSize, start, end)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "读取 Relay Guardian 事件失败: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, result)
}

type relayGuardianActionRequest struct {
	Generation uint64 `json:"generation"`
	Minutes    int    `json:"minutes,omitempty"`
}

func relayGuardianActionError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrRelayGuardianNotEnforcing):
		writeError(c, http.StatusConflict, "Relay Guardian 仅在 enforce 模式允许写操作")
	case errors.Is(err, auth.ErrRelayGuardianStaleGeneration):
		writeError(c, http.StatusConflict, "Guardian 状态已变化，请刷新后重试")
	case errors.Is(err, auth.ErrRelayGuardianInvalidState):
		writeError(c, http.StatusConflict, "当前 Guardian 状态不允许该操作")
	case errors.Is(err, auth.ErrRelayGuardianRuntimeUnavailable):
		writeError(c, http.StatusServiceUnavailable, "Guardian 运行态暂不可用，请稍后重试")
	case errors.Is(err, database.ErrRelayGuardianAccountNotFound):
		writeError(c, http.StatusNotFound, "Relay 账号不存在")
	default:
		writeError(c, http.StatusInternalServerError, err.Error())
	}
}

func (h *Handler) ReleaseRelayGuardian(c *gin.Context) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || accountID <= 0 {
		writeError(c, http.StatusBadRequest, "账号 ID 无效")
		return
	}
	var req relayGuardianActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if err := h.store.ReleaseRelayGuardian(accountID, req.Generation); err != nil {
		relayGuardianActionError(c, err)
		return
	}
	status, ok := h.store.RelayGuardianAccountStatus(accountID)
	if !ok {
		writeError(c, http.StatusNotFound, "Relay 账号不存在")
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *Handler) TemporaryBypassRelayGuardian(c *gin.Context) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || accountID <= 0 {
		writeError(c, http.StatusBadRequest, "账号 ID 无效")
		return
	}
	var req relayGuardianActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if req.Minutes < 1 || req.Minutes > 60 {
		writeError(c, http.StatusBadRequest, "minutes 必须在 1 到 60 之间")
		return
	}
	if err := h.store.TemporaryBypassRelayGuardian(accountID, req.Generation, req.Minutes); err != nil {
		relayGuardianActionError(c, err)
		return
	}
	status, ok := h.store.RelayGuardianAccountStatus(accountID)
	if !ok {
		writeError(c, http.StatusNotFound, "Relay 账号不存在")
		return
	}
	c.JSON(http.StatusOK, status)
}
