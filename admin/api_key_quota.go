package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
)

// ResetAPIKeyQuota manually renews one API key's configured quota while
// preserving its cumulative historical usage.
func (h *Handler) ResetAPIKeyQuota(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(c, http.StatusBadRequest, "无效的 API Key ID")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	row, err := h.db.GetAPIKeyByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(c, http.StatusNotFound, "API Key 不存在")
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if row.QuotaLimit <= 0 {
		writeError(c, http.StatusBadRequest, "该 API Key 未配置额度限制")
		return
	}

	if err := h.db.ResetAPIKeyQuota(ctx, id); err != nil {
		writeInternalError(c, err)
		return
	}
	h.invalidateAPIKeyRuntimeCaches(ctx, row.Key)
	security.SecurityAuditLog("API_KEY_QUOTA_RESET", fmt.Sprintf("id=%d ip=%s", id, c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"message": "API Key 额度已重置"})
}

// ResetAllAPIKeyQuotas renews every configured API key quota in one database
// statement so the operation cannot be left half-complete.
func (h *Handler) ResetAllAPIKeyQuotas(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	keys, err := h.db.ListAPIKeys(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	resetCount, err := h.db.ResetAllAPIKeyQuotas(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}

	// The proxy caches quota_used by raw API key. Evict every affected entry so
	// exhausted keys become usable immediately instead of waiting for the TTL.
	h.deleteRuntimeCache(ctx, adminAPIKeyCountNamespace, "all")
	for _, key := range keys {
		if key.QuotaLimit > 0 {
			h.deleteRuntimeCache(ctx, adminAPIKeyCacheNamespace, key.Key)
		}
	}
	security.SecurityAuditLog("API_KEY_QUOTA_RESET_ALL", fmt.Sprintf("count=%d ip=%s", resetCount, c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{
		"message":     "所有 API Key 额度已重置",
		"reset_count": resetCount,
	})
}
