package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/proxy"
	"github.com/codex2api/security/cyblearn"
	"github.com/codex2api/security/cybroute"
	"github.com/gin-gonic/gin"
)

const (
	relayCYBLearningPollInterval          = 5 * time.Second
	relayCYBRuleReloadInterval            = 30 * time.Second
	relayCYBLearningCallTimeout           = 90 * time.Second
	relayCYBLearningMaxAttempts           = 5
	relayCYBCandidateMaxAttempts          = 3
	relayCYBRecentBenignLimit             = 1000
	relayCYBRuleGuardWindow               = 10 * time.Minute
	relayCYBRuleGuardMinRequests          = 100
	relayCYBRuleGuardMaxPercent           = 20
	relayCYBLegacyBackfillLimit           = 100
	relayCYBLegacyBackfillMaxFailures     = 3
	relayCYBLegacyBackfillRetryBasePeriod = time.Second
	relayCYBLegacyBackfillSafetyLag       = 10 * time.Minute
)

var errRelayCYBRecentTrafficUnavailable = errors.New("relay CYB recent traffic unavailable")

type relayCYBLearningConfigResponse struct {
	Enabled                  bool                                    `json:"enabled"`
	Model                    string                                  `json:"model"`
	UpdatedAt                time.Time                               `json:"updated_at"`
	AvailableModels          []string                                `json:"available_models"`
	RelayGroupID             int64                                   `json:"relay_group_id"`
	RelayGroupName           string                                  `json:"relay_group_name"`
	Stats                    database.RelayCYBLearningStats          `json:"stats"`
	SampleWriter             database.RelayAuditWriterStats          `json:"sample_writer"`
	Notifications            []database.RelayCYBLearningNotification `json:"notifications"`
	InternalRequestsExcluded bool                                    `json:"internal_requests_excluded"`
}

type updateRelayCYBLearningConfigRequest struct {
	Enabled bool   `json:"enabled"`
	Model   string `json:"model"`
}

func (h *Handler) StartRelayCYBLearning(ctx context.Context) {
	if h == nil || h.db == nil || h.store == nil || h.imageProxy == nil {
		return
	}
	h.relayCYBLearningStartOnce.Do(func() {
		if err := h.reloadRelayCYBLearnedRules(ctx); err != nil {
			log.Printf("Relay CYB 学习规则初始加载失败: %v", err)
		}
		h.startDBBackgroundTaskWithParent(ctx, h.runRelayCYBLegacyBackfill)
		h.startDBBackgroundTaskWithParent(ctx, h.runRelayCYBLearningWorker)
	})
}

func (h *Handler) runRelayCYBLearningWorker(ctx context.Context) {
	pollTicker := time.NewTicker(relayCYBLearningPollInterval)
	reloadTicker := time.NewTicker(relayCYBRuleReloadInterval)
	defer pollTicker.Stop()
	defer reloadTicker.Stop()
	for {
		if err := h.processOneRelayCYBLearningSample(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Relay CYB 自动学习任务失败: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-reloadTicker.C:
			if err := h.enforceRelayCYBRuleGuard(ctx); err != nil && ctx.Err() == nil {
				log.Printf("Relay CYB 自动规则保险丝检查失败: %v", err)
			}
			if err := h.reloadRelayCYBLearnedRules(ctx); err != nil && ctx.Err() == nil {
				log.Printf("Relay CYB 学习规则热加载失败: %v", err)
			}
		case <-pollTicker.C:
		}
	}
}

func (h *Handler) processOneRelayCYBLearningSample(ctx context.Context) error {
	settings, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return nil
	}
	model := strings.TrimSpace(settings.Model)
	if model == "" {
		return nil
	}
	groupID := proxy.ConfiguredCYBRelayGroupID()
	if groupID <= 0 || !h.relayCYBGroupSupportsModel(model, groupID) {
		return nil
	}
	sample, err := h.db.ClaimNextRelayCYBMissSample(ctx, model)
	if err != nil || sample == nil {
		return err
	}
	if strings.TrimSpace(sample.UserText) == "" {
		return h.db.MarkRelayCYBLearningRejected(
			ctx,
			sample.RequestID,
			sample.LearningAttempts,
			"漏放请求没有可用于学习的用户语料",
		)
	}

	prompt := cyblearn.BuildPrompt(sample.UserText)
	var candidate cyblearn.Candidate
	var candidateErr error
	for generation := 0; generation < relayCYBCandidateMaxAttempts; generation++ {
		body, _ := json.Marshal(map[string]any{
			"model":             model,
			"input":             prompt,
			"stream":            false,
			"store":             false,
			"max_output_tokens": 2000,
		})
		callCtx, cancel := context.WithTimeout(ctx, relayCYBLearningCallTimeout)
		status, response, callErr := h.imageProxy.ExecuteInternalRelayResponse(callCtx, body)
		cancel()
		if callErr != nil {
			return h.retryRelayCYBLearningSample(ctx, sample, callErr)
		}
		if status < 200 || status >= 300 {
			return h.retryRelayCYBLearningSample(
				ctx,
				sample,
				fmt.Errorf("Relay 分组模型调用 HTTP %d", status),
			)
		}
		candidate, candidateErr = cyblearn.ParseCandidate(extractResponseOutputText(response))
		if candidateErr == nil {
			candidateErr = cyblearn.ValidateCandidate(candidate, sample.UserText)
		}
		if candidateErr == nil {
			candidateErr = h.validateRelayCYBCandidateAgainstRecentTraffic(ctx, candidate)
			if errors.Is(candidateErr, errRelayCYBRecentTrafficUnavailable) {
				return h.retryRelayCYBLearningSample(ctx, sample, candidateErr)
			}
		}
		if candidateErr == nil {
			break
		}
		prompt = cyblearn.BuildPromptWithFeedback(
			sample.UserText,
			relayCYBCandidateFeedback(candidateErr),
		)
	}
	if candidateErr != nil {
		return h.db.MarkRelayCYBLearningRejected(
			ctx,
			sample.RequestID,
			sample.LearningAttempts,
			candidateErr.Error(),
		)
	}
	latestSettings, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		return h.retryRelayCYBLearningSample(ctx, sample, err)
	}
	if !latestSettings.Enabled ||
		!strings.EqualFold(strings.TrimSpace(latestSettings.Model), model) {
		return h.db.MarkRelayCYBLearningRetry(
			ctx,
			sample.RequestID,
			sample.LearningAttempts,
			"学习设置已变化，候选未启用并等待重新处理",
			time.Now(),
			false,
		)
	}
	ruleName := fmt.Sprintf("cyb_auto_%s", candidate.Name)
	if _, err := h.db.ApplyRelayCYBLearnedRule(
		ctx,
		sample.RequestID,
		sample.LearningAttempts,
		ruleName,
		candidate.Pattern,
		candidate.Rationale,
		model,
	); err != nil {
		if errors.Is(err, database.ErrRelayCYBLearnedRuleDisabled) {
			return h.db.MarkRelayCYBLearningRejected(
				ctx,
				sample.RequestID,
				sample.LearningAttempts,
				"候选表达式与已由保险丝停用的规则重复，不会重新启用",
			)
		}
		if errors.Is(err, database.ErrRelayCYBLearningClaimStale) {
			retryErr := h.db.MarkRelayCYBLearningRetry(
				ctx,
				sample.RequestID,
				sample.LearningAttempts,
				"学习任务已过期或设置变化，候选未启用",
				time.Now(),
				false,
			)
			if errors.Is(retryErr, database.ErrRelayCYBLearningClaimStale) {
				return nil
			}
			return retryErr
		}
		return h.retryRelayCYBLearningSample(ctx, sample, err)
	}
	return h.reloadRelayCYBLearnedRules(ctx)
}

func relayCYBCandidateFeedback(err error) string {
	message := ""
	if err != nil {
		message = err.Error()
	}
	switch {
	case strings.Contains(message, "模型未返回 JSON"),
		strings.Contains(message, "候选规则 JSON 无效"):
		return "上一候选不是严格有效的 JSON 对象；请只返回要求的四个字段。"
	case strings.Contains(message, "没有命中原漏放样本"):
		return "上一候选的 pattern 没有命中原用户语料；请保留至少两个共同风险特征并确保命中。"
	case strings.Contains(message, "泛化变体"):
		return "上一候选的 pattern 没有通过 positive_variants 校验；请先生成 2 到 4 条不同短变体，再确保 pattern 逐条命中。"
	case strings.Contains(message, "良性语料"),
		strings.Contains(message, "近期普通请求"):
		return "上一候选过宽并命中了普通语料；请增加共同风险特征并收窄每个匹配分支。"
	case strings.Contains(message, "至少需要两个同时成立"):
		return "上一候选每条匹配分支的必需文字风险特征不足两个；请增加第二个同时成立的特征。"
	case strings.Contains(message, "近似复制原样本"),
		strings.Contains(message, "复制原漏放样本"):
		return "上一候选过度复制原文；请保留共同风险特征并改写泛化变体。"
	case strings.Contains(message, "RE2"),
		strings.Contains(message, "规则名称"),
		strings.Contains(message, "规则长度"),
		strings.Contains(message, "匹配空文本"),
		strings.Contains(message, "内部样本分隔"):
		return "上一候选的名称或 RE2 结构不合法；请使用英文 snake_case 名称和非空匹配的 Go RE2 正则。"
	default:
		return "上一候选未通过本地机械校验；请重新生成并逐项自检所有要求。"
	}
}

func (h *Handler) validateRelayCYBCandidateAgainstRecentTraffic(
	ctx context.Context,
	candidate cyblearn.Candidate,
) error {
	rule, err := cyblearn.CompileRule(candidate.Name, candidate.Pattern)
	if err != nil {
		return err
	}
	texts, err := h.db.ListRecentOfficialDefaultAuditTexts(ctx, relayCYBRecentBenignLimit)
	if err != nil {
		return fmt.Errorf("%w: 读取近期良性回归语料失败: %v",
			errRelayCYBRecentTrafficUnavailable, err)
	}
	hits := 0
	for _, text := range texts {
		if rule.MatchString(text) {
			hits++
		}
	}
	if len(texts) >= relayCYBRuleGuardMinRequests &&
		hits >= 3 &&
		hits*100 > len(texts) {
		return fmt.Errorf("候选规则命中近期普通请求 %d/%d，疑似过宽", hits, len(texts))
	}
	return nil
}

func (h *Handler) enforceRelayCYBRuleGuard(ctx context.Context) error {
	settings, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil || !settings.Enabled {
		return err
	}
	window, err := h.db.RelayCYBRuleHitsSince(ctx, time.Now().Add(-relayCYBRuleGuardWindow))
	if err != nil {
		return err
	}
	if window.TotalRequests < relayCYBRuleGuardMinRequests {
		return nil
	}
	rules, err := h.db.ListEnabledRelayCYBRules(ctx)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		hits := window.HitsByRule[strings.ToLower(relayCYBRuleRuntimeName(rule))]
		if hits*100 <= window.TotalRequests*relayCYBRuleGuardMaxPercent {
			continue
		}
		reason := fmt.Sprintf(
			"10 分钟窗口命中 %d/%d（超过 %d%%），已由运行时保险丝自动停用",
			hits,
			window.TotalRequests,
			relayCYBRuleGuardMaxPercent,
		)
		if _, err := h.db.DisableRelayCYBRule(ctx, rule.ID, reason); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) retryRelayCYBLearningSample(
	ctx context.Context,
	sample *database.RelayCYBMissSample,
	cause error,
) error {
	if sample == nil {
		return cause
	}
	terminal := sample.LearningAttempts >= relayCYBLearningMaxAttempts
	delay := relayCYBLearningRetryDelay(sample.LearningAttempts)
	message := "学习模型暂时不可用"
	if cause != nil {
		message = cause.Error()
	}
	if err := h.db.MarkRelayCYBLearningRetry(
		ctx,
		sample.RequestID,
		sample.LearningAttempts,
		message,
		time.Now().Add(delay),
		terminal,
	); err != nil {
		return err
	}
	return nil
}

func relayCYBLearningRetryDelay(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return 30 * time.Second
	case attempt == 2:
		return 2 * time.Minute
	case attempt == 3:
		return 10 * time.Minute
	default:
		return time.Hour
	}
}

func (h *Handler) reloadRelayCYBLearnedRules(ctx context.Context) error {
	settings, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		cybroute.PublishLearnedRules(nil)
		return nil
	}
	rules, err := h.db.ListEnabledRelayCYBRules(ctx)
	if err != nil {
		return err
	}
	patterns := make([]cyblearn.Rule, 0, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.Pattern) == "" {
			continue
		}
		compiled, err := cyblearn.CompileRule(relayCYBRuleRuntimeName(rule), rule.Pattern)
		if err != nil {
			return fmt.Errorf("加载自动规则 %d 失败: %w", rule.ID, err)
		}
		patterns = append(patterns, compiled)
	}
	cybroute.PublishLearnedRules(patterns)
	return nil
}

func relayCYBRuleRuntimeName(rule database.RelayCYBRule) string {
	return fmt.Sprintf("auto_rule_%d", rule.ID)
}

func (h *Handler) GetRelayCYBLearningConfig(c *gin.Context) {
	if h == nil || h.db == nil || h.store == nil {
		writeError(c, http.StatusServiceUnavailable, "CYB 学习服务不可用")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	settings, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	stats, err := h.db.GetRelayCYBLearningStats(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	notifications, err := h.db.ListRelayCYBLearningNotifications(ctx, time.Now().Add(-24*time.Hour), 50)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	notifications = aggregateRelayCYBLearningNotifications(notifications, 10)
	groupID := proxy.ConfiguredCYBRelayGroupID()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, relayCYBLearningConfigResponse{
		Enabled:                  settings.Enabled,
		Model:                    settings.Model,
		UpdatedAt:                settings.UpdatedAt,
		AvailableModels:          h.relayCYBGroupModels(ctx, groupID),
		RelayGroupID:             groupID,
		RelayGroupName:           h.relayCYBGroupName(groupID),
		Stats:                    stats,
		SampleWriter:             h.db.RelayCYBSampleWriterStats(),
		Notifications:            notifications,
		InternalRequestsExcluded: true,
	})
}

func aggregateRelayCYBLearningNotifications(
	items []database.RelayCYBLearningNotification,
	limit int,
) []database.RelayCYBLearningNotification {
	if limit <= 0 {
		return []database.RelayCYBLearningNotification{}
	}
	out := make([]database.RelayCYBLearningNotification, 0, min(limit, len(items)))
	grouped := make(map[string]int)
	for _, item := range items {
		key := ""
		switch item.EventType {
		case "failed", "rejected":
			key = item.EventType
		}
		if key != "" {
			if index, exists := grouped[key]; exists {
				out[index].Count += max(1, item.Count)
				continue
			}
			grouped[key] = len(out)
		}
		if item.Count <= 0 {
			item.Count = 1
		}
		out = append(out, item)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (h *Handler) UpdateRelayCYBLearningConfig(c *gin.Context) {
	if h == nil || h.db == nil || h.store == nil {
		writeError(c, http.StatusServiceUnavailable, "CYB 学习服务不可用")
		return
	}
	var request updateRelayCYBLearningConfigRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "学习配置格式无效")
		return
	}
	request.Model = strings.TrimSpace(request.Model)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	current, err := h.db.GetRelayCYBLearningSettings(ctx)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if request.Model == "" {
		request.Model = current.Model
	}
	groupID := proxy.ConfiguredCYBRelayGroupID()
	if request.Enabled && groupID <= 0 {
		writeError(c, http.StatusConflict, "CYB Relay 分组尚未配置")
		return
	}
	if request.Enabled && !h.relayCYBGroupSupportsModel(request.Model, groupID) {
		writeError(c, http.StatusBadRequest, "所选模型不在当前 Relay 分组的可调度模型中")
		return
	}
	if !request.Enabled && !h.relayCYBGroupSupportsModel(request.Model, groupID) {
		request.Model = current.Model
	}
	if _, err := h.db.UpdateRelayCYBLearningSettings(ctx, request.Enabled, request.Model); err != nil {
		writeInternalError(c, err)
		return
	}
	if err := h.reloadRelayCYBLearnedRules(ctx); err != nil {
		writeInternalError(c, err)
		return
	}
	h.GetRelayCYBLearningConfig(c)
}

func (h *Handler) ListRelayCYBLearnedRules(c *gin.Context) {
	if h == nil || h.db == nil {
		writeError(c, http.StatusServiceUnavailable, "CYB 学习服务不可用")
		return
	}
	page := positiveQueryInt(c, "page", 1)
	pageSize := positiveQueryInt(c, "page_size", 20)
	if pageSize > 100 {
		writeError(c, http.StatusBadRequest, "page_size 不能超过 100")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	result, err := h.db.ListRelayCYBRulesPage(ctx, page, pageSize)
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

func (h *Handler) relayCYBGroupModels(ctx context.Context, groupID int64) []string {
	if h == nil || h.store == nil || groupID <= 0 {
		return []string{}
	}
	groupSet := map[int64]struct{}{groupID: {}}
	models := make(map[string]string)
	wildcardOAuth := make([]*auth.Account, 0)
	for _, account := range h.store.Accounts() {
		if account == nil || !account.InAnyGroup(groupSet) || !account.AllowsAPIKey(0) {
			continue
		}
		if account.IsRelayStyle() {
			for _, model := range account.OpenAIResponsesModels() {
				if value := strings.TrimSpace(model); value != "" {
					models[strings.ToLower(value)] = value
				}
			}
			continue
		}
		configured := account.CodexModels()
		if len(configured) == 0 {
			wildcardOAuth = append(wildcardOAuth, account)
			continue
		}
		for _, model := range configured {
			if value := strings.TrimSpace(model); value != "" {
				models[strings.ToLower(value)] = value
			}
		}
	}
	if len(wildcardOAuth) > 0 {
		for _, model := range proxy.SupportedModelIDs(ctx, h.db) {
			for _, account := range wildcardOAuth {
				if account.SupportsCodexModel(model) {
					models[strings.ToLower(model)] = model
					break
				}
			}
		}
	}
	out := make([]string, 0, len(models))
	for _, model := range models {
		out = append(out, model)
	}
	sort.Strings(out)
	return out
}

func (h *Handler) relayCYBGroupSupportsModel(model string, groupID int64) bool {
	model = strings.TrimSpace(model)
	if model == "" || h == nil || h.store == nil || groupID <= 0 {
		return false
	}
	groupSet := map[int64]struct{}{groupID: {}}
	for _, account := range h.store.Accounts() {
		if account == nil || !account.InAnyGroup(groupSet) || !account.AllowsAPIKey(0) {
			continue
		}
		if account.IsRelayStyle() {
			if account.SupportsOpenAIResponsesModel(model) {
				return true
			}
			continue
		}
		if account.SupportsCodexModel(model) {
			return true
		}
	}
	return false
}

func (h *Handler) relayCYBGroupName(groupID int64) string {
	if h == nil || h.store == nil || groupID <= 0 {
		return ""
	}
	names := h.store.ResolveGroupNames([]int64{groupID})
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
