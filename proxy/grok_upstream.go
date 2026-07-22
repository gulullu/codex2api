package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Grok CLI 请求头契约的默认值（与 Grok CLI 0.2.106 实抓流量对齐），可用环境变量覆盖，
// 上游升级 CLI 版本导致指纹校验失败时无需改代码。
// 0.2.106 契约：UA 为 "grok-pager/<v> grok-shell/<v> (<os>; <arch>)"，
// identifier=grok-pager、mode=interactive，不再携带 client-surface / client-name 头。
var (
	grokClientVersion    = grokEnv("GROK_CLIENT_VERSION", "0.2.106")
	grokClientIdentifier = grokEnv("GROK_CLIENT_IDENTIFIER", "grok-pager")
	grokClientMode       = grokEnv("GROK_CLIENT_MODE", "interactive")
	grokTokenAuth        = grokEnv("GROK_TOKEN_AUTH", "xai-grok-cli")
	// x-compaction-at：CLI 声明的客户端侧压缩阈值（上游 context window 500k，CLI 报 400k）。
	grokCompactionAt = grokEnv("GROK_COMPACTION_AT", "400000")
)

func grokEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// grokUserAgentOS 返回 UA 里的平台名。官方 CLI 用 "macos" 而非 Go 的 "darwin"。
func grokUserAgentOS() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

func grokUserAgent() string {
	if grokClientIdentifier == "grok-shell" {
		return fmt.Sprintf("grok-shell/%s (%s; %s)", grokClientVersion, grokUserAgentOS(), runtime.GOARCH)
	}
	return fmt.Sprintf("%s/%s grok-shell/%s (%s; %s)", grokClientIdentifier, grokClientVersion, grokClientVersion, grokUserAgentOS(), runtime.GOARCH)
}

// grokAgentID 为每个账号生成稳定的 agent 标识（32 位 hex，与 Grok CLI 的
// global agent id 形态一致）。
func grokAgentID(account *auth.Account) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "codex2api:grok-agent:%d", account.ID()))
	return hex.EncodeToString(sum[:16])
}

func grokRandomHexID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

// applyGrokRequestHeaders 按 Grok CLI 的推理头契约装配上游请求头。
// API Key 凭据不发 x-xai-token-auth / x-authenticateresponse（与 Grok CLI 一致）。
func applyGrokRequestHeaders(req *http.Request, account *auth.Account, bearer string, downstreamHeaders http.Header) {
	if req == nil {
		return
	}
	isAPIKey := account.GrokAuthKind() == auth.GrokAuthKindAPIKey

	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", grokUserAgent())
	req.Header.Set("x-grok-client-version", grokClientVersion)
	req.Header.Set("x-grok-client-identifier", grokClientIdentifier)
	req.Header.Set("x-grok-client-mode", grokClientMode)
	if grokCompactionAt != "" {
		req.Header.Set("x-compaction-at", grokCompactionAt)
	}
	if !isAPIKey {
		req.Header.Set("x-xai-token-auth", grokTokenAuth)
		req.Header.Set("x-authenticateresponse", "authenticate-response")
	}

	req.Header.Set("x-grok-agent-id", grokAgentID(account))
	sessionID := ""
	if downstreamHeaders != nil {
		sessionID = strings.TrimSpace(downstreamHeaders.Get("Session_id"))
	}
	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	req.Header.Set("x-grok-session-id", sessionID)
	req.Header.Set("x-grok-conv-id", sessionID)
	req.Header.Set("x-grok-req-id", grokRandomHexID())

	if userID := account.GrokUserID(); userID != "" && !isAPIKey {
		req.Header.Set("x-userid", userID)
		req.Header.Set("x-grok-user-id", userID)
	}
	applyAccountCustomHeaders(req, account)
	RecordUpstreamUserAgent(req.Context(), req.Header.Get("User-Agent"))
}

// grokEndpointForBody 根据请求体推断上游 path（目前统一走 /responses，
// 下游三协议在进入执行器前都已被翻译成 Responses 体）。
func grokResponsesEndpoint(baseURL string) string {
	return auth.OpenAIResponsesEndpoint(baseURL, "/v1/responses")
}

// ExecuteGrokRequest 向 Grok 上游发送 Responses 请求。
// 复用 relay（openai_responses）的整条下游管道：进入这里的 requestBody 已是
// Responses 协议体，直接投递到 Grok chat-proxy / xAI API 的 /responses 端点。
func ExecuteGrokRequest(ctx context.Context, account *auth.Account, requestBody []byte, proxyOverride string, headers http.Header) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resetUpstreamUserAgentAudit(ctx)
	resetWsAcquireAudit(ctx)

	baseURL, bearer := account.GrokCredentials()
	if baseURL == "" || bearer == "" {
		return nil, ErrNoAvailableAccount()
	}
	account.Mu().RLock()
	proxyURL := account.ProxyURL
	account.Mu().RUnlock()
	if proxyOverride != "" {
		proxyURL = proxyOverride
	}

	// Grok 上游不认识 Codex 专属字段，投递前剥离。
	requestBody = sanitizeGrokRequestBody(requestBody)

	endpoint := grokResponsesEndpoint(baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, ErrInternalError("创建请求失败", err)
	}
	applyGrokRequestHeaders(req, account, bearer, headers)
	if model := gjson.GetBytes(requestBody, "model").String(); model != "" {
		req.Header.Set("x-grok-model-override", model)
	}

	resp, err := getPooledClient(account, proxyURL).Do(req)
	if err != nil {
		if shouldRecyclePooledClient(err) {
			recyclePooledClient(account, proxyURL)
		}
		return nil, ErrUpstream(0, "请求 Grok 上游失败", err)
	}
	recordGrokRateLimitHeaders(account, resp.Header)
	return resp, nil
}

// recordGrokRateLimitHeaders 采集上游逐请求返回的配额余量头（x-ratelimit-*），
// 写入账号运行时快照供账号列表展示。任一头缺失时不更新（避免半截观测覆盖完整值）。
func recordGrokRateLimitHeaders(account *auth.Account, header http.Header) {
	if account == nil || header == nil {
		return
	}
	parse := func(key string) (int64, bool) {
		raw := strings.TrimSpace(header.Get(key))
		if raw == "" {
			return 0, false
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			return 0, false
		}
		return v, true
	}
	limitTokens, ok1 := parse("x-ratelimit-limit-tokens")
	remainTokens, ok2 := parse("x-ratelimit-remaining-tokens")
	limitReqs, ok3 := parse("x-ratelimit-limit-requests")
	remainReqs, ok4 := parse("x-ratelimit-remaining-requests")
	if !ok1 && !ok2 && !ok3 && !ok4 {
		return
	}
	account.SetGrokRateLimitSnapshot(auth.GrokRateLimitSnapshot{
		LimitTokens:       limitTokens,
		RemainingTokens:   remainTokens,
		LimitRequests:     limitReqs,
		RemainingRequests: remainReqs,
		UpdatedAt:         time.Now(),
	})
}

// sanitizeGrokRequestBody 剥离 Codex 管道注入的、Grok 上游不接受的字段。
func sanitizeGrokRequestBody(body []byte) []byte {
	if !gjson.ValidBytes(body) {
		return body
	}
	for _, path := range []string{"client_metadata", "prompt_cache_key", "service_tier", "safety_identifier"} {
		if gjson.GetBytes(body, path).Exists() {
			if updated, err := sjson.DeleteBytes(body, path); err == nil {
				body = updated
			}
		}
	}
	return body
}

// ExecuteRelayStyleRequest 按账号类型分派 relay 风格执行器：grok 账号走 Grok
// 上游，其余走 OpenAI Responses 中转。两者共享同一条下游 Responses 管道。
func ExecuteRelayStyleRequest(ctx context.Context, account *auth.Account, requestBody []byte, proxyOverride string, headers http.Header) (*http.Response, error) {
	if account.IsGrokAPI() {
		return ExecuteGrokRequest(ctx, account, requestBody, proxyOverride, headers)
	}
	return ExecuteOpenAIResponsesRequest(ctx, account, requestBody, proxyOverride, headers)
}

// relayUpstreamEndpointForAccount 返回 relay 风格账号的上游 /responses 端点（用于日志/记账）。
func relayUpstreamEndpointForAccount(account *auth.Account) string {
	if account.IsGrokAPI() {
		baseURL, _ := account.GrokCredentials()
		return grokResponsesEndpoint(baseURL)
	}
	baseURL, _ := account.OpenAIResponsesCredentials()
	return auth.OpenAIResponsesEndpoint(baseURL, "/v1/responses")
}

// ==================== 模型目录 ====================

// FetchGrokModelIDs 用凭据探测 Grok 上游模型目录（GET /models），返回可用模型 ID
// 列表（过滤 hidden；API Key 凭据只保留 supported_in_api 的模型）。
// 条目兼容字符串与对象两种形态、data/models 两种容器（与 Grok CLI 目录响应一致）。
func FetchGrokModelIDs(ctx context.Context, account *auth.Account) ([]string, error) {
	baseURL, bearer := account.GrokCredentials()
	if baseURL == "" || bearer == "" {
		return nil, fmt.Errorf("grok 账号缺少可用凭据")
	}
	isAPIKey := account.GrokAuthKind() == auth.GrokAuthKindAPIKey

	endpoint := auth.OpenAIResponsesEndpoint(baseURL, "/v1/models")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	applyGrokRequestHeaders(req, account, bearer, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := getPooledClient(account, account.GetProxyURL()).Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Grok 模型列表失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(gjson.GetBytes(body, "error.message").String())
		if message == "" {
			message = truncateForLog(body, 200)
		}
		return nil, fmt.Errorf("Grok 模型列表返回 %d: %s", resp.StatusCode, message)
	}

	seen := make(map[string]struct{})
	var models []string
	collect := func(items gjson.Result) {
		if !items.IsArray() {
			return
		}
		items.ForEach(func(_, item gjson.Result) bool {
			id := ""
			if item.Type == gjson.String {
				id = strings.TrimSpace(item.String())
			} else if item.IsObject() {
				if item.Get("hidden").Bool() {
					return true
				}
				if isAPIKey {
					if supported := item.Get("supported_in_api"); supported.Exists() && !supported.Bool() {
						return true
					}
					if supported := item.Get("supportedInApi"); supported.Exists() && !supported.Bool() {
						return true
					}
				}
				id = strings.TrimSpace(item.Get("id").String())
				if id == "" {
					id = strings.TrimSpace(item.Get("model").String())
				}
			}
			if id != "" {
				if _, exists := seen[strings.ToLower(id)]; !exists {
					seen[strings.ToLower(id)] = struct{}{}
					models = append(models, id)
				}
			}
			return true
		})
	}
	parsed := gjson.ParseBytes(body)
	collect(parsed.Get("data"))
	collect(parsed.Get("models"))
	if len(models) == 0 {
		return nil, fmt.Errorf("Grok 上游返回了空模型目录")
	}
	return auth.NormalizeAccountModels(models), nil
}

// ==================== 错误分类与冷却映射 ====================

// IsGrokFreeQuotaExhaustedError 识别免费额度耗尽（模型级，Grok 上游 24h 重置）。
func IsGrokFreeQuotaExhaustedError(body []byte) bool {
	return bytes.Contains(bytes.ToLower(body), []byte("used all the included free usage"))
}

// IsGrokSpendingLimitError 识别账号级超支限制。
func IsGrokSpendingLimitError(body []byte) bool {
	lower := bytes.ToLower(body)
	return bytes.Contains(lower, []byte("spending-limit")) || bytes.Contains(lower, []byte("spending limit"))
}

// IsGrokPermanentDenialError 识别权限性永久拒绝（凭据对该端点无访问权）。
func IsGrokPermanentDenialError(body []byte) bool {
	return bytes.Contains(bytes.ToLower(body), []byte("access to the chat endpoint is denied"))
}

// applyGrokCooldownForModel 是 Grok 账号的上游错误 → 调度状态映射
// （对应 applyCooldownForModel 的 Codex 语义）：
//   - 免费额度耗尽 → 模型冷却 24h；
//   - 超支限制 → 账号冷却 24h；
//   - 429 → Retry-After 或 1 分钟，上限 15 分钟；
//   - 401 → 短冷却 + 异步强刷 AT（RT 失效时刷新路径会自行标 error）；
//   - 403 权限拒绝 → 账号标错误。
func (h *Handler) applyGrokCooldownForModel(account *auth.Account, statusCode int, body []byte, resp *http.Response, model string) codex429Decision {
	if h == nil || h.store == nil || account == nil {
		return codex429Decision{}
	}
	if IsGrokFreeQuotaExhaustedError(body) {
		cooldownModel := model
		if cooldownModel == "" {
			cooldownModel = strings.TrimSpace(gjson.GetBytes(body, "model").String())
		}
		if cooldownModel != "" {
			cooldown := h.store.MarkModelCooldown(account, cooldownModel, 24*time.Hour, "usage_limited")
			log.Printf("Grok 账号 %d 模型 %s 免费额度耗尽，冷却到 %s", account.ID(), cooldownModel, cooldown.ResetAt.Format(time.RFC3339))
			return codex429Decision{Scope: rateLimitScopeModel, Reason: "usage_limited", Model: cooldownModel, ResetAt: cooldown.ResetAt, Cooldown: time.Until(cooldown.ResetAt)}
		}
		h.store.MarkCooldown(account, 24*time.Hour, "usage_limited")
		log.Printf("Grok 账号 %d 免费额度耗尽，账号冷却 24h", account.ID())
		return codex429Decision{Reason: "usage_limited", Cooldown: 24 * time.Hour}
	}
	if IsGrokSpendingLimitError(body) {
		h.store.MarkCooldown(account, 24*time.Hour, "usage_limited")
		log.Printf("Grok 账号 %d 触发超支限制，账号冷却 24h", account.ID())
		return codex429Decision{Reason: "usage_limited", Cooldown: 24 * time.Hour}
	}

	switch statusCode {
	case http.StatusTooManyRequests:
		cooldown := time.Minute
		if resp != nil {
			if retryAfter := parseRetryAfterHeader(resp.Header.Get("Retry-After")); retryAfter > 0 {
				cooldown = retryAfter
			}
		}
		if cooldown > 15*time.Minute {
			cooldown = 15 * time.Minute
		}
		h.store.MarkCooldown(account, cooldown, "rate_limited")
		log.Printf("Grok 账号 %d 被限速，冷却 %s", account.ID(), cooldown)
		return codex429Decision{Reason: "rate_limited", Cooldown: cooldown}
	case http.StatusUnauthorized, http.StatusForbidden:
		if IsGrokPermanentDenialError(body) {
			log.Printf("Grok 账号 %d 权限被永久拒绝，标记为错误", account.ID())
			h.store.MarkError(account, upstreamAccountErrorMessage(statusCode, body))
			return codex429Decision{}
		}
		// OAuth AT 可能过期/被吊销：短冷却挡住并发，异步强刷；RT 失效由刷新路径转 error。
		h.store.MarkCooldown(account, time.Minute, "unauthorized")
		if account.GrokAuthKind() == auth.GrokAuthKindOAuth {
			go func(dbID int64) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := h.store.RefreshSingle(ctx, dbID); err != nil {
					log.Printf("Grok 账号 %d 401 后强刷失败: %v", dbID, err)
				}
			}(account.ID())
		}
		return codex429Decision{Reason: "unauthorized", Cooldown: time.Minute}
	}
	return codex429Decision{}
}

// parseRetryAfterHeader 解析 Retry-After 头（秒数或 HTTP 日期）。
func parseRetryAfterHeader(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
		return seconds
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}
