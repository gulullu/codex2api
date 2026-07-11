package promptfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	DefaultReviewBaseURL        = "https://api.openai.com"
	DefaultReviewModel          = "omni-moderation-latest"
	DefaultReviewTimeoutSeconds = 10
	HighRiskReviewFailureScore  = 200
)

type ReviewClient struct {
	HTTPClient *http.Client
}

var DefaultReviewClient = ReviewClient{}

type reviewRequest struct {
	Model string `json:"model,omitempty"`
	Input string `json:"input"`
}

type reviewResponse struct {
	Model   string         `json:"model"`
	Results []reviewResult `json:"results"`
}

type reviewResult struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

// ReviewOutcome exposes the full moderation result needed by routing policy.
// Flagged is the provider's raw aggregate flag. Categories are OR-merged across
// results and CategoryScores retain the maximum score observed per category.
type ReviewOutcome struct {
	Model          string             `json:"model"`
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`

	// The image policy is evaluated per raw result before aggregation so a
	// non-standard flagged result with empty category maps cannot be hidden by a
	// later result that does contain category metadata.
	imagePolicyEvaluated bool
	imagePolicyFlagged   bool
}

func newReviewOutcome(model string) ReviewOutcome {
	return ReviewOutcome{
		Model:          strings.TrimSpace(model),
		Categories:     make(map[string]bool),
		CategoryScores: make(map[string]float64),
	}
}

// FlaggedForEndpoint applies the existing endpoint-specific moderation policy
// to a detailed outcome. Text endpoints use the provider's aggregate flagged
// value; image endpoints retain the narrower image policy below.
func (o ReviewOutcome) FlaggedForEndpoint(endpoint string) bool {
	if !isImageModerationTarget(endpoint) {
		return o.Flagged
	}
	if o.imagePolicyEvaluated {
		return o.imagePolicyFlagged
	}
	return reviewResultBlocks(reviewResult{
		Flagged:        o.Flagged,
		Categories:     o.Categories,
		CategoryScores: o.CategoryScores,
	})
}

func NormalizeReviewConfig(cfg ReviewConfig) ReviewConfig {
	defaults := DefaultReviewConfig()
	// 规范化多 key：按行/逗号/分号/空白切分，去空去重，再以换行拼回，
	// 便于存储与轮询（issue #289）。单 key 配置行为不变。
	cfg.APIKey = strings.Join(parseReviewAPIKeys(cfg.APIKey), "\n")
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaults.BaseURL
	}
	cfg.Model = strings.TrimSpace(cfg.Model)
	if cfg.Model == "" {
		cfg.Model = defaults.Model
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if cfg.TimeoutSeconds > 60 {
		cfg.TimeoutSeconds = 60
	}
	return cfg
}

// APIKeyList 解析配置的审查 API key 列表。可用换行/逗号/分号/空白分隔多个 key，
// 以便把 Moderations 的 TPM 额度分摊到多个 OpenAI 账号上（issue #289）。
// 去除空白项与重复项并保持顺序。
func (cfg ReviewConfig) APIKeyList() []string {
	return parseReviewAPIKeys(cfg.APIKey)
}

func parseReviewAPIKeys(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})
	seen := make(map[string]struct{}, len(fields))
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		key := strings.TrimSpace(f)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func (cfg ReviewConfig) Ready() bool {
	cfg = NormalizeReviewConfig(cfg)
	return cfg.Enabled && len(cfg.APIKeyList()) > 0 && cfg.BaseURL != ""
}

func ValidateReviewConfig(cfg ReviewConfig) error {
	cfg = NormalizeReviewConfig(cfg)
	if cfg.Enabled && len(cfg.APIKeyList()) == 0 {
		return fmt.Errorf("at least one review api key is required when prompt filter review is enabled")
	}
	if cfg.BaseURL == "" {
		return nil
	}
	_, err := reviewEndpoint(cfg.BaseURL)
	return err
}

// reviewKeyCursor 为多 key 轮询提供全局起点游标，让并发请求均匀分摊 TPM 额度。
var reviewKeyCursor atomic.Uint64

func (c ReviewClient) ReviewText(ctx context.Context, text string, cfg ReviewConfig, requestEndpoint string) (bool, string, error) {
	outcome, err := c.ReviewTextDetailed(ctx, text, cfg)
	return outcome.FlaggedForEndpoint(requestEndpoint), outcome.Model, err
}

// ReviewTextDetailed performs the same moderation request and key failover as
// ReviewText while preserving category-level evidence for downstream routing.
// ReviewText remains the compatibility wrapper for existing callers.
func (c ReviewClient) ReviewTextDetailed(ctx context.Context, text string, cfg ReviewConfig) (ReviewOutcome, error) {
	cfg = NormalizeReviewConfig(cfg)
	empty := newReviewOutcome(cfg.Model)
	if !cfg.Ready() {
		return empty, nil
	}
	if strings.TrimSpace(text) == "" {
		return empty, nil
	}
	endpoint, err := reviewEndpoint(cfg.BaseURL)
	if err != nil {
		return empty, err
	}
	payload, err := json.Marshal(reviewRequest{
		Model: cfg.Model,
		Input: text,
	})
	if err != nil {
		return empty, err
	}

	keys := cfg.APIKeyList()
	// 轮询起点 + 遇到限流/失效 key（429/401/403/5xx/网络错误）自动切换下一个 key。
	start := reviewKeyCursor.Add(1) - 1
	var lastErr error
	for i := 0; i < len(keys); i++ {
		key := keys[(start+uint64(i))%uint64(len(keys))]
		outcome, retriable, reqErr := c.reviewOnceDetailed(ctx, endpoint, key, payload, cfg)
		if reqErr == nil {
			return outcome, nil
		}
		lastErr = reqErr
		if !retriable {
			return empty, reqErr
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("review request failed")
	}
	return empty, lastErr
}

// reviewOnceDetailed 用单个 key 发起一次 Moderations 请求。retriable 表示该错误是否
// 值得切换到下一个 key 重试（限流/失效 key/服务端错误/网络错误）。
func (c ReviewClient) reviewOnceDetailed(ctx context.Context, endpoint, apiKey string, payload []byte, cfg ReviewConfig) (ReviewOutcome, bool, error) {
	empty := newReviewOutcome(cfg.Model)
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return empty, false, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// 网络错误：换下一个 key 再试。
		return empty, true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return empty, reviewStatusRetriable(resp.StatusCode), fmt.Errorf("review request failed with status %d", resp.StatusCode)
	}

	var decoded reviewResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return empty, false, err
	}
	if len(decoded.Results) == 0 {
		return empty, false, fmt.Errorf("review response missing results")
	}
	outcome := newReviewOutcome(decoded.Model)
	if outcome.Model == "" {
		outcome.Model = cfg.Model
	}
	outcome.imagePolicyEvaluated = true
	for _, result := range decoded.Results {
		outcome.Flagged = outcome.Flagged || result.Flagged
		outcome.imagePolicyFlagged = outcome.imagePolicyFlagged || reviewResultBlocks(result)
		for category, flagged := range result.Categories {
			if flagged {
				outcome.Categories[category] = true
			} else if _, exists := outcome.Categories[category]; !exists {
				outcome.Categories[category] = false
			}
		}
		for category, score := range result.CategoryScores {
			if current, exists := outcome.CategoryScores[category]; !exists || score > current {
				outcome.CategoryScores[category] = score
			}
		}
	}
	return outcome, false, nil
}

// reviewStatusRetriable 判断某个 HTTP 状态码是否应切换到下一个 key 重试：
// 429（TPM/RPM 限流，本 issue 主因）、401/403（key 失效）、5xx（服务端错误）。
func reviewStatusRetriable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return status >= 500
}

// isImageModerationTarget 判断请求端点是否为生图端点（/v1/images/*）。
func isImageModerationTarget(endpoint string) bool {
	return strings.Contains(strings.ToLower(endpoint), "image")
}

// reviewResultBlocks 仅用于生图端点：拦截性内容、高风险 illicit 与仇恨/威胁类别；
// violence/self-harm 不由本层硬拦，避免误伤历史、游戏、武侠等生图场景。
// 文本端点仍直接使用 provider 的全类别 flagged 判定。
func reviewResultBlocks(r reviewResult) bool {
	// 非标准审核响应（既无类别也无分数）时退回旧行为，避免静默关审核。
	if len(r.Categories) == 0 && len(r.CategoryScores) == 0 {
		return r.Flagged
	}
	// 未成年性内容：类别命中或低分即拦（零容忍）。
	if r.Categories["sexual/minors"] || r.CategoryScores["sexual/minors"] >= 0.15 {
		return true
	}
	// 成人色情：按 OpenAI 自身校准的类别判定拦截。
	if r.Categories["sexual"] {
		return true
	}
	// 作恶指导：炸弹/毒品/武器/暴恐（illicit / illicit-violent）。压测确认化学课(火药三要素)、
	// 抗战暴行、坑儒、武侠喷血等良性中文内容此两类均为 0.00，炸弹/毒品/暴恐为 0.94+，分离干净。
	if r.Categories["illicit"] || r.CategoryScores["illicit"] >= 0.5 {
		return true
	}
	if r.Categories["illicit/violent"] || r.CategoryScores["illicit/violent"] >= 0.5 {
		return true
	}
	// 仇恨/威胁：良性中文样本此类均为 0，按 OpenAI 校准类别拦截。
	if r.Categories["hate"] || r.Categories["hate/threatening"] || r.Categories["harassment/threatening"] {
		return true
	}
	// 不拦 violence / violence-graphic / self-harm：武侠喷血(0.85)、历史屠杀、游戏Boss战、历史自刎都踩这些类，拦了必误伤本服务核心内容，交由上游生图模型把关。
	return false
}

func ApplyReviewResult(verdict Verdict, flagged bool, model string, reviewErr error, cfg ReviewConfig) Verdict {
	cfg = NormalizeReviewConfig(cfg)
	verdict.Reviewed = true
	verdict.ReviewFlagged = flagged
	verdict.ReviewModel = strings.TrimSpace(model)
	if verdict.ReviewModel == "" {
		verdict.ReviewModel = cfg.Model
	}
	if reviewErr != nil {
		verdict.ReviewError = reviewErr.Error()
		if cfg.FailClosed {
			verdict.Action = ActionBlock
			verdict.Reason = "prompt review failed: " + reviewErr.Error()
		} else if reviewFailureShouldFailClosed(verdict) {
			verdict.Action = ActionBlock
			verdict.Reason = "high-risk prompt review failed: " + reviewErr.Error()
		} else {
			verdict.Action = ActionAllow
			verdict.Reason = "prompt review failed; allowed by policy: " + reviewErr.Error()
		}
		return verdict
	}
	if !flagged {
		verdict.Action = ActionAllow
		verdict.Reason = "prompt review cleared local filter match"
		return verdict
	}
	verdict.Reason = "prompt review confirmed local filter match"
	return verdict
}

func reviewFailureShouldFailClosed(verdict Verdict) bool {
	return IsHighRiskReviewVerdict(verdict)
}

func IsHighRiskReviewVerdict(verdict Verdict) bool {
	if verdict.Score >= HighRiskReviewFailureScore || verdict.RawScore >= HighRiskReviewFailureScore || verdict.StrictHit {
		return true
	}
	for _, match := range verdict.Matched {
		if match.Strict {
			return true
		}
	}
	return false
}

func reviewEndpoint(baseURL string) (string, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultReviewBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("review base_url must start with http:// or https://")
	}
	if strings.HasSuffix(parsed.Path, "/moderations") {
		return parsed.String(), nil
	}
	path := strings.TrimRight(parsed.Path, "/")
	if strings.HasSuffix(path, "/v1") {
		parsed.Path = path + "/moderations"
	} else {
		parsed.Path = path + "/v1/moderations"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
