package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// ==================== Anthropic 错误格式 ====================

// sendAnthropicError 发送 Anthropic 格式的错误响应
func sendAnthropicError(c *gin.Context, statusCode int, errType, message string) {
	c.JSON(statusCode, gin.H{
		"type": "error",
		"error": gin.H{
			"type":    errType,
			"message": message,
		},
	})
}

// sendAnthropicStreamError 在流式模式中发送错误事件
func sendAnthropicStreamError(c *gin.Context, errType, message string) {
	fmt.Fprint(c.Writer, anthropicStreamErrorSSE(errType, message))
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func anthropicStreamErrorSSE(errType, message string) string {
	payload, err := json.Marshal(gin.H{
		"type": "error",
		"error": gin.H{
			"type":    errType,
			"message": message,
		},
	})
	if err != nil {
		payload = []byte(`{"type":"error","error":{"type":"api_error","message":"failed to encode stream error"}}`)
	}
	return fmt.Sprintf("event: error\ndata: %s\n\n", payload)
}

// mapHTTPStatusToAnthropicError 将 HTTP 状态码映射为 Anthropic 错误类型
func mapHTTPStatusToAnthropicError(statusCode int) string {
	switch {
	case statusCode == 400:
		return "invalid_request_error"
	case statusCode == 401:
		return "authentication_error"
	case statusCode == 403:
		return "permission_error"
	case statusCode == 404:
		return "not_found_error"
	case statusCode == 429:
		return "rate_limit_error"
	case statusCode == 529:
		return "overloaded_error"
	case statusCode >= 500:
		return "api_error"
	default:
		return "api_error"
	}
}

func sendFinalAnthropicUpstreamError(c *gin.Context, statusCode int, body []byte) {
	// An upstream account 401 is not a downstream client credential failure.
	if statusCode == http.StatusUnauthorized && !isMissingScopeUnauthorized(body) {
		sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", "账号池暂无可用账号（上游账号鉴权失效），请稍后重试")
		return
	}
	// OAuth 403 is account-scoped after all safe retries are exhausted. Relay
	// front-door 403 can instead be a WAF/policy response and must stay visible.
	if statusCode == http.StatusForbidden && !strings.EqualFold(c.GetString(contextUpstreamAccountType), auth.UpstreamOpenAIResponses) {
		sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", "账号池暂无可用账号（上游账号被拒绝访问：额度/套餐或工作区受限），请稍后重试")
		return
	}
	errType := mapHTTPStatusToAnthropicError(statusCode)
	message := gjson.GetBytes(body, "error.message").String()
	if message == "" {
		message = fmt.Sprintf("Upstream returned status %d", statusCode)
	}
	sendAnthropicError(c, statusCode, errType, message)
}

func anthropicFinalResponseStatusForContext(c *gin.Context, statusCode int, body []byte) int {
	if statusCode == http.StatusForbidden && c != nil &&
		!strings.EqualFold(c.GetString(contextUpstreamAccountType), auth.UpstreamOpenAIResponses) {
		return http.StatusServiceUnavailable
	}
	return anthropicFinalResponseStatus(statusCode, body)
}

func anthropicResponseFailedCanonicalStatus(c *gin.Context, outcome streamOutcome, policy *responseFailedRequestPolicy, payload []byte) int {
	if policy == nil {
		return canonicalStreamStatus(outcome)
	}
	if policy != nil && outcome.logStatusCode == http.StatusForbidden {
		return policy.canonicalStatus
	}
	return anthropicFinalResponseStatusForContext(c, canonicalStreamStatus(outcome), responseFailedErrorBody(payload))
}

// ==================== /v1/messages Handler ====================

// Messages 处理 /v1/messages 请求（Anthropic Messages API → Codex Responses）
func (h *Handler) Messages(c *gin.Context) {
	h.beginPayloadRuleRequest(c)

	// 1. 读取请求体
	rawBody, err := readRawRequestBody(c)
	if err != nil {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "Failed to read request body")
		return
	}
	h.captureUpstreamCybFeedbackRequest(c, "/v1/messages", rawBody, false)
	originalInboundBody := append([]byte(nil), rawBody...)

	if len(rawBody) == 0 {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "Request body is empty")
		return
	}

	// 验证 JSON
	if !gjson.ValidBytes(rawBody) {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "Invalid JSON in request body")
		return
	}

	// 检查请求体大小
	if len(rawBody) > security.MaxRequestBodySize {
		sendAnthropicError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", "Request body too large")
		return
	}

	// 基本验证
	model := gjson.GetBytes(rawBody, "model").String()
	if model == "" {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "model is required")
		return
	}
	if !gjson.GetBytes(rawBody, "messages").Exists() {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "messages is required")
		return
	}
	isStream := gjson.GetBytes(rawBody, "stream").Bool()

	// 2. 翻译请求: Anthropic → Codex
	modelMappingJSON := h.store.GetModelMapping()
	codexBody, originalModel, err := TranslateAnthropicToCodexWithModels(rawBody, modelMappingJSON, h.supportedModelIDs(c.Request.Context()))
	if err != nil {
		sendAnthropicError(c, http.StatusBadRequest, "invalid_request_error", "Request translation failed: "+err.Error())
		return
	}
	codexBody, _, _, _ = h.applyConfiguredModelMappingToBody(codexBody, h.supportedModelIDs(c.Request.Context()))
	effectiveModel := effectiveRequestModel(codexBody, model)
	if isImageOnlyModel(effectiveModel) {
		sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", fmt.Sprintf("model %s is only supported on /v1/images/generations and /v1/images/edits", effectiveModel))
		return
	}
	if h.enforceAPIKeyLimitsAndReply(c, effectiveModel) {
		return
	}
	releaseAPIKeyConcurrency, ok := h.acquireAPIKeyConcurrency(c)
	if !ok {
		return
	}
	if releaseAPIKeyConcurrency != nil {
		defer releaseAPIKeyConcurrency()
	}
	// /v1/messages 同时允许官方 Codex OAuth 账号与中转（OpenAI Responses API）账号：
	// 翻译后的请求体本身就是 Responses 形态，中转账号直接以 HTTP 转发，
	// 使仅接入中转的用户也能使用 Claude Code（issue #181）。
	accountFilter := accountFilterForResponsesModel(effectiveModel, modelIDInList(effectiveModel, SupportedModelIDs(c.Request.Context(), h.db)))
	accountFilter = h.withModelCooldownFilter(effectiveModel, accountFilter)
	baseCodexBody := codexBody
	codexBody, payloadRulesPreApplied := h.prepareCodexPayloadRules(c, baseCodexBody, effectiveModel, accountFilter)
	if h.inspectPromptFilterCanonicalResponses(c, baseCodexBody, codexBody, originalInboundBody, "/v1/messages", model) {
		return
	}
	promptDecision, _ := promptRiskDecisionFromContext(c)

	// 提取 reasoning effort（从翻译后的 codex body 中）
	reasoningEffort := extractReasoningEffort(baseCodexBody)
	serviceTier := extractServiceTier(baseCodexBody)
	ruleIdentity := h.freezePayloadRuleIdentity(c)
	sessionIdentity := resolveRequestSessionIdentity(c.Request.Header, baseCodexBody)
	apiKeyID := requestAPIKeyID(c)
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(c.Request.Header, baseCodexBody), apiKeyID)

	// 3. 带重试的上游请求
	maxRetries := h.getMaxRetries()
	maxRateLimitRetries := h.getMaxRateLimitRetries()
	generalRetries := 0
	rateLimitRetries := 0
	var lastStatusCode int
	var lastBody []byte
	lastFailureWasRelay := false
	var pendingFinalFailure *retryAttemptUsageSpec
	retryExclusions := newRetryAccountExclusions()
	routeRequirement := promptDecision
	var wsHTTPFallback websocketHTTPFallbackState
	registerWebsocketHTTPFallbackAuditState(c, &wsHTTPFallback)

	var lastUpstreamCancel context.CancelFunc
	defer func() {
		if lastUpstreamCancel != nil {
			lastUpstreamCancel()
		}
	}()

	for attempt := 0; ; attempt++ {
		account, stickyProxyURL, circuitAttempt, selectedDecision, retainedHTTPFallback := wsHTTPFallback.TakeRouted()
		if !retainedHTTPFallback {
			account, stickyProxyURL, selectedDecision, circuitAttempt = h.nextCircuitPermittedRoutedAccountForSession(c, affinityKey, apiKeyID, retryExclusions, accountFilter, routeRequirement)
		}
		if releaseRoutedAttemptIfContextDone(c.Request.Context(), h.store, account, circuitAttempt) {
			return
		}
		promptDecision = selectedDecision
		if account == nil {
			if c.Request.Context().Err() != nil {
				return
			}
			syntheticFinal := func() retryAttemptUsageSpec {
				return retryAttemptUsageSpec{
					Endpoint:             "/v1/messages",
					Model:                model,
					EffectiveModel:       effectiveModel,
					DurationMs:           logicalRequestDurationMs(c),
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               isStream,
					ViaWebsocket:         false,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
				}
			}
			if routeErr, ok := routeSelectionErrorFromContext(c); ok {
				spec := routeSelectionFailureSpecFor(routeErr)
				publishHTTPFinalWithAudit(c,
					func() { sendAnthropicError(c, spec.HTTPStatusCode, spec.AnthropicErrorType, routeErr.Message) },
					func() {
						h.logRouteSelectionError(c, "/v1/messages", model, effectiveModel, isStream, false, attempt, routeErr, spec)
					},
					nil,
				)
				return
			}
			if (routeRequirement.routesToCybRelay() || lastFailureWasRelay) && lastStatusCode > 0 && len(lastBody) > 0 {
				visibleStatus := anthropicFinalResponseStatusForContext(c, lastStatusCode, lastBody)
				errorKind := upstreamErrorKind(lastStatusCode, lastBody, codex429Decision{})
				errorMessage := usageLogErrorMessage(lastStatusCode, lastBody)
				publishHTTPFinalWithAudit(c,
					func() { sendFinalAnthropicUpstreamError(c, lastStatusCode, lastBody) },
					func() {
						h.logPendingOrSyntheticFinalFailureAs(c, pendingFinalFailure, syntheticFinal(), visibleStatus, errorKind, errorMessage)
					},
					nil,
				)
				return
			}
			if routeRequirement.routesToCybRelay() {
				publishHTTPFinalWithAudit(c,
					func() { sendCybRelayUnavailableAnthropic(c) },
					func() { h.logCybRelayUnavailable(c, "/v1/messages", model, effectiveModel, isStream, false, attempt) },
					nil,
				)
				return
			}
			if lastStatusCode == http.StatusTooManyRequests && len(lastBody) > 0 {
				errorKind := upstreamErrorKind(lastStatusCode, lastBody, codex429Decision{})
				publishHTTPFinalWithAudit(c,
					func() {
						sendAnthropicError(c, http.StatusTooManyRequests, "rate_limit_error", "All accounts rate limited")
					},
					func() {
						h.logPendingOrSyntheticFinalFailureAs(c, pendingFinalFailure, syntheticFinal(), http.StatusTooManyRequests, errorKind, "All accounts rate limited")
					},
					nil,
				)
				return
			}
			noAccountMessage := noAvailableAnthropicAccountMessage(effectiveModel)
			publishHTTPFinalWithAudit(c,
				func() { sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", noAccountMessage) },
				func() {
					h.logPendingOrSyntheticFinalFailureAs(c, pendingFinalFailure, syntheticFinal(), http.StatusServiceUnavailable, ErrorCodeNoAvailableAccount, noAccountMessage)
				},
				nil,
			)
			return
		}
		lastFailureWasRelay = false
		lastStatusCode = 0
		lastBody = nil

		start := time.Now()
		proxyURL := h.resolveProxyForAttempt(account, stickyProxyURL)
		if !retainedHTTPFallback {
			h.store.BindSessionAffinity(affinityKey, account, proxyURL)
		}
		setUpstreamAccountContext(c, account)
		if wsHTTPFallback.ForceHTTP() {
			log.Printf("上游 WebSocket → HTTP 降级尝试启动 (fallback_id=%s, source=%s, attempt=%d, account=%d, endpoint=/v1/messages, ws_elapsed_ms=%d)", wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsHTTPFallback.WSElapsed().Milliseconds())
		}
		isRelayAccount := account.IsOpenAIResponsesAPI()
		attemptEffectiveModel := effectiveModel
		useWebsocket := h.shouldUseWebsocketForHTTP() && !wsHTTPFallback.ForceHTTP() && !isRelayAccount
		upstreamEndpoint := "/v1/responses"
		if isRelayAccount {
			relayBaseURL, _ := account.OpenAIResponsesCredentials()
			upstreamEndpoint = auth.OpenAIResponsesEndpoint(relayBaseURL, "/v1/responses")
		}

		apiKey := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		apiKey = strings.TrimSpace(apiKey)
		// 兼容 Anthropic 客户端多种认证方式
		if apiKey == "" {
			for _, hdr := range []string{"x-api-key", "anthropic-auth-token"} {
				if v := strings.TrimSpace(c.GetHeader(hdr)); v != "" {
					apiKey = v
					break
				}
			}
		}

		deviceCfg := h.deviceCfg
		if deviceCfg == nil {
			deviceCfg = &DeviceProfileConfig{StabilizeDeviceProfile: false}
		}

		downstreamHeaders := c.Request.Header.Clone()
		upstreamSessionID := resolveUpstreamSessionID(apiKeyID, sessionIdentity.upstreamSeed, sessionIdentity.explicitUpstreamID, useWebsocket)
		if lastUpstreamCancel != nil {
			lastUpstreamCancel()
		}
		upstreamCtx, upstreamCancel := newDrainableUpstreamContext(c.Request.Context(), upstreamDrainTimeout)
		upstreamCtx = WithPayloadRuleIdentity(upstreamCtx, ruleIdentity)
		upstreamCtx = withPayloadRuleSnapshot(upstreamCtx, freezePayloadRuleSnapshot(c))
		if payloadRulesPreApplied {
			upstreamCtx = withPayloadRulesPreApplied(upstreamCtx)
		}
		lastUpstreamCancel = upstreamCancel
		ttftGuard := newFirstTokenTimeoutGuard(currentFirstTokenTimeout(), upstreamCancel)
		var resp *http.Response
		var reqErr error
		if releaseRoutedAttemptIfContextDone(c.Request.Context(), h.store, account, circuitAttempt) {
			ttftGuard.Stop()
			upstreamCancel()
			return
		}
		if isRelayAccount {
			serviceTier = extractServiceTier(baseCodexBody)
			upstreamBody := baseCodexBody
			if mappedBody, mappedModel, ok := h.applyAccountModelMappingToBody(upstreamBody, account); ok {
				upstreamBody = mappedBody
				attemptEffectiveModel = mappedModel
			}
			resp, reqErr = ExecuteOpenAIResponsesRequest(upstreamCtx, account, upstreamBody, proxyURL, downstreamHeaders)
		} else {
			// service_tier 记账按 payload 规则改写后的值归因（仅 Codex 路径套用规则）。
			if payloadRulesPreApplied {
				serviceTier = extractServiceTier(codexBody)
			} else {
				serviceTier = EffectiveRequestedServiceTierWithSnapshot(freezePayloadRuleSnapshot(c), codexBody, attemptEffectiveModel, downstreamHeaders, ruleIdentity)
			}
			httpSessionID := resolveUpstreamSessionID(apiKeyID, sessionIdentity.upstreamSeed, sessionIdentity.explicitUpstreamID, false)
			upstreamCtx, transportObservation := withUpstreamTransportObservation(upstreamCtx)
			var actualWebsocket bool
			resp, reqErr, actualWebsocket = executeRequestWithWebsocketFramePreflight(
				upstreamCtx, account, codexBody, codexBody, upstreamSessionID, httpSessionID,
				proxyURL, apiKey, deviceCfg, downstreamHeaders, useWebsocket,
			)
			useWebsocket = applyUpstreamTransportObservation(c, transportObservation, actualWebsocket)
		}
		durationMs := int(time.Since(start).Milliseconds())

		if reqErr != nil {
			if frameErr, ok := websocketContextBoundFrameError(reqErr); ok {
				ttftGuard.Stop()
				circuitAttempt.Release(h.store, account)
				message := websocketLargeFrameContextBoundMessage(frameErr)
				publishHTTPFinalWithAudit(c,
					func() { sendAnthropicError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", message) },
					func() {
						h.logPendingOrSyntheticFinalFailureAs(c, pendingFinalFailure, retryAttemptUsageSpec{
							AccountID: 0, Endpoint: "/v1/messages", Model: model,
							EffectiveModel: attemptEffectiveModel, DurationMs: durationMs,
							ReasoningEffort: reasoningEffort, UpstreamEndpoint: upstreamEndpoint,
							Stream: isStream, ViaWebsocket: false, RequestedServiceTier: serviceTier, Attempt: attempt,
						}, http.StatusRequestEntityTooLarge, websocketLargeFrameContextBoundKind, message)
					},
					nil,
				)
				return
			}
			timedOut := ttftGuard.TimedOut()
			ttftGuard.Stop()
			localContentionKind := websocketLocalContentionKind(reqErr)
			localContention := useWebsocket && localContentionKind != ""
			fallbackEligibleLocalContention := c.Request.Context().Err() == nil && shouldFallbackWebsocketLocalContentionToHTTP(reqErr, useWebsocket, rawBody, sessionIdentity)
			clientContextErr := c.Request.Context().Err()
			clientGone := clientContextErr != nil
			if clientGone && requestErrorCausedByClientContext(clientContextErr, reqErr) {
				circuitAttempt.Release(h.store, account)
				return
			}
			if timedOut {
				reqErr = firstTokenTimeoutError(currentFirstTokenTimeout())
			}
			kind := classifyTransportFailure(reqErr)
			if wsHTTPFallback.ForceHTTP() && !useWebsocket {
				wsHTTPFallback.LogHTTPAttemptCompletion("/v1/messages", account.ID(), attempt+1, durationMs, 0, logStatusUpstreamStreamBreak)
			}
			fallbackLocalContention := !timedOut && fallbackEligibleLocalContention
			if useWebsocket && (kind == upstreamErrorKindMessageTooBig || fallbackLocalContention) {
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/messages",
					Model:                model,
					EffectiveModel:       attemptEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     upstreamEndpoint,
					Stream:               isStream,
					ViaWebsocket:         true,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    localContentionKind,
				}, reqErr, false)
				wsElapsed := time.Since(start)
				fallbackSource := websocketMessageTooBigSource(reqErr.Error())
				if fallbackLocalContention {
					fallbackSource = websocketLocalContentionSource(reqErr)
				}
				wsHTTPFallback.RetainRouted(account, proxyURL, wsElapsed, fallbackSource, circuitAttempt, selectedDecision)
				log.Printf("上游 WebSocket 降级 HTTP，保留账号租约 (fallback_id=%s, source=%s, attempt=%d, account=%d, endpoint=/v1/messages, ws_elapsed_ms=%d): %v", wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsElapsed.Milliseconds(), reqErr)
				continue
			}
			retryable := shouldRetryTransportFailure(reqErr, kind)
			if localContention && !fallbackEligibleLocalContention {
				retryable = false
			}
			shouldRetry := false
			if retryable {
				shouldRetry = shouldRetryRequestError(reqErr, &generalRetries, maxRetries)
			}
			relayTransportFailure := false
			if !localContention {
				transportEvidenceContext := c.Request.Context()
				if clientGone {
					transportEvidenceContext = context.Background()
				}
				relayTransportFailure = circuitAttempt.UpstreamTransportFailure(transportEvidenceContext, kind, timedOut)
			}
			if relayTransportFailure {
				recyclePooledClient(account, proxyURL)
			}
			relayRequestFailure := selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI() &&
				kind != "" && kind != upstreamErrorKindMessageTooBig && c.Request.Context().Err() == nil
			requestFailureSpec := retryAttemptUsageSpec{
				AccountID: account.ID(), Endpoint: "/v1/messages", Model: model,
				EffectiveModel: attemptEffectiveModel, DurationMs: durationMs,
				ReasoningEffort: reasoningEffort, UpstreamEndpoint: upstreamEndpoint,
				Stream: isStream, ViaWebsocket: useWebsocket,
				RequestedServiceTier: serviceTier, Attempt: attempt,
			}
			terminalRequestFailure := !shouldRetry && kind != "" && kind != upstreamErrorKindMessageTooBig
			if shouldRetry && kind != "" && kind != upstreamErrorKindMessageTooBig && c.Request.Context().Err() == nil {
				pending := canonicalRequestFailureSpecWithKind(requestFailureSpec, reqErr, localContentionKind)
				pendingFinalFailure = rememberPendingFinalFailure(c, pending)
				lastFailureWasRelay = relayRequestFailure
				if relayRequestFailure {
					lastStatusCode = pending.StatusCode
					lastBody = upstreamFailureBody(pending.ErrorMessage)
				} else {
					lastStatusCode = 0
					lastBody = nil
				}
			}
			if !localContention && shouldPenalizeTransportFailure(kind) && !(timedOut && shouldRetry) {
				h.store.ReportRequestFailure(account, kind, time.Duration(durationMs)*time.Millisecond)
			}
			circuitAttempt.Release(h.store, account)
			if !localContention || (timedOut && fallbackEligibleLocalContention) {
				h.store.UnbindSessionAffinity(affinityKey, account.ID())
			}
			if clientGone {
				hiddenSpec := requestFailureSpec
				hiddenSpec.StatusCode = relayTransportFailureAuditStatus(relayTransportFailure)
				hiddenSpec.UpstreamErrorKind = localContentionKind
				h.logRetryRequestErrorFailure(c, hiddenSpec, reqErr, timedOut)
				return
			}
			publishTerminalRequestFailure := func() {
				publishHTTPFinalWithAudit(c,
					func() { sendAnthropicError(c, http.StatusBadGateway, "api_error", "Upstream request failed") },
					func() {
						h.logFinalRequestErrorFailureAs(c, requestFailureSpec, reqErr, http.StatusBadGateway, localContentionKind)
					},
					func() {
						hiddenSpec := requestFailureSpec
						hiddenSpec.StatusCode = relayTransportFailureAuditStatus(relayTransportFailure)
						hiddenSpec.UpstreamErrorKind = localContentionKind
						h.logRetryRequestErrorFailure(c, hiddenSpec, reqErr, timedOut)
					},
				)
			}
			if timedOut && shouldRetry {
				retryExclusions.MarkSoftFirstTokenTimeout(account.ID())
				log.Printf("上游首字超时，断开并重试 (attempt %d/%d, account %d, /v1/messages): %v", attempt+1, maxRetries+1, account.ID(), reqErr)
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/messages",
					Model:                model,
					EffectiveModel:       attemptEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     upstreamEndpoint,
					Stream:               isStream,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    localContentionKind,
				}, reqErr, true)
				continue
			}
			if !localContention && !timedOut {
				retryExclusions.MarkHard(account.ID())
			}

			if !retryable {
				if terminalRequestFailure {
					publishTerminalRequestFailure()
				} else {
					sendAnthropicError(c, http.StatusBadGateway, "api_error", "Upstream request failed")
				}
				return
			}

			log.Printf("上游请求失败 (attempt %d, /v1/messages): %v", attempt+1, reqErr)
			if shouldRetry {
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/messages",
					Model:                model,
					EffectiveModel:       attemptEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     upstreamEndpoint,
					Stream:               isStream,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
				}, reqErr, false)
				continue
			}
			if terminalRequestFailure {
				publishTerminalRequestFailure()
			} else {
				sendAnthropicError(c, http.StatusBadGateway, "api_error", "Upstream request failed")
			}
			return
		}

		if resp.StatusCode != http.StatusOK {
			ttftGuard.Stop()
			if wsHTTPFallback.ForceHTTP() && !useWebsocket {
				wsHTTPFallback.LogHTTPAttemptCompletion("/v1/messages", account.ID(), attempt+1, durationMs, 0, resp.StatusCode)
			}
			errBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			clientGone := c.Request.Context().Err() != nil
			h.reportUpstreamHTTPFailure(account, resp.StatusCode, time.Duration(durationMs)*time.Millisecond)
			SyncCodexUsageState(h.store, account, resp)
			if usagePct, ok := parseCodexUsageHeaders(resp, account); ok {
				h.store.PersistUsageSnapshot(account, usagePct)
			}
			finishRelayHTTPCircuitAttempt(circuitAttempt, account, resp.StatusCode)
			circuitAttempt.Release(h.store, account)
			h.store.UnbindSessionAffinity(affinityKey, account.ID())
			retryExclusions.MarkHard(account.ID())

			log.Printf("上游返回错误 (attempt %d, status %d, /v1/messages): %s", attempt+1, resp.StatusCode, string(errBody))
			logUpstreamError("/v1/messages", resp.StatusCode, model, account.ID(), errBody)
			h.logUpstreamCyberPolicy(c, "/v1/messages", model, errBody)
			decision := h.applyCooldownForModel(account, resp.StatusCode, errBody, resp, attemptEffectiveModel)
			shouldRetry := shouldRetryTextHTTPStatusForRequest(resp.StatusCode, account, requestRequiresBoundUpstreamAccount(c, rawBody), &generalRetries, &rateLimitRetries, maxRetries, maxRateLimitRetries)
			usageTiers := resolveUsageServiceTiers("", serviceTier)
			relayFailure := selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI()
			failureKind := upstreamErrorKind(resp.StatusCode, errBody, decision)
			failureMessage := usageLogErrorMessage(resp.StatusCode, errBody)
			failureUsage := &database.UsageLogInput{
				AccountID:            account.ID(),
				Endpoint:             "/v1/messages",
				Model:                model,
				EffectiveModel:       attemptEffectiveModel,
				StatusCode:           resp.StatusCode,
				DurationMs:           durationMs,
				ReasoningEffort:      reasoningEffort,
				InboundEndpoint:      "/v1/messages",
				UpstreamEndpoint:     upstreamEndpoint,
				Stream:               isStream,
				ViaWebsocket:         useWebsocket,
				ServiceTier:          usageTiers.ServiceTier,
				RequestedServiceTier: usageTiers.RequestedServiceTier,
				ActualServiceTier:    usageTiers.ActualServiceTier,
				BillingServiceTier:   usageTiers.BillingServiceTier,
				IsRetryAttempt:       attempt > 0,
				AttemptIndex:         attempt + 1,
				UpstreamErrorKind:    failureKind,
				ErrorMessage:         failureMessage,
			}

			if clientGone {
				h.logUsageForRequest(c, httpFinalUsageCopy(failureUsage, resp.StatusCode, true))
				return
			}
			if shouldRetry {
				h.logUsageForRequest(c, httpFinalUsageCopy(failureUsage, resp.StatusCode, true))
				lastStatusCode = resp.StatusCode
				lastBody = errBody
				lastFailureWasRelay = relayFailure
				pendingFinalFailure = rememberPendingFinalFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/messages",
					Model:                model,
					EffectiveModel:       attemptEffectiveModel,
					StatusCode:           resp.StatusCode,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     upstreamEndpoint,
					Stream:               isStream,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    failureKind,
					ErrorMessage:         failureMessage,
				})
				continue
			}

			visibleStatusCode := anthropicFinalResponseStatusForContext(c, resp.StatusCode, errBody)
			publishHTTPFinalWithAudit(c,
				func() {
					sendFinalAnthropicUpstreamError(c, resp.StatusCode, errBody)
				},
				func() {
					h.logUsageForRequest(c, httpFinalUsageCopy(failureUsage, visibleStatusCode, false))
				},
				func() {
					h.logUsageForRequest(c, httpFinalUsageCopy(failureUsage, resp.StatusCode, true))
				},
			)
			return
		}

		// ========== 成功路径 ==========
		account.Mu().RLock()
		c.Set("x-account-email", account.Email)
		account.Mu().RUnlock()
		c.Set("x-account-proxy", proxyURL)
		c.Set("x-model", attemptEffectiveModel)
		c.Set("x-reasoning-effort", reasoningEffort)

		var firstTokenMs int
		var usage *UsageInfo
		var actualServiceTier string
		ttftRecorded := false
		gotTerminal := false
		deltaCharCount := 0
		var readErr error
		var writeErr error
		clientGone := false
		wroteAnyBody := false
		terminalDelivered := false
		var terminalFailurePayload []byte
		var anthropicResp *anthropicResponse

		if isStream {
			// 流式响应：逐事件翻译为 Anthropic SSE
			c.Header("Content-Type", "text/event-stream")
			c.Header("Cache-Control", "no-cache")
			c.Header("Connection", "keep-alive")
			c.Header("X-Accel-Buffering", "no")

			flusher, ok := c.Writer.(http.Flusher)
			if !ok {
				ttftGuard.Stop()
				sendAnthropicError(c, http.StatusInternalServerError, "api_error", "Streaming not supported")
				resp.Body.Close()
				circuitAttempt.Release(h.store, account)
				return
			}

			translator := newAnthropicStreamTranslator(originalModel)
			streamWriter := h.newStreamFlushWriter(c.Writer, flusher)
			var pendingFirstTokenEvents bytes.Buffer

			readErr = ReadSSEStream(resp.Body, func(data []byte) bool {
				parsed := gjson.ParseBytes(data)
				eventType := parsed.Get("type").String()
				if c.Request.Context().Err() != nil {
					clientGone = true
				}

				// TTFT 跟踪
				ttftGuard.MarkProgress(eventType)
				isFirstToken := isFirstTokenResultForMode(parsed, currentFirstTokenMode())
				if !ttftRecorded && isFirstToken {
					firstTokenMs = int(time.Since(start).Milliseconds())
					ttftRecorded = true
				}

				// 累计 delta 字符数
				if eventType == "response.output_text.delta" || isCodexToolInputDeltaEvent(eventType) {
					deltaCharCount += len(parsed.Get("delta").String())
				}

				// 提取 usage
				if eventType == "response.completed" || eventType == "response.incomplete" {
					h.pinCybRelayResponseID(c, data)
					usage = extractUsageFromResult(parsed.Get("response.usage"))
					if tier := parsed.Get("response.service_tier").String(); tier != "" {
						actualServiceTier = tier
					}
					gotTerminal = true
				}
				if eventType == "response.failed" {
					terminalFailurePayload = append([]byte(nil), data...)
					gotTerminal = true
					if shouldSuppressRetryableResponseFailedBeforeFirstTokenForRequest(eventType, terminalFailurePayload, account, requestRequiresBoundUpstreamAccount(c, rawBody), ttftRecorded, wroteAnyBody, attempt, maxRetries, c.Request.Context().Err(), writeErr) {
						pendingFirstTokenEvents.Reset()
						return false
					}
					if clientGone {
						pendingFirstTokenEvents.Reset()
						return false
					}

					failedPolicy := classifyResponseFailedRequest(account, requestRequiresBoundUpstreamAccount(c, rawBody), terminalFailurePayload)
					// A failed Responses terminal event is never a successful Anthropic
					// message_stop. If it cannot be transparently retried (or content
					// was already emitted), terminate the Anthropic stream with an error.
					pendingFirstTokenEvents.Reset()
					visibleStatus := anthropicResponseFailedCanonicalStatus(c, failedPolicy.outcome, failedPolicy, terminalFailurePayload)
					errorType := mapHTTPStatusToAnthropicError(visibleStatus)
					if visibleStatus == http.StatusServiceUnavailable {
						errorType = "overloaded_error"
					}
					if err := streamWriter.WriteString(anthropicStreamErrorSSE(errorType, failedPolicy.outcome.failureMessage)); err != nil {
						writeErr = err
						clientGone = true
					} else if err := streamWriter.Flush(); err != nil {
						writeErr = err
						clientGone = true
					} else {
						wroteAnyBody = true
						terminalDelivered = true
					}
					return false
				}

				// 翻译并写入
				events := translator.translateEvent(data)
				if !clientGone && len(events) > 0 {
					var payload bytes.Buffer
					for _, evt := range events {
						payload.WriteString(anthropicEventToSSE(evt))
					}
					payloadString := payload.String()
					shouldDefer := !ttftRecorded && !gotTerminal && isPreContentLifecycleEvent(eventType)
					if shouldDefer {
						pendingFirstTokenEvents.WriteString(payloadString)
						if pendingFirstTokenEvents.Len() <= 1024*1024 {
							return eventType != "response.completed" && eventType != "response.failed"
						}
						payloadString = pendingFirstTokenEvents.String()
						pendingFirstTokenEvents.Reset()
					} else if pendingFirstTokenEvents.Len() > 0 {
						payloadString = pendingFirstTokenEvents.String() + payloadString
						pendingFirstTokenEvents.Reset()
					}
					if err := streamWriter.WriteString(payloadString); err != nil {
						writeErr = err
						clientGone = true
					} else {
						wroteAnyBody = true
						if isResponsesTerminalEventType(eventType) {
							if err := streamWriter.Flush(); err != nil {
								writeErr = err
								clientGone = true
							} else {
								terminalDelivered = true
							}
						}
					}
				}

				return !isResponsesTerminalEventType(eventType)
			})
			if !clientGone && c.Request.Context().Err() == nil && writeErr == nil && wroteAnyBody {
				writeErr = streamWriter.Flush()
				if writeErr != nil {
					clientGone = true
				}
			}

		} else {
			// 非流式：缓冲所有事件后构建完整 JSON 响应
			var lastCompletedData []byte
			translator := newAnthropicStreamTranslator(originalModel)
			accumulator := newAnthropicResponseAccumulator(originalModel)

			readErr = ReadSSEStream(resp.Body, func(data []byte) bool {
				parsed := gjson.ParseBytes(data)
				eventType := parsed.Get("type").String()
				accumulator.apply(translator.translateEvent(data))

				ttftGuard.MarkProgress(eventType)
				if !ttftRecorded && isFirstTokenResultForMode(parsed, currentFirstTokenMode()) {
					firstTokenMs = int(time.Since(start).Milliseconds())
					ttftRecorded = true
				}
				if eventType == "response.output_text.delta" || isCodexToolInputDeltaEvent(eventType) {
					deltaCharCount += len(parsed.Get("delta").String())
				}
				if eventType == "response.completed" || eventType == "response.incomplete" {
					h.pinCybRelayResponseID(c, data)
					usage = extractUsageFromResult(parsed.Get("response.usage"))
					if tier := parsed.Get("response.service_tier").String(); tier != "" {
						actualServiceTier = tier
					}
					lastCompletedData = data
					gotTerminal = true
					return false
				}
				if eventType == "response.failed" {
					terminalFailurePayload = append([]byte(nil), data...)
					gotTerminal = true
					return false
				}
				return true
			})

			if lastCompletedData != nil {
				anthropicResp = accumulator.build(lastCompletedData)
			}
		}

		// 断流检测 + token 估算
		totalDuration := int(time.Since(start).Milliseconds())
		outcome := classifyStreamOutcome(c.Request.Context().Err(), readErr, writeErr, gotTerminal)
		if ttftGuard.TimedOut() && !ttftRecorded && !gotTerminal {
			outcome = firstTokenTimeoutOutcome(currentFirstTokenTimeout())
		}
		ttftGuard.Stop()
		var responseFailedPolicy *responseFailedRequestPolicy
		if len(terminalFailurePayload) > 0 {
			responseFailedPolicy = classifyResponseFailedRequest(account, requestRequiresBoundUpstreamAccount(c, rawBody), terminalFailurePayload)
			outcome = responseFailedPolicy.outcome
			// 流式 response.failed 也要把额度耗尽/限流账号冷却下来，
			// 否则该账号会保持高分继续被调度（与 /v1/responses 路径保持一致）。
			responseFailedDecision := h.applyResponseFailedCooldown(account, terminalFailurePayload, resp, attemptEffectiveModel)
			if responseFailedDecision.Reason != "" {
				outcome.failureKind = upstreamErrorKind(outcome.logStatusCode, responseFailedErrorBody(terminalFailurePayload), responseFailedDecision)
			}
		}
		disconnected := clientGone || c.Request.Context().Err() != nil || writeErr != nil
		clientGoneFinal := disconnected && !(isStream && terminalDelivered)
		if wsHTTPFallback.ForceHTTP() && !useWebsocket {
			wsHTTPFallback.LogHTTPAttemptCompletion("/v1/messages", account.ID(), attempt+1, totalDuration, firstTokenMs, outcome.logStatusCode)
		}
		if shouldFallbackWebsocketMessageTooBigToHTTP(outcome, useWebsocket, wroteAnyBody, c.Request.Context().Err(), writeErr) {
			h.logTransparentStreamRetryFailure(c, retryAttemptUsageSpec{
				AccountID:            account.ID(),
				Endpoint:             "/v1/messages",
				Model:                model,
				EffectiveModel:       attemptEffectiveModel,
				DurationMs:           totalDuration,
				FirstTokenMs:         firstTokenMs,
				ReasoningEffort:      reasoningEffort,
				UpstreamEndpoint:     upstreamEndpoint,
				Stream:               isStream,
				ViaWebsocket:         true,
				RequestedServiceTier: serviceTier,
				ActualServiceTier:    actualServiceTier,
				Attempt:              attempt,
			}, outcome)
			wsElapsed := time.Since(start)
			resp.Body.Close()
			wsHTTPFallback.RetainRouted(account, proxyURL, wsElapsed, websocketMessageTooBigSource(outcome.failureMessage), circuitAttempt, selectedDecision)
			log.Printf("上游 WebSocket 1009，首包前保留账号租约并降级 HTTP (fallback_id=%s, source=%s, attempt=%d, account=%d, endpoint=/v1/messages, ws_elapsed_ms=%d): %s",
				wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsElapsed.Milliseconds(), outcome.failureMessage)
			continue
		}
		if shouldTransparentRetryStream(responseFailedRetryOutcome(outcome, responseFailedPolicy), attempt, maxRetries, wroteAnyBody, c.Request.Context().Err(), writeErr) {
			log.Printf("上游流在首包前断开，重试 (attempt %d/%d, account %d, /v1/messages): %s",
				attempt+1, maxRetries+1, account.ID(), outcome.failureMessage)
			h.logTransparentStreamRetryFailure(c, retryAttemptUsageSpec{
				AccountID:            account.ID(),
				Endpoint:             "/v1/messages",
				Model:                model,
				EffectiveModel:       attemptEffectiveModel,
				DurationMs:           totalDuration,
				FirstTokenMs:         firstTokenMs,
				ReasoningEffort:      reasoningEffort,
				UpstreamEndpoint:     upstreamEndpoint,
				Stream:               isStream,
				ViaWebsocket:         useWebsocket,
				RequestedServiceTier: serviceTier,
				ActualServiceTier:    actualServiceTier,
				Attempt:              attempt,
			}, outcome)
			pending := canonicalStreamFailureSpec(retryAttemptUsageSpec{
				AccountID:            account.ID(),
				Endpoint:             "/v1/messages",
				Model:                model,
				EffectiveModel:       attemptEffectiveModel,
				DurationMs:           totalDuration,
				FirstTokenMs:         firstTokenMs,
				ReasoningEffort:      reasoningEffort,
				UpstreamEndpoint:     upstreamEndpoint,
				Stream:               isStream,
				ViaWebsocket:         useWebsocket,
				RequestedServiceTier: serviceTier,
				ActualServiceTier:    actualServiceTier,
				Attempt:              attempt,
			}, outcome)
			pendingFinalFailure = rememberPendingFinalFailure(c, pending)
			lastFailureWasRelay = selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI()
			if lastFailureWasRelay {
				lastStatusCode = pending.StatusCode
				lastBody = upstreamFailureBody(pending.ErrorMessage)
			} else {
				lastStatusCode = 0
				lastBody = nil
			}
			recyclePooledClient(account, proxyURL)
			SyncCodexUsageState(h.store, account, resp)
			if isFirstTokenTimeoutOutcome(outcome) {
				retryExclusions.MarkSoftFirstTokenTimeout(account.ID())
			} else {
				retryExclusions.MarkHard(account.ID())
				h.store.ReportRequestFailure(account, outcome.failureKind, time.Duration(totalDuration)*time.Millisecond)
			}
			resp.Body.Close()
			circuitAttempt.FinishStreamOutcome(c.Request.Context(), outcome, isFirstTokenTimeoutOutcome(outcome))
			circuitAttempt.Release(h.store, account)
			h.store.UnbindSessionAffinity(affinityKey, account.ID())
			continue
		}

		// A truncated Anthropic stream is never a successful message_stop. Once
		// output has reached the client it cannot be replayed safely, so terminate
		// the existing SSE stream with an explicit Anthropic error event. Before
		// any output, preserve normal HTTP error semantics instead of an empty 200.
		// Preserve the upstream terminal outcome across the synthetic downstream
		// terminal publication. A failure to write/flush that synthetic terminal
		// must hide the attempt without rewriting an upstream EOF (598) as a
		// downstream disconnect (499).
		terminalRawStatusCode := outcome.logStatusCode
		logStatusCode := anthropicResponseFailedCanonicalStatus(c, outcome, responseFailedPolicy, terminalFailurePayload)
		if clientGoneFinal {
			logStatusCode = terminalRawStatusCode
		}
		if !clientGoneFinal && isStream && outcome.logStatusCode == logStatusUpstreamStreamBreak {
			canonicalStatus := canonicalStreamStatus(outcome)
			if wroteAnyBody {
				delivered := publishHTTPFinalResponseErr(c, func() error {
					flusher, ok := c.Writer.(http.Flusher)
					if !ok {
						return fmt.Errorf("Anthropic terminal stream writer does not support flushing")
					}
					streamWriter := newStreamFlushWriter(c.Writer, flusher)
					if err := streamWriter.WriteString(anthropicStreamErrorSSE(mapHTTPStatusToAnthropicError(canonicalStatus), outcome.failureMessage)); err != nil {
						return err
					}
					if err := streamWriter.Flush(); err != nil {
						return err
					}
					return nil
				})
				if delivered {
					terminalDelivered = true
				} else {
					log.Printf("failed to publish truncated Anthropic stream terminal (account %d)", account.ID())
					clientGoneFinal = true
					logStatusCode = terminalRawStatusCode
				}
			} else {
				delivered := publishHTTPFinalResponse(c, func() {
					c.Header("Content-Type", "application/json; charset=utf-8")
					sendAnthropicError(c, canonicalStatus, mapHTTPStatusToAnthropicError(canonicalStatus), outcome.failureMessage)
				})
				if !delivered {
					clientGoneFinal = true
					logStatusCode = terminalRawStatusCode
				}
			}
		}

		if !clientGoneFinal && !isStream {
			var delivered bool
			switch {
			case len(terminalFailurePayload) > 0:
				failureBody := responseFailedErrorBody(terminalFailurePayload)
				rawStatusCode := outcome.logStatusCode
				visibleStatusCode := anthropicResponseFailedCanonicalStatus(c, outcome, responseFailedPolicy, terminalFailurePayload)
				logStatusCode = visibleStatusCode
				delivered = publishHTTPFinalResponse(c, func() {
					if responseFailedPolicy != nil &&
						responseFailedPolicy.outcome.logStatusCode == http.StatusForbidden &&
						responseFailedPolicy.canonicalStatus == http.StatusServiceUnavailable {
						sendAnthropicError(c, http.StatusServiceUnavailable, "overloaded_error", "账号池暂无可用账号（上游账号被拒绝访问：额度/套餐或工作区受限），请稍后重试")
						return
					}
					sendFinalAnthropicUpstreamError(c, rawStatusCode, failureBody)
				})
			case anthropicResp != nil:
				delivered = publishHTTPFinalResponse(c, func() {
					c.JSON(http.StatusOK, anthropicResp)
				})
			default:
				delivered = publishHTTPFinalResponse(c, func() {
					sendAnthropicError(c, http.StatusBadGateway, "api_error", "No complete response received from upstream")
				})
			}
			if !delivered {
				clientGoneFinal = true
				logStatusCode = terminalRawStatusCode
			}
		}

		h.store.BindSessionAffinity(affinityKey, account, proxyURL)

		hiddenAttempt := clientGoneFinal
		if outcome.logStatusCode != http.StatusOK {
			log.Printf("流异常结束 (account %d, /v1/messages, status %d): %s，已转发约 %d 字符",
				account.ID(), outcome.logStatusCode, outcome.failureMessage, deltaCharCount)
			if deltaCharCount > 0 {
				estOutputTokens := deltaCharCount / 3
				if estOutputTokens < 1 {
					estOutputTokens = 1
				}
				usage = &UsageInfo{
					OutputTokens:     estOutputTokens,
					CompletionTokens: estOutputTokens,
					TotalTokens:      estOutputTokens,
				}
			}
		}

		usageTiers := resolveUsageServiceTiers(actualServiceTier, serviceTier)
		c.Set("x-service-tier", usageTiers.ServiceTier)

		logInput := &database.UsageLogInput{
			AccountID:            account.ID(),
			Endpoint:             "/v1/messages",
			Model:                model,
			EffectiveModel:       attemptEffectiveModel,
			StatusCode:           logStatusCode,
			DurationMs:           totalDuration,
			IsRetryAttempt:       attempt > 0,
			AttemptIndex:         attempt + 1,
			FirstTokenMs:         firstTokenMs,
			ReasoningEffort:      reasoningEffort,
			InboundEndpoint:      "/v1/messages",
			UpstreamEndpoint:     upstreamEndpoint,
			Stream:               isStream,
			ViaWebsocket:         useWebsocket,
			ServiceTier:          usageTiers.ServiceTier,
			RequestedServiceTier: usageTiers.RequestedServiceTier,
			ActualServiceTier:    usageTiers.ActualServiceTier,
			BillingServiceTier:   usageTiers.BillingServiceTier,
			GuardianAttemptOnly:  hiddenAttempt,
		}
		if logStatusCode != http.StatusOK {
			logInput.ErrorMessage = usageLogErrorMessage(logStatusCode, []byte(outcome.failureMessage))
			logInput.UpstreamErrorKind = outcome.failureKind
		}
		if usage != nil {
			logInput.PromptTokens = usage.PromptTokens
			logInput.CompletionTokens = usage.CompletionTokens
			logInput.TotalTokens = usage.TotalTokens
			logInput.InputTokens = usage.InputTokens
			logInput.OutputTokens = usage.OutputTokens
			logInput.ReasoningTokens = usage.ReasoningTokens
			logInput.CachedTokens = usage.CachedTokens
		}
		h.logUsageForRequest(c, logInput)

		resp.Body.Close()
		SyncCodexUsageState(h.store, account, resp)
		if outcome.penalize {
			recyclePooledClient(account, proxyURL)
			h.store.ReportRequestFailure(account, outcome.failureKind, time.Duration(totalDuration)*time.Millisecond)
			h.store.UnbindSessionAffinity(affinityKey, account.ID())
		} else if outcome.logStatusCode == http.StatusOK {
			h.store.ClearModelCooldown(account, attemptEffectiveModel)
			h.store.ReportRequestSuccess(account, time.Duration(totalDuration)*time.Millisecond)
		}
		if outcome.logStatusCode == http.StatusOK {
			circuitAttempt.Success()
		} else {
			finishRelayStreamOutcomeForAccount(circuitAttempt, account, c.Request.Context(), outcome, isFirstTokenTimeoutOutcome(outcome))
		}
		circuitAttempt.Release(h.store, account)
		return
	}
}
