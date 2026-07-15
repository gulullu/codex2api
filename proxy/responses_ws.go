package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codex2api/api"
	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	responsesWSFirstMessageTimeout = 30 * time.Second
	responsesWSWriteTimeout        = 30 * time.Second
	responsesWSFriendlyUpstreamErr = "上游服务临时繁忙，请稍后重试"
)

var responsesWSUpgrader = websocket.Upgrader{
	EnableCompression: true,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// responsesWSTestHookSet contains deterministic scheduling hooks used only by
// tests. The whole immutable set is atomically swapped so handler/reader
// goroutines never race with test setup or cleanup.
type responsesWSTestHookSet struct {
	terminalWriteCommitted  func()
	postTerminalBookkeeping func()
	clientReadClosed        func(error)
}

var responsesWSTestHooks atomic.Pointer[responsesWSTestHookSet]

var errResponsesWSClientGone = errors.New("responses websocket client disconnected")

type responsesWSClientMessage struct {
	messageType int
	payload     []byte
	err         error
	first       bool
}

type responsesWSTerminalPublication struct {
	begin  func()
	finish func(bool)
}

func (p *responsesWSTerminalPublication) Begin() {
	if p != nil && p.begin != nil {
		p.begin()
	}
}

func (p *responsesWSTerminalPublication) Finish(delivered bool) {
	if p != nil && p.finish != nil {
		p.finish(delivered)
	}
}

type responsesWSRetryableStreamError struct {
	outcome streamOutcome
}

func (e *responsesWSRetryableStreamError) Error() string {
	if e == nil {
		return ""
	}
	return e.outcome.failureMessage
}

type responsesWSCloseError struct {
	code   int
	reason string
	err    error
}

func (e *responsesWSCloseError) Error() string {
	if e == nil {
		return ""
	}
	if e.err != nil {
		return e.err.Error()
	}
	return e.reason
}

func (e *responsesWSCloseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// ResponsesWebSocket handles OpenAI Responses API WebSocket ingress.
// The client sends response.create JSON frames and receives upstream Responses
// events as JSON text frames.
func (h *Handler) ResponsesWebSocket(c *gin.Context) {
	if !isResponsesWebSocketUpgradeRequest(c.Request) {
		api.SendErrorWithStatus(c, api.NewAPIError(
			api.ErrCodeInvalidRequest,
			"WebSocket upgrade required (Upgrade: websocket)",
			api.ErrorTypeInvalidRequest,
		), http.StatusUpgradeRequired)
		return
	}

	conn, err := responsesWSUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Responses WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(int64(security.MaxRequestBodySize))
	connectionCtx, cancelConnection := context.WithCancel(c.Request.Context())
	defer cancelConnection()
	c.Request = c.Request.WithContext(connectionCtx)
	var turnInFlight atomic.Bool
	var queuedMessage atomic.Bool
	var terminalStateMu sync.Mutex
	terminalDeliveredToClient := false
	terminalPublication := &responsesWSTerminalPublication{
		begin: func() {
			terminalStateMu.Lock()
		},
		finish: func(delivered bool) {
			if delivered {
				terminalDeliveredToClient = true
			}
			terminalStateMu.Unlock()
		},
	}
	messages := make(chan responsesWSClientMessage, 1)
	go func() {
		defer close(messages)
		for turn := 0; ; turn++ {
			first := turn == 0
			if first {
				_ = conn.SetReadDeadline(time.Now().Add(responsesWSFirstMessageTimeout))
			} else {
				_ = conn.SetReadDeadline(time.Time{})
			}
			messageType, reader, readErr := conn.NextReader()
			if readErr != nil {
				if hooks := responsesWSTestHooks.Load(); hooks != nil && hooks.clientReadClosed != nil {
					hooks.clientReadClosed(readErr)
				}
				select {
				case messages <- responsesWSClientMessage{err: readErr, first: first}:
				default:
				}
				cancelConnection()
				return
			}
			// The upstream protocol permits only one in-flight response per
			// connection. Inspect the frame header before reading its body so an
			// early pipelined 48 MB request cannot be buffered while the current
			// turn is still producing output. Once the terminal frame has been
			// delivered, one next turn may be read while the current turn finishes
			// its audit bookkeeping.
			if queuedMessage.Load() {
				closeResponsesWS(conn, websocket.ClosePolicyViolation, "too many queued websocket messages")
				cancelConnection()
				return
			}
			if turnInFlight.Load() {
				terminalStateMu.Lock()
				delivered := terminalDeliveredToClient
				terminalStateMu.Unlock()
				if !delivered {
					closeResponsesWS(conn, websocket.ClosePolicyViolation, "a response is already in progress")
					cancelConnection()
					return
				}
			}
			payload, readErr := io.ReadAll(reader)
			if readErr == nil {
				_ = conn.SetReadDeadline(time.Time{})
			} else {
				if hooks := responsesWSTestHooks.Load(); hooks != nil && hooks.clientReadClosed != nil {
					hooks.clientReadClosed(readErr)
				}
				select {
				case messages <- responsesWSClientMessage{messageType: messageType, err: readErr, first: first}:
				default:
				}
				cancelConnection()
				return
			}
			queuedMessage.Store(true)
			message := responsesWSClientMessage{messageType: messageType, payload: payload, first: first}
			select {
			case messages <- message:
			default:
				queuedMessage.Store(false)
				closeResponsesWS(conn, websocket.ClosePolicyViolation, "too many queued websocket messages")
				cancelConnection()
				return
			}
		}
	}()

	for {
		var message responsesWSClientMessage
		var ok bool
		select {
		case <-connectionCtx.Done():
			// Preserve an already-reported reader error (notably the first-frame
			// timeout) instead of making the cancellation branch swallow it.
			select {
			case message, ok = <-messages:
				if !ok || message.err == nil {
					return
				}
			default:
				return
			}
		case message, ok = <-messages:
			if !ok {
				return
			}
		}
		if message.err != nil {
			if websocket.IsCloseError(message.err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
				return
			}
			if message.first {
				log.Printf("Responses WebSocket first message read failed: %v", message.err)
			}
			return
		}
		if connectionCtx.Err() != nil {
			return
		}
		turnInFlight.Store(true)
		terminalStateMu.Lock()
		terminalDeliveredToClient = false
		terminalStateMu.Unlock()
		queuedMessage.Store(false)

		if message.messageType != websocket.TextMessage && message.messageType != websocket.BinaryMessage {
			apiErr := api.NewAPIError(api.ErrCodeInvalidRequest, "unsupported websocket message type", api.ErrorTypeInvalidRequest)
			_ = writeResponsesWSError(conn, apiErr)
			closeResponsesWS(conn, websocket.CloseUnsupportedData, apiErr.Message)
			return
		}

		if err := h.forwardResponsesWebSocketTurn(c, conn, message.payload, terminalPublication); err != nil {
			turnInFlight.Store(false)
			if errors.Is(err, errResponsesWSClientGone) {
				return
			}
			var closeErr *responsesWSCloseError
			if errors.As(err, &closeErr) {
				closeResponsesWS(conn, closeErr.code, closeErr.reason)
				return
			}
			closeResponsesWS(conn, websocket.CloseInternalServerErr, "upstream websocket proxy failed")
			return
		}
		turnInFlight.Store(false)
	}
}

func (h *Handler) forwardResponsesWebSocketTurn(c *gin.Context, conn *websocket.Conn, rawPayload []byte, terminalPublication *responsesWSTerminalPublication) error {
	if c.Request.Context().Err() != nil {
		return errResponsesWSClientGone
	}
	beginLogicalRequest(c)
	h.captureUpstreamCybFeedbackRequest(c, "/v1/responses", rawPayload, true)
	rawBody, model, apiErr := normalizeResponsesWebSocketClientPayload(rawPayload)
	if apiErr != nil {
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, apiErr)
	}

	supportedModels := h.supportedModelIDs(c.Request.Context())
	rawBody, requestModel, mappedModel, mappingApplied := h.applyConfiguredModelMappingToBody(rawBody, supportedModels)
	c.Set("raw_body", rawBody)
	if mappedModel != "" {
		model = mappedModel
	}
	logModel := requestModel
	if logModel == "" {
		logModel = model
	}

	validator := api.NewValidator(rawBody)
	rules := api.ResponsesAPIValidationRulesForModel(model)
	rules["model"] = append(rules["model"], api.ModelValidator(supportedModels))
	if result := validator.ValidateRequest(rules); !result.Valid {
		apiErr = validator.ToAPIError()
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, apiErr)
	}

	if len(rawBody) > security.MaxRequestBodySize {
		apiErr = api.NewAPIError(api.ErrCodeInvalidRequest, "请求体过大", api.ErrorTypeInvalidRequest)
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.CloseMessageTooBig, apiErr.Message, apiErr)
	}
	if err := security.ValidateModelName(model); err != nil {
		apiErr = api.NewAPIError(api.ErrCodeInvalidParameter, "model 参数无效", api.ErrorTypeInvalidRequest)
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, err)
	}
	if h.inspectPromptFilterOpenAIForWebSocket(c, conn, rawBody, "/v1/responses", model) {
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, "prompt blocked", nil)
	}
	promptDecision, _ := promptRiskDecisionFromContext(c)

	rawBody = normalizeServiceTierField(rawBody)
	rawBody, historyRepair := normalizeResponsesFunctionCallHistory(rawBody)
	c.Set("raw_body", rawBody)
	if historyRepair.DroppedCalls > 0 {
		log.Printf("已清理 Responses 历史空函数名项 (endpoint=/v1/responses websocket calls=%d outputs=%d)", historyRepair.DroppedCalls, historyRepair.DroppedOutputs)
	}
	if err := ValidateResponsesFunctionNames(rawBody); err != nil {
		apiErr = api.NewAPIError(api.ErrCodeInvalidParameter, err.Error(), api.ErrorTypeInvalidRequest)
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, err)
	}

	sessionIdentity := resolveRequestSessionIdentity(c.Request.Header, rawBody)
	apiKeyID := requestAPIKeyID(c)
	h.loadResponseRouteOwner(c, rawBody)
	h.loadEncryptedContextAffinity(c, rawBody)
	affinityKey := sessionAffinityKey(resolveSchedulerAffinityID(c.Request.Header, rawBody), apiKeyID)
	respCacheOwner := responseCacheOwner(apiKeyID)
	reasoningEffort := extractReasoningEffort(rawBody)
	serviceTier := extractServiceTier(rawBody)
	if serviceTier != "" {
		c.Set("x-service-tier", resolveServiceTier("", serviceTier))
	}

	codexBody, expandedInputRaw := PrepareResponsesWebSocketBody(rawBody)
	if err := validateResponsesImageGenerationSizes(codexBody); err != nil {
		apiErr = api.NewAPIError(api.ErrCodeInvalidParameter, err.Error(), api.ErrorTypeInvalidRequest)
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, err)
	}
	effectiveModel := effectiveRequestModel(codexBody, model)
	logEffectiveModel := usageEffectiveModelForMapping(logModel, effectiveModel, mappingApplied)
	if status, msg := h.enforceAPIKeyLimits(c, effectiveModel); status != 0 {
		errType := api.ErrorTypeRateLimit
		errCode := api.ErrCodeRateLimitReached
		closeCode := websocket.CloseTryAgainLater
		if status == http.StatusForbidden {
			errType = api.ErrorTypePermission
			errCode = api.ErrCodeInvalidRequest
			closeCode = websocket.ClosePolicyViolation
		}
		apiErr = api.NewAPIError(errCode, msg, errType)
		_ = writeResponsesWSError(conn, apiErr)
		return newResponsesWSCloseError(closeCode, apiErr.Message, apiErr)
	}
	releaseAPIKeyConcurrency, concurrencyErr, ok := h.acquireAPIKeyConcurrencyForWebSocket(c)
	if !ok {
		_ = writeResponsesWSError(conn, concurrencyErr)
		return newResponsesWSCloseError(websocket.CloseTryAgainLater, concurrencyErr.Message, concurrencyErr)
	}
	if releaseAPIKeyConcurrency != nil {
		defer releaseAPIKeyConcurrency()
	}

	accountFilter := accountFilterForModel(effectiveModel)
	relayCfg := h.cybRelayConfig()
	if promptDecision.routesToCybRelay() || (relayCfg.Enabled && relayCfg.GroupID > 0) {
		allowCodexAccounts := modelIDInList(effectiveModel, SupportedModelIDs(c.Request.Context(), h.db))
		accountFilter = accountFilterForResponsesModelWithOriginal(logModel, effectiveModel, allowCodexAccounts)
	}
	accountFilter = h.withModelCooldownFilter(effectiveModel, accountFilter)

	wsRetrySettings := CurrentRuntimeSettings()
	hideUpstreamErrors := wsRetrySettings.CodexWSHideErrors
	silentRetryEnabled := wsRetrySettings.CodexWSSilentRetry
	maxRetries := wsRetrySettings.CodexWSSilentRetries
	if !silentRetryEnabled {
		maxRetries = 0
	}
	maxRateLimitRetries := maxRetries
	generalRetries := 0
	rateLimitRetries := 0
	var lastStatusCode int
	var lastBody []byte
	var lastRetryableUpstreamErr *api.APIError
	lastFailureWasRelay := false
	var pendingFinalFailure *retryAttemptUsageSpec
	retryExclusions := newRetryAccountExclusions()
	routeRequirement := promptDecision
	invalidEncryptedContentRetried := false
	var wsHTTPFallback websocketHTTPFallbackState
	registerWebsocketHTTPFallbackAuditState(c, &wsHTTPFallback)
	var requestStickyRetry requestStickyRetryState
	var lastUpstreamCancel context.CancelFunc
	defer func() {
		if lastUpstreamCancel != nil {
			lastUpstreamCancel()
		}
	}()

	for attempt := 0; ; attempt++ {
		account, stickyProxyURL, circuitAttempt, selectedDecision, retainedHTTPFallback := wsHTTPFallback.TakeRouted()
		if !retainedHTTPFallback {
			selectionFilter := requestStickyRetry.AccountFilter(accountFilter)
			account, stickyProxyURL, selectedDecision, circuitAttempt = h.nextCircuitPermittedRoutedAccountForSession(c, affinityKey, apiKeyID, retryExclusions, selectionFilter, routeRequirement)
			requestStickyRetry.Apply(account, &stickyProxyURL)
		}
		if releaseRoutedAttemptIfContextDone(c.Request.Context(), h.store, account, circuitAttempt) {
			return errResponsesWSClientGone
		}
		promptDecision = selectedDecision
		if account == nil {
			if c.Request.Context().Err() != nil {
				return errResponsesWSClientGone
			}
			var logDeliveredFailure func()
			closeCode := websocket.CloseTryAgainLater
			if routeErr, ok := routeSelectionErrorFromContext(c); ok {
				spec := routeSelectionFailureSpecFor(routeErr)
				apiErr = routeSelectionAPIError(routeErr, spec)
				closeCode = spec.WebSocketCloseCode
				logDeliveredFailure = func() {
					h.logRouteSelectionError(c, "/v1/responses", logModel, logEffectiveModel, true, true, attempt, routeErr, spec)
				}
			} else if lastFailureWasRelay && lastRetryableUpstreamErr != nil {
				apiErr = responsesWSClientUpstreamAPIError(lastRetryableUpstreamErr, hideUpstreamErrors)
				logDeliveredFailure = func() { h.logPendingFinalFailure(c, pendingFinalFailure) }
			} else if lastFailureWasRelay && lastStatusCode > 0 && len(lastBody) > 0 {
				apiErr = responsesWSUpstreamAPIError(lastStatusCode, lastBody)
				logDeliveredFailure = func() { h.logPendingFinalFailure(c, pendingFinalFailure) }
			} else if routeRequirement.routesToCybRelay() {
				if err := writeCybRelayUnavailableWebSocket(conn); err != nil {
					return errResponsesWSClientGone
				}
				h.logCybRelayUnavailable(c, "/v1/responses", logModel, logEffectiveModel, true, true, attempt)
				return newResponsesWSCloseError(closeCode, "CYB relay unavailable", nil)
			} else if lastRetryableUpstreamErr != nil {
				apiErr = responsesWSClientUpstreamAPIError(lastRetryableUpstreamErr, hideUpstreamErrors)
				logDeliveredFailure = func() { h.logPendingFinalFailure(c, pendingFinalFailure) }
			} else if lastStatusCode > 0 && len(lastBody) > 0 {
				apiErr = responsesWSUpstreamAPIError(lastStatusCode, lastBody)
				logDeliveredFailure = func() { h.logPendingFinalFailure(c, pendingFinalFailure) }
			} else {
				apiErr = api.NewAPIError(api.ErrCodeServiceUnavailable, noAvailableAccountMessage(effectiveModel), api.ErrorTypeServer)
				logDeliveredFailure = func() {
					h.logPendingFinalFailureAs(c, pendingFinalFailure, http.StatusServiceUnavailable, ErrorCodeNoAvailableAccount, noAvailableAccountMessage(effectiveModel))
				}
			}
			if err := writeResponsesWSError(conn, apiErr); err != nil {
				return errResponsesWSClientGone
			}
			if logDeliveredFailure != nil {
				logDeliveredFailure()
			}
			return newResponsesWSCloseError(closeCode, apiErr.Message, apiErr)
		}
		lastFailureWasRelay = false
		lastStatusCode = 0
		lastBody = nil
		lastRetryableUpstreamErr = nil
		if encryptedContextNeedsDowngrade(c) {
			repairedRawBody, repair, repairErr := h.repairEncryptedContextForAccountSwitch(c, rawBody)
			if repairErr != nil {
				circuitAttempt.Release(h.store, account)
				apiErr = api.NewAPIError(api.ErrCodeInvalidRequest, repairErr.Error(), api.ErrorTypeInvalidRequest)
				if err := writeResponsesWSError(conn, apiErr); err != nil {
					return errResponsesWSClientGone
				}
				h.logPendingFinalFailureAs(c, pendingFinalFailure, http.StatusBadRequest, "invalid_encrypted_content", repairErr.Error())
				return newResponsesWSCloseError(websocket.ClosePolicyViolation, apiErr.Message, repairErr)
			}
			rawBody = repairedRawBody
			codexBody, expandedInputRaw = PrepareResponsesWebSocketBody(rawBody)
			log.Printf("encrypted context owner unavailable or conflicted; downgraded before WebSocket routing (dropped=%d converted=%d)", repair.Dropped, repair.Converted)
		}

		start := time.Now()
		proxyURL := h.resolveProxyForAttempt(account, stickyProxyURL)
		if !retainedHTTPFallback {
			h.store.BindSessionAffinity(affinityKey, account, proxyURL)
		}
		setUpstreamAccountContext(c, account)
		attemptEffectiveModel := effectiveModel
		attemptLogEffectiveModel := logEffectiveModel
		if wsHTTPFallback.ForceHTTP() {
			log.Printf("Responses WebSocket upstream HTTP fallback attempt started (fallback_id=%s, source=%s, attempt=%d, account=%d, ws_elapsed_ms=%d)", wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsHTTPFallback.WSElapsed().Milliseconds())
		}

		apiKey := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
		deviceCfg := h.deviceCfg
		if deviceCfg == nil {
			deviceCfg = &DeviceProfileConfig{StabilizeDeviceProfile: false}
		}
		downstreamHeaders := c.Request.Header.Clone()

		if lastUpstreamCancel != nil {
			lastUpstreamCancel()
		}
		upstreamCtx, upstreamCancel := newDrainableUpstreamContext(c.Request.Context(), upstreamDrainTimeout)
		lastUpstreamCancel = upstreamCancel
		ttftGuard := newFirstTokenTimeoutGuard(currentFirstTokenTimeout(), upstreamCancel)
		useWebsocket := !wsHTTPFallback.ForceHTTP() && !account.IsOpenAIResponsesAPI()
		// 生图请求改走 HTTP 上游（客户端仍是 WS）：WebSocket 上游传输大体积
		// 图片数据会卡死（issue #220）；自然语言生图意图也需保留图片工具（issue #288）。
		if useWebsocket && rawResponsesBodyShouldForceHTTPForImageGeneration(rawBody) {
			useWebsocket = false
		}
		// WebSocket 上游下剥离自动注入的图片工具，防止模型自主生图卡死。
		upstreamBody := codexBody
		if account.IsOpenAIResponsesAPI() {
			relayBody, deleteErr := sjson.DeleteBytes(rawBody, "type")
			if deleteErr == nil {
				upstreamBody = PrepareOpenAIResponsesBody(relayBody)
			} else {
				upstreamBody = PrepareOpenAIResponsesBody(rawBody)
			}
			if mappedBody, mappedModel, ok := h.applyAccountModelMappingToBodyForModels(upstreamBody, account, logModel, effectiveModel); ok {
				upstreamBody = mappedBody
				attemptEffectiveModel = mappedModel
				attemptLogEffectiveModel = usageEffectiveModelForMapping(logModel, attemptEffectiveModel, true)
			}
		} else if useWebsocket {
			upstreamBody = stripResponsesImageGenerationTool(codexBody)
		}
		// 在 useWebsocket 最终确定后再派生上游身份键：与 handler.go 的
		// Responses/ChatCompletions 路径一致——无显式会话默认每请求隔离上游身份，
		// WS 路径交给 ExecuteRequest 的 stateless 槽位池处理。
		upstreamSessionID := resolveUpstreamSessionID(apiKeyID, sessionIdentity.upstreamSeed, sessionIdentity.explicitUpstreamID, useWebsocket)
		var resp *http.Response
		var reqErr error
		if releaseRoutedAttemptIfContextDone(c.Request.Context(), h.store, account, circuitAttempt) {
			ttftGuard.Stop()
			upstreamCancel()
			return errResponsesWSClientGone
		}
		if account.IsOpenAIResponsesAPI() {
			resp, reqErr = ExecuteOpenAIResponsesRequest(upstreamCtx, account, upstreamBody, proxyURL, downstreamHeaders)
		} else {
			resp, reqErr = ExecuteRequest(upstreamCtx, account, upstreamBody, upstreamSessionID, proxyURL, apiKey, deviceCfg, downstreamHeaders, useWebsocket)
		}
		durationMs := int(time.Since(start).Milliseconds())

		if reqErr != nil {
			timedOut := ttftGuard.TimedOut()
			ttftGuard.Stop()
			localContentionKind := websocketLocalContentionKind(reqErr)
			localContention := useWebsocket && localContentionKind != ""
			fallbackEligibleLocalContention := c.Request.Context().Err() == nil && shouldFallbackWebsocketLocalContentionToHTTP(reqErr, useWebsocket, rawBody, sessionIdentity)
			clientContextErr := c.Request.Context().Err()
			clientGone := clientContextErr != nil
			if clientGone && requestErrorCausedByClientContext(clientContextErr, reqErr) {
				circuitAttempt.Release(h.store, account)
				return errResponsesWSClientGone
			}
			if timedOut {
				reqErr = firstTokenTimeoutError(currentFirstTokenTimeout())
			}
			kind := classifyTransportFailure(reqErr)
			if wsHTTPFallback.ForceHTTP() && !useWebsocket {
				wsHTTPFallback.LogHTTPAttemptCompletion("/v1/responses", account.ID(), attempt+1, durationMs, 0, logStatusUpstreamStreamBreak)
			}
			fallbackLocalContention := !timedOut && fallbackEligibleLocalContention
			if useWebsocket && (kind == upstreamErrorKindMessageTooBig || fallbackLocalContention) {
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
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
				log.Printf("Responses WebSocket upstream fallback to HTTP; retaining account lease (fallback_id=%s, source=%s, attempt=%d, account=%d, ws_elapsed_ms=%d): %v", wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsElapsed.Milliseconds(), reqErr)
				continue
			}
			retryable := shouldRetryTransportFailure(reqErr, kind)
			if localContention && !fallbackEligibleLocalContention {
				retryable = false
			}
			shouldRetry := false
			if silentRetryEnabled && retryable && attempt < maxRetries {
				shouldRetry = shouldRetryRequestError(reqErr, &generalRetries, maxRetries)
			}
			requestFailureSpec := retryAttemptUsageSpec{
				AccountID:            account.ID(),
				Endpoint:             "/v1/responses",
				Model:                logModel,
				EffectiveModel:       attemptLogEffectiveModel,
				DurationMs:           durationMs,
				ReasoningEffort:      reasoningEffort,
				UpstreamEndpoint:     "/v1/responses",
				Stream:               true,
				ViaWebsocket:         useWebsocket,
				RequestedServiceTier: serviceTier,
				Attempt:              attempt,
			}
			relayRequestFailure := selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI() &&
				kind != "" && kind != upstreamErrorKindMessageTooBig && c.Request.Context().Err() == nil
			terminalRequestFailure := !shouldRetry && kind != "" && kind != upstreamErrorKindMessageTooBig && c.Request.Context().Err() == nil
			if shouldRetry && kind != "" && kind != upstreamErrorKindMessageTooBig && c.Request.Context().Err() == nil {
				pending := canonicalRequestFailureSpecWithKind(requestFailureSpec, reqErr, localContentionKind)
				pendingFinalFailure = rememberPendingFinalFailure(c, pending)
				// The TTFT timeout path continues below before reaching the generic
				// retry block. Preserve whether this attempt was a required Relay
				// failure now, otherwise a subsequent pool-exhaustion decision can
				// overwrite the real upstream failure with relay_route_unavailable.
				lastFailureWasRelay = relayRequestFailure
				if relayRequestFailure {
					lastStatusCode = pending.StatusCode
					lastBody = upstreamFailureBody(pending.ErrorMessage)
				} else {
					lastStatusCode = 0
					lastBody = nil
				}
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
			// Preserve sticky retries for non-Relay accounts only. Relay transport
			// failure must rotate away from the failed front door.
			stickyRetry := shouldRetry && !localContention && !timedOut && kind != "" && h.stickyTransportRetryEnabled() && !relayTransportFailure
			if !localContention && shouldPenalizeTransportFailure(kind) && !(timedOut && shouldRetry) && !stickyRetry {
				h.store.ReportRequestFailure(account, kind, time.Duration(durationMs)*time.Millisecond)
			}
			if stickyRetry {
				requestStickyRetry.Retain(account, proxyURL)
			}
			circuitAttempt.Release(h.store, account)
			if !stickyRetry && (!localContention || (timedOut && fallbackEligibleLocalContention)) {
				h.store.UnbindSessionAffinity(affinityKey, account.ID())
			}
			if clientGone {
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					StatusCode:           relayTransportFailureAuditStatus(relayTransportFailure),
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    localContentionKind,
				}, reqErr, timedOut)
				return errResponsesWSClientGone
			}
			writeTerminalRequestFailure := func(closeCode int) error {
				apiErr = api.NewAPIError(api.ErrCodeUpstreamError, reqErr.Error(), api.ErrorTypeUpstream)
				clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
				if err := writeResponsesWSError(conn, clientErr); err != nil {
					hiddenSpec := requestFailureSpec
					hiddenSpec.StatusCode = relayTransportFailureAuditStatus(relayTransportFailure)
					h.logRetryRequestErrorFailure(c, hiddenSpec, reqErr, timedOut)
					return errResponsesWSClientGone
				}
				if terminalRequestFailure {
					h.logFinalRequestErrorFailureWithKind(c, requestFailureSpec, reqErr, localContentionKind)
				}
				return newResponsesWSCloseError(closeCode, clientErr.Message, reqErr)
			}
			if timedOut && shouldRetry {
				retryExclusions.MarkSoftFirstTokenTimeout(account.ID())
				log.Printf("Responses WebSocket upstream first token timeout, retrying with another account (attempt %d/%d, account %d): %v", attempt+1, maxRetries+1, account.ID(), reqErr)
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    localContentionKind,
				}, reqErr, true)
				continue
			}
			if !localContention && !timedOut && !stickyRetry {
				retryExclusions.MarkHard(account.ID())
			}

			if !retryable {
				return writeTerminalRequestFailure(websocket.CloseInternalServerErr)
			}
			log.Printf("Responses WebSocket upstream request failed (attempt %d): %v", attempt+1, reqErr)
			lastRetryableUpstreamErr = api.NewAPIError(api.ErrCodeUpstreamError, reqErr.Error(), api.ErrorTypeUpstream)
			if shouldRetry {
				lastFailureWasRelay = relayRequestFailure
				if !lastFailureWasRelay {
					lastStatusCode = 0
					lastBody = nil
				}
				if stickyRetry {
					log.Printf("传输错误粘滞重试：保留账号 %d 与会话亲和 (attempt %d/%d, ws)", account.ID(), attempt+1, maxRetries+1)
				}
				h.logRetryRequestErrorFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
				}, reqErr, false)
				if !h.waitBeforeRetry(c.Request.Context()) {
					return errResponsesWSClientGone
				}
				continue
			}
			return writeTerminalRequestFailure(websocket.CloseTryAgainLater)
		}

		if resp.StatusCode != http.StatusOK {
			ttftGuard.Stop()
			if wsHTTPFallback.ForceHTTP() && !useWebsocket {
				wsHTTPFallback.LogHTTPAttemptCompletion("/v1/responses", account.ID(), attempt+1, durationMs, 0, resp.StatusCode)
			}
			errBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			clientGone := c.Request.Context().Err() != nil

			if !clientGone && !invalidEncryptedContentRetried && isInvalidEncryptedContentError(resp.StatusCode, errBody) {
				repairedRawBody, repair := repairInvalidEncryptedContentFromResponsesBody(rawBody)
				if repair.Changed && !repair.InputEmpty {
					h.invalidateEncryptedContextBindings(c)
					invalidEncryptedContentRetried = true
					rawBody = repairedRawBody
					codexBody, expandedInputRaw = PrepareResponsesWebSocketBody(rawBody)
					log.Printf("Responses WebSocket upstream rejected encrypted_content; repaired encrypted history and retried once (attempt %d, dropped=%d converted=%d)", attempt+1, repair.Dropped, repair.Converted)
					repairFailure := retryAttemptUsageSpec{
						AccountID:            account.ID(),
						Endpoint:             "/v1/responses",
						Model:                logModel,
						EffectiveModel:       attemptLogEffectiveModel,
						StatusCode:           resp.StatusCode,
						DurationMs:           durationMs,
						ReasoningEffort:      reasoningEffort,
						UpstreamEndpoint:     "/v1/responses",
						Stream:               true,
						ViaWebsocket:         useWebsocket,
						RequestedServiceTier: serviceTier,
						Attempt:              attempt,
						UpstreamErrorKind:    upstreamErrorKind(resp.StatusCode, errBody, codex429Decision{}),
						ErrorMessage:         usageLogErrorMessage(resp.StatusCode, errBody),
					}
					h.logRetryAttemptFailure(c, repairFailure)
					pendingFinalFailure = rememberPendingFinalFailure(c, repairFailure)
					lastRetryableUpstreamErr = nil
					lastFailureWasRelay = false
					lastStatusCode = 0
					lastBody = nil
					circuitAttempt.Release(h.store, account)
					h.store.UnbindSessionAffinity(affinityKey, account.ID())
					continue
				}
			}

			if kind := classifyHTTPFailure(resp.StatusCode); kind != "" {
				h.store.ReportRequestFailure(account, kind, time.Duration(durationMs)*time.Millisecond)
			}
			SyncCodexUsageState(h.store, account, resp)
			circuitAttempt.Failure(resp.StatusCode)
			circuitAttempt.Release(h.store, account)
			h.store.UnbindSessionAffinity(affinityKey, account.ID())
			retryExclusions.MarkHard(account.ID())

			log.Printf("Responses WebSocket upstream returned error (attempt %d, status %d): %s", attempt+1, resp.StatusCode, upstreamErrorConsoleBody(errBody))
			logUpstreamError("/v1/responses", resp.StatusCode, logModel, account.ID(), errBody)
			h.logUpstreamCyberPolicy(c, "/v1/responses", logModel, errBody)
			decision := h.applyCooldownForModel(account, resp.StatusCode, errBody, resp, attemptEffectiveModel)
			shouldRetry := false
			if silentRetryEnabled && attempt < maxRetries {
				shouldRetry = shouldRetryTextHTTPStatus(resp.StatusCode, account, &generalRetries, &rateLimitRetries, maxRetries, maxRateLimitRetries)
			}
			usageTiers := resolveUsageServiceTiers("", serviceTier)
			relayFailure := selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI()
			failureKind := upstreamErrorKind(resp.StatusCode, errBody, decision)
			failureMessage := usageLogErrorMessage(resp.StatusCode, errBody)
			var finalCloseErr error
			if !shouldRetry && !clientGone {
				apiErr = responsesWSUpstreamAPIError(resp.StatusCode, errBody)
				clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
				if err := writeResponsesWSError(conn, clientErr); err != nil {
					clientGone = true
				} else {
					finalCloseErr = newResponsesWSCloseError(websocket.CloseTryAgainLater, clientErr.Message, apiErr)
				}
			}
			h.logUsageForRequest(c, &database.UsageLogInput{
				AccountID:            account.ID(),
				Endpoint:             "/v1/responses",
				Model:                logModel,
				EffectiveModel:       attemptLogEffectiveModel,
				StatusCode:           resp.StatusCode,
				DurationMs:           durationMs,
				ReasoningEffort:      reasoningEffort,
				InboundEndpoint:      "/v1/responses",
				UpstreamEndpoint:     "/v1/responses",
				Stream:               true,
				ViaWebsocket:         useWebsocket,
				ServiceTier:          usageTiers.ServiceTier,
				RequestedServiceTier: usageTiers.RequestedServiceTier,
				ActualServiceTier:    usageTiers.ActualServiceTier,
				BillingServiceTier:   usageTiers.BillingServiceTier,
				IsRetryAttempt:       attempt > 0,
				AttemptIndex:         attempt + 1,
				UpstreamErrorKind:    failureKind,
				ErrorMessage:         failureMessage,
				GuardianAttemptOnly:  shouldRetry || clientGone,
			})

			if clientGone {
				return errResponsesWSClientGone
			}
			if shouldRetry {
				lastStatusCode = resp.StatusCode
				lastBody = errBody
				lastRetryableUpstreamErr = responsesWSUpstreamAPIError(resp.StatusCode, errBody)
				lastFailureWasRelay = relayFailure
				pendingFinalFailure = rememberPendingFinalFailure(c, retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					StatusCode:           resp.StatusCode,
					DurationMs:           durationMs,
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
					UpstreamErrorKind:    failureKind,
					ErrorMessage:         failureMessage,
				})
				if !h.waitBeforeRetry(c.Request.Context()) {
					return errResponsesWSClientGone
				}
				continue
			}

			return finalCloseErr
		}
		transparentRetryAllowed := silentRetryEnabled && attempt < maxRetries
		var fallbackLog *websocketHTTPFallbackState
		if wsHTTPFallback.ForceHTTP() && !useWebsocket {
			fallbackLog = &wsHTTPFallback
		}
		if err := h.streamResponsesWSUpstream(c, conn, resp, account, circuitAttempt, proxyURL, affinityKey, logModel, attemptEffectiveModel, attemptLogEffectiveModel, reasoningEffort, serviceTier, respCacheOwner, expandedInputRaw, start, attempt, ttftGuard, transparentRetryAllowed, hideUpstreamErrors, useWebsocket, fallbackLog, attempt+1, terminalPublication); err != nil {
			var retryErr *responsesWSRetryableStreamError
			if errors.As(err, &retryErr) {
				if useWebsocket && isWebsocketMessageTooBigOutcome(retryErr.outcome) {
					wsElapsed := time.Since(start)
					wsHTTPFallback.RetainRouted(account, proxyURL, wsElapsed, websocketMessageTooBigSource(retryErr.outcome.failureMessage), circuitAttempt, selectedDecision)
					log.Printf("Responses WebSocket upstream close 1009 before first event; retaining account lease and falling back to HTTP (fallback_id=%s, source=%s, attempt=%d, account=%d, ws_elapsed_ms=%d): %s", wsHTTPFallback.ID(), wsHTTPFallback.Source(), attempt+1, account.ID(), wsElapsed.Milliseconds(), retryErr.outcome.failureMessage)
					continue
				}
				lastRetryableUpstreamErr = api.NewAPIError(api.ErrCodeUpstreamError, retryErr.outcome.failureMessage, api.ErrorTypeUpstream)
				lastFailureWasRelay = selectedDecision.routesToCybRelay() && account.IsOpenAIResponsesAPI()
				pending := canonicalStreamFailureSpec(retryAttemptUsageSpec{
					AccountID:            account.ID(),
					Endpoint:             "/v1/responses",
					Model:                logModel,
					EffectiveModel:       attemptLogEffectiveModel,
					DurationMs:           int(time.Since(start).Milliseconds()),
					ReasoningEffort:      reasoningEffort,
					UpstreamEndpoint:     "/v1/responses",
					Stream:               true,
					ViaWebsocket:         useWebsocket,
					RequestedServiceTier: serviceTier,
					Attempt:              attempt,
				}, retryErr.outcome)
				pendingFinalFailure = rememberPendingFinalFailure(c, pending)
				if lastFailureWasRelay {
					lastStatusCode = pending.StatusCode
					lastBody = upstreamFailureBody(pending.ErrorMessage)
				} else {
					lastStatusCode = 0
					lastBody = nil
				}
				if transparentRetryAllowed {
					if isFirstTokenTimeoutOutcome(retryErr.outcome) {
						retryExclusions.MarkSoftFirstTokenTimeout(account.ID())
					} else {
						retryExclusions.MarkHard(account.ID())
					}
					log.Printf("Responses WebSocket upstream stream ended before first token, retrying (attempt %d/%d, account %d): %s", attempt+1, maxRetries+1, account.ID(), retryErr.outcome.failureMessage)
					// 首字超时已白等一轮,不再叠加重试间隔;其余首包前断流按配置间隔等待
					if !isFirstTokenTimeoutOutcome(retryErr.outcome) && !h.waitBeforeRetry(c.Request.Context()) {
						return errResponsesWSClientGone
					}
					continue
				}
				apiErr = api.NewAPIError(api.ErrCodeUpstreamError, retryErr.outcome.failureMessage, api.ErrorTypeUpstream)
				clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
				_ = writeResponsesWSError(conn, clientErr)
				return newResponsesWSCloseError(websocket.CloseTryAgainLater, clientErr.Message, apiErr)
			}
			if errors.Is(err, errResponsesWSClientGone) {
				return err
			}
			if shouldRetryErr, ok := err.(*responsesWSCloseError); ok && shouldRetryErr.code == websocket.CloseTryAgainLater {
				h.store.UnbindSessionAffinity(affinityKey, account.ID())
			}
			return err
		}
		return nil
	}
}

func (h *Handler) streamResponsesWSUpstream(
	c *gin.Context,
	conn *websocket.Conn,
	resp *http.Response,
	account *auth.Account,
	circuitAttempt *relayCircuitAttempt,
	proxyURL string,
	affinityKey string,
	model string,
	effectiveModel string,
	logEffectiveModel string,
	reasoningEffort string,
	serviceTier string,
	respCacheOwner string,
	expandedInputRaw string,
	start time.Time,
	attempt int,
	ttftGuard *firstTokenTimeoutGuard,
	transparentRetryAllowed bool,
	hideUpstreamErrors bool,
	viaWebsocket bool,
	fallbackLog *websocketHTTPFallbackState,
	fallbackAttempt int,
	terminalPublications ...*responsesWSTerminalPublication,
) error {
	// Keep this helper's historical signature for direct callers. The passed
	// retry flag is attempt-specific; runtime configuration is consulted only
	// to decide whether a final retryable response.failed should be hidden and
	// rewritten as a structured error instead of leaked as a raw success frame.
	silentRetryEnabled := transparentRetryAllowed || CurrentRuntimeSettings().CodexWSSilentRetry
	SyncCodexUsageState(h.store, account, resp)

	account.Mu().RLock()
	c.Set("x-account-email", account.Email)
	account.Mu().RUnlock()
	c.Set("x-account-proxy", proxyURL)
	c.Set("x-model", model)
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
	var imageLogInfo imageUsageLogInfo
	var terminalFailurePayload []byte
	wroteAnyBody := false
	terminalDelivered := false
	markTerminalDelivered := func() {
		if terminalDelivered {
			return
		}
		terminalDelivered = true
	}
	var terminalPublication *responsesWSTerminalPublication
	if len(terminalPublications) > 0 {
		terminalPublication = terminalPublications[0]
	}
	// 首 token 前收到不可重试的 response.failed 时置位:不把原始失败帧透传给客户端,
	// 循环外改写 error 帧并按错误类别用非正常 close code 关闭,
	// 让下游中转/计费方明确感知失败,而不是把它当成一次正常结束的会话。
	abortedForErrorClose := false
	pendingFirstTokenMessages := make([][]byte, 0, 4)
	pendingFirstTokenBytes := 0
	encryptedCapture := newEncryptedContextCapture(requestAPIKeyID(c))

	flushPendingFirstTokenMessages := func() bool {
		for _, pending := range pendingFirstTokenMessages {
			if err := writeResponsesWSMessage(conn, pending); err != nil {
				writeErr = err
				clientGone = true
				return false
			}
			wroteAnyBody = true
		}
		pendingFirstTokenMessages = pendingFirstTokenMessages[:0]
		pendingFirstTokenBytes = 0
		return true
	}

	readErr = ReadSSEStream(resp.Body, func(data []byte) bool {
		encryptedCapture.Observe(data)
		parsed := gjson.ParseBytes(data)
		eventType := parsed.Get("type").String()
		if c.Request.Context().Err() != nil {
			clientGone = true
		}
		ttftGuard.MarkProgress(eventType)
		isFirstToken := isFirstTokenResultForMode(parsed, currentFirstTokenMode())
		if !ttftRecorded && isFirstToken {
			firstTokenMs = int(time.Since(start).Milliseconds())
			ttftRecorded = true
		}
		if eventType == "response.output_text.delta" {
			deltaCharCount += len(parsed.Get("delta").String())
		}
		if image, ok := extractImageFromOutputItemDone(data, model); ok {
			imageLogInfo = mergeImageUsageLogInfo(imageLogInfo, imageUsageLogInfoFromImage(image))
		}
		if eventType == "response.completed" {
			h.commitEncryptedContextCapture(account, encryptedCapture)
		}
		if eventType == "response.completed" || eventType == "response.incomplete" {
			h.pinCybRelayResponseID(c, data)
			usage = extractUsageFromResult(parsed.Get("response.usage"))
			if tier := parsed.Get("response.service_tier").String(); tier != "" {
				actualServiceTier = tier
			}
			if eventType == "response.completed" {
				cacheCompletedResponse(respCacheOwner, []byte(expandedInputRaw), data)
			}
			gotTerminal = true
		}
		if eventType == "response.failed" {
			terminalFailurePayload = append([]byte(nil), data...)
			gotTerminal = true
		}
		if !clientGone {
			shouldDefer := !ttftRecorded && !gotTerminal && isPreContentLifecycleEvent(eventType)
			if shouldDefer {
				pendingFirstTokenMessages = append(pendingFirstTokenMessages, append([]byte(nil), data...))
				pendingFirstTokenBytes += len(data)
				if pendingFirstTokenBytes <= 1024*1024 {
					return eventType != "response.completed" && eventType != "response.failed"
				}
				if !flushPendingFirstTokenMessages() {
					return false
				}
			} else {
				// 首包前收到可重试的 response.failed（额度耗尽/限流/5xx/401）时，
				// 不把失败帧下发给客户端：丢弃尚未发送的前导缓冲并提前结束读取，
				// 让外层循环透明换到健康账号重试，避免客户端反复 Reconnecting。
				// 已经向客户端写过内容（wroteAnyBody / 已记录首 token）则照常透传。
				if (silentRetryEnabled || hideUpstreamErrors) && eventType == "response.failed" && !ttftRecorded && !wroteAnyBody && responseFailedRetryable(terminalFailurePayload) {
					pendingFirstTokenMessages = pendingFirstTokenMessages[:0]
					pendingFirstTokenBytes = 0
					if !transparentRetryAllowed {
						abortedForErrorClose = true
					}
					return false
				}
				// 首 token 前的不可重试 response.failed(如 context_length_exceeded)
				// 不透传原始失败帧:丢弃前导缓冲并提前结束读取,循环外按真实错误
				// 语义返回 error 帧 + 非正常 close code(与 SSE 路径返回 4xx 对齐)。
				// 可重试的失败不在此拦截:silent retry 开启时由上面的分支换号重试,
				// 关闭时按既有约定原样透传失败帧。
				if shouldReturnHTTPErrorForResponseFailed(eventType, ttftRecorded, wroteAnyBody, clientGone) &&
					!responseFailedRetryable(terminalFailurePayload) {
					pendingFirstTokenMessages = pendingFirstTokenMessages[:0]
					pendingFirstTokenBytes = 0
					abortedForErrorClose = true
					return false
				}
				if len(pendingFirstTokenMessages) > 0 && !flushPendingFirstTokenMessages() {
					return false
				}
				terminalEvent := isResponsesTerminalEventType(eventType)
				if terminalEvent {
					terminalPublication.Begin()
				}
				err := writeResponsesWSMessage(conn, data)
				if hooks := responsesWSTestHooks.Load(); terminalEvent && err == nil && hooks != nil && hooks.terminalWriteCommitted != nil {
					hooks.terminalWriteCommitted()
				}
				if terminalEvent {
					terminalPublication.Finish(err == nil)
				}
				if err != nil {
					writeErr = err
					clientGone = true
				} else {
					wroteAnyBody = true
					if terminalEvent {
						markTerminalDelivered()
						if hooks := responsesWSTestHooks.Load(); hooks != nil && hooks.postTerminalBookkeeping != nil {
							hooks.postTerminalBookkeeping()
						}
					}
				}
			}
		}
		return !isResponsesTerminalEventType(eventType)
	})

	totalDuration := int(time.Since(start).Milliseconds())
	outcome := classifyStreamOutcome(c.Request.Context().Err(), readErr, writeErr, gotTerminal)
	if ttftGuard.TimedOut() && !ttftRecorded && !gotTerminal {
		outcome = firstTokenTimeoutOutcome(currentFirstTokenTimeout())
	}
	ttftGuard.Stop()
	if outcome.verifyAccountAuth {
		h.store.VerifyAccountAuthAsync(account)
	}
	var responseFailedDecision codex429Decision
	if len(terminalFailurePayload) > 0 {
		outcome = classifyResponseFailedOutcome(terminalFailurePayload)
		responseFailedDecision = h.applyResponseFailedCooldown(account, terminalFailurePayload, resp, effectiveModel)
		if responseFailedDecision.Reason != "" {
			outcome.failureKind = upstreamErrorKind(outcome.logStatusCode, responseFailedErrorBody(terminalFailurePayload), responseFailedDecision)
		}
		// 流式 response.failed（HTTP 200）里的 cyber_policy 处罚也要记录，
		// 否则只有非 2xx 错误体才会被记入提示词过滤日志。
		h.logUpstreamCyberPolicy(c, "/v1/responses", model, responseFailedErrorBody(terminalFailurePayload))
	}
	// A client may send its normal Close immediately after receiving the terminal
	// event.  Once that event was delivered, the logical request is canonical;
	// a later close must not retroactively hide the success/failure row.
	clientGoneFinal := !terminalDelivered && (clientGone || c.Request.Context().Err() != nil || writeErr != nil)
	if fallbackLog != nil {
		fallbackLog.LogHTTPAttemptCompletion("/v1/responses", account.ID(), fallbackAttempt, totalDuration, firstTokenMs, outcome.logStatusCode)
	}
	if shouldFallbackWebsocketMessageTooBigToHTTP(outcome, viaWebsocket, wroteAnyBody, c.Request.Context().Err(), writeErr) {
		h.logTransparentStreamRetryFailure(c, retryAttemptUsageSpec{
			AccountID:            account.ID(),
			Endpoint:             "/v1/responses",
			Model:                model,
			EffectiveModel:       logEffectiveModel,
			DurationMs:           totalDuration,
			FirstTokenMs:         firstTokenMs,
			ReasoningEffort:      reasoningEffort,
			UpstreamEndpoint:     "/v1/responses",
			Stream:               true,
			ViaWebsocket:         viaWebsocket,
			RequestedServiceTier: serviceTier,
			ActualServiceTier:    actualServiceTier,
			Attempt:              attempt,
		}, outcome)
		resp.Body.Close()
		return &responsesWSRetryableStreamError{outcome: outcome}
	}
	if transparentRetryAllowed && outcome.penalize && !wroteAnyBody && c.Request.Context().Err() == nil && writeErr == nil {
		h.logTransparentStreamRetryFailure(c, retryAttemptUsageSpec{
			AccountID:            account.ID(),
			Endpoint:             "/v1/responses",
			Model:                model,
			EffectiveModel:       logEffectiveModel,
			DurationMs:           totalDuration,
			FirstTokenMs:         firstTokenMs,
			ReasoningEffort:      reasoningEffort,
			UpstreamEndpoint:     "/v1/responses",
			Stream:               true,
			ViaWebsocket:         viaWebsocket,
			RequestedServiceTier: serviceTier,
			ActualServiceTier:    actualServiceTier,
			Attempt:              attempt,
		}, outcome)
		resp.Body.Close()
		if !isFirstTokenTimeoutOutcome(outcome) {
			h.store.ReportRequestFailure(account, outcome.failureKind, time.Duration(totalDuration)*time.Millisecond)
		}
		circuitAttempt.FinishStreamOutcome(c.Request.Context(), outcome, isFirstTokenTimeoutOutcome(outcome))
		circuitAttempt.Release(h.store, account)
		h.store.UnbindSessionAffinity(affinityKey, account.ID())
		return &responsesWSRetryableStreamError{outcome: outcome}
	}
	var preparedClientCloseErr error
	if !clientGoneFinal && outcome.logStatusCode != http.StatusOK && (len(terminalFailurePayload) == 0 || !wroteAnyBody) {
		apiErr := api.NewAPIError(api.ErrCodeUpstreamError, outcome.failureMessage, api.ErrorTypeUpstream)
		clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
		closeCode := websocket.CloseInternalServerErr
		if abortedForErrorClose {
			closeCode = responsesWSCloseCodeForStatus(outcome.logStatusCode)
		} else if hideUpstreamErrors && len(terminalFailurePayload) > 0 {
			closeCode = websocket.CloseTryAgainLater
		}
		terminalPublication.Begin()
		err := writeResponsesWSError(conn, clientErr)
		if hooks := responsesWSTestHooks.Load(); err == nil && hooks != nil && hooks.terminalWriteCommitted != nil {
			hooks.terminalWriteCommitted()
		}
		terminalPublication.Finish(err == nil)
		if err != nil {
			writeErr = err
			clientGone = true
			clientGoneFinal = true
		} else {
			markTerminalDelivered()
			if hooks := responsesWSTestHooks.Load(); hooks != nil && hooks.postTerminalBookkeeping != nil {
				hooks.postTerminalBookkeeping()
			}
			preparedClientCloseErr = newResponsesWSCloseError(closeCode, clientErr.Message, apiErr)
		}
	}
	if outcome.logStatusCode != http.StatusOK {
		log.Printf("Responses WebSocket stream ended abnormally (account %d, status %d): %s, relayed about %d chars", account.ID(), outcome.logStatusCode, outcome.failureMessage, deltaCharCount)
		if deltaCharCount > 0 && usage == nil {
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
	hiddenAttempt := clientGoneFinal
	logStatusCode := canonicalStreamStatus(outcome)
	if hiddenAttempt {
		logStatusCode = outcome.logStatusCode
	}
	logInput := &database.UsageLogInput{
		AccountID:            account.ID(),
		Endpoint:             "/v1/responses",
		Model:                model,
		EffectiveModel:       logEffectiveModel,
		StatusCode:           logStatusCode,
		DurationMs:           totalDuration,
		IsRetryAttempt:       attempt > 0,
		AttemptIndex:         attempt + 1,
		FirstTokenMs:         firstTokenMs,
		ReasoningEffort:      reasoningEffort,
		InboundEndpoint:      "/v1/responses",
		UpstreamEndpoint:     "/v1/responses",
		Stream:               true,
		ViaWebsocket:         viaWebsocket,
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
	applyImageUsageLogInfo(logInput, imageLogInfo)
	h.logUsageForRequest(c, logInput)

	resp.Body.Close()
	if outcome.penalize {
		recyclePooledClient(account, proxyURL)
		h.store.ReportRequestFailure(account, outcome.failureKind, time.Duration(totalDuration)*time.Millisecond)
		h.store.UnbindSessionAffinity(affinityKey, account.ID())
	} else if outcome.logStatusCode == http.StatusOK {
		h.store.ClearModelCooldown(account, effectiveModel)
		h.store.ConfirmResponsesAvailableSince(account, start)
		h.store.ReportRequestSuccess(account, time.Duration(totalDuration)*time.Millisecond)
	}
	if outcome.logStatusCode == http.StatusOK {
		circuitAttempt.Success()
	} else {
		circuitAttempt.FinishStreamOutcome(c.Request.Context(), outcome, isFirstTokenTimeoutOutcome(outcome))
	}
	circuitAttempt.Release(h.store, account)

	if clientGoneFinal {
		return errResponsesWSClientGone
	}
	if preparedClientCloseErr != nil {
		return preparedClientCloseErr
	}
	if abortedForErrorClose && !wroteAnyBody {
		// 首 token 前上游失败且未向客户端写过任何帧:发结构化 error 帧后按错误类别
		// 关闭连接,避免下游把"正常收尾的会话"当成功并按预估 input token 计费。
		apiErr := api.NewAPIError(api.ErrCodeUpstreamError, outcome.failureMessage, api.ErrorTypeUpstream)
		clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
		_ = writeResponsesWSError(conn, clientErr)
		return newResponsesWSCloseError(responsesWSCloseCodeForStatus(outcome.logStatusCode), clientErr.Message, apiErr)
	}
	if outcome.logStatusCode != http.StatusOK && hideUpstreamErrors && len(terminalFailurePayload) > 0 && !wroteAnyBody {
		apiErr := api.NewAPIError(api.ErrCodeUpstreamError, outcome.failureMessage, api.ErrorTypeUpstream)
		clientErr := responsesWSClientUpstreamAPIError(apiErr, true)
		_ = writeResponsesWSError(conn, clientErr)
		return newResponsesWSCloseError(websocket.CloseTryAgainLater, clientErr.Message, apiErr)
	}
	if outcome.logStatusCode != http.StatusOK && len(terminalFailurePayload) == 0 {
		apiErr := api.NewAPIError(api.ErrCodeUpstreamError, outcome.failureMessage, api.ErrorTypeUpstream)
		clientErr := responsesWSClientUpstreamAPIError(apiErr, hideUpstreamErrors)
		_ = writeResponsesWSError(conn, clientErr)
		return newResponsesWSCloseError(websocket.CloseInternalServerErr, clientErr.Message, apiErr)
	}
	return nil
}

func normalizeResponsesWebSocketClientPayload(raw []byte) ([]byte, string, *api.APIError) {
	trimmed := []byte(strings.TrimSpace(string(raw)))
	if len(trimmed) == 0 {
		return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, "empty websocket request payload", api.ErrorTypeInvalidRequest)
	}
	if len(trimmed) > security.MaxRequestBodySize {
		return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, "请求体过大", api.ErrorTypeInvalidRequest)
	}
	if !gjson.ValidBytes(trimmed) {
		return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, "invalid websocket request payload", api.ErrorTypeInvalidRequest)
	}

	eventType := strings.TrimSpace(gjson.GetBytes(trimmed, "type").String())
	normalized := trimmed
	switch eventType {
	case "":
		eventType = "response.create"
		var err error
		normalized, err = sjson.SetBytes(normalized, "type", eventType)
		if err != nil {
			return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, "invalid websocket request payload", api.ErrorTypeInvalidRequest)
		}
	case "response.create":
	case "response.append":
		return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, "response.append is not supported; use response.create with previous_response_id", api.ErrorTypeInvalidRequest)
	default:
		return nil, "", api.NewAPIError(api.ErrCodeInvalidRequest, fmt.Sprintf("unsupported websocket request type: %s", eventType), api.ErrorTypeInvalidRequest)
	}

	model := strings.TrimSpace(gjson.GetBytes(normalized, "model").String())
	if model == "" {
		return nil, "", api.NewAPIError(api.ErrCodeMissingField, "model is required in response.create payload", api.ErrorTypeInvalidRequest)
	}
	previousResponseID := strings.TrimSpace(gjson.GetBytes(normalized, "previous_response_id").String())
	if strings.HasPrefix(previousResponseID, "msg_") {
		return nil, "", api.NewAPIError(api.ErrCodeInvalidParameter, "previous_response_id must be a response.id (resp_*), not a message id", api.ErrorTypeInvalidRequest)
	}

	return normalized, model, nil
}

func (h *Handler) inspectPromptFilterOpenAIForWebSocket(c *gin.Context, conn *websocket.Conn, rawBody []byte, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterPayload(rawBody, endpoint, cfg, h.cybRelayConfig().UserTextRescanEnabled())
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	return h.inspectCybRelayPrompt(c, rawBody, scan, endpoint, model)
}

func isResponsesWebSocketUpgradeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(r.Header.Get("Connection"))), "upgrade")
}

func writeResponsesWSError(conn *websocket.Conn, apiErr *api.APIError) error {
	if apiErr == nil {
		apiErr = api.NewAPIError(api.ErrCodeServerError, "Internal server error", api.ErrorTypeServer)
	}
	payload, err := json.Marshal(struct {
		Type  string        `json:"type"`
		Error *api.APIError `json:"error"`
	}{
		Type:  "error",
		Error: apiErr,
	})
	if err != nil {
		return err
	}
	return writeResponsesWSMessage(conn, payload)
}

func responsesWSClientUpstreamAPIError(apiErr *api.APIError, hideUpstreamErrors bool) *api.APIError {
	if !hideUpstreamErrors {
		return apiErr
	}
	return api.NewAPIError(api.ErrCodeUpstreamError, responsesWSFriendlyUpstreamErr, api.ErrorTypeUpstream)
}

func writeResponsesWSMessage(conn *websocket.Conn, payload []byte) error {
	if conn == nil {
		return errResponsesWSClientGone
	}
	_ = conn.SetWriteDeadline(time.Now().Add(responsesWSWriteTimeout))
	return conn.WriteMessage(websocket.TextMessage, payload)
}

func closeResponsesWS(conn *websocket.Conn, code int, reason string) {
	if conn == nil {
		return
	}
	reason = truncateWebSocketCloseReason(reason)
	msg := websocket.FormatCloseMessage(code, reason)
	_ = conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(responsesWSWriteTimeout))
}

func truncateWebSocketCloseReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) <= 120 {
		return reason
	}
	return reason[:120]
}

func newResponsesWSCloseError(code int, reason string, err error) error {
	return &responsesWSCloseError{
		code:   code,
		reason: truncateWebSocketCloseReason(reason),
		err:    err,
	}
}

// responsesWSCloseCodeForStatus 把上游失败的 HTTP 语义状态码映射为 WebSocket close code:
// 429 → 1013(稍后重试);其余 4xx 确定性客户端错误 → 1008(策略拒绝);5xx → 1011。
func responsesWSCloseCodeForStatus(statusCode int) int {
	switch {
	case statusCode == http.StatusTooManyRequests:
		return websocket.CloseTryAgainLater
	case statusCode >= 400 && statusCode < 500:
		return websocket.ClosePolicyViolation
	default:
		return websocket.CloseInternalServerErr
	}
}

func responsesWSUpstreamAPIError(statusCode int, body []byte) *api.APIError {
	message := usageLogErrorMessage(statusCode, body)
	if strings.TrimSpace(message) == "" {
		message = fmt.Sprintf("upstream returned HTTP %d", statusCode)
	}
	errCode := api.ErrCodeUpstreamError
	errType := api.ErrorTypeUpstream
	switch statusCode {
	case http.StatusTooManyRequests:
		errCode = api.ErrCodeRateLimitReached
		errType = api.ErrorTypeRateLimit
	case http.StatusUnauthorized, http.StatusForbidden:
		errCode = api.ErrCodeInvalidAuth
		errType = api.ErrorTypeAuthentication
	case http.StatusBadRequest:
		errCode = api.ErrCodeInvalidRequest
		errType = api.ErrorTypeInvalidRequest
	}
	return api.NewAPIError(errCode, message, errType)
}
