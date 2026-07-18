package wsrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var errWebsocketWriteNotStarted = errors.New("websocket request write did not start")

// ==================== WebSocket 执行器常量 ====================

const (
	// Beta header 用于启用 WebSocket 响应 API
	responsesWebsocketBetaHeader = "responses_websockets=2026-02-06"

	// Codex WebSocket 端点
	CodexWsEndpoint = "/responses"
)

const (
	websocketMaxRequestFrameBytesEnv     = "CODEX_WS_MAX_REQUEST_FRAME_BYTES"
	defaultWebsocketMaxRequestFrameBytes = 16 * 1024 * 1024
	// Keep the configurable ceiling aligned with the normal HTTP request-body
	// ceiling. A larger WS threshold could select HTTP fallback for a payload the
	// HTTP ingress/runtime cannot safely accept.
	maximumWebsocketMaxRequestFrameBytes = 48 * 1024 * 1024
)

func shouldSendWebsocketUserAgent() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CODEX_WS_SEND_USER_AGENT"))) {
	case "0", "false", "no", "n", "off":
		return false
	default:
		return true
	}
}

// statelessOneShotEnabled 是否禁用无显式会话请求的 WS 连接复用（每请求独享连接、
// 用完即毁）。这是杜绝一切连接级状态跨请求/跨用户泄漏的硬隔离逃生阀，代价是
// 逐请求握手（高 RPM 下可能触发上游握手限流 503）。
func statelessOneShotEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CODEX_WS_STATELESS_ONESHOT"))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// resolveHandshakeSessionID 决定 WS 握手头 Session_id/Conversation_id 的取值。
// 该头是逐连接冻结的：建连时发送一次，连接复用时永不更新。因此对会在多个请求
// （乃至共享同一 API Key 的多个终端用户）间复用的 stateless 连接，绝不能携带任何
// "单个请求的身份"（如每请求随机 prompt_cache_key）——若上游按连接级
// Conversation_id 绑定会话状态，第一个请求的对话身份会泄漏给后续复用该连接的
// 所有用户，造成跨用户上下文污染（issue #268/#308 同类，"用户2串到用户1的上下文"）。
//
//   - 显式会话（非 stateless）：连接按会话专用，头 = 会话 ID（原行为）。
//   - stateless + 默认隔离（poolRouteKey 非空）：返回空串 → 不发送该组头，
//     上游没有任何可绑定的连接级会话身份；逐请求身份完全由帧体内每请求唯一的
//     prompt_cache_key 承担。
//   - stateless + per-api-key 模式（poolRouteKey 为空）：沿用帧体的确定性
//     cache key（该模式显式选择按 Key 共享上游缓存，头与帧体一致才有缓存收益）。
func resolveHandshakeSessionID(sessionID, poolRouteKey string, wsBody []byte) string {
	if !proxy.IsStatelessWebsocketSessionID(sessionID) {
		return sessionID
	}
	if strings.TrimSpace(poolRouteKey) != "" {
		return ""
	}
	if cacheKey := strings.TrimSpace(gjson.GetBytes(wsBody, "prompt_cache_key").String()); cacheKey != "" {
		return cacheKey
	}
	return sessionID
}

// prepareSafePoolFrameMetadata mirrors the official Codex WebSocket client:
// values that may change between turns travel in each response.create frame,
// not in the immutable HTTP-upgrade headers of a reused socket.
func prepareSafePoolFrameMetadata(body []byte, ginHeaders http.Header) ([]byte, bool) {
	prepared := bytes.Clone(body)
	flatSessionID := strings.TrimSpace(gjson.GetBytes(prepared, "client_metadata.session_id").String())
	flatThreadID := strings.TrimSpace(gjson.GetBytes(prepared, "client_metadata.thread_id").String())

	// The nested turn metadata is canonical in the official client. Direct
	// headers are only compatibility projections and must never overwrite a
	// conflicting body identity. Semantic comparison permits harmless JSON key
	// ordering/whitespace differences while rejecting a different snapshot.
	bodyTurnMetadata := gjson.GetBytes(prepared, "client_metadata.x-codex-turn-metadata")
	headerTurnMetadata := strings.TrimSpace(ginHeaders.Get("X-Codex-Turn-Metadata"))
	var bodyCanonical []byte
	if bodyTurnMetadata.Exists() {
		if bodyTurnMetadata.Type != gjson.String {
			return body, false
		}
		var ok bool
		bodyCanonical, ok = canonicalSafePoolTurnMetadata(bodyTurnMetadata.String(), flatSessionID, flatThreadID)
		if !ok {
			return body, false
		}
	}
	if headerTurnMetadata != "" {
		headerCanonical, ok := canonicalSafePoolTurnMetadata(headerTurnMetadata, flatSessionID, flatThreadID)
		if !ok {
			return body, false
		}
		if bodyTurnMetadata.Exists() {
			if !bytes.Equal(bodyCanonical, headerCanonical) {
				return body, false
			}
		} else {
			var err error
			prepared, err = sjson.SetBytes(prepared, "client_metadata.x-codex-turn-metadata", headerTurnMetadata)
			if err != nil {
				return body, false
			}
		}
	}

	for _, mapping := range []struct {
		header string
		key    string
	}{
		{header: "X-Codex-Turn-State", key: "x-codex-turn-state"},
		{header: "Traceparent", key: "ws_request_header_traceparent"},
		{header: "Tracestate", key: "ws_request_header_tracestate"},
	} {
		if value := strings.TrimSpace(ginHeaders.Get(mapping.header)); value != "" {
			path := "client_metadata." + mapping.key
			if existing := gjson.GetBytes(prepared, path); existing.Exists() && strings.TrimSpace(existing.String()) != value {
				return body, false
			}
			var err error
			prepared, err = sjson.SetBytes(prepared, path, value)
			if err != nil {
				return body, false
			}
		}
	}
	return prepared, true
}

func canonicalSafePoolTurnMetadata(raw, flatSessionID, flatThreadID string) ([]byte, bool) {
	var decoded any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &decoded); err != nil {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}
	for key, expected := range map[string]string{
		"session_id": flatSessionID,
		"thread_id":  flatThreadID,
	} {
		value, exists := object[key]
		if !exists {
			continue
		}
		identity, ok := value.(string)
		if !ok || strings.TrimSpace(identity) == "" || identity != expected {
			return nil, false
		}
	}
	canonical, err := json.Marshal(decoded)
	return canonical, err == nil
}

// ==================== WebSocket 执行器 ====================

// Executor WebSocket 执行器
type Executor struct {
	manager                  *Manager
	mu                       sync.RWMutex
	wsURLOverrideTest        string
	beforeOwnerAdmissionTest func()
}

// NewExecutor 创建 WebSocket 执行器
func NewExecutor() *Executor {
	return &Executor{
		manager: GetManager(),
	}
}

// NewExecutorWithManager 创建带指定管理器的执行器
func NewExecutorWithManager(manager *Manager) *Executor {
	return &Executor{
		manager: manager,
	}
}

// ExecuteRequestViaWebsocket 通过 WebSocket 发送请求
func (e *Executor) ExecuteRequestViaWebsocket(
	ctx context.Context,
	account *auth.Account,
	requestBody []byte,
	sessionID string,
	proxyOverride string,
	apiKey string,
	deviceCfg *proxy.DeviceProfileConfig,
	ginHeaders http.Header,
	poolRouteKey string,
) (*WsResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	account.Mu().RLock()
	accessToken := account.AccessToken
	accountIDStr := account.AccountID
	account.Mu().RUnlock()

	if accessToken == "" {
		return nil, fmt.Errorf("无可用 access_token")
	}

	// 准备请求体
	wsBody := e.prepareWebsocketBody(requestBody, sessionID)
	prevRespID := strings.TrimSpace(gjson.GetBytes(wsBody, "previous_response_id").String())
	continuationRequest := prevRespID != ""
	contextBound := continuationRequest || (strings.TrimSpace(sessionID) != "" && !proxy.IsStatelessWebsocketSessionID(sessionID))
	frameLimit := websocketMaxRequestFrameBytes()
	// Reject the base serialized frame before prepareSafePoolFrameMetadata clones
	// it. This avoids an unnecessary second ~27 MiB allocation for the incident
	// class while still occurring after prepareWebsocketBody has produced the
	// actual response.create wire payload.
	if frameErr := websocketFramePreflightError(len(wsBody), frameLimit, contextBound); frameErr != nil {
		return nil, frameErr
	}

	// Safe-pool frame metadata changes the serialized response.create frame but
	// does not depend on handshake headers. Select and preflight the exact frame
	// before prepareWebsocketHeaders, because device-profile stabilization may
	// update its cache while constructing headers. Oversized frames must remain
	// completely side-effect free up to this point.
	safeBody, frameMetadataKnown := prepareSafePoolFrameMetadata(wsBody, ginHeaders)
	poolPolicy := resolveStatelessPoolPolicy(account, e.manager)
	frameBody := wsBody
	if frameMetadataKnown && (poolPolicy.mode == statelessPoolSafe || poolPolicy.mode == statelessPoolOneShot) {
		frameBody = safeBody
	}
	if frameErr := websocketFramePreflightError(len(frameBody), frameLimit, contextBound); frameErr != nil {
		return nil, frameErr
	}

	headerSessionID := resolveHandshakeSessionID(sessionID, poolRouteKey, wsBody)

	// 构建 WebSocket URL
	wsURL := strings.TrimSpace(e.wsURLOverrideTest)
	if wsURL == "" {
		httpURL := proxy.CodexBaseURL + CodexWsEndpoint
		var err error
		wsURL, err = buildWebsocketURL(httpURL)
		if err != nil {
			return nil, fmt.Errorf("构建 WebSocket URL 失败: %w", err)
		}
	}

	// Resin 反向代理：改写 WS URL 为 Resin 反代地址
	if proxy.IsResinEnabled() {
		wsURL = proxy.BuildWebSocketURL(wsURL)
	}

	// 准备请求头
	headers := e.prepareWebsocketHeaders(accessToken, account, accountIDStr, headerSessionID, apiKey, deviceCfg, ginHeaders)

	// Resin 反代：注入账号身份头
	if proxy.IsResinEnabled() {
		headers.Set("X-Resin-Account", proxy.ResinAccountID(account))
	}

	// Safe reuse is scoped to the official Codex session+thread owner. Complete
	// the handshake half of the identity after the exact frame has passed
	// preflight, then perform the same owner checks as before.
	safeHeaders, handshakeKnown := safePoolOwnerHandshakeHeaders(headers, safeBody)
	ownerKey, ownerKeyKnown := safePoolOwnerKey(safeBody, apiKey)
	requestEligible := safePoolRequestEligible(safeBody)
	ownerKnown := ownerKeyKnown && handshakeKnown && frameMetadataKnown && requestEligible
	if poolPolicy.mode == statelessPoolSafe {
		switch {
		case ownerKnown:
			e.manager.safePoolOwnerEligible.Add(1)
		case !ownerKeyKnown:
			e.manager.safePoolOwnerMissing.Add(1)
		case !handshakeKnown:
			e.manager.safePoolOwnerRejected.Add(1)
			e.manager.safePoolOwnerHandshakeRejected.Add(1)
		case !frameMetadataKnown:
			e.manager.safePoolOwnerRejected.Add(1)
			e.manager.safePoolFrameMetadataRejected.Add(1)
		case !requestEligible:
			e.manager.safePoolRequestIneligible.Add(1)
		}
	}
	if poolPolicy.mode != statelessPoolSafe {
		e.manager.retireSafePoolAccountIfPolicyDisabled(account)
	}
	safeIdentity := safeConnectionIdentity{}
	if ownerKnown && poolPolicy.mode == statelessPoolSafe {
		safeIdentity = safeConnectionIdentity{
			ownerKey:             ownerKey,
			handshakeFingerprint: safePoolHeaderFingerprint(safeHeaders),
		}
	}

	// 获取或创建连接。无显式会话的请求（stateless 连接 ID）在确定性 cache key
	// 的槽位池内复用连接，避免持续高 RPM 下逐请求握手触发上游限流。
	//
	// 连接池 baseKey 必须按 API Key 稳定，绝不能等于每请求唯一的上游身份键，否则
	// 默认隔离模式下每请求都变 → 槽位池失效 → 逐请求握手触发 503。
	// poolRouteKey（来自上游确定性键）非空时优先用它作 baseKey：连接复用按 API Key
	// 稳定命中同一组 8 槽。
	//
	// 隔离说明：默认隔离模式下，每请求的上游身份隔离由写入每个 response.create 帧体的
	// 每请求唯一 prompt_cache_key 保证（见 proxy/executor.go 注入处）。握手头里的
	// Session_id/Conversation_id 是逐连接冻结的，绝不能携带任何单个请求的身份
	// （见 resolveHandshakeSessionID）。
	//
	// CODEX_WS_STATELESS_ONESHOT=1 时禁用槽位复用：每个无会话请求独享一条连接、
	// 用完即毁（彻底杜绝任何连接级状态跨请求泄漏，代价是逐请求握手）。
	// 续链亲和：上游无服务端存储时，previous_response_id 的上下文只存活在产出
	// 该响应的那条 WS 连接里。带续链 ID 的请求优先取回原连接（独占成功才用），
	// 否则落到随机槽位会触发上游 "previous response not found"。
	poolSessionID := sessionID
	var wc *WsConnection
	var pr *PendingRequest
	var err2 error
	safePoolRequest := false
	if continuationRequest {
		if poolPolicy.mode == statelessPoolHTTPFallback {
			return nil, fmt.Errorf("%w: safe websocket reuse is process-fused and connection-local state cannot move to HTTP", proxy.ErrWebsocketContinuationUnavailable)
		}
		if poolPolicy.mode == statelessPoolOneShot {
			return nil, fmt.Errorf("%w: one-shot websocket policy cannot resume connection-local previous_response_id state", proxy.ErrWebsocketContinuationUnavailable)
		}
		if poolPolicy.mode == statelessPoolSafe {
			if !ownerKnown {
				return nil, fmt.Errorf("%w: safe websocket owner is missing, conflicting, or ineligible for previous_response_id", proxy.ErrWebsocketContinuationUnavailable)
			}
			generation, current := e.manager.safePoolOwnerGeneration(account.ID(), ownerKey)
			if !current {
				return nil, fmt.Errorf("%w: safe websocket owner is not admitted in the current tag generation", proxy.ErrWebsocketContinuationUnavailable)
			}
			safeIdentity.generation = generation
		}
		var pwc *WsConnection
		var ppr *PendingRequest
		var slotKey string
		var preferredErr error
		if poolPolicy.mode == statelessPoolSafe {
			pwc, ppr, slotKey, preferredErr = e.manager.AcquirePreferredConnection(ctx, prevRespID, account.ID(), apiKey, safeIdentity)
		} else {
			pwc, ppr, slotKey, preferredErr = e.manager.AcquirePreferredConnection(ctx, prevRespID, account.ID(), apiKey)
		}
		if preferredErr != nil {
			return nil, preferredErr
		}
		if pwc != nil {
			wc, pr, poolSessionID = pwc, ppr, slotKey
			safePoolRequest = pwc.safeReusable.Load()
			if safePoolRequest {
				wsBody = safeBody
				headers = safeHeaders
			}
		}
	}
	requestLocalOneShot := false
	if wc == nil && !continuationRequest && poolPolicy.mode == statelessPoolSafe && ownerKnown {
		// Admission is deliberately owner-scoped and process-lifetime. A sample
		// miss or a full per-account budget changes only this request's transport:
		// it stays on the already-selected account and uses one unique WS socket.
		// Continuations never enter this gate because their connection-local state
		// is authoritative and must be resumed on the bound connection above.
		if e.beforeOwnerAdmissionTest != nil {
			e.beforeOwnerAdmissionTest()
		}
		// Hold only the account read lock across the final tag/policy check and
		// the in-memory admission commit. A concurrent tag removal therefore
		// linearizes either before this check (no admission) or after the commit
		// (the already-admitted owner may finish, while the normal pre-write gate
		// retires the connection). No network operation occurs under this lock.
		account.Mu().RLock()
		latestPolicy := resolveStatelessPoolPolicyWithTags(account, e.manager, account.Tags)
		decision := safePoolOwnerRejectedBySample
		generation := uint64(0)
		if latestPolicy.mode == statelessPoolSafe {
			decision, generation = e.manager.admitSafePoolOwner(
				account.ID(),
				ownerKey,
				currentSafePoolOwnerAdmissionConfig(),
			)
		}
		account.Mu().RUnlock()
		poolPolicy = latestPolicy
		if poolPolicy.mode != statelessPoolSafe {
			e.manager.retireSafePoolAccountIfPolicyDisabled(account)
		} else if decision == safePoolOwnerRejectedByLifecycle {
			return nil, ErrManagerStopped
		} else {
			requestLocalOneShot = !decision.admitted()
			if decision.admitted() {
				safeIdentity.generation = generation
			}
		}
	}
	baseKey := strings.TrimSpace(poolRouteKey)
	if baseKey == "" && headerSessionID != sessionID {
		baseKey = headerSessionID
	}
	oneShotRequest := false
	if wc == nil {
		if poolPolicy.mode == statelessPoolHTTPFallback {
			return nil, fmt.Errorf("%w: safe websocket reuse is process-fused before request write", proxy.ErrWebsocketSafePoolFallback)
		} else if poolPolicy.mode == statelessPoolSafe && ownerKnown && requestLocalOneShot {
			wsBody = safeBody
			headers = safeHeaders
			poolSessionID = "stateless-" + uuid.NewString()
			wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, poolSessionID, headers, proxyOverride)
			oneShotRequest = err2 == nil && wc != nil
		} else if poolPolicy.mode == statelessPoolSafe && ownerKnown {
			wsBody = safeBody
			headers = safeHeaders
			safeBaseKey := safePoolOwnedRouteKey(baseKey, ownerKey, safeHeaders)
			wc, pr, poolSessionID, err2 = e.manager.AcquireSafeReusableConnection(ctx, account, wsURL, safeBaseKey, poolPolicy.slots, poolPolicy.wait, safeHeaders, safeIdentity, proxyOverride)
			safePoolRequest = err2 == nil && wc != nil
		} else if poolPolicy.mode == statelessPoolSafe {
			// Owner-ineligible traffic preserves the unenrolled tagged baseline: one
			// isolated physical WS for this request. It never enters the reusable
			// pool and therefore cannot cross a session/thread boundary. Recording
			// it as an HTTP fallback produced thousands of misleading hidden 502s.
			if continuationRequest {
				return nil, fmt.Errorf("%w: safe websocket owner is unavailable for previous_response_id", proxy.ErrWebsocketContinuationUnavailable)
			}
			e.manager.safePoolOwnerOneShotFallbacks.Add(1)
			poolSessionID = "stateless-" + uuid.NewString()
			if frameMetadataKnown {
				wsBody = safeBody
			}
			if handshakeKnown {
				headers = safeHeaders
			}
			wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, poolSessionID, headers, proxyOverride)
			oneShotRequest = err2 == nil && wc != nil
		} else if poolPolicy.mode == statelessPoolOneShot {
			// The operator's explicit hard kill switch is the only policy that
			// deliberately receives a unique physical socket per request.
			poolSessionID = "stateless-" + uuid.NewString()
			if frameMetadataKnown {
				wsBody = safeBody
			}
			if handshakeKnown {
				headers = safeHeaders
			}
			wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, poolSessionID, headers, proxyOverride)
			oneShotRequest = err2 == nil && wc != nil
		} else if proxy.IsStatelessWebsocketSessionID(sessionID) && baseKey != "" {
			switch poolPolicy.mode {
			case statelessPoolLegacy:
				wc, pr, poolSessionID, err2 = e.manager.AcquireReusableConnection(ctx, account, wsURL, baseKey, sessionID, StatelessConnectionSlots, headers, proxyOverride)
			default:
				wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, sessionID, headers, proxyOverride)
				oneShotRequest = err2 == nil && wc != nil
			}
		} else {
			wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, sessionID, headers, proxyOverride)
		}
	}
	if err2 != nil {
		return nil, err2
	}
	if safePoolRequest {
		if !e.manager.safePoolIdentityUsable(account, safeIdentity) {
			if wc != nil && wc.session != nil && pr != nil {
				wc.session.RemovePendingRequest(pr.RequestID)
			}
			if wc != nil {
				wc.retireAfterLease.Store(true)
				e.manager.DiscardConnection(wc)
			}
			if continuationRequest {
				return nil, fmt.Errorf("%w: safe websocket generation or policy changed before request write", proxy.ErrWebsocketContinuationUnavailable)
			}
			return nil, fmt.Errorf("%w: safe websocket generation or policy changed before request write", proxy.ErrWebsocketSafePoolFallback)
		}
	}

	// 发送请求，失败时最多重试 2 次（重建连接）。
	// 用 DiscardConnection 按连接指针精确清理：续链亲和取回的连接其 PoolKey
	// 可能与当前请求的 proxy 组合不同，按参数重算 key 会漏删。
	markTerminalProofPolicy := func(conn *WsConnection) {
		if oneShotRequest && conn != nil {
			// Publish this before the data write begins: an immediate terminal
			// followed by close 1006/EOF may prove this one non-reusable lease
			// committed, without relaxing legacy reusable-connection semantics.
			conn.allowAbruptTerminalProof.Store(true)
		}
	}
	markTerminalProofPolicy(wc)
	sendCurrentRequest := func(conn *WsConnection, body []byte, requestID string) error {
		if safePoolRequest {
			return e.sendSafePoolRequest(conn, body, requestID, account, safeIdentity, continuationRequest)
		}
		return e.sendRequest(conn, body, requestID)
	}
	sendErr := sendCurrentRequest(wc, wsBody, pr.RequestID)
	for retries := 0; !safePoolRequest && !continuationRequest && shouldRetryWebsocketSendError(sendErr) && retries < 2; retries++ {
		wc.session.RemovePendingRequest(pr.RequestID)
		e.manager.DiscardConnection(wc)

		// 短暂退避，避免瞬间重连风暴
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(retries+1) * 200 * time.Millisecond):
		}

		wc, pr, err2 = e.manager.AcquireConnection(ctx, account, wsURL, poolSessionID, headers, proxyOverride)
		if err2 != nil {
			return nil, err2
		}
		markTerminalProofPolicy(wc)
		sendErr = sendCurrentRequest(wc, wsBody, pr.RequestID)
	}
	if sendErr != nil {
		wc.session.RemovePendingRequest(pr.RequestID)
		e.manager.DiscardConnection(wc)
		if errors.Is(sendErr, proxy.ErrWebsocketWriteUncertain) {
			return nil, sendErr
		}
		if safePoolRequest {
			return nil, fmt.Errorf("safe websocket request failed before socket write: %w", sendErr)
		}
		if continuationRequest {
			return nil, fmt.Errorf("%w: failed to write response-bound websocket request: %v", proxy.ErrWebsocketContinuationUnavailable, sendErr)
		}
		return nil, fmt.Errorf("发送 WebSocket 请求失败: %w", sendErr)
	}

	// 启动心跳
	e.manager.StartHeartbeat(wc)

	return &WsResponse{
		conn:        wc,
		pendingReq:  pr,
		sessionID:   poolSessionID,
		manager:     e.manager,
		apiKey:      apiKey,
		readErrChan: make(chan error, 1),
		safePool:    safePoolRequest,
		oneShot:     oneShotRequest,
		reuseFence:  poolPolicy.reuseFence,
	}, nil
}

func shouldRetryWebsocketSendError(err error) bool {
	return errors.Is(err, errWebsocketWriteNotStarted)
}

// prepareWebsocketBody 准备 WebSocket 请求体
func (e *Executor) prepareWebsocketBody(body []byte, sessionID string) []byte {
	if len(body) == 0 {
		return nil
	}

	// 克隆并修改请求体
	wsBody := bytes.Clone(body)

	// 1. 确保 instructions 字段存在
	if !gjson.GetBytes(wsBody, "instructions").Exists() {
		wsBody, _ = sjson.SetBytes(wsBody, "instructions", "")
	}

	// 2. 清理多余字段（prompt_cache_retention 上游不接受，会返回 400 Unsupported parameter，必须删除）
	wsBody, _ = sjson.DeleteBytes(wsBody, "prompt_cache_retention")
	wsBody, _ = sjson.DeleteBytes(wsBody, "safety_identifier")
	wsBody, _ = sjson.DeleteBytes(wsBody, "disable_response_storage")

	// 3. 注入 prompt_cache_key
	// stateless sessionID 只是连接池隔离用的一次性随机 ID，注入它会让上游
	// prompt cache 每次请求都 miss；此时保留请求体中已有的确定性 cache key
	//（由 proxy.ExecuteRequest 注入或客户端自带）。
	existingCacheKey := strings.TrimSpace(gjson.GetBytes(wsBody, "prompt_cache_key").String())
	if sessionID != "" && !proxy.IsStatelessWebsocketSessionID(sessionID) {
		wsBody, _ = sjson.SetBytes(wsBody, "prompt_cache_key", sessionID)
	} else if existingCacheKey != "" {
		wsBody, _ = sjson.SetBytes(wsBody, "prompt_cache_key", existingCacheKey)
	}

	// 4. 设置请求类型和 stream
	wsBody, _ = sjson.SetBytes(wsBody, "type", "response.create")
	wsBody, _ = sjson.SetBytes(wsBody, "stream", true)

	return wsBody
}

func websocketMaxRequestFrameBytes() int {
	return integerFromEnv(websocketMaxRequestFrameBytesEnv, defaultWebsocketMaxRequestFrameBytes, 1024*1024, maximumWebsocketMaxRequestFrameBytes)
}

func websocketFramePreflightError(frameBytes, limitBytes int, contextBound bool) *proxy.WebsocketFramePreflightError {
	if frameBytes < limitBytes {
		return nil
	}
	return &proxy.WebsocketFramePreflightError{
		FrameBytes:   frameBytes,
		LimitBytes:   limitBytes,
		ContextBound: contextBound,
	}
}

// prepareWebsocketHeaders 准备 WebSocket 请求头
func (e *Executor) prepareWebsocketHeaders(accessToken string, account *auth.Account, accountID, sessionID, apiKey string, deviceCfg *proxy.DeviceProfileConfig, ginHeaders http.Header) http.Header {
	headers := http.Header{}

	// 认证头
	headers.Set("Authorization", "Bearer "+accessToken)

	// Beta header 启用 WebSocket 响应 API
	headers.Set("OpenAI-Beta", responsesWebsocketBetaHeader)

	usedGeneratedHeaders := false
	if shouldSendWebsocketUserAgent() {
		if account == nil {
			account = &auth.Account{AccountID: accountID}
		}
		var userAgent, version string
		userAgent, version, usedGeneratedHeaders = proxy.ResolveCodexOutboundClientHeadersWithDecision(account, apiKey, deviceCfg, ginHeaders)
		headers.Set("User-Agent", userAgent)
		if version != "" {
			headers.Set("Version", version)
		}
	}
	if betaFeatures := strings.TrimSpace(ginHeaders.Get("X-Codex-Beta-Features")); betaFeatures != "" {
		headers.Set("X-Codex-Beta-Features", betaFeatures)
	} else if deviceCfg != nil && strings.TrimSpace(deviceCfg.BetaFeatures) != "" {
		headers.Set("X-Codex-Beta-Features", strings.TrimSpace(deviceCfg.BetaFeatures))
	}

	// Originator
	if originator := strings.TrimSpace(ginHeaders.Get("Originator")); !usedGeneratedHeaders && originator != "" && proxy.IsCodexOfficialClientByHeaders("", originator) {
		headers.Set("Originator", originator)
	} else {
		headers.Set("Originator", proxy.Originator)
	}
	// X-Oai-Attestation：DeviceCheck 设备认证头（上游 openai/codex#20619），
	// 仅在下游携带时透传，本代理不伪造（假 token 服务端验证必败，反而暴露）。
	for _, name := range []string{"X-Codex-Turn-State", "X-Codex-Turn-Metadata", "X-Client-Request-Id", "X-Responsesapi-Include-Timing-Metrics", "X-Oai-Attestation"} {
		if value := strings.TrimSpace(ginHeaders.Get(name)); value != "" {
			headers.Set(name, value)
		}
	}

	// Account ID
	if accountID != "" {
		headers.Set("Chatgpt-Account-Id", accountID)
	}
	if sessionID = strings.TrimSpace(sessionID); sessionID != "" {
		headers.Set("Session_id", sessionID)
		headers.Set("Conversation_id", sessionID)
	}
	for name, value := range account.GetCustomHeaders() {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		headers.Set(name, value)
	}

	return headers
}

// sendRequest 发送 WebSocket 请求
func (e *Executor) sendRequest(wc *WsConnection, body []byte, requestID string) error {
	if !wc.IsConnected() {
		return fmt.Errorf("%w: websocket connection is not connected", errWebsocketWriteNotStarted)
	}
	if err := wc.ensureReadLeaseForSend(requestID); err != nil {
		return fmt.Errorf("%w: %v", errWebsocketWriteNotStarted, err)
	}
	return wc.WriteMessage(websocket.TextMessage, body)
}

func (e *Executor) sendSafePoolRequest(wc *WsConnection, body []byte, requestID string, account *auth.Account, identity safeConnectionIdentity, continuation bool) error {
	if !wc.IsConnected() {
		return fmt.Errorf("%w: websocket connection is not connected", errWebsocketWriteNotStarted)
	}
	if err := wc.ensureReadLeaseForSend(requestID); err != nil {
		return fmt.Errorf("%w: %v", errWebsocketWriteNotStarted, err)
	}
	return wc.writeMessageChecked(websocket.TextMessage, body, func() error {
		if e.manager.safePoolIdentityUsable(account, identity) && identity.matches(wc) {
			return nil
		}
		wc.retireAfterLease.Store(true)
		if continuation {
			return fmt.Errorf("%w: safe websocket generation or policy changed at the write boundary", proxy.ErrWebsocketContinuationUnavailable)
		}
		return fmt.Errorf("%w: safe websocket generation or policy changed at the write boundary", proxy.ErrWebsocketSafePoolFallback)
	})
}

// ==================== WebSocket 响应处理 ====================

// WsResponse WebSocket 响应包装器
type WsResponse struct {
	conn        *WsConnection
	pendingReq  *PendingRequest
	sessionID   string
	manager     *Manager
	readErrChan chan error
	closed      bool
	// apiKey 发起本请求的下游 API Key，用于 response_id → 连接绑定的归属校验。
	apiKey string
	// connBroken 标记读流因上游 WS 异常(非正常关闭)或下游写入失败而终止；
	// Close() 据此销毁坏连接而非归还连接池复用。受 mu 保护。
	connBroken bool
	// streamCompleted 标记读流已消费到明确的终止边界(response.completed /
	// response.incomplete / response.failed / 上游 error 帧)。Close() 只在此标记为 true 且未标记
	// connBroken 时才归还连接复用；其余情况(下游断开、ctx 取消、上游关闭、
	// 握手失败后未读流等)上游可能仍在该连接上推送残留帧，归还复用会把上一个
	// 请求的响应串给下一个用户(issue #308)，必须销毁。受 mu 保护。
	streamCompleted bool
	// safePool enables strict response identity/sequence validation and a
	// terminal reuse fence. It is set only for the explicit opt-in safe pool;
	// owner-rejected requests preserve isolated one-shot WS, while generation or
	// policy invalidation before a reusable write falls back on the same account.
	safePool          bool
	oneShot           bool
	reuseFence        time.Duration
	responseID        string
	lastSeq           int64
	seenSeq           bool
	seenCreated       bool
	outputItems       map[int64]safePoolOutputItem
	itemOutputIndex   map[string]int64
	callItemID        map[string]string
	contentParts      map[string]map[int64]string
	preludeFrames     [][]byte
	preludeBytes      int
	preludeResponseID string
	mu                sync.Mutex
}

type safePoolOutputItem struct {
	id       string
	itemType string
}

type safePoolEventAction uint8

const (
	safePoolEventForward safePoolEventAction = iota
	safePoolEventBuffered
	safePoolEventFlushPrelude
	safePoolEventRetire

	safePoolMaxPreludeFrames = 8
	safePoolMaxPreludeBytes  = 64 << 10
)

// ReadStream 读取 SSE 流
func (r *WsResponse) ReadStream(callback func(data []byte) bool) error {
	if r.conn == nil {
		return fmt.Errorf("websocket connection is not available")
	}
	if r.pendingReq != nil {
		if err := r.conn.ensureReadLeaseForResponse(r.pendingReq.RequestID); err != nil {
			return fmt.Errorf("websocket connection is not available: %w", err)
		}
	}

	for {
		msgType, payload, err := r.conn.ReadMessage()
		if err != nil {
			// ReadStream only returns successfully after consuming an explicit
			// response terminal frame. Any socket close here, including 1000/1001,
			// is premature and must preserve the real close error for the consumer.
			r.markConnBroken()
			if r.safePool {
				if isolationErr := r.conn.safePoolReadIsolationFailure(); isolationErr != nil {
					return fmt.Errorf("%w: %v", proxy.ErrWebsocketIsolationViolation, isolationErr)
				}
			}
			// ExecuteRequestViaWebsocket returns WsResponse only after the
			// response.create write was committed. A premature read failure is
			// therefore uncertain in every WS mode, including one-shot fallback
			// sockets. Replaying it could duplicate execution or billing. Explicit
			// payload/policy closes remain deterministic request rejections.
			// A local read-limit failure is normalized to close 1009 for diagnostics,
			// but it means the upstream response already exceeded this process's
			// buffer after request commit. It must never be mistaken for a proven
			// pre-execution peer rejection and replayed over HTTP.
			if errors.Is(err, websocket.ErrReadLimit) {
				return fmt.Errorf("%w: local websocket response exceeded read limit after request commit: %w", proxy.ErrWebsocketReadUncertain, err)
			}
			var closeErr *websocket.CloseError
			if !errors.As(err, &closeErr) || (closeErr.Code != websocket.CloseMessageTooBig && closeErr.Code != websocket.ClosePolicyViolation) {
				return fmt.Errorf("%w: %w", proxy.ErrWebsocketReadUncertain, err)
			}
			return fmt.Errorf("websocket read error: %w", err)
		}

		// 只处理文本消息
		if msgType != websocket.TextMessage {
			if msgType == websocket.BinaryMessage {
				if r.safePool {
					err := fmt.Errorf("%w: unexpected binary message", proxy.ErrWebsocketIsolationViolation)
					r.markConnBroken()
					if r.manager != nil && r.conn.session != nil {
						r.manager.TripSafePoolFuse(r.conn.session.AccountID, err)
					}
					return err
				}
				r.markConnBroken()
				return fmt.Errorf("%w: unexpected binary message from websocket", proxy.ErrWebsocketReadUncertain)
			}
			continue
		}

		// 清理消息
		payload = bytes.TrimSpace(payload)
		if len(payload) == 0 {
			continue
		}

		// 解析并处理消息
		if err := r.handleMessage(payload, callback); err != nil {
			if err == io.EOF {
				// 到达终止边界(完成/失败/错误帧)。若中途下游写入失败已标记
				// connBroken，Close() 仍会销毁连接。
				r.markStreamCompleted()
				return nil
			}
			return err
		}
	}
}

// handleMessage 处理单条 WebSocket 消息
func (r *WsResponse) handleMessage(payload []byte, callback func(data []byte) bool) error {
	action := safePoolEventForward
	if r.safePool {
		var err error
		action, err = r.validateSafePoolEvent(payload)
		if err != nil {
			r.markConnBroken()
			if r.manager != nil && r.conn != nil && r.conn.session != nil {
				if errors.Is(err, errSafePoolProtocolCompatibility) {
					r.manager.TripSafePoolCompatibilityFuse(r.conn.session.AccountID, err)
				} else {
					r.manager.TripSafePoolFuse(r.conn.session.AccountID, err)
				}
			}
			if errors.Is(err, errSafePoolProtocolCompatibility) {
				return fmt.Errorf("%w: %v", proxy.ErrWebsocketReadUncertain, err)
			}
			return err
		}
		if action == safePoolEventBuffered {
			return nil
		}
		if action == safePoolEventRetire {
			if r.conn != nil {
				r.conn.retireAfterLease.Store(true)
			}
			if r.manager != nil {
				r.manager.safePoolCompatibilityDrops.Add(1)
				if r.conn != nil && r.conn.session != nil {
					eventType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
					if eventType == "" {
						eventType = "unknown"
					}
					r.manager.TripSafePoolCompatibilityFuse(r.conn.session.AccountID, fmt.Errorf("%w: unowned extension event %s", errSafePoolProtocolCompatibility, eventType))
				}
			}
			return nil
		}
		if action == safePoolEventFlushPrelude {
			for _, frame := range r.preludeFrames {
				if !callback(frame) {
					r.preludeFrames = nil
					r.preludeBytes = 0
					r.markConnBroken()
					return io.EOF
				}
			}
			r.preludeFrames = nil
			r.preludeBytes = 0
		}
	}
	// 上游错误帧：透传给下游(转成 SSE 错误事件)，而不是转成 Go error 后静默关闭 pipe。
	// 否则下游只会读到一个底层 read error → 表现为空响应，无从得知具体错误。
	if errEvent, isErr := r.buildErrorEvent(payload); isErr {
		if r.safePool {
			// Even a request-scoped bare error has no response identity that can
			// prove the physical socket returned to a clean boundary.
			r.markConnBroken()
		}
		// 连接级寿命限制错误：针对连接而非单个请求，这条连接上的后续
		// response.create 一律失败，而 Ping 探活仍会成功；归还池会持续毒害
		// 后续请求（含续链亲和定向回来的），必须标记销毁 (issue #346)。
		if isConnLimitErrorFrame(payload) {
			r.markConnBroken()
		}
		// 把错误内容作为 SSE 数据写给下游，让客户端看到完整错误 JSON。
		callback(errEvent)
		// 错误即终止：结束流(等价于 response.failed)。
		return io.EOF
	}

	// 标准化完成事件类型
	payload = normalizeCompletionEvent(payload)
	eventType := gjson.GetBytes(payload, "type").String()
	safeTerminalBound := false
	if r.safePool && (eventType == "response.completed" || eventType == "response.incomplete") && r.manager != nil && r.conn != nil {
		respID := gjson.GetBytes(payload, "response.id").String()
		if respID != "" {
			if r.pendingReq == nil {
				err := fmt.Errorf("%w: terminal response %q has no active lease", proxy.ErrWebsocketIsolationViolation, respID)
				r.markConnBroken()
				if r.conn.session != nil {
					r.manager.TripSafePoolFuse(r.conn.session.AccountID, err)
				}
				return err
			}
			if err := r.conn.beginSafeTerminalRelease(r.pendingReq.RequestID); err != nil {
				isolationErr := fmt.Errorf("%w: %v", proxy.ErrWebsocketIsolationViolation, err)
				r.markConnBroken()
				if r.conn.session != nil {
					r.manager.TripSafePoolFuse(r.conn.session.AccountID, isolationErr)
				}
				return isolationErr
			}
			accountID := int64(0)
			if r.conn.session != nil {
				accountID = r.conn.session.AccountID
			}
			// Publish before the downstream callback: the callback can make the
			// terminal visible to a client that immediately starts its next turn.
			// The release barrier above prevents that continuation from entering
			// this socket until Close has removed the previous pending lease.
			r.manager.BindResponseConn(respID, r.conn, r.sessionID, accountID, r.apiKey)
			safeTerminalBound = true
		}
	}

	// 调用回调
	if !callback(payload) {
		// 下游写入失败(broken pipe / 客户端断开)：响应流在非终止边界被截断，
		// 上游仍会在这条连接上继续推送本响应的剩余帧。连接必须销毁，
		// 归还池中复用会把残留帧串给下一个请求(issue #308)。
		r.markConnBroken()
		return io.EOF
	}

	// 检查是否是终止事件
	if eventType == "response.completed" || eventType == "response.failed" || eventType == "response.incomplete" {
		// 续链亲和：记录本响应由哪条连接产出，后续带 previous_response_id 的
		// 请求可回到原连接（上游无服务端存储时上下文只存活在连接内）。
		if !safeTerminalBound && (eventType == "response.completed" || eventType == "response.incomplete") && r.manager != nil && r.conn != nil {
			if respID := gjson.GetBytes(payload, "response.id").String(); respID != "" {
				accountID := int64(0)
				if r.conn.session != nil {
					accountID = r.conn.session.AccountID
				}
				r.manager.BindResponseConn(respID, r.conn, r.sessionID, accountID, r.apiKey)
			}
		}
		return io.EOF
	}

	return nil
}

func (r *WsResponse) validateSafePoolEvent(payload []byte) (safePoolEventAction, error) {
	eventType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
	if eventType == "" {
		return safePoolEventForward, fmt.Errorf("%w: event type is empty", proxy.ErrWebsocketIsolationViolation)
	}
	// An error may legitimately be the first/only frame. It is delivered to the
	// current request, but handleMessage marks the socket non-reusable.
	if eventType == "error" {
		return safePoolEventForward, nil
	}

	if !r.seenCreated {
		// The official Codex client accepts metadata/timing controls before
		// response.created. Buffer them until created is validated so an
		// abandoned or delayed prelude can never escape on its own. Standard
		// response.metadata may carry a candidate response id; if it does, the
		// subsequent created frame must prove the same id.
		if safePoolPreludeEvent(eventType) {
			if strings.TrimSpace(gjson.GetBytes(payload, "item_id").String()) != "" ||
				strings.TrimSpace(gjson.GetBytes(payload, "item.id").String()) != "" {
				return safePoolEventForward, fmt.Errorf("%w: prelude %s carries item ownership", proxy.ErrWebsocketIsolationViolation, eventType)
			}
			candidateID := eventResponseID(payload)
			sequence := gjson.GetBytes(payload, "sequence_number")
			if sequence.Exists() && sequence.Int() < 0 {
				return safePoolEventForward, fmt.Errorf("%w: %s has negative sequence_number %d", proxy.ErrWebsocketIsolationViolation, eventType, sequence.Int())
			}
			if candidateID != "" {
				if r.preludeResponseID != "" && r.preludeResponseID != candidateID {
					return safePoolEventForward, fmt.Errorf("%w: metadata prelude response id changed from %s to %s", proxy.ErrWebsocketIsolationViolation, r.preludeResponseID, candidateID)
				}
				r.preludeResponseID = candidateID
			}
			if len(r.preludeFrames) >= safePoolMaxPreludeFrames || r.preludeBytes+len(payload) > safePoolMaxPreludeBytes {
				return safePoolEventForward, fmt.Errorf("%w: response metadata prelude exceeds %d frames or %d bytes", proxy.ErrWebsocketIsolationViolation, safePoolMaxPreludeFrames, safePoolMaxPreludeBytes)
			}
			r.preludeFrames = append(r.preludeFrames, bytes.Clone(payload))
			r.preludeBytes += len(payload)
			return safePoolEventBuffered, nil
		}
		if eventType != "response.created" {
			if safePoolEventUnowned(payload) && !safePoolKnownPayloadEvent(eventType) {
				return safePoolEventRetire, nil
			}
			return safePoolEventForward, fmt.Errorf("%w: first response event is %s, want response.created", proxy.ErrWebsocketIsolationViolation, eventType)
		}
	}

	sequence := gjson.GetBytes(payload, "sequence_number")
	seq := int64(0)
	if sequence.Exists() {
		seq = sequence.Int()
		if seq < 0 {
			return safePoolEventForward, fmt.Errorf("%w: %s has negative sequence_number %d", proxy.ErrWebsocketIsolationViolation, eventType, seq)
		}
	}
	if !r.seenCreated {
		responseID := strings.TrimSpace(gjson.GetBytes(payload, "response.id").String())
		if responseID == "" {
			return safePoolEventForward, fmt.Errorf("%w: response.created has no response.id", errSafePoolProtocolCompatibility)
		}
		if r.conn != nil && r.conn.hasRecentResponseID(responseID) {
			return safePoolEventForward, fmt.Errorf("%w: delayed response.created repeated terminal response %s", proxy.ErrWebsocketIsolationViolation, responseID)
		}
		if r.preludeResponseID != "" && r.preludeResponseID != responseID {
			return safePoolEventForward, fmt.Errorf("%w: response.created id %s does not match metadata prelude %s", proxy.ErrWebsocketIsolationViolation, responseID, r.preludeResponseID)
		}
		r.responseID = responseID
		if sequence.Exists() {
			r.lastSeq = seq
			r.seenSeq = true
		}
		r.seenCreated = true
		r.outputItems = make(map[int64]safePoolOutputItem)
		r.itemOutputIndex = make(map[string]int64)
		r.callItemID = make(map[string]string)
		r.contentParts = make(map[string]map[int64]string)
		if len(r.preludeFrames) > 0 {
			return safePoolEventFlushPrelude, nil
		}
		return safePoolEventForward, nil
	}
	if eventType == "response.created" {
		return safePoolEventForward, fmt.Errorf("%w: duplicate response.created for active lease", proxy.ErrWebsocketIsolationViolation)
	}
	// These request-local Codex control events may omit both identity and
	// sequence. Unowned controls are safe once response.created established the
	// single in-flight boundary. Owned controls must still pass the generic
	// response check below, and controls must never claim an item graph.
	if safePoolActiveUnscopedControlEvent(eventType) {
		if strings.TrimSpace(gjson.GetBytes(payload, "item_id").String()) != "" ||
			strings.TrimSpace(gjson.GetBytes(payload, "item.id").String()) != "" {
			return safePoolEventForward, fmt.Errorf("%w: active control %s carries item ownership", proxy.ErrWebsocketIsolationViolation, eventType)
		}
		if safePoolEventUnowned(payload) {
			return safePoolEventForward, nil
		}
	}
	if safePoolEventUnowned(payload) && !safePoolKnownPayloadEvent(eventType) {
		return safePoolEventRetire, nil
	}
	// Sequence numbers are a useful integrity signal when the upstream emits
	// them, but private Codex control events and current official client fixtures
	// do not guarantee universal presence or gap-free numbering. Enforce strict
	// monotonicity when present; response and item identities remain mandatory.
	if sequence.Exists() && r.seenSeq && seq <= r.lastSeq {
		return safePoolEventForward, fmt.Errorf("%w: sequence_number %d did not advance beyond %d", proxy.ErrWebsocketIsolationViolation, seq, r.lastSeq)
	}
	if responseID := eventResponseID(payload); responseID != "" && responseID != r.responseID {
		return safePoolEventForward, fmt.Errorf("%w: response id changed from %s to %s", proxy.ErrWebsocketIsolationViolation, r.responseID, responseID)
	}
	if err := r.validateSafePoolItemGraph(eventType, payload); err != nil {
		return safePoolEventForward, err
	}

	if safePoolTerminalEvent(eventType) {
		terminalID := strings.TrimSpace(gjson.GetBytes(payload, "response.id").String())
		if terminalID == "" {
			return safePoolEventForward, fmt.Errorf("%w: terminal %s has no response.id", errSafePoolProtocolCompatibility, eventType)
		}
		if terminalID != r.responseID {
			return safePoolEventForward, fmt.Errorf("%w: terminal %s has response.id %q, want %q", proxy.ErrWebsocketIsolationViolation, eventType, terminalID, r.responseID)
		}
		if status := strings.TrimSpace(gjson.GetBytes(payload, "response.status").String()); status != "" {
			expected := strings.TrimPrefix(eventType, "response.")
			if eventType == "response.done" {
				expected = "completed"
			}
			if status != expected {
				return safePoolEventForward, fmt.Errorf("%w: terminal %s carries response.status %q, want %q", proxy.ErrWebsocketIsolationViolation, eventType, status, expected)
			}
		}
		if r.conn != nil {
			r.conn.recordRecentResponseID(terminalID)
		}
	}
	if sequence.Exists() {
		r.lastSeq = seq
		r.seenSeq = true
	}
	return safePoolEventForward, nil
}

func safePoolPreludeEvent(eventType string) bool {
	switch eventType {
	case "response.metadata", "codex.response.metadata", "responsesapi.websocket_timing", "codex.rate_limits":
		return true
	default:
		return false
	}
}

func safePoolActiveUnscopedControlEvent(eventType string) bool {
	switch eventType {
	case "response.metadata", "codex.response.metadata", "responsesapi.websocket_timing", "codex.rate_limits":
		return true
	default:
		return false
	}
}

func safePoolEventUnowned(payload []byte) bool {
	return eventResponseID(payload) == "" &&
		strings.TrimSpace(gjson.GetBytes(payload, "item_id").String()) == "" &&
		strings.TrimSpace(gjson.GetBytes(payload, "item.id").String()) == ""
}

func safePoolKnownPayloadEvent(eventType string) bool {
	if eventType == "response.created" || safePoolTerminalEvent(eventType) {
		return true
	}
	for _, prefix := range []string{
		"response.output_",
		"response.content_",
		"response.output_text.",
		"response.refusal.",
		"response.reasoning_",
		"response.function_",
		"response.file_",
		"response.web_",
		"response.image_",
		"response.code_",
		"response.computer_",
		"response.custom_",
		"response.mcp_",
		"response.tool_",
		"response.shell_",
		"response.apply_patch_",
	} {
		if strings.HasPrefix(eventType, prefix) {
			return true
		}
	}
	return false
}

func requiredSafePoolIndex(payload []byte, path, eventType string) (int64, error) {
	value := gjson.GetBytes(payload, path)
	if !value.Exists() {
		return 0, fmt.Errorf("%w: %s has no %s", errSafePoolProtocolCompatibility, eventType, path)
	}
	index := value.Int()
	if index < 0 {
		return 0, fmt.Errorf("%w: %s has negative %s %d", proxy.ErrWebsocketIsolationViolation, eventType, path, index)
	}
	return index, nil
}

func (r *WsResponse) validateSafePoolItemReference(eventType string, payload []byte, itemID string) (int64, error) {
	registeredIndex, known := r.itemOutputIndex[itemID]
	if !known {
		return 0, fmt.Errorf("%w: %s references unknown item %s", proxy.ErrWebsocketIsolationViolation, eventType, itemID)
	}
	outputIndex, err := requiredSafePoolIndex(payload, "output_index", eventType)
	if err != nil {
		return 0, err
	}
	if outputIndex != registeredIndex {
		return 0, fmt.Errorf("%w: %s item %s moved from output_index %d to %d", proxy.ErrWebsocketIsolationViolation, eventType, itemID, registeredIndex, outputIndex)
	}
	return outputIndex, nil
}

func (r *WsResponse) bindSafePoolCallID(callID, itemID string) error {
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return nil
	}
	if previous, exists := r.callItemID[callID]; exists && previous != itemID {
		return fmt.Errorf("%w: call_id %s moved from item %s to %s", proxy.ErrWebsocketIsolationViolation, callID, previous, itemID)
	}
	if r.callItemID == nil {
		r.callItemID = make(map[string]string)
	}
	r.callItemID[callID] = itemID
	return nil
}

func safePoolSyntheticCallItemID(callID string) string {
	return "\x00call:" + strings.TrimSpace(callID)
}

func (r *WsResponse) validateSafePoolItemGraph(eventType string, payload []byte) error {
	switch eventType {
	case "response.output_item.added":
		outputIndex, err := requiredSafePoolIndex(payload, "output_index", eventType)
		if err != nil {
			return err
		}
		itemID := strings.TrimSpace(gjson.GetBytes(payload, "item.id").String())
		callID := strings.TrimSpace(gjson.GetBytes(payload, "item.call_id").String())
		if itemID == "" && callID != "" {
			itemID = safePoolSyntheticCallItemID(callID)
		}
		if itemID == "" {
			return fmt.Errorf("%w: response.output_item.added has no item.id", errSafePoolProtocolCompatibility)
		}
		itemType := strings.TrimSpace(gjson.GetBytes(payload, "item.type").String())
		if itemType == "" {
			return fmt.Errorf("%w: response.output_item.added item %s has no type", errSafePoolProtocolCompatibility, itemID)
		}
		if previous, duplicate := r.outputItems[outputIndex]; duplicate {
			return fmt.Errorf("%w: output_index %d already belongs to item %s", proxy.ErrWebsocketIsolationViolation, outputIndex, previous.id)
		}
		if previousIndex, duplicate := r.itemOutputIndex[itemID]; duplicate {
			return fmt.Errorf("%w: item %s already belongs to output_index %d", proxy.ErrWebsocketIsolationViolation, itemID, previousIndex)
		}
		r.outputItems[outputIndex] = safePoolOutputItem{id: itemID, itemType: itemType}
		r.itemOutputIndex[itemID] = outputIndex
		if err := r.bindSafePoolCallID(callID, itemID); err != nil {
			return err
		}
		return nil

	case "response.output_item.done":
		itemID := strings.TrimSpace(gjson.GetBytes(payload, "item.id").String())
		callID := strings.TrimSpace(gjson.GetBytes(payload, "item.call_id").String())
		if itemID == "" {
			itemID = strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
		}
		if itemID == "" && callID != "" {
			itemID = safePoolSyntheticCallItemID(callID)
		}
		if itemID == "" {
			return fmt.Errorf("%w: response.output_item.done has no item identity", errSafePoolProtocolCompatibility)
		}
		outputIndex, err := requiredSafePoolIndex(payload, "output_index", eventType)
		if err != nil {
			return err
		}
		itemType := strings.TrimSpace(gjson.GetBytes(payload, "item.type").String())
		if itemType == "" {
			return fmt.Errorf("%w: response.output_item.done item %s has no type", errSafePoolProtocolCompatibility, itemID)
		}
		if registeredIndex, known := r.itemOutputIndex[itemID]; known {
			if registeredIndex != outputIndex {
				return fmt.Errorf("%w: %s item %s moved from output_index %d to %d", proxy.ErrWebsocketIsolationViolation, eventType, itemID, registeredIndex, outputIndex)
			}
			if itemType != r.outputItems[outputIndex].itemType {
				return fmt.Errorf("%w: item %s changed type from %s to %s", proxy.ErrWebsocketIsolationViolation, itemID, r.outputItems[outputIndex].itemType, itemType)
			}
			return r.bindSafePoolCallID(callID, itemID)
		}
		if previous, occupied := r.outputItems[outputIndex]; occupied {
			return fmt.Errorf("%w: output_index %d already belongs to item %s", proxy.ErrWebsocketIsolationViolation, outputIndex, previous.id)
		}
		// Public Responses events carry complete identity on done. Accept a
		// done-only lifecycle even if an added frame was omitted by a compatible
		// upstream, while still rooting the item in this response/index.
		r.outputItems[outputIndex] = safePoolOutputItem{id: itemID, itemType: itemType}
		r.itemOutputIndex[itemID] = outputIndex
		return r.bindSafePoolCallID(callID, itemID)

	case "response.content_part.added":
		itemID := strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
		if itemID == "" {
			return fmt.Errorf("%w: response.content_part.added has no item_id", errSafePoolProtocolCompatibility)
		}
		if _, err := r.validateSafePoolItemReference(eventType, payload, itemID); err != nil {
			return err
		}
		contentIndex, err := requiredSafePoolIndex(payload, "content_index", eventType)
		if err != nil {
			return err
		}
		partType := strings.TrimSpace(gjson.GetBytes(payload, "part.type").String())
		if partType == "" {
			return fmt.Errorf("%w: response.content_part.added item %s has no part.type", errSafePoolProtocolCompatibility, itemID)
		}
		if r.contentParts[itemID] == nil {
			r.contentParts[itemID] = make(map[int64]string)
		}
		if previousType, duplicate := r.contentParts[itemID][contentIndex]; duplicate {
			return fmt.Errorf("%w: item %s content_index %d already has type %s", proxy.ErrWebsocketIsolationViolation, itemID, contentIndex, previousType)
		}
		r.contentParts[itemID][contentIndex] = partType
		return nil

	case "response.content_part.done":
		itemID := strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
		if itemID == "" {
			return fmt.Errorf("%w: response.content_part.done has no item_id", errSafePoolProtocolCompatibility)
		}
		if _, err := r.validateSafePoolItemReference(eventType, payload, itemID); err != nil {
			return err
		}
		contentIndex, err := requiredSafePoolIndex(payload, "content_index", eventType)
		if err != nil {
			return err
		}
		partType, known := r.contentParts[itemID][contentIndex]
		doneType := strings.TrimSpace(gjson.GetBytes(payload, "part.type").String())
		if !known {
			if doneType == "" {
				return fmt.Errorf("%w: response.content_part.done has neither prior part nor part.type", errSafePoolProtocolCompatibility)
			}
			if r.contentParts[itemID] == nil {
				r.contentParts[itemID] = make(map[int64]string)
			}
			r.contentParts[itemID][contentIndex] = doneType
			return nil
		}
		if doneType != "" && doneType != partType {
			return fmt.Errorf("%w: item %s content_index %d changed type from %s to %s", proxy.ErrWebsocketIsolationViolation, itemID, contentIndex, partType, doneType)
		}
		return nil
	}

	itemID := strings.TrimSpace(gjson.GetBytes(payload, "item_id").String())
	if itemID == "" {
		itemID = strings.TrimSpace(gjson.GetBytes(payload, "item.id").String())
	}
	resolvedByCallID := false
	if itemID == "" {
		callID := strings.TrimSpace(gjson.GetBytes(payload, "call_id").String())
		if callID == "" {
			callID = strings.TrimSpace(gjson.GetBytes(payload, "item.call_id").String())
		}
		if callID != "" {
			var known bool
			itemID, known = r.callItemID[callID]
			if !known {
				return fmt.Errorf("%w: %s references unknown call_id %s", errSafePoolProtocolCompatibility, eventType, callID)
			}
			resolvedByCallID = true
		}
	}
	if itemID == "" {
		if eventResponseID(payload) == "" && !safePoolUnscopedEventAllowed(eventType) {
			return fmt.Errorf("%w: %s has neither response nor registered item ownership", errSafePoolProtocolCompatibility, eventType)
		}
		return nil
	}
	if resolvedByCallID && !gjson.GetBytes(payload, "output_index").Exists() {
		if _, known := r.itemOutputIndex[itemID]; !known {
			return fmt.Errorf("%w: %s call identity has no registered output item", errSafePoolProtocolCompatibility, eventType)
		}
	} else {
		if _, err := r.validateSafePoolItemReference(eventType, payload, itemID); err != nil {
			return err
		}
	}
	if content := gjson.GetBytes(payload, "content_index"); content.Exists() {
		contentIndex, err := requiredSafePoolIndex(payload, "content_index", eventType)
		if err != nil {
			return err
		}
		if expectedPartType := safePoolExpectedContentPartType(eventType); expectedPartType != "" {
			partType, known := r.contentParts[itemID][contentIndex]
			if !known {
				return fmt.Errorf("%w: %s references unknown item %s content_index %d", proxy.ErrWebsocketIsolationViolation, eventType, itemID, contentIndex)
			}
			if partType != expectedPartType {
				return fmt.Errorf("%w: %s references %s content instead of %s", proxy.ErrWebsocketIsolationViolation, eventType, partType, expectedPartType)
			}
		}
	}
	return nil
}

// Only event families whose protocol lifecycle is explicitly rooted in
// response.content_part.added require a registered content part. Reasoning
// delta families also carry content_index in some server versions but may be
// rooted directly in the reasoning output item, so they retain item/output
// ownership checks without an unsupported content-part assumption.
func safePoolExpectedContentPartType(eventType string) string {
	switch eventType {
	case "response.output_text.delta", "response.output_text.done":
		return "output_text"
	case "response.refusal.delta", "response.refusal.done":
		return "refusal"
	default:
		return ""
	}
}

func safePoolTerminalEvent(eventType string) bool {
	switch eventType {
	case "response.completed", "response.failed", "response.incomplete", "response.done":
		return true
	default:
		return false
	}
}

func safePoolUnscopedEventAllowed(eventType string) bool {
	switch eventType {
	case "response.metadata", "responsesapi.websocket_timing", "codex.rate_limits":
		return true
	default:
		return false
	}
}

func eventResponseID(payload []byte) string {
	if responseID := strings.TrimSpace(gjson.GetBytes(payload, "response.id").String()); responseID != "" {
		return responseID
	}
	return strings.TrimSpace(gjson.GetBytes(payload, "response_id").String())
}

// buildErrorEvent 判断 payload 是否为上游错误帧；若是，返回一个下游可识别的
// response.failed SSE 事件(保留原始错误内容)，第二个返回值标记是否为错误帧。
func (r *WsResponse) buildErrorEvent(payload []byte) ([]byte, bool) {
	if len(payload) == 0 {
		return nil, false
	}
	if gjson.GetBytes(payload, "type").String() != "error" {
		return nil, false
	}

	status := int(gjson.GetBytes(payload, "status").Int())
	if status == 0 {
		status = int(gjson.GetBytes(payload, "status_code").Int())
	}

	errMsg := gjson.GetBytes(payload, "error.message").String()
	if errMsg == "" {
		errMsg = gjson.GetBytes(payload, "message").String()
	}
	if errMsg == "" && status > 0 {
		errMsg = http.StatusText(status)
	}
	if errMsg == "" {
		errMsg = "upstream websocket error"
	}

	// 构造 response.failed 事件：下游 ReadSSEStream 已识别该类型为终止失败，
	// 与 HTTP 路径的错误语义对齐；同时保留原始上游错误对象供客户端排查。
	// 上游错误对象可能是带换行的 pretty-printed JSON，必须压缩成单行，
	// 否则经 SSE data: 行编码后下游只能读到第一行（错误信息被截断）。
	errObj := compactJSONOneLine(gjson.GetBytes(payload, "error").Raw)
	if errObj == "" {
		errObj = fmt.Sprintf(`{"message":%q,"code":%d}`, errMsg, status)
	}
	event := fmt.Sprintf(`{"type":"response.failed","response":{"status":"failed","error":%s}}`, errObj)
	if status > 0 {
		event = fmt.Sprintf(`{"type":"response.failed","response":{"status":"failed","status_code":%d,"error":%s}}`, status, errObj)
	}
	return []byte(event), true
}

// isConnLimitErrorFrame 判断上游错误帧是否为连接级寿命限制错误
// (websocket_connection_limit_reached)：该错误按连接而非按请求生效，
// 复用此连接必然继续失败。
func isConnLimitErrorFrame(payload []byte) bool {
	code := gjson.GetBytes(payload, "error.code").String()
	if code == "" {
		code = gjson.GetBytes(payload, "code").String()
	}
	return code == "websocket_connection_limit_reached"
}

// normalizeCompletionEvent 标准化完成事件类型
func normalizeCompletionEvent(payload []byte) []byte {
	if gjson.GetBytes(payload, "type").String() == "response.done" {
		updated, err := sjson.SetBytes(payload, "type", "response.completed")
		if err == nil && len(updated) > 0 {
			return updated
		}
	}
	return payload
}

// compactJSONOneLine 把可能带换行的 JSON 压缩为单行；非法 JSON 或空串返回 ""。
func compactJSONOneLine(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(raw)); err != nil {
		return ""
	}
	return buf.String()
}

// markConnBroken 标记底层连接因上游 WS 异常或下游写入失败而不可复用（幂等，受 mu 保护）。
func (r *WsResponse) markConnBroken() {
	r.mu.Lock()
	r.connBroken = true
	r.mu.Unlock()
}

// markStreamCompleted 标记读流已消费到明确的终止边界（幂等，受 mu 保护）。
func (r *WsResponse) markStreamCompleted() {
	r.mu.Lock()
	r.streamCompleted = true
	r.mu.Unlock()
}

// Close 关闭响应并归还连接
func (r *WsResponse) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true

	// Establish the reuse fence before removing the Session pending marker.
	// That ordering closes the only window in which another acquirer could see
	// an idle connection before the terminal quarantine became visible.
	if r.conn != nil && r.safePool && !r.connBroken && r.streamCompleted {
		r.conn.setReuseFence(r.reuseFence)
	}

	// 根据读流的结束方式决定连接去向：
	//   - 读到终止边界(completed/failed/error 帧)且无异常：归还连接池继续复用。
	//   - 其余任何情况一律销毁并移出连接池：
	//     * 上游 WS 异常(close 1006/1009/1011、read error) → 坏连接复用会断流且 fd 滞留 CLOSE_WAIT；
	//     * 下游写入失败 / ctx 取消 / 上游正常关闭 / 握手失败后未读流 → 流没消费到边界，
	//       上游可能仍在推送残留帧，复用会串会话(issue #308)。
	if r.conn != nil {
		reusable := !r.oneShot && !r.connBroken && r.streamCompleted
		leaseID := ""
		if r.pendingReq != nil {
			leaseID = r.pendingReq.RequestID
		}
		if r.conn.session != nil && r.pendingReq != nil {
			r.conn.session.RemovePendingRequest(r.pendingReq.RequestID)
		}
		if reusable {
			r.manager.ReleaseConnection(r.conn)
			// Wake a continuation only after the terminal fence is visible, the
			// previous pending marker is gone and Release has completed.
			if r.safePool {
				r.conn.finishSafeTerminalRelease(leaseID)
			}
		} else {
			// Do not wake before Discard removes the pool pointer and response
			// bindings. WsConnection.Close releases the barrier on that path.
			r.manager.DiscardConnection(r.conn)
		}
	}

	return nil
}

// HTTPResponse 返回 HTTP 握手响应
func (r *WsResponse) HTTPResponse() *http.Response {
	if r.conn != nil {
		return r.conn.HTTPResponse()
	}
	return nil
}

// ==================== 辅助函数 ====================

// buildWebsocketURL 从 HTTP URL 构建 WebSocket URL
func buildWebsocketURL(httpURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(httpURL))
	if err != nil {
		return "", err
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	}

	return parsed.String(), nil
}

// ==================== 全局执行器实例 ====================

var globalExecutor *Executor
var executorOnce sync.Once

// GetExecutor 获取全局执行器实例
func GetExecutor() *Executor {
	executorOnce.Do(func() {
		globalExecutor = NewExecutor()
	})
	return globalExecutor
}

// ShutdownExecutor 关闭全局执行器和管理器
func ShutdownExecutor() {
	ShutdownManager()
}

// ExecuteRequestWebsocket 通过 WebSocket 发送请求
// 返回一个模拟的 http.Response 用于兼容现有代码
func ExecuteRequestWebsocket(ctx context.Context, account *auth.Account, requestBody []byte, sessionID string, proxyOverride string, apiKey string, deviceCfg *proxy.DeviceProfileConfig, headers http.Header, poolRouteKey string) (*http.Response, error) {
	exec := GetExecutor()
	wsResp, err := exec.ExecuteRequestViaWebsocket(ctx, account, requestBody, sessionID, proxyOverride, apiKey, deviceCfg, headers, poolRouteKey)
	if err != nil {
		// 握手阶段的上游 401（token 失效/撤销）还原成真实状态码的 HTTP 响应返回，
		// 而不是 transport 错误：否则 401 在使用日志里只会以 598/transport 出现，
		// 且账号既不触发 unauthorized 冷却也不触发鉴权探针，失效账号会一直留在
		// 调度池里被反复拨号（对比 HTTP 路径的 401 直接可见并立即冷却）。
		if resp, ok := handshakeUnauthorizedHTTPResponse(err); ok {
			return resp, nil
		}
		return nil, err
	}

	// 检查 HTTP 握手响应状态。WebSocket 握手成功的标准状态是 101，
	// 但这里要包装成现有 handler 可消费的 SSE HTTP 200 响应。
	handshakeResp := wsResp.HTTPResponse()
	statusCode, handshakeHeader, handshakeFailed := normalizeWebsocketHandshakeResponse(handshakeResp)
	if handshakeFailed {
		detail := formatFailedHandshakeHTTPBody(statusCode, handshakeResp)
		wsResp.Close()
		return &http.Response{
			StatusCode: statusCode,
			Header:     handshakeHeader.Clone(),
			Body:       io.NopCloser(strings.NewReader(detail)),
		}, nil
	}

	return websocketResponseToHTTP(ctx, wsResp, statusCode, handshakeHeader), nil
}

func websocketResponseToHTTP(ctx context.Context, wsResp *WsResponse, statusCode int, handshakeHeader http.Header) *http.Response {
	if ctx == nil {
		ctx = context.Background()
	}

	pr, pw := io.Pipe()
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       pr,
	}

	// 从 HTTP 握手响应中复制头信息
	if handshakeHeader != nil {
		for key, values := range handshakeHeader {
			for _, v := range values {
				resp.Header.Add(key, v)
			}
		}
	}

	// 设置 SSE 响应头
	resp.Header.Set("Content-Type", "text/event-stream")
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Connection", "keep-alive")

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// 先关 pipe 再关 WS 响应：pipe 以第一个错误为准，保证下游读到的是
			// cancellation 而不是随后销毁连接引发的 read error。
			_ = pw.CloseWithError(ctx.Err())
			_ = wsResp.Close()
		case <-done:
		}
	}()

	// 在后台读取 WebSocket 流并写入 pipe
	go func() {
		defer close(done)
		defer pw.Close()
		defer wsResp.Close()

		err := wsResp.ReadStream(func(data []byte) bool {
			// SSE 的 data: 负载以换行为界，含换行的帧（如 pretty-printed JSON）
			// 必须先压缩成单行，否则下游解析器只能读到第一行。
			if bytes.IndexByte(data, '\n') >= 0 {
				if compacted := compactJSONOneLine(string(data)); compacted != "" {
					data = []byte(compacted)
				} else {
					data = bytes.ReplaceAll(data, []byte("\n"), []byte(" "))
				}
			}
			// 将数据编码为 SSE 格式
			if _, err := pw.Write([]byte("data: ")); err != nil {
				return false
			}
			if _, err := pw.Write(data); err != nil {
				return false
			}
			if _, err := pw.Write([]byte("\n\n")); err != nil {
				return false
			}
			return true
		})

		if err != nil && err != io.EOF {
			pw.CloseWithError(err)
		}
	}()

	return resp
}

func normalizeWebsocketHandshakeResponse(handshakeResp *http.Response) (statusCode int, header http.Header, failed bool) {
	if handshakeResp == nil {
		return http.StatusOK, http.Header{}, false
	}

	statusCode = handshakeResp.StatusCode
	header = handshakeResp.Header
	if statusCode == http.StatusSwitchingProtocols || (statusCode >= 200 && statusCode < 300) {
		return http.StatusOK, header, false
	}
	return statusCode, header, true
}
