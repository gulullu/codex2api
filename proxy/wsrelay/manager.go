package wsrelay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
	"github.com/gorilla/websocket"
)

func newSessionBusyAcquireError(wait time.Duration, causes ...error) error {
	if len(causes) > 0 && causes[0] != nil {
		return fmt.Errorf("%w: acquire websocket connection interrupted after %s waiting for busy session: %w", proxy.ErrWebsocketSessionBusy, wait, causes[0])
	}
	return fmt.Errorf("%w: acquire websocket connection timed out after %s waiting for busy session", proxy.ErrWebsocketSessionBusy, wait)
}

func newLocalCapacityAcquireError(wait time.Duration, causes ...error) error {
	if len(causes) > 0 && causes[0] != nil {
		return fmt.Errorf("%w: acquire websocket connection interrupted after %s waiting for account connection capacity: %w", proxy.ErrWebsocketLocalCapacity, wait, causes[0])
	}
	return fmt.Errorf("%w: acquire websocket connection timed out after %s waiting for account connection capacity", proxy.ErrWebsocketLocalCapacity, wait)
}

// ==================== 连接池管理器 ====================

// ConnectionState 连接状态
type ConnectionState int32

const (
	StateDisconnected ConnectionState = 0
	StateConnecting   ConnectionState = 1
	StateConnected    ConnectionState = 2
	StateClosing      ConnectionState = 3
)

// WsConnection WebSocket 连接包装
type WsConnection struct {
	// WebSocket 连接
	conn *websocket.Conn

	// 握手时实际发送给上游的 User-Agent。连接复用时每个请求沿用该值，
	// 不能用当前配置重新推导，否则设置变更后会记录并未发送的 UA。
	upstreamUserAgent      string
	upstreamUserAgentKnown bool

	// 创建/复用该连接的账号。仅用于读取当前动态并发上限，让 response_id
	// 续链复用路径也能在账号上限下调后收敛空闲连接数。
	account *auth.Account

	// 会话
	session *Session

	// 连接 URL
	URL string

	// 连接池键
	PoolKey string

	// 连接状态
	state atomic.Int32

	// Legacy socket activity used by the existing five-minute expiry path.
	// Business traffic and successful heartbeat Pong both refresh this value so
	// disabling the opt-in business-idle reclaimer preserves rb28/v2.5.9.
	lastUsed atomic.Int64

	// lastBusinessUsed is refreshed only by request/response business traffic.
	// Heartbeat/Pong transport liveness must never extend this deadline.
	lastBusinessUsed atomic.Int64

	// 最近入站活动时间（数据帧/对端 Ping/Pong 回执，UnixNano）。仅供 probe
	// 免往返判断：近期有入站即 TCP 双向可证活。0 表示尚无入站，probe 走完整
	// 往返。刻意不并入 lastUsed，避免对端 Ping 顺带延长空闲逐出。
	lastInbound atomic.Int64

	// 创建时间（UnixNano），用于连接年龄判断（上游有 60 分钟连接寿命上限）。
	// 构造后不再修改；为 0 表示未知（测试用字面量构造），视为未到龄。
	createdAt int64

	// safeReusable marks connections admitted through the opt-in safe pool.
	// reuseNotBefore is a terminal-frame fence: while it is in the future the
	// healthy idle socket remains in place but cannot receive a new lease.
	safeReusable   atomic.Bool
	reuseNotBefore atomic.Int64
	// allowAbruptTerminalProof is set before the first request write only for
	// physical sockets that this executor will never reuse (one-shot/default
	// isolated stateless requests). Together with safeReusable, it permits a
	// same-lease terminal frame to prove write commitment across close 1006/EOF.
	// Legacy/default reusable sockets deliberately leave it false so a delayed
	// terminal from an older lease cannot be attributed to the current write.
	allowAbruptTerminalProof atomic.Bool
	// retireAfterLease is set when the global/account rollout policy is removed
	// while a request is still active. The active response may finish, but this
	// physical socket can never receive another lease.
	retireAfterLease atomic.Bool
	// safeOwnerKey and handshakeFingerprint are immutable and populated before
	// the permanent reader starts. They prevent continuation and ordinary reuse
	// from crossing a Codex session/thread or a connection-scoped identity.
	safeOwnerKey         string
	handshakeFingerprint string
	// safeGeneration binds the socket to the account-local master-tag
	// generation that admitted its owner. Removing and re-adding the tag always
	// creates a new generation; an old socket can finish an already-written turn
	// but can never be acquired, published, or written again.
	safeGeneration uint64
	// recent response IDs detect a delayed duplicate response.created from a
	// prior lease before any such frame can reach the downstream callback.
	safeHistoryMu     sync.Mutex
	recentResponseIDs map[string]struct{}
	// safeTerminalRelease is a one-shot barrier for the narrow interval after
	// a terminal frame has been delivered and its response binding published,
	// but before WsResponse.Close removes the previous Session pending marker.
	// A continuation may wait for this barrier; an actually in-flight turn has
	// no barrier and must still fail immediately as busy.
	safeTerminalMu      sync.Mutex
	safeTerminalRelease *safeTerminalRelease

	// 写操作锁
	writeMu sync.Mutex
	// writeMessageFunc is a test-only fault seam. Production leaves it nil and
	// always writes through Gorilla.
	writeMessageFunc func(messageType int, data []byte) error

	// 永久 reader、业务帧 lease 与探活状态。读取状态按需初始化，兼容测试中
	// 通过字面量构造且没有底层 socket 的 WsConnection。
	readStateOnce       sync.Once
	readPumpOnce        sync.Once
	readFailureOnce     sync.Once
	controlHandlersOnce sync.Once
	readState           *wsReadState
	// promotionMu serializes a pre-publication read-pump failure with the
	// handshake -> first lease -> pool publication transition.
	promotionMu sync.Mutex

	probeGateOnce sync.Once
	probeGate     chan struct{}
	probeStateMu  sync.Mutex
	probePayload  string
	probeResult   chan struct{}

	// 底层 socket 与断开回调只关闭/调用一次。
	closeOnce          sync.Once
	closeErr           error
	disconnectNotified atomic.Bool

	// HTTP 握手响应
	httpResp *http.Response

	// 连接关闭回调
	onDisconnected func(accountID int64)

	// 永久 reader 失败回调。Manager 使用指针级 CompareAndDelete 精确移除
	// 当前连接，避免误删同 PoolKey 下已经重建的连接。
	onReadFailure func(wc *WsConnection)
}

func effectiveProxyURL(account *auth.Account, proxyOverride string) string {
	proxyURL := ""
	if account != nil {
		account.Mu().RLock()
		proxyURL = account.ProxyURL
		account.Mu().RUnlock()
	}
	if strings.TrimSpace(proxyOverride) != "" {
		proxyURL = proxyOverride
	}
	return strings.TrimSpace(proxyURL)
}

// NewWsConnection 创建 WebSocket 连接
func NewWsConnection(conn *websocket.Conn, session *Session, wsURL string) *WsConnection {
	now := time.Now().UnixNano()
	wc := &WsConnection{
		conn:      conn,
		session:   session,
		URL:       wsURL,
		createdAt: now,
	}
	wc.lastUsed.Store(now)
	wc.lastBusinessUsed.Store(now)
	wc.state.Store(int32(StateConnected))
	return wc
}

// Touch records business activity while retaining the legacy socket activity
// timestamp used when the opt-in reclaimer is disabled.
func (wc *WsConnection) Touch() {
	now := time.Now().UnixNano()
	wc.lastUsed.Store(now)
	wc.lastBusinessUsed.Store(now)
}

// touchTransport records transport liveness only. In particular, a heartbeat
// Pong must not make a business-idle connection appear recently used.
func (wc *WsConnection) touchTransport() {
	wc.lastUsed.Store(time.Now().UnixNano())
}

func (wc *WsConnection) businessIdleFor(now time.Time) time.Duration {
	if wc == nil {
		return 0
	}
	last := wc.lastBusinessUsed.Load()
	if last <= 0 {
		// Literal test/legacy connections without a business timestamp fail
		// closed and are never reclaimed by the opt-in policy.
		return 0
	}
	idle := now.Sub(time.Unix(0, last))
	if idle < 0 {
		return 0
	}
	return idle
}

// touchInbound 记录一次入站活动（数据帧/对端 Ping/我方 Ping 的 Pong 回执）。
func (wc *WsConnection) touchInbound() {
	wc.lastInbound.Store(time.Now().UnixNano())
}

// recentInboundWithin 最近 window 内是否有入站活动。
func (wc *WsConnection) recentInboundWithin(window time.Duration) bool {
	ts := wc.lastInbound.Load()
	if ts == 0 {
		return false
	}
	return time.Since(time.Unix(0, ts)) <= window
}

// IsExpired 检查连接是否过期
func (wc *WsConnection) IsExpired() bool {
	lastUsed := time.Unix(0, wc.lastUsed.Load())
	return time.Since(lastUsed) > IdleTimeout
}

// IsOverAge 检查连接是否超过最大寿命（MaxConnLifetime）。到龄连接不能再接新请求：
// 上游按连接建立时间计 60 分钟寿命，撞线后 response.create 一律报错，但 Ping
// 探活仍成功，必须按年龄主动识别。
func (wc *WsConnection) IsOverAge() bool {
	if wc.createdAt == 0 {
		return false
	}
	return time.Since(time.Unix(0, wc.createdAt)) > MaxConnLifetime
}

// IsConnected 检查是否已连接
func (wc *WsConnection) IsConnected() bool {
	return wc.state.Load() == int32(StateConnected)
}

func (wc *WsConnection) setReuseFence(duration time.Duration) {
	if wc == nil || duration <= 0 {
		return
	}
	wc.reuseNotBefore.Store(time.Now().Add(duration).UnixNano())
}

func (wc *WsConnection) reuseFenceActive() bool {
	if wc == nil {
		return false
	}
	notBefore := wc.reuseNotBefore.Load()
	return notBefore > 0 && time.Now().UnixNano() < notBefore
}

func (wc *WsConnection) reuseFenceRemaining() time.Duration {
	if wc == nil {
		return 0
	}
	remaining := time.Until(time.Unix(0, wc.reuseNotBefore.Load()))
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (wc *WsConnection) hasRecentResponseID(responseID string) bool {
	if wc == nil || responseID == "" {
		return false
	}
	wc.safeHistoryMu.Lock()
	defer wc.safeHistoryMu.Unlock()
	_, exists := wc.recentResponseIDs[responseID]
	return exists
}

func (wc *WsConnection) recordRecentResponseID(responseID string) {
	if wc == nil || responseID == "" {
		return
	}
	wc.safeHistoryMu.Lock()
	defer wc.safeHistoryMu.Unlock()
	if wc.recentResponseIDs == nil {
		wc.recentResponseIDs = make(map[string]struct{})
	}
	if _, exists := wc.recentResponseIDs[responseID]; !exists && len(wc.recentResponseIDs) >= safePoolMaxRecentResponseIDs {
		// Never evict old IDs and reopen a delayed-frame hole. The active
		// response graph protects the current lease; retire at this terminal
		// boundary instead of admitting another lease.
		wc.retireAfterLease.Store(true)
		return
	}
	wc.recentResponseIDs[responseID] = struct{}{}
}

const safePoolMaxRecentResponseIDs = 4096

type safeTerminalRelease struct {
	leaseID string
	done    chan struct{}
}

func (wc *WsConnection) beginSafeTerminalRelease(leaseID string) error {
	if wc == nil || strings.TrimSpace(leaseID) == "" {
		return fmt.Errorf("safe websocket terminal release requires a lease id")
	}
	wc.safeTerminalMu.Lock()
	defer wc.safeTerminalMu.Unlock()
	if wc.safeTerminalRelease != nil {
		return fmt.Errorf("safe websocket terminal release is already pending for lease %q", wc.safeTerminalRelease.leaseID)
	}
	wc.safeTerminalRelease = &safeTerminalRelease{
		leaseID: leaseID,
		done:    make(chan struct{}),
	}
	return nil
}

func (wc *WsConnection) finishSafeTerminalRelease(leaseID string) {
	if wc == nil {
		return
	}
	wc.safeTerminalMu.Lock()
	barrier := wc.safeTerminalRelease
	if barrier != nil && (leaseID == "" || barrier.leaseID == leaseID) {
		wc.safeTerminalRelease = nil
		close(barrier.done)
	}
	wc.safeTerminalMu.Unlock()
}

func (wc *WsConnection) safeTerminalReleaseDone() <-chan struct{} {
	if wc == nil {
		return nil
	}
	wc.safeTerminalMu.Lock()
	defer wc.safeTerminalMu.Unlock()
	if wc.safeTerminalRelease == nil {
		return nil
	}
	return wc.safeTerminalRelease.done
}

// Close 安全关闭连接
func (wc *WsConnection) Close() error {
	if wc == nil {
		return nil
	}
	wc.closeOnce.Do(func() {
		wc.state.Store(int32(StateClosing))
		// Wake a continuation waiting for the response-level Close path. It will
		// revalidate the pool pointer and observe that this socket is gone.
		wc.finishSafeTerminalRelease("")
		if wc.conn != nil {
			wc.closeErr = wc.conn.Close()
		}
		wc.state.Store(int32(StateDisconnected))
	})
	if wc.onDisconnected != nil && wc.session != nil && wc.disconnectNotified.CompareAndSwap(false, true) {
		wc.onDisconnected(wc.session.AccountID)
	}
	return wc.closeErr
}

// SetState 设置连接状态
func (wc *WsConnection) SetState(state ConnectionState) {
	wc.state.Store(int32(state))
}

// WriteMessage 安全写入消息
func (wc *WsConnection) WriteMessage(messageType int, data []byte) error {
	return wc.writeMessageChecked(messageType, data, nil)
}

func (wc *WsConnection) writeMessageChecked(messageType int, data []byte, beforeWrite func() error) error {
	wc.writeMu.Lock()
	defer wc.writeMu.Unlock()

	if !wc.IsConnected() || (wc.conn == nil && wc.writeMessageFunc == nil) {
		return fmt.Errorf("%w: websocket connection is not connected", errWebsocketWriteNotStarted)
	}
	if beforeWrite != nil {
		if err := beforeWrite(); err != nil {
			return fmt.Errorf("%w: %w", errWebsocketWriteNotStarted, err)
		}
	}
	leaseID, tracksLease, err := wc.beginReadLeaseWrite(messageType)
	if err != nil {
		return fmt.Errorf("%w: %v", errWebsocketWriteNotStarted, err)
	}

	var writeErr error
	if wc.writeMessageFunc != nil {
		writeErr = wc.writeMessageFunc(messageType, data)
	} else {
		wc.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
		defer wc.conn.SetWriteDeadline(time.Time{})
		writeErr = wc.conn.WriteMessage(messageType, data)
	}
	if tracksLease {
		if completedErr := wc.completeReadLeaseWrite(leaseID, writeErr); completedErr != nil {
			// Gorilla cannot prove how many bytes reached the peer when a data write
			// fails. Treat every post-attempt failure as an uncertain committed turn;
			// replaying it can duplicate work and billing.
			return fmt.Errorf("%w: %w", proxy.ErrWebsocketWriteUncertain, completedErr)
		}
		return nil
	}
	return writeErr
}

// HTTPResponse 返回 HTTP 握手响应
func (wc *WsConnection) HTTPResponse() *http.Response {
	return wc.httpResp
}

// ==================== 连接池管理器 ====================

// Manager WebSocket 连接池管理器
type Manager struct {
	// 连接池（accountID -> *WsConnection）
	connections sync.Map

	// 会话池（accountID -> *Session）
	sessions sync.Map

	// 拨号器配置
	dialer *websocket.Dialer

	// 清理定时器
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	stopOnce      sync.Once
	cleanupWG     sync.WaitGroup

	// lifecycleMu closes operation admission before Stop waits, avoiding the
	// WaitGroup Add/Wait race. stopCtx cancels in-flight handshakes; Stop waits
	// for admitted acquire/replace operations before the final closeAll sweep.
	lifecycleMu sync.Mutex
	stopped     bool
	stopCtx     context.Context
	stopCancel  context.CancelFunc
	operationWG sync.WaitGroup

	// 连接回调
	onConnected    func(accountID int64, session *Session)
	onDisconnected func(accountID int64)

	// 读写锁保护回调设置
	mu sync.RWMutex

	// pool key 级别串行化，避免同一逻辑 session 在 acquire 阶段竞争同一条连接。
	// 固定条带替代永不回收的 sync.Map，oneshot 随机 key 不再造成锁表增长；
	// 极少量哈希碰撞只会保守地串行化不同 key，不影响正确性。
	keyLocks [managerLockStripeCount]sync.Mutex
	// replacementLocks make Remove+fresh Acquire one logical key operation.
	// Normal key acquisitions pass through the corresponding gate before taking
	// keyLocks; a replacement keeps the gate for its whole remove/redial cycle.
	replacementLocks [managerLockStripeCount]sync.Mutex
	// Account-level serialization keeps ordinary capacity strict across dynamic
	// session/pool keys. Pending dials, active sockets (bound or not), and
	// unbound idle sockets count here; bound-idle continuation sockets use the
	// separately bounded global/per-account pool below.
	accountLocks   [managerLockStripeCount]sync.Mutex
	capacityMu     sync.Mutex
	pendingCreates map[int64]int
	// safePoolPendingCreates is the safe-owner subset of pendingCreates. It is
	// tracked separately so the rollout slot limit remains strict across
	// parallel cold dials without charging unrelated one-shot handshakes.
	safePoolPendingCreates map[int64]int

	// account ID -> safePoolFuseState. Process-local by design: it is a
	// transport escape hatch, never a database/account-status mutation.
	safePoolFuses sync.Map
	// safePoolAccounts tracks account-level safe-pool lifecycle presence for the
	// read-only runtime snapshot. Admission publishes it before any cold dial so
	// a tag retirement cannot miss an owner that has not created a socket yet.
	safePoolAccounts                sync.Map
	safePoolDialAttempts            atomic.Uint64
	safePoolDialSuccess             atomic.Uint64
	safePoolDialFailures            atomic.Uint64
	safePoolReuseHits               atomic.Uint64
	safePoolSaturations             atomic.Uint64
	safePoolFuseTrips               atomic.Uint64
	safePoolCompatibilityDrops      atomic.Uint64
	safePoolCompatibilityFallbacks  atomic.Uint64
	safePoolOwnerEligible           atomic.Uint64
	safePoolOwnerMissing            atomic.Uint64
	safePoolOwnerRejected           atomic.Uint64
	safePoolRequestIneligible       atomic.Uint64
	safePoolOwnerAdmittedNew        atomic.Uint64
	safePoolOwnerAdmittedExisting   atomic.Uint64
	safePoolOwnerSampleRejected     atomic.Uint64
	safePoolOwnerBudgetRejected     atomic.Uint64
	safePoolOwnerOneShotFallbacks   atomic.Uint64
	safePoolOwnerConfigErrors       atomic.Uint64
	safePoolOwnerHandshakeRejected  atomic.Uint64
	safePoolFrameMetadataRejected   atomic.Uint64
	safePoolGenerationInvalidations atomic.Uint64
	safePoolRetiredOwners           atomic.Uint64
	continuationBudgetEvictions     atomic.Uint64
	ownerAdmissionMu                sync.Mutex
	safePoolAdmittedOwners          map[int64]map[string]uint64
	safePoolAccountGenerations      map[int64]uint64
	ownerAdmissionSalt              [32]byte
	ownerAdmissionSaltValid         bool

	// response_id -> 连接 绑定（续链亲和）。上游 chatgpt backend 无服务端存储时，
	// previous_response_id 的上下文只存活在产生该响应的那条 WS 连接里；带续链 ID
	// 的请求必须回到原连接，落到别的槽位会得到 "previous response not found"。
	// 参考 sub2api openai_ws_state_store 的 BindResponseConn/GetResponseConn。
	respConnMu       sync.Mutex
	respConnBindings map[string]responseConnBinding
	// respConnSummaries indexes the same bindings by physical connection. It
	// keeps hot-path capacity and continuation-budget checks proportional to
	// live sockets (hundreds), not response IDs retained for TTL (tens of
	// thousands at 10k RPM).
	respConnSummaries            map[*WsConnection]*responseConnSummary
	respConnSummaryAccountCounts map[int64]int
	// responseBindingOrder is an intrusive generation FIFO for the bounded
	// response-ID table. The generation is already unique and monotonic, so this
	// avoids a 65k-entry scan for every Bind once the table reaches its ceiling.
	responseBindingOrder            map[uint64]string
	responseBindingOldestGeneration uint64
	// responseBindingGeneration is incremented under respConnMu for every
	// published Bind. Unlike wall-clock expiry it cannot collide within one
	// process, so continuation eviction can detect a concurrent rebind exactly.
	responseBindingGeneration uint64
	// continuationMu serializes cross-account bound-idle budget convergence.
	// It is never acquired while an account lock is held.
	continuationMu              sync.Mutex
	continuationGlobalLimit     int
	continuationPerAccountLimit int

	// 可选的探活函数（用于测试替换），nil 时使用默认 probeConnection
	probeFunc func(wc *WsConnection) bool

	// 可选的保活 Ping 函数（用于测试替换），nil 时使用默认 SendHeartbeat
	keepalivePingFunc func(wc *WsConnection) error

	// Business-idle reclaim metrics and bounded reconnect attribution. These do
	// not participate in routing and remain inert while the feature is disabled.
	idleReclaimEligible       atomic.Uint64
	idleReclaimReclaimed      atomic.Uint64
	idleReclaimSkippedBusy    atomic.Uint64
	idleReclaimSkippedContext atomic.Uint64
	idleReclaimReconnect      atomic.Uint64
	idleReclaimPendingKeys    atomic.Int64
	idleReclaimMu             sync.Mutex
	idleReclaimedKeys         map[string]time.Time
	idleReclaimNextLog        atomic.Int64
	idleReclaimLastLogged     atomic.Uint64

	// 测试钩子：连接写入池后、首个 pending/read lease 建立前触发。
	afterConnectionStored          func(wc *WsConnection)
	afterReplacementRemoved        func(key string)
	beforeCapacityEviction         func()
	beforeContinuationRevalidation func(wc *WsConnection)
	beforeOwnerAdmissionCommit     func()
}

var ErrManagerStopped = errors.New("websocket manager stopped")

// managerLockStripeCount must remain a power of two. Separate key/account
// arrays prevent an unrelated key hash collision from participating in the
// key -> account lock ordering used by acquire paths.
const managerLockStripeCount = 1024

// responseConnBinding 记录某个 response_id 由哪条连接产出。
// conn 指针同时用作身份校验：同 poolKey 下连接被重建后旧绑定自动失效。
// apiKey 为产出该响应的下游 API Key（明文，仅存内存），lookup 时要求匹配，
// 防止跨 Key 用他人 response_id 定向挤上他人连接（与 response cache 的
// owner 隔离同一原则）。
type responseConnBinding struct {
	conn                 *WsConnection
	sessionKey           string
	accountID            int64
	apiKey               string
	safeOwnerKey         string
	handshakeFingerprint string
	safeGeneration       uint64
	expiresAt            time.Time
	generation           uint64
}

type responseConnSummary struct {
	responseGenerations map[string]uint64
	accountID           int64
	latestGeneration    uint64
	latestExpiresAt     time.Time
}

const (
	// responseConnBindingTTL is independent of physical Pong keepalive. Once it
	// expires the socket loses continuation exemption and rejoins ordinary cap.
	responseConnBindingTTL = IdleTimeout
	// At the 10k-RPM target, a five-minute continuation TTL can retain about
	// 50k logical response IDs. Keep bounded headroom above that live set so a
	// normal pause does not evict valid previous_response_id state in seconds.
	responseConnBindingMaxEntries = 65536

	defaultContinuationGlobalLimit     = 512
	defaultContinuationPerAccountLimit = 128
	minContinuationSocketLimit         = 1
	maxContinuationSocketLimit         = responseConnBindingMaxEntries
)

const (
	continuationGlobalLimitEnv     = "CODEX_WS_CONTINUATION_MAX_CONNECTIONS_GLOBAL"
	continuationPerAccountLimitEnv = "CODEX_WS_CONTINUATION_MAX_CONNECTIONS_PER_ACCOUNT"
)

func parseContinuationSocketLimit(envName string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(envName))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minContinuationSocketLimit || value > maxContinuationSocketLimit {
		return fallback
	}
	return value
}

func continuationSocketLimitsFromEnv() (globalLimit int, perAccountLimit int) {
	globalLimit = parseContinuationSocketLimit(continuationGlobalLimitEnv, defaultContinuationGlobalLimit)
	perAccountLimit = parseContinuationSocketLimit(continuationPerAccountLimitEnv, defaultContinuationPerAccountLimit)
	if perAccountLimit > globalLimit {
		perAccountLimit = globalLimit
	}
	return globalLimit, perAccountLimit
}

// wsWriteBufferPool 在所有上游 WS 连接间共享写缓冲，降低高并发下的内存占用。
var wsWriteBufferPool = &sync.Pool{}

// NewManager 创建连接池管理器
func NewManager() *Manager {
	stopCtx, stopCancel := context.WithCancel(context.Background())
	continuationGlobalLimit, continuationPerAccountLimit := continuationSocketLimitsFromEnv()
	ownerAdmissionSalt, ownerAdmissionSaltValid := newSafePoolOwnerSampleSalt()
	m := &Manager{
		dialer: &websocket.Dialer{
			HandshakeTimeout:  HandshakeTimeout,
			EnableCompression: true,
			// 上游 Codex WS 帧可达 48-91KB，默认 4KB 缓冲会导致单帧多轮 syscall；
			// 调大到 64KB 减少读写循环次数，写缓冲走共享池复用。
			ReadBufferSize:  64 * 1024,
			WriteBufferSize: 64 * 1024,
			WriteBufferPool: wsWriteBufferPool,
			NetDialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		stopCleanup:                 make(chan struct{}),
		stopCtx:                     stopCtx,
		stopCancel:                  stopCancel,
		continuationGlobalLimit:     continuationGlobalLimit,
		continuationPerAccountLimit: continuationPerAccountLimit,
		ownerAdmissionSalt:          ownerAdmissionSalt,
		ownerAdmissionSaltValid:     ownerAdmissionSaltValid,
	}

	// 启动后台清理
	m.cleanupTicker = time.NewTicker(30 * time.Second)
	m.cleanupWG.Add(1)
	go m.cleanupLoop()

	return m
}

// cleanupLoop 定期清理过期连接
func (m *Manager) cleanupLoop() {
	defer m.cleanupWG.Done()
	for {
		select {
		case <-m.cleanupTicker.C:
			m.evictExpired()
		case <-m.stopCleanup:
			m.cleanupTicker.Stop()
			return
		}
	}
}

// evictExpired 清理过期连接和会话（含到龄且空闲的连接，主动轮转避免撞上游寿命上限）
func (m *Manager) evictExpired() {
	// Expire continuation bindings on every cleanup tick independently of the
	// socket keepalive timestamp. Pong may keep a healthy socket reusable, but
	// it cannot extend response affinity: once the binding expires, the socket
	// rejoins ordinary per-account capacity and converges there.
	m.pruneResponseConnBindings()
	accounts := make(map[int64]*auth.Account)
	m.connections.Range(func(_, value any) bool {
		wc := value.(*WsConnection)
		if wc.session == nil {
			m.DiscardConnection(wc)
			return true
		}
		// Serialize cleanup with promotion/reuse. In particular, do not observe
		// the tiny Store -> first lease transition as an idle connection.
		accountLock := m.accountLock(wc.session.AccountID)
		accountLock.Lock()
		if current, ok := m.connections.Load(wc.PoolKey); ok && current == wc {
			if !wc.IsConnected() || isEvictableIdleExpired(wc) || isRotatableOverAge(wc) {
				m.DiscardConnection(wc)
			} else if wc.account != nil {
				accounts[wc.session.AccountID] = wc.account
			}
		}
		accountLock.Unlock()
		return true
	})

	m.sessions.Range(func(key, value any) bool {
		s := value.(*Session)
		// A published session is owned by its current physical connection. Do
		// not expire it independently by LastActiveAt: business frames update
		// connection lastUsed, and a long quiet response may legitimately have
		// an in-flight lease while neither timestamp changes. The account lock
		// also makes this check atomic with successful connection promotion.
		accountLock := m.accountLock(s.AccountID)
		accountLock.Lock()
		current, hasConnection := m.connections.Load(key)
		wc, validConnection := current.(*WsConnection)
		orphaned := !hasConnection || !validConnection || wc == nil || wc.session != s
		if !s.IsConnected() || orphaned {
			if m.sessions.CompareAndDelete(key, s) {
				s.Close()
			}
		}
		accountLock.Unlock()
		return true
	})

	for accountID, account := range accounts {
		accountLock := m.accountLock(accountID)
		accountLock.Lock()
		m.trimIdleAccountConnections(accountID, accountConnectionLimit(account), nil)
		accountLock.Unlock()
	}
	// This second pass is a runtime-gated extension. When disabled it returns
	// immediately and the cleanup behavior above remains byte-for-byte intact.
	m.reclaimBusinessIdleConnections(time.Now())
	// Cross-account continuation convergence is a top-level phase. Never call
	// it while an account lock from ordinary capacity is held.
	m.enforceContinuationSocketBudgets()
}

// Stop 停止管理器
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		m.lifecycleMu.Lock()
		m.stopped = true
		stopCancel := m.stopCancel
		m.lifecycleMu.Unlock()
		stopCancel()
		close(m.stopCleanup)
		m.cleanupWG.Wait()
		m.operationWG.Wait()
		// No admitted operation can Store or AddPending after this point. Waiting
		// before the sweep is important because Session.Close is not a terminal
		// admission gate: closing first could otherwise be followed by AddPending.
		m.closeAll()
		m.ownerAdmissionMu.Lock()
		m.safePoolAdmittedOwners = nil
		m.safePoolAccountGenerations = nil
		m.ownerAdmissionMu.Unlock()
		m.safePoolAccounts = sync.Map{}
	})
}

// closeAll 关闭所有连接
func (m *Manager) closeAll() {
	m.connections.Range(func(_, value any) bool {
		wc := value.(*WsConnection)
		m.DiscardConnection(wc)
		return true
	})

	m.sessions.Range(func(key, value any) bool {
		s := value.(*Session)
		if m.sessions.CompareAndDelete(key, s) {
			s.Close()
		}
		return true
	})
}

// SetOnConnected 设置连接回调
func (m *Manager) SetOnConnected(fn func(accountID int64, session *Session)) {
	m.mu.Lock()
	m.onConnected = fn
	m.mu.Unlock()
}

// SetOnDisconnected 设置断开回调
func (m *Manager) SetOnDisconnected(fn func(accountID int64)) {
	m.mu.Lock()
	m.onDisconnected = fn
	m.mu.Unlock()
}

// getOnDisconnected 获取断开回调
func (m *Manager) getOnDisconnected() func(accountID int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onDisconnected
}

// getOnConnected 获取连接回调
func (m *Manager) getOnConnected() func(accountID int64, session *Session) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onConnected
}

func (m *Manager) beginOperation(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.lifecycleMu.Lock()
	if m.stopped {
		m.lifecycleMu.Unlock()
		return nil, nil, ErrManagerStopped
	}
	m.operationWG.Add(1)
	stopCtx := m.stopCtx
	m.lifecycleMu.Unlock()

	opCtx, cancel := context.WithCancel(ctx)
	stopForward := context.AfterFunc(stopCtx, cancel)
	select {
	case <-stopCtx.Done():
		cancel()
	default:
	}
	var doneOnce sync.Once
	done := func() {
		doneOnce.Do(func() {
			stopForward()
			cancel()
			m.operationWG.Done()
		})
	}
	return opCtx, done, nil
}

func keyLockStripe(key string) uint64 {
	// Inline FNV-1a avoids an allocation/interface on the hot acquire path.
	const (
		offset64 = uint64(14695981039346656037)
		prime64  = uint64(1099511628211)
	)
	hash := offset64
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= prime64
	}
	return hash & (managerLockStripeCount - 1)
}

func (m *Manager) keyLock(key string) *sync.Mutex {
	return &m.keyLocks[keyLockStripe(key)]
}

func (m *Manager) replacementLock(key string) *sync.Mutex {
	return &m.replacementLocks[keyLockStripe(key)]
}

// lockPoolKey enters the replacement gate and then the ordinary key stripe.
// Releasing the gate after keyLock is held lets normal operations run with the
// same concurrency as before while a full replacement can exclude all of them.
func (m *Manager) lockPoolKey(key string, keyLock *sync.Mutex) {
	replacementLock := m.replacementLock(key)
	replacementLock.Lock()
	keyLock.Lock()
	replacementLock.Unlock()
}

func (m *Manager) accountLock(accountID int64) *sync.Mutex {
	// Fibonacci hashing spreads both sequential and sparse database IDs.
	stripe := (uint64(accountID) * uint64(11400714819323198485)) & (managerLockStripeCount - 1)
	return &m.accountLocks[stripe]
}

func accountConnectionLimit(account *auth.Account) int {
	if account != nil {
		if limit := account.GetDynamicConcurrencyLimit(); limit > 0 {
			return int(limit)
		}
	}
	// 尚未完成调度快照初始化的账号保留原有槽位上限，生产请求进入账号池后
	// DynamicConcurrencyLimit 会始终为正数。
	return StatelessConnectionSlots
}

type idleAccountConnection struct {
	wc       *WsConnection
	lastUsed int64
}

type continuationBudgetCandidate struct {
	wc               *WsConnection
	accountID        int64
	latestGeneration uint64
}

type continuationBudgetSnapshot struct {
	latest     map[*WsConnection]uint64
	candidates []continuationBudgetCandidate
	perAccount map[int64]int
}

func (s continuationBudgetSnapshot) globalCount() int {
	return len(s.candidates)
}

func (m *Manager) newResponseConnSummaryLocked(wc *WsConnection, accountID int64) *responseConnSummary {
	if m.respConnSummaries == nil {
		m.respConnSummaries = make(map[*WsConnection]*responseConnSummary)
	}
	if m.respConnSummaryAccountCounts == nil {
		m.respConnSummaryAccountCounts = make(map[int64]int)
	}
	summary := &responseConnSummary{
		responseGenerations: make(map[string]uint64),
		accountID:           accountID,
	}
	m.respConnSummaries[wc] = summary
	m.respConnSummaryAccountCounts[accountID]++
	return summary
}

func (m *Manager) deleteResponseConnSummaryLocked(wc *WsConnection) {
	summary := m.respConnSummaries[wc]
	if summary == nil {
		return
	}
	delete(m.respConnSummaries, wc)
	if count := m.respConnSummaryAccountCounts[summary.accountID]; count <= 1 {
		delete(m.respConnSummaryAccountCounts, summary.accountID)
	} else {
		m.respConnSummaryAccountCounts[summary.accountID] = count - 1
	}
}

func (m *Manager) rebuildResponseBindingOrderLocked() {
	m.responseBindingOrder = make(map[uint64]string, len(m.respConnBindings))
	m.responseBindingOldestGeneration = 0
	for responseID, binding := range m.respConnBindings {
		if binding.generation == 0 {
			continue
		}
		m.responseBindingOrder[binding.generation] = responseID
		if m.responseBindingOldestGeneration == 0 || binding.generation < m.responseBindingOldestGeneration {
			m.responseBindingOldestGeneration = binding.generation
		}
		if binding.generation > m.responseBindingGeneration {
			m.responseBindingGeneration = binding.generation
		}
	}
}

func (m *Manager) advanceResponseBindingOldestLocked() {
	oldest := m.responseBindingOldestGeneration
	if oldest == 0 {
		return
	}
	for oldest <= m.responseBindingGeneration {
		if _, exists := m.responseBindingOrder[oldest]; exists {
			m.responseBindingOldestGeneration = oldest
			return
		}
		oldest++
	}
	m.responseBindingOldestGeneration = 0
}

func (m *Manager) deleteResponseBindingOrderLocked(binding responseConnBinding) {
	if binding.generation == 0 || m.responseBindingOrder == nil {
		return
	}
	delete(m.responseBindingOrder, binding.generation)
}

func (m *Manager) recordResponseBindingOrderLocked(responseID string, binding responseConnBinding) {
	if m.responseBindingOrder == nil {
		m.responseBindingOrder = make(map[uint64]string, 64)
	}
	m.responseBindingOrder[binding.generation] = responseID
	if m.responseBindingOldestGeneration == 0 || binding.generation < m.responseBindingOldestGeneration {
		m.responseBindingOldestGeneration = binding.generation
	}
}

func (m *Manager) evictOldestResponseConnBindingLocked() bool {
	m.advanceResponseBindingOldestLocked()
	for m.responseBindingOldestGeneration != 0 {
		generation := m.responseBindingOldestGeneration
		responseID, exists := m.responseBindingOrder[generation]
		if !exists {
			m.advanceResponseBindingOldestLocked()
			continue
		}
		binding, current := m.respConnBindings[responseID]
		if !current || binding.generation != generation {
			delete(m.responseBindingOrder, generation)
			m.advanceResponseBindingOldestLocked()
			continue
		}
		m.removeResponseConnBindingLocked(responseID)
		return true
	}
	return false
}

func (m *Manager) rebuildResponseConnSummariesLocked() {
	m.respConnSummaries = make(map[*WsConnection]*responseConnSummary)
	m.respConnSummaryAccountCounts = make(map[int64]int)
	for responseID, binding := range m.respConnBindings {
		if binding.conn == nil {
			continue
		}
		summary := m.respConnSummaries[binding.conn]
		if summary == nil {
			summary = m.newResponseConnSummaryLocked(binding.conn, binding.accountID)
		}
		summary.responseGenerations[responseID] = binding.generation
		if binding.generation >= summary.latestGeneration {
			summary.latestGeneration = binding.generation
			summary.latestExpiresAt = binding.expiresAt
		}
	}
	m.rebuildResponseBindingOrderLocked()
}

func (m *Manager) recomputeResponseConnSummaryLocked(wc *WsConnection) {
	summary := m.respConnSummaries[wc]
	if summary == nil {
		return
	}
	summary.latestGeneration = 0
	summary.latestExpiresAt = time.Time{}
	for responseID, indexedGeneration := range summary.responseGenerations {
		binding, exists := m.respConnBindings[responseID]
		if !exists || binding.conn != wc {
			delete(summary.responseGenerations, responseID)
			continue
		}
		if indexedGeneration != binding.generation {
			summary.responseGenerations[responseID] = binding.generation
		}
		if binding.generation >= summary.latestGeneration {
			summary.latestGeneration = binding.generation
			summary.latestExpiresAt = binding.expiresAt
		}
	}
	if len(summary.responseGenerations) == 0 {
		m.deleteResponseConnSummaryLocked(wc)
	}
}

// removeResponseConnBindingBatchLocked removes any number of IDs owned by one
// physical connection and repairs its summary once. Bulk expiry/dead-connection
// cleanup must not call the single-ID latest-generation repair N times: that
// turns a large response history on one socket into O(N^2) work.
func (m *Manager) removeResponseConnBindingBatchLocked(wc *WsConnection, responseIDs []string) {
	if wc == nil || len(responseIDs) == 0 {
		return
	}
	summary := m.respConnSummaries[wc]
	for _, responseID := range responseIDs {
		binding, exists := m.respConnBindings[responseID]
		if !exists || binding.conn != wc {
			continue
		}
		delete(m.respConnBindings, responseID)
		m.deleteResponseBindingOrderLocked(binding)
		if summary != nil {
			delete(summary.responseGenerations, responseID)
		}
	}
	if summary == nil {
		m.advanceResponseBindingOldestLocked()
		return
	}
	if len(summary.responseGenerations) == 0 {
		m.deleteResponseConnSummaryLocked(wc)
		m.advanceResponseBindingOldestLocked()
		return
	}
	m.recomputeResponseConnSummaryLocked(wc)
	m.advanceResponseBindingOldestLocked()
}

func (m *Manager) removeResponseConnBindingLocked(responseID string) {
	binding, ok := m.respConnBindings[responseID]
	if !ok {
		return
	}
	delete(m.respConnBindings, responseID)
	m.deleteResponseBindingOrderLocked(binding)
	summary := m.respConnSummaries[binding.conn]
	if summary == nil {
		m.advanceResponseBindingOldestLocked()
		return
	}
	delete(summary.responseGenerations, responseID)
	if len(summary.responseGenerations) == 0 {
		m.deleteResponseConnSummaryLocked(binding.conn)
		m.advanceResponseBindingOldestLocked()
		return
	}
	if binding.generation != summary.latestGeneration {
		m.advanceResponseBindingOldestLocked()
		return
	}
	m.recomputeResponseConnSummaryLocked(binding.conn)
	m.advanceResponseBindingOldestLocked()
}

func (m *Manager) publishResponseConnBindingLocked(responseID string, binding responseConnBinding) {
	if _, exists := m.respConnBindings[responseID]; exists {
		m.removeResponseConnBindingLocked(responseID)
	}
	m.respConnBindings[responseID] = binding
	m.recordResponseBindingOrderLocked(responseID, binding)
	summary := m.respConnSummaries[binding.conn]
	if summary == nil {
		summary = m.newResponseConnSummaryLocked(binding.conn, binding.accountID)
	}
	summary.responseGenerations[responseID] = binding.generation
	if binding.generation >= summary.latestGeneration {
		summary.latestGeneration = binding.generation
		summary.latestExpiresAt = binding.expiresAt
	}
}

func (m *Manager) removeResponseConnBindingsForConnectionLocked(wc *WsConnection) {
	if wc == nil {
		return
	}
	if summary := m.respConnSummaries[wc]; summary != nil {
		for responseID := range summary.responseGenerations {
			if binding, exists := m.respConnBindings[responseID]; exists && binding.conn == wc {
				delete(m.respConnBindings, responseID)
				m.deleteResponseBindingOrderLocked(binding)
			}
		}
		m.deleteResponseConnSummaryLocked(wc)
		m.advanceResponseBindingOldestLocked()
		return
	}
	// Defensive fallback for tests or data created before the secondary index.
	for responseID, binding := range m.respConnBindings {
		if binding.conn == wc {
			delete(m.respConnBindings, responseID)
			m.deleteResponseBindingOrderLocked(binding)
		}
	}
	m.advanceResponseBindingOldestLocked()
}

func (m *Manager) pruneResponseConnBindingsLocked(now time.Time) {
	if len(m.respConnSummaries) == 0 && len(m.respConnBindings) > 0 {
		m.rebuildResponseConnSummariesLocked()
	}
	removeAll := make(map[*WsConnection]struct{})
	removeIDs := make(map[*WsConnection][]string)
	orphanIDs := make([]string, 0)
	for responseID, binding := range m.respConnBindings {
		wc := binding.conn
		if wc == nil {
			orphanIDs = append(orphanIDs, responseID)
			continue
		}
		if _, alreadyRemoving := removeAll[wc]; alreadyRemoving {
			continue
		}
		if !wc.IsConnected() || isEvictableIdleExpired(wc) || isRotatableOverAge(wc) {
			removeAll[wc] = struct{}{}
			delete(removeIDs, wc)
			continue
		}
		if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc {
			removeAll[wc] = struct{}{}
			delete(removeIDs, wc)
			continue
		}
		if now.After(binding.expiresAt) {
			removeIDs[wc] = append(removeIDs[wc], responseID)
		}
	}
	for _, responseID := range orphanIDs {
		if binding, exists := m.respConnBindings[responseID]; exists {
			delete(m.respConnBindings, responseID)
			m.deleteResponseBindingOrderLocked(binding)
		}
	}
	for wc := range removeAll {
		m.removeResponseConnBindingsForConnectionLocked(wc)
	}
	for wc, responseIDs := range removeIDs {
		if _, removingAll := removeAll[wc]; !removingAll {
			m.removeResponseConnBindingBatchLocked(wc, responseIDs)
		}
	}
	m.advanceResponseBindingOldestLocked()
}

// responseConnSummarySnapshotLocked returns the newest live Bind generation
// per physical connection without scanning the full response-ID table.
func (m *Manager) responseConnSummarySnapshotLocked(now time.Time) map[*WsConnection]uint64 {
	if len(m.respConnSummaries) == 0 && len(m.respConnBindings) > 0 {
		m.rebuildResponseConnSummariesLocked()
	}
	latest := make(map[*WsConnection]uint64, len(m.respConnSummaries))
	stale := make([]*WsConnection, 0)
	for wc, summary := range m.respConnSummaries {
		if wc == nil || summary == nil || summary.latestGeneration == 0 || now.After(summary.latestExpiresAt) ||
			!wc.IsConnected() || isEvictableIdleExpired(wc) || isRotatableOverAge(wc) {
			stale = append(stale, wc)
			continue
		}
		if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc {
			stale = append(stale, wc)
			continue
		}
		latest[wc] = summary.latestGeneration
	}
	for _, wc := range stale {
		m.removeResponseConnBindingsForConnectionLocked(wc)
	}
	return latest
}

// latestLiveResponseBindingsLocked keeps the historical prune+snapshot
// semantics for periodic cleanup and cap repair. Hot acquire/release paths use
// the secondary connection index directly.
func (m *Manager) latestLiveResponseBindingsLocked(now time.Time) map[*WsConnection]uint64 {
	m.pruneResponseConnBindingsLocked(now)
	return m.responseConnSummarySnapshotLocked(now)
}

func (m *Manager) pruneResponseConnBindings() {
	if m == nil {
		return
	}
	m.respConnMu.Lock()
	m.latestLiveResponseBindingsLocked(time.Now())
	m.respConnMu.Unlock()
}

func (m *Manager) snapshotLiveResponseBindings() map[*WsConnection]uint64 {
	if m == nil {
		return map[*WsConnection]uint64{}
	}
	m.respConnMu.Lock()
	latest := m.responseConnSummarySnapshotLocked(time.Now())
	m.respConnMu.Unlock()
	return latest
}

// continuationBudgetSnapshotLocked counts distinct live response-bound idle
// sockets. Active sockets can still own older bindings, but they belong to
// ordinary capacity and are never continuation-budget victims. Caller holds
// respConnMu; the returned latest map shares no mutable binding objects.
func (m *Manager) continuationBudgetSnapshotLocked(now time.Time) continuationBudgetSnapshot {
	latest := m.responseConnSummarySnapshotLocked(now)
	snapshot := continuationBudgetSnapshot{
		latest:     latest,
		candidates: make([]continuationBudgetCandidate, 0, len(latest)),
		perAccount: make(map[int64]int),
	}
	for wc, generation := range latest {
		if wc == nil || wc.session == nil || wc.session.PendingCount() != 0 || !wc.IsConnected() {
			continue
		}
		accountID := wc.session.AccountID
		snapshot.candidates = append(snapshot.candidates, continuationBudgetCandidate{
			wc:               wc,
			accountID:        accountID,
			latestGeneration: generation,
		})
		snapshot.perAccount[accountID]++
	}
	return snapshot
}

func olderContinuationCandidate(left, right continuationBudgetCandidate) bool {
	if left.latestGeneration != right.latestGeneration {
		return left.latestGeneration < right.latestGeneration
	}
	return left.wc.PoolKey < right.wc.PoolKey
}

// selectContinuationBudgetVictim first repairs every per-account violation,
// then the global violation. Within the eligible set it sacrifices the socket
// whose newest live Bind generation is oldest, so one stale response ID cannot
// make a connection with a newer continuation look old.
func selectContinuationBudgetVictim(
	snapshot continuationBudgetSnapshot,
	globalLimit int,
	perAccountLimit int,
) (continuationBudgetCandidate, bool) {
	var victim continuationBudgetCandidate
	found := false
	for _, candidate := range snapshot.candidates {
		if snapshot.perAccount[candidate.accountID] <= perAccountLimit {
			continue
		}
		if !found || olderContinuationCandidate(candidate, victim) {
			victim = candidate
			found = true
		}
	}
	if found {
		return victim, true
	}
	if snapshot.globalCount() <= globalLimit {
		return continuationBudgetCandidate{}, false
	}
	for _, candidate := range snapshot.candidates {
		if !found || olderContinuationCandidate(candidate, victim) {
			victim = candidate
			found = true
		}
	}
	return victim, found
}

func (m *Manager) continuationSocketLimits() (globalLimit int, perAccountLimit int) {
	globalLimit = m.continuationGlobalLimit
	perAccountLimit = m.continuationPerAccountLimit
	if globalLimit < minContinuationSocketLimit || globalLimit > maxContinuationSocketLimit {
		globalLimit = defaultContinuationGlobalLimit
	}
	if perAccountLimit < minContinuationSocketLimit || perAccountLimit > maxContinuationSocketLimit {
		perAccountLimit = defaultContinuationPerAccountLimit
	}
	if perAccountLimit > globalLimit {
		perAccountLimit = globalLimit
	}
	return globalLimit, perAccountLimit
}

func (m *Manager) continuationBudgetMayBeExceeded(accountID int64) bool {
	if m == nil {
		return false
	}
	globalLimit, perAccountLimit := m.continuationSocketLimits()
	m.respConnMu.Lock()
	globalCount := len(m.respConnSummaries)
	accountCount := m.respConnSummaryAccountCounts[accountID]
	m.respConnMu.Unlock()
	// Summaries include active sockets, while the budget only counts idle ones.
	// They are therefore a conservative O(1) pressure test: false positives run
	// the exact convergence scan, false negatives are impossible.
	return globalCount > globalLimit || accountCount > perAccountLimit
}

// discardContinuationBudgetCandidate re-locks one cross-account snapshot
// candidate using the normal pool-key -> account -> binding order. It never
// waits for those locks while holding respConnMu, revalidates both liveness and
// LRU generation, removes map ownership and all bindings atomically, then
// closes the socket only after every routing lock has been released.
func (m *Manager) discardContinuationBudgetCandidate(
	candidate continuationBudgetCandidate,
	globalLimit int,
	perAccountLimit int,
) bool {
	wc := candidate.wc
	if wc == nil {
		return false
	}
	keyLock := m.keyLock(wc.PoolKey)
	m.lockPoolKey(wc.PoolKey, keyLock)
	accountLock := m.accountLock(candidate.accountID)
	accountLock.Lock()

	m.respConnMu.Lock()
	snapshot := m.continuationBudgetSnapshotLocked(time.Now())
	currentVictim, overBudget := selectContinuationBudgetVictim(snapshot, globalLimit, perAccountLimit)
	current, isCurrent := m.connections.Load(wc.PoolKey)
	actualGeneration, stillBound := snapshot.latest[wc]
	valid := overBudget && currentVictim.wc == wc && isCurrent && current == wc &&
		wc.session != nil && wc.session.AccountID == candidate.accountID &&
		wc.IsConnected() && wc.session.PendingCount() == 0 && stillBound &&
		actualGeneration == candidate.latestGeneration
	removed := false
	if valid {
		removed = m.connections.CompareAndDelete(wc.PoolKey, wc)
		if removed {
			m.sessions.CompareAndDelete(wc.PoolKey, wc.session)
			m.removeResponseConnBindingsForConnectionLocked(wc)
		}
	}
	m.respConnMu.Unlock()
	accountLock.Unlock()
	keyLock.Unlock()

	if !removed {
		return false
	}
	m.continuationBudgetEvictions.Add(1)
	if wc.session != nil {
		wc.session.Close()
	}
	_ = wc.Close()
	return true
}

// enforceContinuationSocketBudgets serializes global convergence but never
// nests continuationMu under accountLock. Each failed revalidation restarts
// from a fresh cross-account snapshot, handling concurrent Bind/Acquire safely.
func (m *Manager) enforceContinuationSocketBudgets() {
	if m == nil {
		return
	}
	globalLimit, perAccountLimit := m.continuationSocketLimits()
	m.continuationMu.Lock()
	defer m.continuationMu.Unlock()
	for attempts := 0; attempts < responseConnBindingMaxEntries*2; attempts++ {
		m.respConnMu.Lock()
		snapshot := m.continuationBudgetSnapshotLocked(time.Now())
		candidate, overBudget := selectContinuationBudgetVictim(snapshot, globalLimit, perAccountLimit)
		m.respConnMu.Unlock()
		if !overBudget {
			return
		}
		if m.beforeContinuationRevalidation != nil {
			m.beforeContinuationRevalidation(candidate.wc)
		}
		m.discardContinuationBudgetCandidate(candidate, globalLimit, perAccountLimit)
	}
}

func (m *Manager) removeResponseConnBindings(wc *WsConnection) {
	if m == nil || wc == nil {
		return
	}
	m.removeResponseConnBindingsForConnections(map[*WsConnection]struct{}{wc: struct{}{}})
}

func (m *Manager) removeResponseConnBindingsForConnections(connections map[*WsConnection]struct{}) {
	if m == nil || len(connections) == 0 {
		return
	}
	m.respConnMu.Lock()
	for wc := range connections {
		m.removeResponseConnBindingsForConnectionLocked(wc)
	}
	m.respConnMu.Unlock()
}

func (m *Manager) idleConnectionCanBeEvicted(wc *WsConnection, protected *WsConnection, protectedKey string) bool {
	if wc == nil || wc == protected || (protectedKey != "" && wc.PoolKey == protectedKey) || wc.session == nil || wc.session.PendingCount() != 0 || !wc.IsConnected() {
		return false
	}
	current, ok := m.connections.Load(wc.PoolKey)
	return ok && current == wc
}

// discardOrdinaryIdleConnection atomically arbitrates ordinary-capacity
// eviction against BindResponseConn. If the candidate acquired a live binding,
// it has moved into the separately-budgeted continuation pool and is excluded
// rather than closed. Otherwise it is removed while respConnMu prevents a
// concurrent bind from publishing a stale pointer.
func (m *Manager) discardOrdinaryIdleConnection(
	wc *WsConnection,
	protected *WsConnection,
	protectedKey string,
) (removed bool, becameBound bool) {
	if !m.idleConnectionCanBeEvicted(wc, protected, protectedKey) {
		return false, false
	}
	m.respConnMu.Lock()
	latestBinding := m.responseConnSummarySnapshotLocked(time.Now())
	if _, isBound := latestBinding[wc]; isBound {
		m.respConnMu.Unlock()
		return false, true
	}
	if !m.idleConnectionCanBeEvicted(wc, protected, protectedKey) {
		m.respConnMu.Unlock()
		return false, false
	}
	removed = m.connections.CompareAndDelete(wc.PoolKey, wc)
	if removed && wc.session != nil {
		m.sessions.CompareAndDelete(wc.PoolKey, wc.session)
	}
	m.respConnMu.Unlock()
	if !removed {
		return false, false
	}
	if wc.session != nil {
		wc.session.Close()
	}
	_ = wc.Close()
	return true, false
}

// evictIdleAccountConnections converges ordinary capacity using only unbound
// idle sockets. A raced binding moves the socket out of the ordinary count.
func (m *Manager) evictIdleAccountConnections(
	idle []idleAccountConnection,
	protected *WsConnection,
	protectedKey string,
	shouldStop func() bool,
	onEvicted func(),
) {
	if m.beforeCapacityEviction != nil {
		m.beforeCapacityEviction()
	}
	sort.Slice(idle, func(i, j int) bool { return idle[i].lastUsed < idle[j].lastUsed })
	for _, candidate := range idle {
		if shouldStop() {
			return
		}
		removed, becameBound := m.discardOrdinaryIdleConnection(candidate.wc, protected, protectedKey)
		if removed || becameBound {
			onEvicted()
		}
	}
}

// convergeAccountConnectionCapacity admits additional ordinary slots while
// evicting only unbound idle sockets. If activating is non-nil, that existing
// connection is protected and consumes an additional slot only when the same
// binding snapshot classified it as bound-idle; an unbound idle connection is
// already included in count. Caller holds this account's accountLock.
func (m *Manager) convergeAccountConnectionCapacity(
	accountID int64,
	limit int,
	protectedKey string,
	activating *WsConnection,
	pendingCreates int,
	additionalSlots int,
) bool {
	if limit < 1 {
		limit = 1
	}
	count := 0
	stale := make([]*WsConnection, 0)
	idle := make([]idleAccountConnection, 0)
	activatingStale := false
	bound := m.snapshotLiveResponseBindings()
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || wc.session == nil || wc.session.AccountID != accountID {
			return true
		}
		if !wc.IsConnected() || isEvictableIdleExpired(wc) || isRotatableOverAge(wc) {
			stale = append(stale, wc)
			if wc == activating {
				activatingStale = true
			}
			return true
		}
		pending := wc.session.PendingCount()
		if _, isBound := bound[wc]; isBound && pending == 0 {
			return true
		}
		count++
		if wc.PoolKey != protectedKey && pending == 0 {
			idle = append(idle, idleAccountConnection{wc: wc, lastUsed: wc.lastUsed.Load()})
		}
		return true
	})
	if activating != nil {
		if _, isBoundIdle := bound[activating]; isBoundIdle && activating.session != nil && activating.session.PendingCount() == 0 {
			additionalSlots++
		}
	}
	for _, wc := range stale {
		m.DiscardConnection(wc)
	}
	if activatingStale {
		return false
	}
	withinLimit := func() bool { return count+pendingCreates+additionalSlots <= limit }
	if withinLimit() {
		return true
	}
	m.evictIdleAccountConnections(
		idle,
		activating,
		protectedKey,
		withinLimit,
		func() { count-- },
	)
	return withinLimit()
}

// ensureAccountConnectionCapacity reserves one new ordinary socket slot.
func (m *Manager) ensureAccountConnectionCapacity(accountID int64, limit int, protectedKey string, pendingCreates int) bool {
	return m.convergeAccountConnectionCapacity(accountID, limit, protectedKey, nil, pendingCreates, 1)
}

// trimIdleAccountConnections converges active sockets plus unbound idle sockets
// to the dynamic limit. Bound-idle continuation sockets are excluded here and
// converged by enforceContinuationSocketBudgets. The protected/current socket
// and every other in-flight request are never interrupted.
// 调用方必须持有该账号的 accountLock。
func (m *Manager) trimIdleAccountConnections(accountID int64, limit int, protected *WsConnection) {
	if limit < 1 {
		limit = 1
	}
	count := 0
	stale := make([]*WsConnection, 0)
	idle := make([]idleAccountConnection, 0)
	bound := m.snapshotLiveResponseBindings()
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || wc.session == nil || wc.session.AccountID != accountID {
			return true
		}
		if !wc.IsConnected() || isEvictableIdleExpired(wc) || isRotatableOverAge(wc) {
			stale = append(stale, wc)
			return true
		}
		pending := wc.session.PendingCount()
		if _, isBound := bound[wc]; isBound && pending == 0 {
			return true
		}
		count++
		if wc != protected && pending == 0 {
			idle = append(idle, idleAccountConnection{wc: wc, lastUsed: wc.lastUsed.Load()})
		}
		return true
	})
	for _, wc := range stale {
		m.DiscardConnection(wc)
	}
	if count <= limit {
		return
	}

	m.evictIdleAccountConnections(
		idle,
		protected,
		"",
		func() bool { return count <= limit },
		func() { count-- },
	)
}

// ensureConnectionActivationCapacity admits an existing idle socket as active
// using one binding snapshot for both classification and counting. This avoids
// double-counting unbound idle reuse and under-counting a raced bound-idle
// activation. Current pending dials are part of admission. A last binding that
// disappears immediately after the snapshot can reclassify one idle socket to
// ordinary at the TTL boundary; combined physical capacity does not grow, and
// Release/the periodic cleanup converges the ordinary label promptly.
func (m *Manager) ensureConnectionActivationCapacity(accountID int64, limit int, wc *WsConnection) bool {
	m.capacityMu.Lock()
	pendingCreates := m.pendingCreates[accountID]
	m.capacityMu.Unlock()
	return m.convergeAccountConnectionCapacity(accountID, limit, wc.PoolKey, wc, pendingCreates, 0)
}

// reserveAccountConnectionCapacity must be called while holding accountLock.
// It reads the limit at the reservation point so a scheduler tier change is
// not masked by a value cached at the start of a longer acquire operation.
func (m *Manager) reserveAccountConnectionCapacity(account *auth.Account, protectedKey string) bool {
	accountID := account.ID()
	limit := accountConnectionLimit(account)
	m.capacityMu.Lock()
	pending := m.pendingCreates[accountID]
	m.capacityMu.Unlock()
	if !m.ensureAccountConnectionCapacity(accountID, limit, protectedKey, pending) {
		return false
	}
	m.capacityMu.Lock()
	if m.pendingCreates == nil {
		m.pendingCreates = make(map[int64]int)
	}
	m.pendingCreates[accountID]++
	m.capacityMu.Unlock()
	return true
}

func (m *Manager) releaseAccountConnectionCapacity(accountID int64) {
	m.capacityMu.Lock()
	if pending := m.pendingCreates[accountID]; pending <= 1 {
		delete(m.pendingCreates, accountID)
	} else {
		m.pendingCreates[accountID] = pending - 1
	}
	m.capacityMu.Unlock()
}

// storeConnectionAndBeginReadLease atomically converts one pending dial
// reservation into one stored connection with its first request lease. Without
// the account lock around this transition, another pool key can observe the
// same physical socket twice (stored + pending create), classify it as idle
// before AddPendingRequest runs, and evict it while its creator is still
// returning from the handshake.
func (m *Manager) storeConnectionAndBeginReadLease(
	ctx context.Context,
	account *auth.Account,
	accountLock *sync.Mutex,
	wc *WsConnection,
	sessionKey string,
) (*PendingRequest, error) {
	return m.storeConnectionAndBeginReadLeaseChecked(ctx, account, accountLock, wc, sessionKey, nil)
}

func (m *Manager) storeConnectionAndBeginReadLeaseChecked(
	ctx context.Context,
	account *auth.Account,
	accountLock *sync.Mutex,
	wc *WsConnection,
	sessionKey string,
	promotionCheck func() bool,
) (*PendingRequest, error) {
	accountID := account.ID()
	accountLock.Lock()
	defer accountLock.Unlock()

	select {
	case <-ctx.Done():
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, ctx.Err()
	default:
	}
	if promotionCheck != nil && !promotionCheck() {
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: rollout capacity or policy changed during dial")
	}

	// A dial reservation can outlive the health-tier limit that admitted it.
	// Revalidate the ordinary-cap budget at promotion time. Other pending dials
	// run this check serially; bound-idle context remains separately budgeted.
	if !m.ensureAccountConnectionCapacity(accountID, accountConnectionLimit(account), wc.PoolKey, 0) {
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: current account connection limit reached")
	}

	// The permanent reader starts immediately after the handshake. Serialize
	// its failure callback with promotion, establish the first lease before map
	// publication, and revalidate both before and after Store so a peer that
	// closes immediately cannot leave a dead session/connection visible.
	wc.promotionMu.Lock()
	defer wc.promotionMu.Unlock()
	if !wc.IsConnected() || wc.session == nil || !wc.session.IsConnected() {
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: connection closed before first lease")
	}
	pr, err := m.addPendingAndBeginReadLease(wc, sessionKey)
	if err != nil {
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, err
	}
	select {
	case <-ctx.Done():
		wc.session.RemovePendingRequest(pr.RequestID)
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, ctx.Err()
	default:
	}
	if !wc.IsConnected() || !wc.session.IsConnected() {
		wc.session.RemovePendingRequest(pr.RequestID)
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: connection closed before publication")
	}
	m.sessions.Store(wc.PoolKey, wc.session)
	m.connections.Store(wc.PoolKey, wc)
	if m.afterConnectionStored != nil {
		m.afterConnectionStored(wc)
	}
	if promotionCheck != nil && !promotionCheck() {
		wc.session.RemovePendingRequest(pr.RequestID)
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: rollout generation or policy changed during publication")
	}
	storedConnection, connectionStored := m.connections.Load(wc.PoolKey)
	storedSession, sessionStored := m.sessions.Load(wc.PoolKey)
	if !wc.IsConnected() || !wc.session.IsConnected() || !connectionStored || storedConnection != wc || !sessionStored || storedSession != wc.session {
		wc.session.RemovePendingRequest(pr.RequestID)
		m.releaseAccountConnectionCapacity(accountID)
		m.discardConnectionState(wc)
		return nil, fmt.Errorf("promote websocket connection: connection closed during publication")
	}
	m.releaseAccountConnectionCapacity(accountID)
	return pr, nil
}

// AcquireConnection 获取或创建连接
// 仅在同一逻辑 session 且连接空闲时复用，避免不同会话共用一条已握手连接。
func (m *Manager) AcquireConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	sessionKey string,
	headers http.Header,
	proxyOverride string,
) (*WsConnection, *PendingRequest, error) {
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer finishOperation()
	return m.acquireConnection(opCtx, account, wsURL, sessionKey, headers, proxyOverride, false)
}

func (m *Manager) acquireConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	sessionKey string,
	headers http.Header,
	proxyOverride string,
	replacementOwner bool,
) (*WsConnection, *PendingRequest, error) {
	key := m.poolKey(account.ID(), wsURL, sessionKey, effectiveProxyURL(account, proxyOverride))
	lock := m.keyLock(key)
	accountLock := m.accountLock(account.ID())
	wait := AcquireInitialBackoff
	var waited time.Duration
	var createLeaseFailures int
	var busyOverflowAttempted bool

	for {
		if replacementOwner {
			lock.Lock()
		} else {
			m.lockPoolKey(key, lock)
		}
		if v, ok := m.connections.Load(key); ok {
			wc := v.(*WsConnection)
			if canReuseConnection(wc) {
				// 发送 Ping 探活，确认连接真正存活
				if m.probe(wc) {
					// 网络 probe 不持有账号锁。同账号其它 pool key 可以并行探活；
					// probe 期间连接可能被账号容量裁剪，因此拿锁后必须复验。
					accountLock.Lock()
					current, exists := m.connections.Load(key)
					if !exists || current != wc || !canReuseConnection(wc) {
						accountLock.Unlock()
						lock.Unlock()
						continue
					}
					if !m.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), wc) {
						accountLock.Unlock()
						lock.Unlock()
						if maxWait := busyAcquireMaxWait(); waited >= maxWait {
							return nil, nil, newLocalCapacityAcquireError(maxWait)
						}
						select {
						case <-ctx.Done():
							return nil, nil, newLocalCapacityAcquireError(waited, ctx.Err())
						case <-time.After(wait):
						}
						waited += wait
						if wait < AcquireMaxBackoff {
							wait *= 2
							if wait > AcquireMaxBackoff {
								wait = AcquireMaxBackoff
							}
						}
						continue
					}
					pr, leaseErr := m.addPendingAndBeginReadLease(wc, sessionKey)
					if leaseErr == nil {
						wc.account = account
						wc.Touch()
						m.trimIdleAccountConnections(account.ID(), accountConnectionLimit(account), wc)
						accountLock.Unlock()
						lock.Unlock()
						return wc, pr, nil
					}
					m.DiscardConnection(wc)
					accountLock.Unlock()
					lock.Unlock()
					continue
				}
				// 探活失败，清理死连接
				m.DiscardConnection(wc)
				lock.Unlock()
				continue
			}
			if wc.IsConnected() && wc.session != nil && wc.session.PendingCount() > 0 {
				lock.Unlock()
				// 连接被同 session 的前一个请求占用：指数退避轮询等待其空闲，
				// 累计等待超过上限则返回错误，避免无界阻塞与固定间隔空转抢锁。
				// 到龄连接也会走到这里等在途请求结束，结束后下一轮循环轮转重建。
				//
				// 短等待(patience)后可溢出到同账号的兄弟槽位（issue #413，默认关闭）：
				// 前一请求长时间流式输出时，同会话的并发请求不再等满整个上限。
				// 只尝试一次；失败（容量满/拨号失败）回落到继续等待，最坏情况与关闭时一致。
				if !busyOverflowAttempted && busyOverflowEnabled() && waited >= busyOverflowPatience() && !isBusyOverflowSessionKey(sessionKey) {
					busyOverflowAttempted = true
					if owc, opr, ok := m.tryAcquireBusyOverflow(ctx, account, wsURL, sessionKey, headers, proxyOverride); ok {
						log.Printf("[WS] busy session 溢出到同账号兄弟连接 (account=%d, waited=%s)", account.ID(), waited.Round(time.Millisecond))
						return owc, opr, nil
					}
				}
				if maxWait := busyAcquireMaxWait(); waited >= maxWait {
					return nil, nil, newSessionBusyAcquireError(maxWait)
				}
				select {
				case <-ctx.Done():
					return nil, nil, newSessionBusyAcquireError(waited, ctx.Err())
				case <-time.After(wait):
				}
				waited += wait
				if wait < AcquireMaxBackoff {
					wait *= 2
					if wait > AcquireMaxBackoff {
						wait = AcquireMaxBackoff
					}
				}
				continue
			}
			m.DiscardConnection(wc)
		}
		accountLock.Lock()
		if !m.reserveAccountConnectionCapacity(account, key) {
			accountLock.Unlock()
			lock.Unlock()
			if maxWait := busyAcquireMaxWait(); waited >= maxWait {
				return nil, nil, newLocalCapacityAcquireError(maxWait)
			}
			select {
			case <-ctx.Done():
				return nil, nil, newLocalCapacityAcquireError(waited, ctx.Err())
			case <-time.After(wait):
			}
			waited += wait
			if wait < AcquireMaxBackoff {
				wait *= 2
				if wait > AcquireMaxBackoff {
					wait = AcquireMaxBackoff
				}
			}
			continue
		}
		// 容量已预留，拨号期间不再持有账号锁；其他 session 可以复用已有连接，
		// 但会把本次 pending create 计入上限，避免并发握手越界。
		accountLock.Unlock()

		wc, err := m.createConnection(ctx, account, wsURL, sessionKey, headers, proxyOverride)
		if err != nil {
			m.releaseAccountConnectionCapacity(account.ID())
			lock.Unlock()
			return nil, nil, err
		}

		// 把 pending dial 原子转换为已存储连接 + 首个 request lease，避免同一
		// 物理连接在 Store 到 AddPendingRequest 的窗口里被重复计数并误淘汰。
		pr, leaseErr := m.storeConnectionAndBeginReadLease(ctx, account, accountLock, wc, sessionKey)
		if leaseErr == nil {
			if earlyErr := wc.waitForEarlyReadFailure(ctx, newConnectionReadFailureGrace); earlyErr != nil {
				wc.session.RemovePendingRequest(pr.RequestID)
				leaseErr = earlyErr
			}
		}
		if leaseErr != nil {
			m.DiscardConnection(wc)
			lock.Unlock()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			createLeaseFailures++
			if createLeaseFailures >= maxCreateLeaseAttempts {
				return nil, nil, fmt.Errorf("reserve new websocket connection after %d attempts: %w", createLeaseFailures, leaseErr)
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			default:
			}
			continue
		}
		lock.Unlock()

		if fn := m.getOnConnected(); fn != nil {
			fn(account.ID(), wc.session)
		}

		return wc, pr, nil
	}
}

// tryAcquireBusyOverflow 在 busy session 等待超过 patience 后，尝试在同账号的有界
// overflow 槽位（<sessionKey>#ovf-N）上复用空闲兄弟连接或新建一条（issue #413）。
// 单遍、尽力而为：槽位也在忙则换下一个；账号容量满或拨号/租约失败即放弃，调用方
// 回落到继续等待原连接——失败路径不会比不开启 overflow 更差。
// 兄弟连接正常入池，由既有的 IdleTimeout/容量裁剪回收。
func (m *Manager) tryAcquireBusyOverflow(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	baseSessionKey string,
	headers http.Header,
	proxyOverride string,
) (*WsConnection, *PendingRequest, bool) {
	proxyURL := effectiveProxyURL(account, proxyOverride)
	accountLimit := accountConnectionLimit(account)
	accountLock := m.accountLock(account.ID())
	for i := 1; i <= BusyOverflowSlots; i++ {
		slotSession := fmt.Sprintf("%s%s%d", baseSessionKey, busyOverflowKeyInfix, i)
		key := m.poolKey(account.ID(), wsURL, slotSession, proxyURL)
		lock := m.keyLock(key)
		lock.Lock()
		if v, ok := m.connections.Load(key); ok {
			wc := v.(*WsConnection)
			if canReuseConnection(wc) {
				if m.probe(wc) {
					accountLock.Lock()
					current, exists := m.connections.Load(key)
					if exists && current == wc && canReuseConnection(wc) {
						pr, leaseErr := m.addPendingAndBeginReadLease(wc, slotSession)
						if leaseErr == nil {
							wc.account = account
							wc.Touch()
							m.trimIdleAccountConnections(account.ID(), accountLimit, wc)
							accountLock.Unlock()
							lock.Unlock()
							return wc, pr, true
						}
						m.DiscardConnection(wc)
					}
					accountLock.Unlock()
					lock.Unlock()
					continue
				}
				m.DiscardConnection(wc)
			} else if wc.IsConnected() && !wc.IsExpired() && wc.session != nil && wc.session.PendingCount() > 0 && !isRotatableOverAge(wc) {
				// 兄弟槽位也在忙：换下一个槽位
				lock.Unlock()
				continue
			} else {
				// 死/到龄/过期连接：清掉腾出槽位，下方直接新建
				m.DiscardConnection(wc)
			}
		}
		accountLock.Lock()
		if _, ok := m.connections.Load(key); ok {
			accountLock.Unlock()
			lock.Unlock()
			continue
		}
		if !m.reserveAccountConnectionCapacity(account, key) {
			// 账号连接容量已满：不为 overflow 挤占更多连接，放弃降级回到等待
			accountLock.Unlock()
			lock.Unlock()
			return nil, nil, false
		}
		accountLock.Unlock()
		wc, err := m.createConnection(ctx, account, wsURL, slotSession, headers, proxyOverride)
		if err != nil {
			m.releaseAccountConnectionCapacity(account.ID())
			lock.Unlock()
			log.Printf("[WS] busy overflow 新建连接失败，回落等待原连接 (account=%d): %v", account.ID(), err)
			return nil, nil, false
		}
		m.connections.Store(key, wc)
		if m.afterConnectionStored != nil {
			m.afterConnectionStored(wc)
		}
		pr, leaseErr := m.addPendingAndBeginReadLease(wc, slotSession)
		if leaseErr == nil {
			if earlyErr := wc.waitForEarlyReadFailure(ctx, newConnectionReadFailureGrace); earlyErr != nil {
				wc.session.RemovePendingRequest(pr.RequestID)
				leaseErr = earlyErr
			}
		}
		m.releaseAccountConnectionCapacity(account.ID())
		if leaseErr != nil {
			m.DiscardConnection(wc)
			lock.Unlock()
			return nil, nil, false
		}
		lock.Unlock()
		if fn := m.getOnConnected(); fn != nil {
			fn(account.ID(), wc.session)
		}
		return wc, pr, true
	}
	return nil, nil, false
}

// StatelessConnectionSlots 无显式会话的请求在每个 (account, cacheKey) 维度下
// 复用的持久连接槽位数。槽位内空闲连接直接复用,避免每个请求都重新握手——
// 持续高 RPM 下逐请求握手会触发上游 WS 握手限流（bad handshake → 503）。
const StatelessConnectionSlots = 8

// maxCreateLeaseAttempts bounds retries when a freshly completed handshake is
// already rejected by its permanent reader before the first request lease can
// be reserved (for example, an immediately queued peer Close frame).
const maxCreateLeaseAttempts = 3

// Give the permanent reader a small, bounded window to surface a Close/error
// already queued with the handshake before returning a newly reserved lease.
const newConnectionReadFailureGrace = 5 * time.Millisecond

// AcquireReusableConnection 在固定槽位内复用或创建连接，返回实际使用的 session key。
// 第一遍只复用已存在且空闲的连接；第二遍在空槽位新建持久连接；槽位全忙时回退到
// fallbackKey 的临时连接。所有路径仍受账号动态并发对应的连接总数上限约束。
func (m *Manager) AcquireReusableConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	baseKey string,
	fallbackKey string,
	slots int,
	headers http.Header,
	proxyOverride string,
) (*WsConnection, *PendingRequest, string, error) {
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer finishOperation()
	ctx = opCtx

	proxyURL := effectiveProxyURL(account, proxyOverride)
	accountLimit := accountConnectionLimit(account)
	if slots < 1 || slots > accountLimit {
		slots = accountLimit
	}
	accountLock := m.accountLock(account.ID())
	// 第一遍：复用空闲连接（探活失败或已断开的顺手清理，让第二遍可以补位）
	for i := 0; i < slots; i++ {
		slotSession := fmt.Sprintf("%s#%d", baseKey, i)
		key := m.poolKey(account.ID(), wsURL, slotSession, proxyURL)
		lock := m.keyLock(key)
		m.lockPoolKey(key, lock)
		if v, ok := m.connections.Load(key); ok {
			wc := v.(*WsConnection)
			if canReuseConnection(wc) {
				if m.probe(wc) {
					accountLock.Lock()
					current, exists := m.connections.Load(key)
					if !exists || current != wc || !canReuseConnection(wc) {
						accountLock.Unlock()
						lock.Unlock()
						continue
					}
					if !m.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), wc) {
						accountLock.Unlock()
						lock.Unlock()
						continue
					}
					pr, leaseErr := m.addPendingAndBeginReadLease(wc, slotSession)
					if leaseErr == nil {
						wc.account = account
						wc.Touch()
						m.trimIdleAccountConnections(account.ID(), accountConnectionLimit(account), wc)
						accountLock.Unlock()
						lock.Unlock()
						return wc, pr, slotSession, nil
					}
					m.DiscardConnection(wc)
					accountLock.Unlock()
					lock.Unlock()
					continue
				}
				m.DiscardConnection(wc)
			} else if !wc.IsConnected() || wc.session == nil || wc.session.PendingCount() == 0 {
				m.DiscardConnection(wc)
			}
		}
		lock.Unlock()
	}
	// 第二遍：在空槽位新建持久连接
	for i := 0; i < slots; i++ {
		slotSession := fmt.Sprintf("%s#%d", baseKey, i)
		key := m.poolKey(account.ID(), wsURL, slotSession, proxyURL)
		lock := m.keyLock(key)
		m.lockPoolKey(key, lock)
		if _, ok := m.connections.Load(key); ok {
			lock.Unlock()
			continue
		}
		accountLock.Lock()
		if _, ok := m.connections.Load(key); ok {
			accountLock.Unlock()
			lock.Unlock()
			continue
		}
		if !m.reserveAccountConnectionCapacity(account, key) {
			accountLock.Unlock()
			lock.Unlock()
			continue
		}
		accountLock.Unlock()
		wc, err := m.createConnection(ctx, account, wsURL, slotSession, headers, proxyOverride)
		if err != nil {
			m.releaseAccountConnectionCapacity(account.ID())
			lock.Unlock()
			return nil, nil, "", err
		}
		pr, leaseErr := m.storeConnectionAndBeginReadLease(ctx, account, accountLock, wc, slotSession)
		if leaseErr == nil {
			if earlyErr := wc.waitForEarlyReadFailure(ctx, newConnectionReadFailureGrace); earlyErr != nil {
				wc.session.RemovePendingRequest(pr.RequestID)
				leaseErr = earlyErr
			}
		}
		if leaseErr != nil {
			m.DiscardConnection(wc)
			lock.Unlock()
			if ctx.Err() != nil {
				return nil, nil, "", ctx.Err()
			}
			continue
		}
		lock.Unlock()
		if fn := m.getOnConnected(); fn != nil {
			fn(account.ID(), wc.session)
		}
		return wc, pr, slotSession, nil
	}
	// 槽位全忙：回退一次性连接
	wc, pr, err := m.AcquireConnection(ctx, account, wsURL, fallbackKey, headers, proxyOverride)
	return wc, pr, fallbackKey, err
}

// addPendingAndBeginReadLease keeps the Session reservation and the pump lease
// atomic from an acquire caller's perspective. On failure it rolls the pending
// request back; the caller discards the unusable connection while holding its
// pool-key acquisition lock.
func (m *Manager) addPendingAndBeginReadLease(wc *WsConnection, sessionKey string) (*PendingRequest, error) {
	if wc == nil || wc.session == nil {
		return nil, fmt.Errorf("begin websocket read lease: connection has no session")
	}
	pr := wc.session.AddPendingRequest(sessionKey)
	if err := wc.BeginReadLease(pr.RequestID); err != nil {
		wc.session.RemovePendingRequest(pr.RequestID)
		return nil, fmt.Errorf("reserve websocket connection: %w", err)
	}
	return pr, nil
}

func canReuseConnection(wc *WsConnection) bool {
	if wc == nil {
		return false
	}
	if !wc.IsConnected() || wc.IsExpired() || wc.IsOverAge() {
		return false
	}
	if wc.safeReusable.Load() && wc.retireAfterLease.Load() {
		return false
	}
	if wc.session == nil {
		return false
	}
	return wc.session.PendingCount() == 0 && wc.readPumpReusable()
}

// isEvictableIdleExpired distinguishes business-idle expiry from a long
// in-flight response that happens to have emitted no data frames recently.
// Pong normally refreshes lastUsed, but PendingCount remains the authoritative
// guard if an otherwise healthy long response is quiet beyond the idle window.
func isEvictableIdleExpired(wc *WsConnection) bool {
	if wc == nil || !wc.IsExpired() {
		return false
	}
	return wc.session == nil || wc.session.PendingCount() == 0
}

// isRotatableOverAge 连接已到龄且当前无在途请求，可安全轮转（销毁重建）。
// 到龄但仍有在途请求的连接不动：50 分钟阈值留了 10 分钟余量，在途流仍能正常
// 收完，等其结束后再轮转，避免掐断在途响应。
func isRotatableOverAge(wc *WsConnection) bool {
	if wc == nil || !wc.IsOverAge() {
		return false
	}
	return wc.session == nil || wc.session.PendingCount() == 0
}

// probeConnection 发送 Ping 检测连接是否真正存活
func probeConnection(wc *WsConnection) bool {
	return probeConnectionWithTimeout(wc, defaultProbeTimeout)
}

// probeRecencyWindow 内有入站活动（数据帧/对端 Ping/Pong 回执）的连接免
// Ping-Pong 往返探活。往返探活在 keyLock 内串行、每次复用叠加一个上游 RTT，
// 请求刚完成后的热复用（最常见路径）不该为此买单；近期入站已证明 TCP 双向
// 存活，且 lease/队列干净由 readPumpReusable 另行把关。窗口取心跳间隔：
// 半开连接最坏在窗口过期后的下一次 probe 或 send 失败重试中被识别。
const probeRecencyWindow = HeartbeatPingInterval

// probe 调用探活函数（支持测试替换）
func (m *Manager) probe(wc *WsConnection) bool {
	return m.probeWithContext(context.Background(), wc)
}

// contextInterruptionError also recognizes a reached deadline during the tiny
// window before context.Err publishes DeadlineExceeded. Timer and Done can
// become ready together; callers must not misclassify that scheduling race as
// proof that a shared physical socket is dead.
func contextInterruptionError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (m *Manager) probeWithContext(ctx context.Context, wc *WsConnection) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if contextInterruptionError(ctx) != nil {
		return false
	}
	m.mu.RLock()
	fn := m.probeFunc
	m.mu.RUnlock()
	if fn != nil {
		// Test hooks can deliberately block. Keep the same cancellation contract
		// as the real probe so preferred-continuation acquisition never outlives
		// the request's TTFT context.
		result := make(chan bool, 1)
		go func() { result <- fn(wc) }()
		select {
		case alive := <-result:
			if contextInterruptionError(ctx) != nil {
				return false
			}
			return alive
		case <-ctx.Done():
			return false
		}
	}
	if wc != nil && wc.IsConnected() && wc.recentInboundWithin(probeRecencyWindow) && wc.readPumpReusable() {
		return contextInterruptionError(ctx) == nil
	}
	alive := probeConnectionWithContext(ctx, wc, defaultProbeTimeout)
	return alive && contextInterruptionError(ctx) == nil
}

func preferredContinuationContextError(ctx context.Context, stage string) error {
	cause := contextInterruptionError(ctx)
	if cause == nil {
		return nil
	}
	return fmt.Errorf("%w: response-bound websocket continuation canceled %s: %w", proxy.ErrWebsocketContinuationUnavailable, stage, cause)
}

// createConnection 创建新 WebSocket 连接
func (m *Manager) createConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	sessionKey string,
	headers http.Header,
	proxyOverride string,
) (*WsConnection, error) {
	return m.createConnectionWithIdentity(ctx, account, wsURL, sessionKey, headers, safeConnectionIdentity{}, proxyOverride)
}

func (m *Manager) createConnectionWithIdentity(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	sessionKey string,
	headers http.Header,
	identity safeConnectionIdentity,
	proxyOverride string,
) (*WsConnection, error) {
	// 浅拷贝共享 dialer，继承全部调优字段（NetDialContext/KeepAlive、读写缓冲、压缩等），
	// 仅按需覆盖 Proxy；避免逐字段重建时漏抄字段（曾导致 NetDialContext/KeepAlive 失效）。
	dialerCopy := *m.dialer
	dialer := &dialerCopy

	// 配置代理（Resin 反代模式下跳过，URL 已包含 Resin 地址）
	proxyURL := effectiveProxyURL(account, proxyOverride)

	if !proxy.IsResinEnabled() && proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL failed: %w", err)
		}
		dialer.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxyURLParsed, nil
		}
	}

	// gorilla/websocket's DialContext does not reliably interrupt the HTTP
	// upgrade response read on every platform once the TCP dial has completed.
	// Track the raw transport only for the handshake window and close it when
	// the merged caller/manager context is canceled. The watcher is disarmed as
	// soon as DialContext returns so operation cleanup cannot close a live WS.
	baseNetDialContext := dialer.NetDialContext
	if baseNetDialContext == nil {
		baseNetDialContext = (&net.Dialer{}).DialContext
	}
	rawConnReady := make(chan net.Conn, 1)
	handshakeDone := make(chan struct{})
	dialer.NetDialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := baseNetDialContext(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		rawConnReady <- rawConn
		return rawConn, nil
	}
	cancelHandshake := context.AfterFunc(ctx, func() {
		select {
		case rawConn := <-rawConnReady:
			_ = rawConn.Close()
		case <-handshakeDone:
		}
	})

	// 创建会话（先精确移除旧 session 避免泄漏）。新 session 在握手成功并
	// 标记 connected 前不发布到 sessions；否则 30s cleanup 会把长握手中的
	// Connected=false session 当失效项删除，握手随后成功却留下无 session 映射。
	poolKey := m.poolKey(account.ID(), wsURL, sessionKey, proxyURL)
	if oldSessionVal, ok := m.sessions.Load(poolKey); ok {
		oldSession := oldSessionVal.(*Session)
		if m.sessions.CompareAndDelete(poolKey, oldSession) {
			oldSession.Close()
		}
	}
	session := NewSession(account.ID(), m)
	if trimmed := strings.TrimSpace(sessionKey); trimmed != "" {
		session.ID = trimmed
	}

	// 拨号连接
	conn, resp, err := dialer.DialContext(ctx, wsURL, headers)
	close(handshakeDone)
	cancelHandshake()
	if err != nil {
		session.Close()
		// bad handshake 时 resp 常非空：附带上游 HTTP 状态/ body，便于测试连接定位。
		return nil, formatDialHandshakeError(err, resp)
	}
	select {
	case <-ctx.Done():
		_ = conn.Close()
		session.Close()
		return nil, ctx.Err()
	default:
	}

	// 创建连接包装
	wc := NewWsConnection(conn, session, wsURL)
	wc.account = account
	wc.PoolKey = poolKey
	wc.upstreamUserAgent = strings.TrimSpace(headers.Get("User-Agent"))
	wc.upstreamUserAgentKnown = true
	wc.httpResp = resp
	wc.onDisconnected = m.getOnDisconnected()
	wc.onReadFailure = m.discardConnectionOnReadFailure
	if identity.valid() {
		// Publish safe-pool identity before starting the sole reader. An
		// immediate post-upgrade business frame must therefore trip the account
		// fuse instead of passing through the ordinary idle-frame path.
		wc.safeOwnerKey = identity.ownerKey
		wc.handshakeFingerprint = identity.handshakeFingerprint
		wc.safeGeneration = identity.generation
		wc.safeReusable.Store(true)
		m.safePoolAccounts.Store(account.ID(), struct{}{})
	}
	session.SetConnected(true)

	// 控制帧处理器必须在唯一永久 reader 启动前安装。
	wc.installControlHandlers()
	wc.StartReadPump()
	m.noteIdleReclaimReconnect(poolKey, time.Now())

	return wc, nil
}

// ReleaseConnection 释放连接（归还池）
func (m *Manager) ReleaseConnection(wc *WsConnection) {
	if wc == nil {
		return
	}
	wc.Touch()
	if wc.account == nil || wc.session == nil {
		return
	}
	if wc.safeReusable.Load() && (wc.retireAfterLease.Load() || m.IsSafePoolFused(wc.session.AccountID) || !m.safePoolConnectionUsable(wc)) {
		m.DiscardConnection(wc)
		return
	}
	accountLock := m.accountLock(wc.session.AccountID)
	accountLock.Lock()
	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc || !wc.IsConnected() {
		accountLock.Unlock()
		return
	}
	// A completed connection that obtained a response binding is excluded as
	// continuation state. If the binding table was full (or no response ID was
	// produced), it remains ordinary unbound idle capacity and converges here.
	m.trimIdleAccountConnections(wc.session.AccountID, accountConnectionLimit(wc.account), wc)
	accountLock.Unlock()
	// The global continuation trim obtains account locks for arbitrary dynamic
	// account IDs, so it must run only after releasing this account's lock.
	if m.continuationBudgetMayBeExceeded(wc.session.AccountID) {
		m.enforceContinuationSocketBudgets()
	}
}

// RemoveConnection 移除连接
func (m *Manager) RemoveConnection(accountID int64, wsURL string, sessionKey string, proxyURL string) {
	key := m.poolKey(accountID, wsURL, sessionKey, proxyURL)
	lock := m.keyLock(key)
	m.lockPoolKey(key, lock)
	defer lock.Unlock()
	m.removeConnectionByKeyLocked(key)
}

// removeConnectionByKeyLocked requires the pool-key lock. Pointer-safe
// deletion prevents a stale remover from deleting a same-key replacement.
func (m *Manager) removeConnectionByKeyLocked(key string) {
	if v, ok := m.connections.LoadAndDelete(key); ok {
		wc := v.(*WsConnection)
		m.discardConnectionState(wc)
		m.removeResponseConnBindings(wc)
		return
	}
	if v, ok := m.sessions.LoadAndDelete(key); ok {
		v.(*Session).Close()
	}
}

// discardConnectionState first makes the connection impossible to select or
// bind again, then closes its session and socket. Binding cleanup is kept
// separate so account-capacity eviction can clean many connections with one
// bounded binding-table scan.
func (m *Manager) discardConnectionState(wc *WsConnection) {
	if m == nil || wc == nil {
		return
	}
	if wc.PoolKey != "" {
		m.connections.CompareAndDelete(wc.PoolKey, wc)
		if wc.session != nil {
			m.sessions.CompareAndDelete(wc.PoolKey, wc.session)
		}
	}
	if wc.session != nil {
		wc.session.Close()
	}
	_ = wc.Close()
}

func (m *Manager) discardConnectionOnReadFailure(wc *WsConnection) {
	if wc == nil {
		return
	}
	if wc.safeReusable.Load() {
		if isolationErr := wc.safePoolReadIsolationFailure(); isolationErr != nil && wc.session != nil {
			m.TripSafePoolFuse(wc.session.AccountID, isolationErr)
		}
	}
	wc.promotionMu.Lock()
	m.DiscardConnection(wc)
	wc.promotionMu.Unlock()
}

// DiscardConnection 关闭并从连接池移除一条坏连接。
// 用于上游 WS 异常路径(read error / close 1006/1009/1011 / broken pipe / unexpected EOF)：
// 关闭底层 socket 解决 CLOSE_WAIT 滞留，并把连接从 connections/sessions 移除，
// 避免坏连接被 ReleaseConnection 归还后又被 canReuseConnection 误判为可复用。
// 使用 CompareAndDelete 按本连接精确删除，防止误删同 PoolKey 下已重建的新连接。
func (m *Manager) DiscardConnection(wc *WsConnection) {
	if m == nil || wc == nil {
		return
	}
	// Remove/close first. A concurrent BindResponseConn either publishes before
	// this transition and is removed below, or observes the dead/non-current
	// connection and refuses to publish a stale continuation binding.
	m.discardConnectionState(wc)
	m.removeResponseConnBindings(wc)
}

// BindResponseConn 记录 response_id 由哪条连接产出（续链亲和）。
func (m *Manager) BindResponseConn(responseID string, wc *WsConnection, sessionKey string, accountID int64, apiKey string) {
	responseID = strings.TrimSpace(responseID)
	if m == nil || responseID == "" || wc == nil {
		return
	}
	unlockSafeValidation := func() {}
	if wc.safeReusable.Load() {
		if wc.account == nil {
			wc.retireAfterLease.Store(true)
			return
		}
		wc.account.Mu().RLock()
		m.ownerAdmissionMu.Lock()
		identityCurrent := resolveStatelessPoolPolicyWithTags(wc.account, m, wc.account.Tags).mode == statelessPoolSafe &&
			m.safePoolIdentityGenerationCurrentLocked(accountID, wc.safeIdentity())
		if !identityCurrent {
			m.ownerAdmissionMu.Unlock()
			wc.account.Mu().RUnlock()
			wc.retireAfterLease.Store(true)
			return
		}
		unlockSafeValidation = func() {
			m.ownerAdmissionMu.Unlock()
			wc.account.Mu().RUnlock()
		}
	}
	m.respConnMu.Lock()
	// Validate while holding the same mutex that protects publication. Discard
	// removes the pool entry and closes the connection before taking this lock,
	// so a bind racing with discard cannot resurrect a dead pointer.
	if !wc.IsConnected() {
		m.respConnMu.Unlock()
		unlockSafeValidation()
		return
	}
	if current, ok := m.connections.Load(wc.PoolKey); !ok || current != wc {
		m.respConnMu.Unlock()
		unlockSafeValidation()
		return
	}
	if m.respConnBindings == nil {
		m.respConnBindings = make(map[string]responseConnBinding, 64)
	}
	_, replacingExisting := m.respConnBindings[responseID]
	if len(m.respConnBindings) >= responseConnBindingMaxEntries && !replacingExisting && len(m.responseBindingOrder) == 0 {
		// This is a defensive repair path for an index reconstructed from legacy
		// or test state. Normal runtime publication always maintains the FIFO and
		// never pays a full-table scan at the ceiling.
		m.latestLiveResponseBindingsLocked(time.Now())
		if len(m.respConnBindings) >= responseConnBindingMaxEntries {
			m.rebuildResponseBindingOrderLocked()
		}
	}
	if len(m.respConnBindings) >= responseConnBindingMaxEntries && !replacingExisting {
		// Keep the bounded ID ceiling in amortized O(1) time by evicting the
		// oldest monotonic Bind generation. Rebuild only if defensive state made
		// the secondary order inconsistent; the final scan is unreachable for
		// normal published bindings and preserves fail-safe boundedness.
		evicted := m.evictOldestResponseConnBindingLocked()
		if !evicted {
			m.rebuildResponseBindingOrderLocked()
			evicted = m.evictOldestResponseConnBindingLocked()
		}
		if !evicted {
			oldestID := ""
			var oldestGeneration uint64
			for existingID, binding := range m.respConnBindings {
				if oldestID == "" || binding.generation < oldestGeneration ||
					(binding.generation == oldestGeneration && existingID < oldestID) {
					oldestID = existingID
					oldestGeneration = binding.generation
				}
			}
			if oldestID != "" {
				m.removeResponseConnBindingLocked(oldestID)
			}
		}
	}
	// Capture publication time under respConnMu, after any bounded-table repair.
	// This keeps expiresAt monotonic with generation even when concurrent binders
	// were scheduled in the opposite order before acquiring the lock.
	now := time.Now()
	m.responseBindingGeneration++
	binding := responseConnBinding{
		conn:                 wc,
		sessionKey:           sessionKey,
		accountID:            accountID,
		apiKey:               apiKey,
		safeOwnerKey:         wc.safeOwnerKey,
		handshakeFingerprint: wc.handshakeFingerprint,
		safeGeneration:       wc.safeGeneration,
		expiresAt:            now.Add(responseConnBindingTTL),
		generation:           m.responseBindingGeneration,
	}
	m.publishResponseConnBindingLocked(responseID, binding)
	m.respConnMu.Unlock()
	unlockSafeValidation()
}

func (m *Manager) lookupResponseBinding(responseID string, accountID int64, apiKey string) (responseConnBinding, bool) {
	responseID = strings.TrimSpace(responseID)
	if m == nil || responseID == "" {
		return responseConnBinding{}, false
	}
	m.respConnMu.Lock()
	now := time.Now()
	binding, ok := m.respConnBindings[responseID]
	if ok && (now.After(binding.expiresAt) || binding.accountID != accountID || binding.apiKey != apiKey) {
		if now.After(binding.expiresAt) {
			m.removeResponseConnBindingLocked(responseID)
		}
		ok = false
	}
	m.respConnMu.Unlock()
	if !ok || binding.conn == nil {
		return responseConnBinding{}, false
	}
	// 指针级校验：连接必须仍在池中且是同一条（防止复用已重建槽位的陈旧绑定）。
	if v, exists := m.connections.Load(binding.conn.PoolKey); !exists || v != binding.conn {
		return responseConnBinding{}, false
	}
	if !binding.conn.IsConnected() {
		return responseConnBinding{}, false
	}
	// Idle/age expiry prevents admitting a new turn, but an already in-flight
	// bound connection is still authoritative for detecting continuation
	// contention. Let AcquirePreferredConnection surface a busy sentinel instead
	// of misclassifying it as a cache miss and crossing to another WS slot.
	if (binding.conn.IsExpired() || binding.conn.IsOverAge()) &&
		(binding.conn.session == nil || binding.conn.session.PendingCount() == 0) {
		return responseConnBinding{}, false
	}
	return binding, true
}

// lookupResponseConn returns the connection and its pool session key for
// compatibility with existing callers. Safe continuation admission uses the
// full immutable binding snapshot so owner/fingerprint fields are enforced.
func (m *Manager) lookupResponseConn(responseID string, accountID int64, apiKey string) (*WsConnection, string) {
	binding, ok := m.lookupResponseBinding(responseID, accountID, apiKey)
	if !ok {
		return nil, ""
	}
	return binding.conn, binding.sessionKey
}

// AcquirePreferredConnection 尝试独占 response_id 绑定的原连接（续链亲和）。
// 成功返回 (连接, pendingRequest, 池内 sessionKey, nil)。没有绑定、绑定失效或原
// 连接已断开时返回 ErrWebsocketContinuationUnavailable；previous_response_id 的
// 上游状态不能安全地转移到普通连接。
//
// 一旦确认仍然有效的绑定连接正忙，必须返回 ErrWebsocketSessionBusy；不能静默
// 换到普通槽位，因为 previous_response_id 的上游上下文只存在于原 WS 连接。
// 同理，绑定连接因本地账号容量无法激活时返回 ErrWebsocketLocalCapacity，交由上层
// 作为本地争用处理，而不是伪装成 cache miss 后跨连接继续。
func (m *Manager) AcquirePreferredConnection(ctx context.Context, responseID string, accountID int64, apiKey string, identities ...safeConnectionIdentity) (*WsConnection, *PendingRequest, string, error) {
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer finishOperation()

	expectedIdentity := safeConnectionIdentity{}
	requireSafeIdentity := len(identities) != 0
	if len(identities) != 0 {
		expectedIdentity = identities[0]
	}
	var wc *WsConnection
	var sessionKey string
	var binding responseConnBinding
	var lock *sync.Mutex
	for {
		var bindingOK bool
		binding, bindingOK = m.lookupResponseBinding(responseID, accountID, apiKey)
		if !bindingOK {
			return nil, nil, "", fmt.Errorf("%w: response binding is missing, expired, mismatched, or disconnected", proxy.ErrWebsocketContinuationUnavailable)
		}
		wc, sessionKey = binding.conn, binding.sessionKey
		if requireSafeIdentity && !wc.safeReusable.Load() {
			return nil, nil, "", fmt.Errorf("%w: response binding belongs to a legacy or isolated websocket", proxy.ErrWebsocketContinuationUnavailable)
		}
		if requireSafeIdentity && (binding.safeOwnerKey != expectedIdentity.ownerKey || binding.handshakeFingerprint != expectedIdentity.handshakeFingerprint) {
			return nil, nil, "", fmt.Errorf("%w: response binding owner or handshake identity mismatch", proxy.ErrWebsocketContinuationUnavailable)
		}
		if requireSafeIdentity && binding.safeGeneration != expectedIdentity.generation {
			return nil, nil, "", fmt.Errorf("%w: response binding belongs to an obsolete safe-pool generation", proxy.ErrWebsocketContinuationUnavailable)
		}
		if wc.safeReusable.Load() {
			if !expectedIdentity.matches(wc) || !m.safePoolIdentityUsable(wc.account, expectedIdentity) {
				m.retireStaleSafeConnection(wc)
				return nil, nil, "", fmt.Errorf("%w: safe websocket continuation owner, generation, or rollout policy is stale", proxy.ErrWebsocketContinuationUnavailable)
			}
			if m.IsSafePoolFused(accountID) {
				return nil, nil, "", fmt.Errorf("%w: safe websocket pool is fused for account", proxy.ErrWebsocketContinuationUnavailable)
			}
			// Binding publication happens immediately after the terminal frame is
			// delivered, while the response defer may need another scheduler tick
			// to remove its Session pending marker. Wait only for that explicitly
			// marked transition; a genuinely active request has no marker and still
			// falls through to the normal immediate busy result.
			if waited, waitErr := waitForSafePoolTerminalRelease(opCtx, wc); waited {
				if waitErr != nil {
					return nil, nil, "", waitErr
				}
				continue
			}
			if wc.reuseFenceActive() {
				if err := waitForSafePoolReuseFence(opCtx, wc); err != nil {
					return nil, nil, "", err
				}
				continue
			}
		}

		lock = m.keyLock(wc.PoolKey)
		m.lockPoolKey(wc.PoolKey, lock)
		if wc.safeReusable.Load() && wc.reuseFenceActive() {
			lock.Unlock()
			if err := waitForSafePoolReuseFence(opCtx, wc); err != nil {
				return nil, nil, "", err
			}
			continue
		}
		break
	}
	defer lock.Unlock()

	accountLock := m.accountLock(accountID)
	if err := preferredContinuationContextError(opCtx, "while waiting for the connection lock"); err != nil {
		return nil, nil, "", err
	}
	// pool-key 加锁后复验：期间可能被其他请求占用或销毁。
	if v, exists := m.connections.Load(wc.PoolKey); !exists || v != wc {
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection was replaced", proxy.ErrWebsocketContinuationUnavailable)
	}
	currentBinding, bindingOK := m.lookupResponseBinding(responseID, accountID, apiKey)
	if !bindingOK || currentBinding.conn != wc || currentBinding.generation != binding.generation {
		return nil, nil, "", fmt.Errorf("%w: response binding changed while reserving its websocket", proxy.ErrWebsocketContinuationUnavailable)
	}
	if wc.safeReusable.Load() && (!expectedIdentity.matches(wc) || !m.safePoolIdentityUsable(wc.account, expectedIdentity)) {
		m.retireStaleSafeConnection(wc)
		return nil, nil, "", fmt.Errorf("%w: safe websocket continuation identity, generation, or policy changed", proxy.ErrWebsocketContinuationUnavailable)
	}
	if !canReuseConnection(wc) {
		if wc.IsConnected() && wc.session != nil && wc.session.IsConnected() && wc.session.PendingCount() > 0 {
			return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection is busy", proxy.ErrWebsocketSessionBusy)
		}
		if wc.session == nil || wc.session.PendingCount() == 0 {
			m.DiscardConnection(wc)
		}
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection is no longer reusable", proxy.ErrWebsocketContinuationUnavailable)
	}
	if !m.probeWithContext(opCtx, wc) {
		if err := preferredContinuationContextError(opCtx, "during the liveness probe"); err != nil {
			return nil, nil, "", err
		}
		m.DiscardConnection(wc)
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection failed liveness probe", proxy.ErrWebsocketContinuationUnavailable)
	}
	if err := preferredContinuationContextError(opCtx, "after the liveness probe"); err != nil {
		return nil, nil, "", err
	}
	if wc.safeReusable.Load() && !m.safePoolIdentityUsable(wc.account, expectedIdentity) {
		m.retireStaleSafeConnection(wc)
		return nil, nil, "", fmt.Errorf("%w: safe websocket continuation generation changed during liveness probe", proxy.ErrWebsocketContinuationUnavailable)
	}
	// probe 可能等待网络，不能占用账号锁。拿到账号锁后再次复验，防止
	// probe 期间连接被其它 pool key 的容量裁剪安全回收。
	accountLock.Lock()
	defer accountLock.Unlock()
	if err := preferredContinuationContextError(opCtx, "while waiting for account capacity"); err != nil {
		return nil, nil, "", err
	}
	if v, exists := m.connections.Load(wc.PoolKey); !exists || v != wc {
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection disappeared during probe", proxy.ErrWebsocketContinuationUnavailable)
	}
	if !canReuseConnection(wc) {
		if wc.IsConnected() && wc.session != nil && wc.session.IsConnected() && wc.session.PendingCount() > 0 {
			return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection became busy during probe", proxy.ErrWebsocketSessionBusy)
		}
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection became unusable during probe", proxy.ErrWebsocketContinuationUnavailable)
	}
	if wc.safeReusable.Load() && (!expectedIdentity.matches(wc) || !m.safePoolIdentityUsable(wc.account, expectedIdentity) || wc.reuseFenceActive()) {
		// accountLock is held here, so do not call the account-wide retire
		// helper recursively. Mark this exact socket non-reusable; the earlier
		// policy gate handles normal hot-disable cleanup for all idle sockets.
		wc.retireAfterLease.Store(true)
		return nil, nil, "", fmt.Errorf("%w: safe websocket continuation failed final owner, fence, or fuse validation", proxy.ErrWebsocketContinuationUnavailable)
	}
	if !m.ensureConnectionActivationCapacity(accountID, accountConnectionLimit(wc.account), wc) {
		return nil, nil, "", fmt.Errorf("%w: response-bound websocket connection cannot be activated at current account capacity", proxy.ErrWebsocketLocalCapacity)
	}
	if err := preferredContinuationContextError(opCtx, "before reserving the continuation lease"); err != nil {
		return nil, nil, "", err
	}
	pr, err := m.addPendingAndBeginReadLease(wc, sessionKey)
	if err != nil {
		m.DiscardConnection(wc)
		return nil, nil, "", fmt.Errorf("%w: reserve response-bound websocket connection: %w", proxy.ErrWebsocketSessionBusy, err)
	}
	wc.Touch()
	if wc.account != nil {
		m.trimIdleAccountConnections(accountID, accountConnectionLimit(wc.account), wc)
	}
	return wc, pr, sessionKey, nil
}

// poolKey 生成连接池键
func (m *Manager) poolKey(accountID int64, wsURL string, sessionKey string, proxyURL string) string {
	return fmt.Sprintf("%d|%s|%s|%s", accountID, wsURL, strings.TrimSpace(sessionKey), strings.TrimSpace(proxyURL))
}

// GetSession 获取会话
func (m *Manager) GetSession(accountID int64, wsURL string, sessionKey string, proxyURL string) (*Session, bool) {
	if v, ok := m.sessions.Load(m.poolKey(accountID, wsURL, sessionKey, proxyURL)); ok {
		return v.(*Session), true
	}
	return nil, false
}

// ConnectionCount 获取连接数量
func (m *Manager) ConnectionCount() int {
	count := 0
	m.connections.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// SessionCount 获取会话数量
func (m *Manager) SessionCount() int {
	count := 0
	m.sessions.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// ReplaceConnection 替换连接（用于重连）
func (m *Manager) ReplaceConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	sessionKey string,
	headers http.Header,
	proxyOverride string,
) (*WsConnection, *PendingRequest, error) {
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer finishOperation()

	key := m.poolKey(account.ID(), wsURL, sessionKey, effectiveProxyURL(account, proxyOverride))
	replacementLock := m.replacementLock(key)
	replacementLock.Lock()
	defer replacementLock.Unlock()

	keyLock := m.keyLock(key)
	keyLock.Lock()
	m.removeConnectionByKeyLocked(key)
	keyLock.Unlock()
	if m.afterReplacementRemoved != nil {
		m.afterReplacementRemoved(key)
	}

	// Keep the replacement gate through the fresh acquire. The internal path
	// bypasses only that gate; it still uses the ordinary key/account locks.
	return m.acquireConnection(opCtx, account, wsURL, sessionKey, headers, proxyOverride, true)
}

// SendHeartbeat 发送心跳 Ping
func (m *Manager) SendHeartbeat(wc *WsConnection) error {
	wc.writeMu.Lock()
	defer wc.writeMu.Unlock()

	if !wc.IsConnected() {
		return fmt.Errorf("connection is not connected")
	}

	deadline := time.Now().Add(10 * time.Second)
	err := wc.conn.WriteControl(websocket.PingMessage, []byte{}, deadline)
	if err != nil {
		log.Printf("WebSocket Ping 失败 (account %d): %v", wc.session.AccountID, err)
		m.DiscardConnection(wc)
		return err
	}
	return nil
}

// StartHeartbeat 启动连接心跳
func (m *Manager) StartHeartbeat(wc *WsConnection) {
	if wc == nil || wc.session == nil || !wc.IsConnected() || !wc.session.IsConnected() {
		return
	}
	wc.session.StartHeartbeat(func() error {
		return m.SendHeartbeat(wc)
	})
}

// 全局管理器实例
var globalManager *Manager
var managerOnce sync.Once

// GetManager 获取全局管理器实例
func GetManager() *Manager {
	managerOnce.Do(func() {
		globalManager = NewManager()
	})
	return globalManager
}

// ShutdownManager 关闭全局管理器
func ShutdownManager() {
	if globalManager != nil {
		globalManager.Stop()
	}
}
