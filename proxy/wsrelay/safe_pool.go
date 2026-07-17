package wsrelay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/codex2api/proxy"
)

var errSafePoolIsolationViolation = errors.New("safe websocket pool isolation violation")
var errSafePoolProtocolCompatibility = errors.New("safe websocket pool protocol compatibility failure")

const safePoolTerminalReleaseWait = 500 * time.Millisecond

type safeConnectionIdentity struct {
	ownerKey             string
	handshakeFingerprint string
}

func (identity safeConnectionIdentity) valid() bool {
	return strings.TrimSpace(identity.ownerKey) != "" && strings.TrimSpace(identity.handshakeFingerprint) != ""
}

func (identity safeConnectionIdentity) matches(wc *WsConnection) bool {
	return identity.valid() && wc != nil &&
		wc.safeOwnerKey == identity.ownerKey &&
		wc.handshakeFingerprint == identity.handshakeFingerprint
}

func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

func waitForSafePoolReuseFence(ctx context.Context, wc *WsConnection) error {
	remaining := wc.reuseFenceRemaining()
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: canceled while waiting for websocket terminal fence: %w", proxy.ErrWebsocketContinuationUnavailable, ctx.Err())
	}
}

func waitForSafePoolTerminalRelease(ctx context.Context, wc *WsConnection) (bool, error) {
	done := wc.safeTerminalReleaseDone()
	if done == nil {
		return false, nil
	}
	timer := time.NewTimer(safePoolTerminalReleaseWait)
	defer timer.Stop()
	select {
	case <-done:
		return true, nil
	case <-ctx.Done():
		return true, fmt.Errorf("%w: canceled while waiting for websocket terminal release: %w", proxy.ErrWebsocketSessionBusy, ctx.Err())
	case <-timer.C:
		return true, fmt.Errorf("%w: timed out waiting for websocket terminal release", proxy.ErrWebsocketSessionBusy)
	}
}

type safePoolFuseState struct {
	trippedAt     time.Time
	reason        string
	compatibility bool
}

type SafePoolMetrics struct {
	DialAttempts           uint64
	DialSuccess            uint64
	DialFailures           uint64
	ReuseHits              uint64
	Saturations            uint64
	FuseTrips              uint64
	CompatibilityDrops     uint64
	CompatibilityFallbacks uint64
	OwnerEligible          uint64
	OwnerMissing           uint64
	OwnerRejected          uint64
	RequestIneligible      uint64
	OwnerAdmittedNew       uint64
	OwnerAdmittedExisting  uint64
	OwnerSampleRejected    uint64
	OwnerBudgetRejected    uint64
	OwnerOneShotFallbacks  uint64
	OwnerConfigErrors      uint64
	ContinuationEvictions  uint64
}

// SafePoolRuntime is an approximate, read-only process snapshot for rollout
// observability. Counters are monotonic for the life of the process; gauges may
// move while the snapshot is collected and therefore must not be used as a
// synchronization primitive.
type SafePoolRuntime struct {
	Metrics                     SafePoolMetrics
	GlobalOneShot               bool
	Scope                       string
	ConfiguredMaxSlots          int
	WaitMillis                  int64
	ReuseFenceMillis            int64
	Connections                 int
	ActiveConnections           int
	IdleConnections             int
	BoundIdleConnections        int
	RetiringConnections         int
	PendingDials                int
	ResponseBindings            int
	FusedAccounts               int
	CompatibilityFusedAccounts  int
	TrackedAccounts             int
	OwnerSampleBPS              int
	OwnerBudgetPerAccount       int
	OwnerAdmissionConfigValid   bool
	OwnerAdmissionSaltReady     bool
	AdmittedOwners              int
	AdmittedOwnerAccounts       int
	OwnerBudgetOvercommitted    int
	ContinuationGlobalLimit     int
	ContinuationPerAccountLimit int
}

func (m *Manager) SafePoolMetricsSnapshot() SafePoolMetrics {
	if m == nil {
		return SafePoolMetrics{}
	}
	return SafePoolMetrics{
		DialAttempts:           m.safePoolDialAttempts.Load(),
		DialSuccess:            m.safePoolDialSuccess.Load(),
		DialFailures:           m.safePoolDialFailures.Load(),
		ReuseHits:              m.safePoolReuseHits.Load(),
		Saturations:            m.safePoolSaturations.Load(),
		FuseTrips:              m.safePoolFuseTrips.Load(),
		CompatibilityDrops:     m.safePoolCompatibilityDrops.Load(),
		CompatibilityFallbacks: m.safePoolCompatibilityFallbacks.Load(),
		OwnerEligible:          m.safePoolOwnerEligible.Load(),
		OwnerMissing:           m.safePoolOwnerMissing.Load(),
		OwnerRejected:          m.safePoolOwnerRejected.Load(),
		RequestIneligible:      m.safePoolRequestIneligible.Load(),
		OwnerAdmittedNew:       m.safePoolOwnerAdmittedNew.Load(),
		OwnerAdmittedExisting:  m.safePoolOwnerAdmittedExisting.Load(),
		OwnerSampleRejected:    m.safePoolOwnerSampleRejected.Load(),
		OwnerBudgetRejected:    m.safePoolOwnerBudgetRejected.Load(),
		OwnerOneShotFallbacks:  m.safePoolOwnerOneShotFallbacks.Load(),
		OwnerConfigErrors:      m.safePoolOwnerConfigErrors.Load(),
		ContinuationEvictions:  m.continuationBudgetEvictions.Load(),
	}
}

// SafePoolRuntimeSnapshot exposes only aggregate transport state. It never
// returns account IDs, API keys, owner keys, response IDs, or fuse reasons.
func (m *Manager) SafePoolRuntimeSnapshot() SafePoolRuntime {
	ownerConfig := currentSafePoolOwnerAdmissionConfig()
	snapshot := SafePoolRuntime{
		GlobalOneShot:             statelessOneShotEnabled(),
		Scope:                     strings.ToLower(strings.TrimSpace(os.Getenv(safePoolScopeEnv))),
		ConfiguredMaxSlots:        configuredSafePoolSlots(nil),
		WaitMillis:                durationFromMillisEnv(safePoolWaitMillisEnv, defaultSafePoolWait, minimumSafePoolWait, maximumSafePoolWait).Milliseconds(),
		ReuseFenceMillis:          durationFromMillisEnv(safePoolFenceMillisEnv, defaultSafePoolReuseFence, minimumSafePoolReuseFence, maximumSafePoolReuseFence).Milliseconds(),
		OwnerSampleBPS:            ownerConfig.sampleBPS,
		OwnerBudgetPerAccount:     ownerConfig.budget,
		OwnerAdmissionConfigValid: ownerConfig.valid,
	}
	if snapshot.Scope == "" {
		snapshot.Scope = "disabled"
	}
	if m == nil {
		return snapshot
	}
	snapshot.Metrics = m.SafePoolMetricsSnapshot()
	snapshot.OwnerAdmissionSaltReady = m.ownerAdmissionSaltValid
	snapshot.ContinuationGlobalLimit = m.continuationGlobalLimit
	snapshot.ContinuationPerAccountLimit = m.continuationPerAccountLimit
	snapshot.AdmittedOwners, snapshot.AdmittedOwnerAccounts, snapshot.OwnerBudgetOvercommitted = m.safePoolOwnerAdmissionSnapshot(ownerConfig.budget)

	boundSafeConnections := make(map[*WsConnection]struct{})
	now := time.Now()
	m.respConnMu.Lock()
	snapshot.ResponseBindings = len(m.respConnBindings)
	for wc, summary := range m.respConnSummaries {
		if wc == nil || summary == nil || now.After(summary.latestExpiresAt) {
			continue
		}
		if wc.safeReusable.Load() {
			boundSafeConnections[wc] = struct{}{}
		}
	}
	m.respConnMu.Unlock()

	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || !wc.safeReusable.Load() {
			return true
		}
		snapshot.Connections++
		if wc.retireAfterLease.Load() {
			snapshot.RetiringConnections++
		}
		if wc.session != nil && wc.session.PendingCount() > 0 {
			snapshot.ActiveConnections++
			return true
		}
		snapshot.IdleConnections++
		if _, bound := boundSafeConnections[wc]; bound {
			snapshot.BoundIdleConnections++
		}
		return true
	})

	m.capacityMu.Lock()
	for _, pending := range m.safePoolPendingCreates {
		snapshot.PendingDials += pending
	}
	m.capacityMu.Unlock()

	m.safePoolFuses.Range(func(_, value any) bool {
		snapshot.FusedAccounts++
		if state, ok := value.(safePoolFuseState); ok && state.compatibility {
			snapshot.CompatibilityFusedAccounts++
		}
		return true
	})
	m.safePoolAccounts.Range(func(_, _ any) bool {
		snapshot.TrackedAccounts++
		return true
	})
	return snapshot
}

func (m *Manager) IsSafePoolFused(accountID int64) bool {
	if m == nil || accountID <= 0 {
		return false
	}
	_, fused := m.safePoolFuses.Load(accountID)
	return fused
}

// TripSafePoolFuse is process-local and deliberately does not mutate account
// status, schedulability, Guardian state or the database. New requests for the
// affected account fail closed to isolated WS/HTTP policy; idle safe-pool
// sockets are removed immediately and active ones are discarded on Close.
func (m *Manager) TripSafePoolFuse(accountID int64, reason error) {
	if m == nil || accountID <= 0 {
		return
	}
	reasonText := "unknown isolation violation"
	if reason != nil {
		reasonText = strings.TrimSpace(reason.Error())
	}
	state := safePoolFuseState{trippedAt: time.Now(), reason: reasonText}
	for {
		existing, loaded := m.safePoolFuses.LoadOrStore(accountID, state)
		if !loaded {
			m.safePoolFuseTrips.Add(1)
			log.Printf("[WS-SafePool] account %d reuse fuse tripped: %s", accountID, reasonText)
			break
		}
		current, ok := existing.(safePoolFuseState)
		if !ok || !current.compatibility {
			break
		}
		if m.safePoolFuses.CompareAndSwap(accountID, current, state) {
			m.safePoolFuseTrips.Add(1)
			log.Printf("[WS-SafePool] account %d compatibility fallback upgraded to isolation fuse: %s", accountID, reasonText)
			break
		}
	}

	m.retireSafePoolAccount(accountID, true)
}

// TripSafePoolCompatibilityFuse downgrades only the process-local WS reuse
// mode when the upstream wire shape is not understood. It shares the same
// fail-closed policy gate as an isolation fuse, but is counted separately so a
// protocol rollout cannot be misreported as cross-request leakage.
func (m *Manager) TripSafePoolCompatibilityFuse(accountID int64, reason error) {
	if m == nil || accountID <= 0 {
		return
	}
	reasonText := "unknown websocket protocol compatibility failure"
	if reason != nil {
		reasonText = strings.TrimSpace(reason.Error())
	}
	state := safePoolFuseState{trippedAt: time.Now(), reason: reasonText, compatibility: true}
	if _, loaded := m.safePoolFuses.LoadOrStore(accountID, state); !loaded {
		m.safePoolCompatibilityFallbacks.Add(1)
		log.Printf("[WS-SafePool] account %d reuse disabled for protocol compatibility: %s", accountID, reasonText)
	}
	m.retireSafePoolAccount(accountID, true)
}

// RetireSafePoolAccount applies a live rollout-policy removal without touching
// account status, tags, schedulability, Guardian or the database. Idle safe
// sockets are closed immediately; active sockets finish their current response
// and are destroyed by ReleaseConnection. The process-local hint makes calls
// for accounts that never used the safe pool O(1).
func (m *Manager) RetireSafePoolAccount(accountID int64) {
	if m == nil || accountID <= 0 {
		return
	}
	if _, tracked := m.safePoolAccounts.LoadAndDelete(accountID); !tracked {
		return
	}
	m.retireSafePoolAccount(accountID, false)
}

func (m *Manager) retireSafePoolAccount(accountID int64, force bool) {
	if m == nil || accountID <= 0 {
		return
	}
	if force {
		m.safePoolAccounts.Delete(accountID)
	}
	accountLock := m.accountLock(accountID)
	accountLock.Lock()
	idle := make([]*WsConnection, 0)
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || !wc.safeReusable.Load() || wc.session == nil || wc.session.AccountID != accountID {
			return true
		}
		wc.retireAfterLease.Store(true)
		if wc.session.PendingCount() == 0 {
			idle = append(idle, wc)
		}
		return true
	})
	accountLock.Unlock()
	for _, wc := range idle {
		m.DiscardConnection(wc)
	}
}

func (m *Manager) resetSafePoolFuseForTest(accountID int64) {
	if m != nil {
		m.safePoolFuses.Delete(accountID)
	}
}

func (m *Manager) safePoolPendingCreateCount(accountID int64) int {
	if m == nil {
		return 0
	}
	m.capacityMu.Lock()
	defer m.capacityMu.Unlock()
	return m.safePoolPendingCreates[accountID]
}

func (m *Manager) reserveSafePoolPendingCreate(accountID int64) {
	m.capacityMu.Lock()
	if m.safePoolPendingCreates == nil {
		m.safePoolPendingCreates = make(map[int64]int)
	}
	m.safePoolPendingCreates[accountID]++
	m.capacityMu.Unlock()
}

func (m *Manager) releaseSafePoolPendingCreate(accountID int64) {
	m.capacityMu.Lock()
	if pending := m.safePoolPendingCreates[accountID]; pending <= 1 {
		delete(m.safePoolPendingCreates, accountID)
	} else {
		m.safePoolPendingCreates[accountID] = pending - 1
	}
	m.capacityMu.Unlock()
}

func currentSafePoolSlots(account *auth.Account, manager *Manager) (int, bool) {
	policy := resolveStatelessPoolPolicy(account, manager)
	if policy.mode != statelessPoolSafe || account == nil {
		return 0, false
	}
	slots := policy.slots
	if accountLimit := accountConnectionLimit(account); slots < 1 || slots > accountLimit {
		slots = accountLimit
	}
	return slots, true
}

// AcquireSafeReusableConnection provides the tagged/all rollout path. Unlike
// the historical pool it never creates an unbounded one-shot overflow socket.
// At saturation it waits briefly for a clean slot, then returns the existing
// typed local-capacity error so the outer request path can keep the same
// account lease and downgrade context-independent work to HTTP.
func (m *Manager) AcquireSafeReusableConnection(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	baseKey string,
	slots int,
	waitLimit time.Duration,
	headers http.Header,
	identity safeConnectionIdentity,
	proxyOverride string,
) (*WsConnection, *PendingRequest, string, error) {
	if account == nil {
		return nil, nil, "", fmt.Errorf("acquire safe websocket connection: nil account")
	}
	if !identity.valid() {
		return nil, nil, "", fmt.Errorf("%w: missing session/thread owner or handshake fingerprint", errSafePoolIsolationViolation)
	}
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer finishOperation()
	ctx = opCtx
	currentSlots, policyActive := currentSafePoolSlots(account, m)
	if !policyActive {
		return nil, nil, "", newLocalCapacityAcquireError(0, fmt.Errorf("safe websocket reuse is no longer enabled"))
	}
	slots = currentSlots

	// Safe reuse deliberately mirrors the official client: one physical socket
	// per session/thread owner, never an account-level pool of interchangeable
	// sockets. slots caps the number of distinct owner sockets retained by this
	// account; it does not create interchangeable slots for one owner.
	accountLimit := accountConnectionLimit(account)
	if slots < 1 || slots > accountLimit {
		slots = accountLimit
	}
	if waitLimit < 0 {
		waitLimit = 0
	}
	started := time.Now()
	backoff := 5 * time.Millisecond
	for {
		currentSlots, policyActive = currentSafePoolSlots(account, m)
		if !policyActive {
			m.RetireSafePoolAccount(account.ID())
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), fmt.Errorf("safe websocket reuse was disabled during acquire"))
		}
		slots = currentSlots
		probeCtx, cancelProbe := context.WithTimeout(ctx, maxDuration(time.Until(started.Add(waitLimit)), time.Millisecond))
		wc, pending, slot, ok, probeInterrupted := m.tryAcquireExistingSafeSlot(probeCtx, account, wsURL, baseKey, slots, identity, proxyOverride)
		parentInterruption := contextInterruptionError(ctx)
		cancelProbe()
		if parentInterruption != nil {
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), parentInterruption)
		}
		if ok {
			if _, stillActive := currentSafePoolSlots(account, m); !stillActive {
				wc.session.RemovePendingRequest(pending.RequestID)
				wc.retireAfterLease.Store(true)
				m.DiscardConnection(wc)
				m.RetireSafePoolAccount(account.ID())
				return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), fmt.Errorf("safe websocket reuse was disabled after probe"))
			}
			return wc, pending, slot, nil
		}
		if _, stillActive := currentSafePoolSlots(account, m); !stillActive {
			m.RetireSafePoolAccount(account.ID())
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), fmt.Errorf("safe websocket reuse was disabled after probe"))
		}
		if probeInterrupted {
			m.safePoolSaturations.Add(1)
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started))
		}

		// The pool-key lock serializes duplicate handshakes for one owner while
		// different owners may dial in parallel under the account's strict pending
		// connection budget. This avoids an account-wide cold-start bottleneck.
		wc, pending, slot, created, createErr := m.tryCreateSafeSlot(ctx, account, wsURL, baseKey, slots, headers, identity, proxyOverride)
		if createErr != nil {
			return nil, nil, "", createErr
		}
		if created {
			return wc, pending, slot, nil
		}

		elapsed := time.Since(started)
		if elapsed >= waitLimit {
			m.safePoolSaturations.Add(1)
			return nil, nil, "", newLocalCapacityAcquireError(elapsed)
		}
		remaining := waitLimit - elapsed
		delay := backoff
		if delay > remaining {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), ctx.Err())
		case <-timer.C:
		}
		if backoff < 25*time.Millisecond {
			backoff *= 2
			if backoff > 25*time.Millisecond {
				backoff = 25 * time.Millisecond
			}
		}
	}
}

func (m *Manager) tryAcquireExistingSafeSlot(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	baseKey string,
	slots int,
	identity safeConnectionIdentity,
	proxyOverride string,
) (*WsConnection, *PendingRequest, string, bool, bool) {
	proxyURL := effectiveProxyURL(account, proxyOverride)
	accountLock := m.accountLock(account.ID())
	for i := 0; i < 1; i++ {
		slotSession := fmt.Sprintf("%s#%d", baseKey, i)
		key := m.poolKey(account.ID(), wsURL, slotSession, proxyURL)
		lock := m.keyLock(key)
		m.lockPoolKey(key, lock)
		value, exists := m.connections.Load(key)
		if !exists {
			lock.Unlock()
			continue
		}
		wc := value.(*WsConnection)
		if !wc.safeReusable.Load() || !identity.matches(wc) {
			m.DiscardConnection(wc)
			lock.Unlock()
			continue
		}
		if wc.retireAfterLease.Load() {
			// A hot policy/tag change may mark an active lease for retirement.
			// A concurrent reacquire must not close that socket underneath the
			// in-flight response; ReleaseConnection owns destruction after the
			// pending request reaches zero.
			if wc.session == nil || wc.session.PendingCount() == 0 {
				m.DiscardConnection(wc)
			}
			lock.Unlock()
			continue
		}
		if wc.reuseFenceActive() {
			lock.Unlock()
			continue
		}
		if canReuseConnection(wc) {
			if m.probeWithContext(ctx, wc) {
				accountLock.Lock()
				current, currentExists := m.connections.Load(key)
				if !currentExists || current != wc || wc.reuseFenceActive() || !canReuseConnection(wc) {
					accountLock.Unlock()
					lock.Unlock()
					continue
				}
				if !m.ensureConnectionActivationCapacity(account.ID(), accountConnectionLimit(account), wc) {
					accountLock.Unlock()
					lock.Unlock()
					continue
				}
				pending, leaseErr := m.addPendingAndBeginReadLease(wc, slotSession)
				if leaseErr == nil {
					wc.account = account
					wc.safeReusable.Store(true)
					wc.Touch()
					m.trimIdleAccountConnections(account.ID(), accountConnectionLimit(account), wc)
					m.safePoolReuseHits.Add(1)
					accountLock.Unlock()
					lock.Unlock()
					return wc, pending, slotSession, true, false
				}
				m.DiscardConnection(wc)
				accountLock.Unlock()
				lock.Unlock()
				continue
			}
			if contextInterruptionError(ctx) != nil {
				lock.Unlock()
				return nil, nil, "", false, true
			}
			m.DiscardConnection(wc)
		} else if !wc.IsConnected() || wc.session == nil || (wc.session.PendingCount() == 0 && !wc.readPumpReusable()) {
			m.DiscardConnection(wc)
		}
		lock.Unlock()
	}
	return nil, nil, "", false, false
}

// ensureSafePoolAccountCapacity enforces the configured count of active or
// unbound owner sockets for one dynamic account. A response-bound idle socket
// is connection-local continuation state, so it is excluded here and governed
// by the manager's separate per-account/global continuation budgets. Eviction
// is arbitrated atomically against BindResponseConn to avoid publishing or
// destroying a stale previous_response_id binding. Caller holds accountLock.
func (m *Manager) ensureSafePoolAccountCapacity(accountID int64, limit int, protectedKey string) bool {
	return m.convergeSafePoolAccountCapacity(accountID, limit, protectedKey, m.safePoolPendingCreateCount(accountID), 1)
}

func (m *Manager) ensureSafePoolPromotionCapacity(accountID int64, limit int, protectedKey string) bool {
	return m.convergeSafePoolAccountCapacity(accountID, limit, protectedKey, m.safePoolPendingCreateCount(accountID), 0)
}

func (m *Manager) convergeSafePoolAccountCapacity(accountID int64, limit int, protectedKey string, pendingCreates, additionalSlots int) bool {
	if limit < 1 {
		return false
	}
	type candidate struct {
		wc       *WsConnection
		lastUsed int64
	}
	count := 0
	idle := make([]candidate, 0)
	bound := m.snapshotLiveResponseBindings()
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || !wc.safeReusable.Load() || wc.session == nil || wc.session.AccountID != accountID {
			return true
		}
		pending := wc.session.PendingCount()
		if _, isBoundIdle := bound[wc]; isBoundIdle && pending == 0 {
			return true
		}
		count++
		if wc.PoolKey != protectedKey && pending == 0 && wc.readPumpReusable() {
			idle = append(idle, candidate{wc: wc, lastUsed: wc.lastUsed.Load()})
		}
		return true
	})
	withinLimit := func() bool { return count+pendingCreates+additionalSlots <= limit }
	if withinLimit() {
		return true
	}
	sort.Slice(idle, func(i, j int) bool {
		if idle[i].lastUsed != idle[j].lastUsed {
			return idle[i].lastUsed < idle[j].lastUsed
		}
		return idle[i].wc.PoolKey < idle[j].wc.PoolKey
	})
	for _, entry := range idle {
		removed, becameBound := m.discardOrdinaryIdleConnection(entry.wc, nil, protectedKey)
		if !removed && !becameBound {
			continue
		}
		// A raced binding moves the socket into the separately budgeted
		// continuation set; either outcome frees one ordinary safe-pool slot.
		count--
		if withinLimit() {
			return true
		}
	}
	return withinLimit()
}

func (m *Manager) tryCreateSafeSlot(
	ctx context.Context,
	account *auth.Account,
	wsURL string,
	baseKey string,
	slots int,
	headers http.Header,
	identity safeConnectionIdentity,
	proxyOverride string,
) (*WsConnection, *PendingRequest, string, bool, error) {
	proxyURL := effectiveProxyURL(account, proxyOverride)
	accountLock := m.accountLock(account.ID())
	for i := 0; i < 1; i++ {
		slotSession := fmt.Sprintf("%s#%d", baseKey, i)
		key := m.poolKey(account.ID(), wsURL, slotSession, proxyURL)
		lock := m.keyLock(key)
		m.lockPoolKey(key, lock)
		if _, exists := m.connections.Load(key); exists {
			lock.Unlock()
			continue
		}
		accountLock.Lock()
		if _, exists := m.connections.Load(key); exists {
			accountLock.Unlock()
			lock.Unlock()
			continue
		}
		if !m.ensureSafePoolAccountCapacity(account.ID(), slots, key) {
			accountLock.Unlock()
			lock.Unlock()
			return nil, nil, "", false, nil
		}
		if !m.reserveAccountConnectionCapacity(account, key) {
			accountLock.Unlock()
			lock.Unlock()
			return nil, nil, "", false, nil
		}
		m.reserveSafePoolPendingCreate(account.ID())
		accountLock.Unlock()

		m.safePoolDialAttempts.Add(1)
		wc, err := m.createConnectionWithIdentity(ctx, account, wsURL, slotSession, headers, identity, proxyOverride)
		if err != nil {
			m.safePoolDialFailures.Add(1)
			m.releaseSafePoolPendingCreate(account.ID())
			m.releaseAccountConnectionCapacity(account.ID())
			lock.Unlock()
			return nil, nil, "", false, err
		}
		m.safePoolDialSuccess.Add(1)
		if _, policyActive := currentSafePoolSlots(account, m); !policyActive {
			m.releaseSafePoolPendingCreate(account.ID())
			m.releaseAccountConnectionCapacity(account.ID())
			m.DiscardConnection(wc)
			lock.Unlock()
			return nil, nil, "", false, nil
		}
		pending, leaseErr := m.storeConnectionAndBeginReadLeaseChecked(ctx, account, accountLock, wc, slotSession, func() bool {
			currentSlots, policyActive := currentSafePoolSlots(account, m)
			return policyActive && m.ensureSafePoolPromotionCapacity(account.ID(), currentSlots, key)
		})
		m.releaseSafePoolPendingCreate(account.ID())
		if leaseErr == nil {
			if earlyErr := wc.waitForEarlyReadFailure(ctx, newConnectionReadFailureGrace); earlyErr != nil {
				wc.session.RemovePendingRequest(pending.RequestID)
				leaseErr = earlyErr
			}
		}
		if leaseErr != nil {
			m.DiscardConnection(wc)
			lock.Unlock()
			if ctx.Err() != nil {
				return nil, nil, "", false, ctx.Err()
			}
			continue
		}
		lock.Unlock()
		if connected := m.getOnConnected(); connected != nil {
			connected(account.ID(), wc.session)
		}
		return wc, pending, slotSession, true, nil
	}
	return nil, nil, "", false, nil
}
