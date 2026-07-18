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
	generation           uint64
}

func (identity safeConnectionIdentity) valid() bool {
	return strings.TrimSpace(identity.ownerKey) != "" &&
		strings.TrimSpace(identity.handshakeFingerprint) != "" &&
		identity.generation > 0
}

func (identity safeConnectionIdentity) matches(wc *WsConnection) bool {
	return identity.valid() && wc != nil &&
		wc.safeOwnerKey == identity.ownerKey &&
		wc.handshakeFingerprint == identity.handshakeFingerprint &&
		wc.safeGeneration == identity.generation
}

func (wc *WsConnection) safeIdentity() safeConnectionIdentity {
	if wc == nil {
		return safeConnectionIdentity{}
	}
	return safeConnectionIdentity{
		ownerKey:             wc.safeOwnerKey,
		handshakeFingerprint: wc.handshakeFingerprint,
		generation:           wc.safeGeneration,
	}
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
	DialAttempts            uint64
	DialSuccess             uint64
	DialFailures            uint64
	ReuseHits               uint64
	Saturations             uint64
	FuseTrips               uint64
	CompatibilityDrops      uint64
	CompatibilityFallbacks  uint64
	OwnerEligible           uint64
	OwnerMissing            uint64
	OwnerRejected           uint64
	RequestIneligible       uint64
	OwnerAdmittedNew        uint64
	OwnerAdmittedExisting   uint64
	OwnerSampleRejected     uint64
	OwnerBudgetRejected     uint64
	OwnerOneShotFallbacks   uint64
	OwnerConfigErrors       uint64
	OwnerHandshakeRejected  uint64
	FrameMetadataRejected   uint64
	GenerationInvalidations uint64
	RetiredOwners           uint64
	ContinuationEvictions   uint64
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
		DialAttempts:            m.safePoolDialAttempts.Load(),
		DialSuccess:             m.safePoolDialSuccess.Load(),
		DialFailures:            m.safePoolDialFailures.Load(),
		ReuseHits:               m.safePoolReuseHits.Load(),
		Saturations:             m.safePoolSaturations.Load(),
		FuseTrips:               m.safePoolFuseTrips.Load(),
		CompatibilityDrops:      m.safePoolCompatibilityDrops.Load(),
		CompatibilityFallbacks:  m.safePoolCompatibilityFallbacks.Load(),
		OwnerEligible:           m.safePoolOwnerEligible.Load(),
		OwnerMissing:            m.safePoolOwnerMissing.Load(),
		OwnerRejected:           m.safePoolOwnerRejected.Load(),
		RequestIneligible:       m.safePoolRequestIneligible.Load(),
		OwnerAdmittedNew:        m.safePoolOwnerAdmittedNew.Load(),
		OwnerAdmittedExisting:   m.safePoolOwnerAdmittedExisting.Load(),
		OwnerSampleRejected:     m.safePoolOwnerSampleRejected.Load(),
		OwnerBudgetRejected:     m.safePoolOwnerBudgetRejected.Load(),
		OwnerOneShotFallbacks:   m.safePoolOwnerOneShotFallbacks.Load(),
		OwnerConfigErrors:       m.safePoolOwnerConfigErrors.Load(),
		OwnerHandshakeRejected:  m.safePoolOwnerHandshakeRejected.Load(),
		FrameMetadataRejected:   m.safePoolFrameMetadataRejected.Load(),
		GenerationInvalidations: m.safePoolGenerationInvalidations.Load(),
		RetiredOwners:           m.safePoolRetiredOwners.Load(),
		ContinuationEvictions:   m.continuationBudgetEvictions.Load(),
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
// account status, tags, schedulability, Guardian or the database. Generation
// invalidation is unconditional: an owner admitted before a cold dial is still
// retired even when no socket ever populated safePoolAccounts.
func (m *Manager) RetireSafePoolAccount(accountID int64) {
	if m == nil || accountID <= 0 {
		return
	}
	m.retireSafePoolAccount(accountID, false)
}

// HandleAccountTagsUpdated is the low-coupling admin hook for dynamic rollout
// tags. IDs and names remain runtime data. Retirement follows the effective
// policy transition rather than one literal tag: under scope=tagged removing
// sys:ws-safe-pool disables reuse, while under scope=all that removal is a
// no-op and adding sys:ws-oneshot is the disabling transition.
func (m *Manager) HandleAccountTagsUpdated(accountID int64, previousTags, currentTags []string) {
	if m == nil || accountID <= 0 {
		return
	}
	account := &auth.Account{DBID: accountID}
	previousSafe := resolveStatelessPoolPolicyWithTags(account, m, previousTags).mode == statelessPoolSafe
	currentSafe := resolveStatelessPoolPolicyWithTags(account, m, currentTags).mode == statelessPoolSafe
	if previousSafe && !currentSafe {
		m.RetireSafePoolAccount(accountID)
	}
}

func (m *Manager) retireSafePoolAccount(accountID int64, force bool) {
	if m == nil || accountID <= 0 {
		return
	}
	m.ownerAdmissionMu.Lock()
	m.invalidateSafePoolGenerationLocked(accountID)
	m.ownerAdmissionMu.Unlock()
	m.retireSafePoolAccountSockets(accountID, force)
}

// retireSafePoolAccountIfPolicyDisabled revalidates the current master policy
// under the account read lock before invalidating a generation. This prevents a
// request carrying an old non-safe policy snapshot from retiring a generation
// that a concurrent tag re-add just admitted.
func (m *Manager) retireSafePoolAccountIfPolicyDisabled(account *auth.Account) {
	if m == nil || account == nil || account.ID() <= 0 {
		return
	}
	account.Mu().RLock()
	policy := resolveStatelessPoolPolicyWithTags(account, m, account.Tags)
	if policy.mode == statelessPoolSafe {
		account.Mu().RUnlock()
		return
	}
	m.ownerAdmissionMu.Lock()
	if len(m.safePoolAdmittedOwners[account.ID()]) == 0 {
		m.ownerAdmissionMu.Unlock()
		account.Mu().RUnlock()
		return
	}
	m.invalidateSafePoolGenerationLocked(account.ID())
	m.ownerAdmissionMu.Unlock()
	account.Mu().RUnlock()
	m.retireSafePoolAccountSockets(account.ID(), false)
}

func (m *Manager) retireSafePoolAccountSockets(accountID int64, force bool) {
	accountLock := m.accountLock(accountID)
	accountLock.Lock()
	idle := make([]*WsConnection, 0)
	retired := make([]*WsConnection, 0)
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || !wc.safeReusable.Load() || wc.session == nil || wc.session.AccountID != accountID {
			return true
		}
		wc.retireAfterLease.Store(true)
		retired = append(retired, wc)
		if wc.session.PendingCount() == 0 {
			idle = append(idle, wc)
		}
		return true
	})
	accountLock.Unlock()
	// Bindings are continuation capabilities and must disappear as soon as the
	// admitting generation is invalidated, including for an active old socket.
	for _, wc := range retired {
		m.removeResponseConnBindings(wc)
	}
	for _, wc := range idle {
		m.DiscardConnection(wc)
	}
}

func (m *Manager) retireStaleSafeConnection(wc *WsConnection) {
	if m == nil || wc == nil {
		return
	}
	wc.retireAfterLease.Store(true)
	m.removeResponseConnBindings(wc)
	if wc.session == nil || wc.session.PendingCount() == 0 {
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

// safePoolIdentityUsable atomically rechecks the dynamic master policy and the
// account-local owner generation. The lock order (account RLock ->
// ownerAdmissionMu) matches admission and tag-update retirement.
func (m *Manager) safePoolIdentityUsable(account *auth.Account, identity safeConnectionIdentity) bool {
	if m == nil || account == nil || !identity.valid() {
		return false
	}
	account.Mu().RLock()
	policyActive := resolveStatelessPoolPolicyWithTags(account, m, account.Tags).mode == statelessPoolSafe
	m.ownerAdmissionMu.Lock()
	generationCurrent := m.safePoolIdentityGenerationCurrentLocked(account.ID(), identity)
	m.ownerAdmissionMu.Unlock()
	account.Mu().RUnlock()
	return policyActive && generationCurrent
}

func (m *Manager) safePoolConnectionUsable(wc *WsConnection) bool {
	return wc != nil && wc.safeReusable.Load() && m.safePoolIdentityUsable(wc.account, wc.safeIdentity())
}

func safePoolAcquireFallback(message string) error {
	return fmt.Errorf("%w: %s", proxy.ErrWebsocketSafePoolFallback, message)
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
	if !m.safePoolIdentityUsable(account, identity) {
		return nil, nil, "", safePoolAcquireFallback("safe websocket owner generation or rollout policy is no longer current")
	}
	opCtx, finishOperation, err := m.beginOperation(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer finishOperation()
	ctx = opCtx
	currentSlots, policyActive := currentSafePoolSlots(account, m)
	if !policyActive {
		return nil, nil, "", safePoolAcquireFallback("safe websocket reuse is no longer enabled")
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
		if !m.safePoolIdentityUsable(account, identity) {
			return nil, nil, "", safePoolAcquireFallback("safe websocket generation changed during acquire")
		}
		currentSlots, policyActive = currentSafePoolSlots(account, m)
		if !policyActive {
			m.retireSafePoolAccountIfPolicyDisabled(account)
			return nil, nil, "", safePoolAcquireFallback("safe websocket reuse was disabled during acquire")
		}
		slots = currentSlots
		probeCtx, cancelProbe := context.WithTimeout(ctx, maxDuration(time.Until(started.Add(waitLimit)), time.Millisecond))
		wc, pending, slot, ok, probeInterrupted, acquireErr := m.tryAcquireExistingSafeSlot(probeCtx, account, wsURL, baseKey, slots, identity, proxyOverride)
		parentInterruption := contextInterruptionError(ctx)
		cancelProbe()
		if parentInterruption != nil {
			return nil, nil, "", newLocalCapacityAcquireError(time.Since(started), parentInterruption)
		}
		if acquireErr != nil {
			return nil, nil, "", acquireErr
		}
		if ok {
			if !m.safePoolIdentityUsable(account, identity) {
				wc.session.RemovePendingRequest(pending.RequestID)
				m.retireStaleSafeConnection(wc)
				return nil, nil, "", safePoolAcquireFallback("safe websocket generation changed after probe")
			}
			return wc, pending, slot, nil
		}
		if !m.safePoolIdentityUsable(account, identity) {
			return nil, nil, "", safePoolAcquireFallback("safe websocket generation changed after probe")
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
) (*WsConnection, *PendingRequest, string, bool, bool, error) {
	if !m.safePoolIdentityUsable(account, identity) {
		return nil, nil, "", false, false, safePoolAcquireFallback("safe websocket generation changed before existing-slot acquire")
	}
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
				if !m.safePoolIdentityUsable(account, identity) {
					m.retireStaleSafeConnection(wc)
					lock.Unlock()
					return nil, nil, "", false, false, safePoolAcquireFallback("safe websocket generation changed during liveness probe")
				}
				accountLock.Lock()
				current, currentExists := m.connections.Load(key)
				if !currentExists || current != wc || wc.reuseFenceActive() || !canReuseConnection(wc) || !m.safePoolIdentityUsable(account, identity) {
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
					return wc, pending, slotSession, true, false, nil
				}
				m.DiscardConnection(wc)
				accountLock.Unlock()
				lock.Unlock()
				continue
			}
			if contextInterruptionError(ctx) != nil {
				lock.Unlock()
				return nil, nil, "", false, true, nil
			}
			m.DiscardConnection(wc)
		} else if !wc.IsConnected() || wc.session == nil || (wc.session.PendingCount() == 0 && !wc.readPumpReusable()) {
			m.DiscardConnection(wc)
		}
		lock.Unlock()
	}
	return nil, nil, "", false, false, nil
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

func (m *Manager) ensureSafePoolPromotionCapacity(accountID int64, limit int, protectedKey string, published bool) bool {
	pendingCreates := m.safePoolPendingCreateCount(accountID)
	// The promoting dial remains reserved until publication is fully validated.
	// Once its socket is in the map, counting both that socket and its own
	// reservation would consume two slots and reject every slots=1 cold start.
	if published && pendingCreates > 0 {
		pendingCreates--
	}
	return m.convergeSafePoolAccountCapacity(accountID, limit, protectedKey, pendingCreates, 0)
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
	if !m.safePoolIdentityUsable(account, identity) {
		return nil, nil, "", false, safePoolAcquireFallback("safe websocket generation changed before dial")
	}
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
		if !m.safePoolIdentityUsable(account, identity) {
			accountLock.Unlock()
			lock.Unlock()
			return nil, nil, "", false, safePoolAcquireFallback("safe websocket generation changed before dial reservation")
		}
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
		if !m.safePoolIdentityUsable(account, identity) {
			m.releaseSafePoolPendingCreate(account.ID())
			m.releaseAccountConnectionCapacity(account.ID())
			m.DiscardConnection(wc)
			lock.Unlock()
			return nil, nil, "", false, safePoolAcquireFallback("safe websocket generation changed after dial")
		}
		pending, leaseErr := m.storeConnectionAndBeginReadLeaseChecked(ctx, account, accountLock, wc, slotSession, func() bool {
			currentSlots, policyActive := currentSafePoolSlots(account, m)
			published := false
			if current, exists := m.connections.Load(key); exists && current == wc {
				published = true
			}
			return policyActive && m.safePoolIdentityUsable(account, identity) && m.ensureSafePoolPromotionCapacity(account.ID(), currentSlots, key, published)
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
		if !m.safePoolIdentityUsable(account, identity) {
			wc.session.RemovePendingRequest(pending.RequestID)
			m.retireStaleSafeConnection(wc)
			lock.Unlock()
			return nil, nil, "", false, safePoolAcquireFallback("safe websocket generation changed after store")
		}
		lock.Unlock()
		if connected := m.getOnConnected(); connected != nil {
			connected(account.ID(), wc.session)
		}
		return wc, pending, slotSession, true, nil
	}
	return nil, nil, "", false, nil
}
