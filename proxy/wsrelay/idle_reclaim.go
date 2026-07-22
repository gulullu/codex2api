package wsrelay

import (
	"log"
	"time"

	"github.com/codex2api/proxy"
)

const (
	// Sampling is operational, not a security boundary. FNV-1a plus a fixed
	// SplitMix64 finalizer gives every dynamic PoolKey a stable allocation-free
	// bucket without logging or retaining the potentially sensitive key.
	idleReclaimFNVOffset        = uint64(14695981039346656037)
	idleReclaimFNVPrime         = uint64(1099511628211)
	idleReclaimSampleSalt       = uint64(0x575349444c455631)
	idleReclaimReconnectTTL     = 2 * time.Hour
	idleReclaimMaxReconnectKeys = 65536
	idleReclaimLogInterval      = 5 * time.Minute
	idleReclaimMaxPerPass       = 8
)

type idleReclaimPolicy struct {
	enabled     bool
	observeOnly bool
	percent     int
	idle        time.Duration
}

// IdleReclaimRuntimeSnapshot is a read-only, cumulative process snapshot.
// Counters intentionally avoid account IDs, owner keys and pool keys.
// SkippedRateLimit counts cleanup passes stopped at the eight-close cap, not
// the number of unvisited connections beyond that cap.
type IdleReclaimRuntimeSnapshot struct {
	Enabled           bool   `json:"enabled"`
	ObserveOnly       bool   `json:"observe_only"`
	Percent           int    `json:"percent"`
	IdleSeconds       int    `json:"idle_seconds"`
	Seen              uint64 `json:"seen"`
	SampleHit         uint64 `json:"sample_hit"`
	IdleCandidate     uint64 `json:"idle_candidate"`
	Eligible          uint64 `json:"eligible"`
	WouldReclaim      uint64 `json:"would_reclaim"`
	Reclaimed         uint64 `json:"reclaimed"`
	SkippedBusy       uint64 `json:"skipped_busy"`
	SkippedContext    uint64 `json:"skipped_context"`
	SkippedRateLimit  uint64 `json:"skipped_rate_limit"`
	Reconnect         uint64 `json:"reconnect"`
	PendingReconnects int64  `json:"pending_reconnects"`
}

func currentIdleReclaimPolicy() idleReclaimPolicy {
	settings := proxy.CurrentRuntimeSettings()
	percent := proxy.NormalizeCodexWSIdleReclaimPercent(settings.CodexWSIdleReclaimPercent)
	idleSeconds := settings.CodexWSIdleReclaimIdleSec
	if idleSeconds <= 0 {
		idleSeconds = 10 * 60
	}
	return idleReclaimPolicy{
		enabled:     settings.CodexWSIdleReclaimEnabled && percent > 0,
		observeOnly: !settings.CodexWSIdleReclaimEnabled && percent > 0,
		percent:     percent,
		idle:        time.Duration(idleSeconds) * time.Second,
	}
}

// idleReclaimPoolKeySampled deterministically buckets every dynamic pool slot.
// No account ID or account name is special-cased. The key is hashed in-place
// and is never included in metrics or logs.
func idleReclaimPoolKeySampled(poolKey string, percent int) bool {
	percent = proxy.NormalizeCodexWSIdleReclaimPercent(percent)
	if poolKey == "" || percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	x := idleReclaimFNVOffset ^ idleReclaimSampleSalt
	for i := 0; i < len(poolKey); i++ {
		x ^= uint64(poolKey[i])
		x *= idleReclaimFNVPrime
	}
	x += idleReclaimSampleSalt
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	bucket := (x ^ (x >> 31)) % 100
	return bucket < uint64(percent)
}

func (m *Manager) IdleReclaimRuntimeSnapshot() IdleReclaimRuntimeSnapshot {
	if m == nil {
		return IdleReclaimRuntimeSnapshot{}
	}
	policy := currentIdleReclaimPolicy()
	return IdleReclaimRuntimeSnapshot{
		Enabled:           policy.enabled,
		ObserveOnly:       policy.observeOnly,
		Percent:           policy.percent,
		IdleSeconds:       int(policy.idle / time.Second),
		Seen:              m.idleReclaimSeen.Load(),
		SampleHit:         m.idleReclaimSampleHit.Load(),
		IdleCandidate:     m.idleReclaimIdleCandidate.Load(),
		Eligible:          m.idleReclaimEligible.Load(),
		WouldReclaim:      m.idleReclaimWouldReclaim.Load(),
		Reclaimed:         m.idleReclaimReclaimed.Load(),
		SkippedBusy:       m.idleReclaimSkippedBusy.Load(),
		SkippedContext:    m.idleReclaimSkippedContext.Load(),
		SkippedRateLimit:  m.idleReclaimSkippedRate.Load(),
		Reconnect:         m.idleReclaimReconnect.Load(),
		PendingReconnects: m.idleReclaimPendingKeys.Load(),
	}
}

func (m *Manager) reclaimBusinessIdleConnections(now time.Time) {
	if m == nil {
		return
	}
	policy := currentIdleReclaimPolicy()
	if !policy.enabled && !policy.observeOnly {
		return
	}

	// Observe-only must not mutate reconnect attribution. Stale reconnect keys
	// are pruned again when enforce mode resumes (or consumed by a reconnect).
	if policy.enabled {
		m.pruneIdleReclaimReconnectKeys(now)
	}
	reclaimedThisPass := 0
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || wc.session == nil {
			return true
		}
		m.idleReclaimSeen.Add(1)
		if wc.businessIdleFor(now) < policy.idle {
			return true
		}
		m.idleReclaimIdleCandidate.Add(1)
		// Active sockets never pay the per-byte PoolKey hashing cost.
		if !idleReclaimPoolKeySampled(wc.PoolKey, policy.percent) {
			return true
		}
		m.idleReclaimSampleHit.Add(1)
		accountID := wc.session.AccountID

		// Account locking is the existing acquire/cleanup ownership boundary.
		// Every production lease takes this lock before final activation, so the
		// checks below and pointer removal cannot race a new business write.
		accountLock := m.accountLock(accountID)
		accountLock.Lock()
		current, exists := m.connections.Load(wc.PoolKey)
		if !exists || current != wc || wc.businessIdleFor(now) < policy.idle {
			accountLock.Unlock()
			return true
		}
		m.idleReclaimEligible.Add(1)

		if !wc.IsConnected() || !wc.session.IsConnected() || wc.session.PendingCount() != 0 ||
			!wc.readPumpReusable() || wc.reuseFenceActive() || wc.safeTerminalReleaseDone() != nil {
			m.idleReclaimSkippedBusy.Add(1)
			accountLock.Unlock()
			return true
		}
		// Hold the socket writer gate through pointer removal and Close. This
		// excludes heartbeat writes as well as any unexpected direct writer.
		if !wc.writeMu.TryLock() {
			m.idleReclaimSkippedBusy.Add(1)
			accountLock.Unlock()
			return true
		}
		reclaimable, becameBound := m.idleReclaimWouldDiscard(wc, now)
		if becameBound {
			m.idleReclaimSkippedContext.Add(1)
			wc.writeMu.Unlock()
			accountLock.Unlock()
			return true
		}
		if !reclaimable {
			m.idleReclaimSkippedBusy.Add(1)
			wc.writeMu.Unlock()
			accountLock.Unlock()
			return true
		}
		m.idleReclaimWouldReclaim.Add(1)
		if policy.observeOnly {
			wc.writeMu.Unlock()
			accountLock.Unlock()
			return true
		}
		removed, becameBound := m.discardOrdinaryIdleConnection(wc, nil, "")
		wc.writeMu.Unlock()
		if becameBound {
			// A live response binding means this socket contains unique upstream
			// continuation state. Never close it; wait for its independent TTL.
			m.idleReclaimSkippedContext.Add(1)
		} else if removed {
			m.rememberIdleReclaimedKey(wc.PoolKey, now)
			m.idleReclaimReclaimed.Add(1)
			reclaimedThisPass++
		}
		accountLock.Unlock()
		if reclaimedThisPass >= idleReclaimMaxPerPass {
			// One increment means one cleanup pass stopped at the close cap;
			// observe-only never takes this shortcut and scans the full pool.
			m.idleReclaimSkippedRate.Add(1)
			return false
		}
		return true
	})
	m.maybeLogIdleReclaimSummary(now, policy)
}

// idleReclaimWouldDiscard mirrors the final continuation arbitration without
// mutating bindings or pool ownership. The enforce path still calls
// discardOrdinaryIdleConnection, which repeats this check under respConnMu
// before any pointer removal.
func (m *Manager) idleReclaimWouldDiscard(wc *WsConnection, now time.Time) (reclaimable bool, becameBound bool) {
	if m == nil || !m.idleConnectionCanBeEvicted(wc, nil, "") {
		return false, false
	}
	m.respConnMu.Lock()
	defer m.respConnMu.Unlock()
	if summary, ok := m.respConnSummaries[wc]; ok && summary != nil && summary.latestGeneration != 0 {
		if !now.After(summary.latestExpiresAt) {
			return false, true
		}
	} else {
		// Defensive read-only fallback for legacy/test state lacking the
		// secondary index. No prune/rebuild is allowed from observe-only.
		for _, binding := range m.respConnBindings {
			if binding.conn == wc && !now.After(binding.expiresAt) {
				return false, true
			}
		}
	}
	if !m.idleConnectionCanBeEvicted(wc, nil, "") {
		return false, false
	}
	return true, false
}

func (m *Manager) rememberIdleReclaimedKey(poolKey string, now time.Time) {
	if m == nil || poolKey == "" {
		return
	}
	m.idleReclaimMu.Lock()
	defer m.idleReclaimMu.Unlock()
	if m.idleReclaimedKeys == nil {
		m.idleReclaimedKeys = make(map[string]time.Time)
	}
	if len(m.idleReclaimedKeys) >= idleReclaimMaxReconnectKeys {
		m.pruneIdleReclaimReconnectKeysLocked(now)
		if len(m.idleReclaimedKeys) >= idleReclaimMaxReconnectKeys {
			return
		}
	}
	if _, exists := m.idleReclaimedKeys[poolKey]; !exists {
		m.idleReclaimPendingKeys.Add(1)
	}
	m.idleReclaimedKeys[poolKey] = now.Add(idleReclaimReconnectTTL)
}

func (m *Manager) noteIdleReclaimReconnect(poolKey string, now time.Time) {
	if m == nil || poolKey == "" || m.idleReclaimPendingKeys.Load() == 0 {
		return
	}
	m.idleReclaimMu.Lock()
	expiresAt, exists := m.idleReclaimedKeys[poolKey]
	if exists {
		delete(m.idleReclaimedKeys, poolKey)
		m.idleReclaimPendingKeys.Add(-1)
	}
	m.idleReclaimMu.Unlock()
	if exists && now.Before(expiresAt) {
		m.idleReclaimReconnect.Add(1)
	}
}

func (m *Manager) pruneIdleReclaimReconnectKeys(now time.Time) {
	if m == nil {
		return
	}
	m.idleReclaimMu.Lock()
	m.pruneIdleReclaimReconnectKeysLocked(now)
	m.idleReclaimMu.Unlock()
}

func (m *Manager) pruneIdleReclaimReconnectKeysLocked(now time.Time) {
	for poolKey, expiresAt := range m.idleReclaimedKeys {
		if !now.Before(expiresAt) {
			delete(m.idleReclaimedKeys, poolKey)
			m.idleReclaimPendingKeys.Add(-1)
		}
	}
}

func (m *Manager) maybeLogIdleReclaimSummary(now time.Time, policy idleReclaimPolicy) {
	if m == nil || (!policy.enabled && !policy.observeOnly) {
		return
	}
	total := m.idleReclaimSeen.Load() + m.idleReclaimSampleHit.Load() +
		m.idleReclaimIdleCandidate.Load() + m.idleReclaimEligible.Load() +
		m.idleReclaimWouldReclaim.Load() + m.idleReclaimReclaimed.Load() +
		m.idleReclaimSkippedBusy.Load() + m.idleReclaimSkippedContext.Load() +
		m.idleReclaimSkippedRate.Load() + m.idleReclaimReconnect.Load()
	if total == 0 || total == m.idleReclaimLastLogged.Load() {
		return
	}
	nowNanos := now.UnixNano()
	nextLog := m.idleReclaimNextLog.Load()
	if nextLog > nowNanos || !m.idleReclaimNextLog.CompareAndSwap(nextLog, now.Add(idleReclaimLogInterval).UnixNano()) {
		return
	}
	m.idleReclaimLastLogged.Store(total)
	snapshot := m.IdleReclaimRuntimeSnapshot()
	mode := "enforce"
	if snapshot.ObserveOnly {
		mode = "observe"
	}
	log.Printf("[WS-Idle-Reclaim] counters=cumulative mode=%s rollout=%d%% idle=%ds seen=%d idle_candidate=%d sample_hit=%d eligible=%d would_reclaim=%d reclaimed=%d skipped_busy=%d skipped_context=%d skipped_rate_limit=%d reconnect=%d pending_reconnect=%d",
		mode, snapshot.Percent, snapshot.IdleSeconds, snapshot.Seen, snapshot.IdleCandidate,
		snapshot.SampleHit, snapshot.Eligible, snapshot.WouldReclaim, snapshot.Reclaimed,
		snapshot.SkippedBusy, snapshot.SkippedContext, snapshot.SkippedRateLimit,
		snapshot.Reconnect, snapshot.PendingReconnects)
}
