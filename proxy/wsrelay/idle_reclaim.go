package wsrelay

import (
	"log"
	"time"

	"github.com/codex2api/proxy"
)

const (
	// Fixed SplitMix64 domain salt. Sampling is operational, not a security
	// boundary; this allocation-free mixer keeps cleanup overhead negligible.
	idleReclaimSampleSalt       = uint64(0x575349444c455631)
	idleReclaimReconnectTTL     = 2 * time.Hour
	idleReclaimMaxReconnectKeys = 65536
	idleReclaimLogInterval      = 5 * time.Minute
)

type idleReclaimPolicy struct {
	enabled bool
	percent int
	idle    time.Duration
}

// IdleReclaimRuntimeSnapshot is a read-only, cumulative process snapshot.
// Counters intentionally avoid account IDs, owner keys and pool keys.
type IdleReclaimRuntimeSnapshot struct {
	Enabled           bool   `json:"enabled"`
	Percent           int    `json:"percent"`
	IdleSeconds       int    `json:"idle_seconds"`
	Eligible          uint64 `json:"eligible"`
	Reclaimed         uint64 `json:"reclaimed"`
	SkippedBusy       uint64 `json:"skipped_busy"`
	SkippedContext    uint64 `json:"skipped_context"`
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
		enabled: settings.CodexWSIdleReclaimEnabled && percent > 0,
		percent: percent,
		idle:    time.Duration(idleSeconds) * time.Second,
	}
}

// idleReclaimAccountSampled deterministically buckets every dynamic account.
// No account ID is special-cased; newly added/replaced accounts automatically
// receive a stable bucket on their first cleanup pass.
func idleReclaimAccountSampled(accountID int64, percent int) bool {
	percent = proxy.NormalizeCodexWSIdleReclaimPercent(percent)
	if accountID <= 0 || percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	x := uint64(accountID) + idleReclaimSampleSalt
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
		Percent:           policy.percent,
		IdleSeconds:       int(policy.idle / time.Second),
		Eligible:          m.idleReclaimEligible.Load(),
		Reclaimed:         m.idleReclaimReclaimed.Load(),
		SkippedBusy:       m.idleReclaimSkippedBusy.Load(),
		SkippedContext:    m.idleReclaimSkippedContext.Load(),
		Reconnect:         m.idleReclaimReconnect.Load(),
		PendingReconnects: m.idleReclaimPendingKeys.Load(),
	}
}

func (m *Manager) reclaimBusinessIdleConnections(now time.Time) {
	if m == nil {
		return
	}
	policy := currentIdleReclaimPolicy()
	if !policy.enabled {
		return
	}

	m.pruneIdleReclaimReconnectKeys(now)
	m.connections.Range(func(_, value any) bool {
		wc, ok := value.(*WsConnection)
		if !ok || wc == nil || wc.session == nil {
			return true
		}
		accountID := wc.session.AccountID
		if !idleReclaimAccountSampled(accountID, policy.percent) || wc.businessIdleFor(now) < policy.idle {
			return true
		}

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
		removed, becameBound := m.discardOrdinaryIdleConnection(wc, nil, "")
		wc.writeMu.Unlock()
		if becameBound {
			// A live response binding means this socket contains unique upstream
			// continuation state. Never close it; wait for its independent TTL.
			m.idleReclaimSkippedContext.Add(1)
		} else if removed {
			m.rememberIdleReclaimedKey(wc.PoolKey, now)
			m.idleReclaimReclaimed.Add(1)
		}
		accountLock.Unlock()
		return true
	})
	m.maybeLogIdleReclaimSummary(now, policy)
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
	if m == nil || !policy.enabled {
		return
	}
	total := m.idleReclaimEligible.Load() + m.idleReclaimReclaimed.Load() +
		m.idleReclaimSkippedBusy.Load() + m.idleReclaimSkippedContext.Load() +
		m.idleReclaimReconnect.Load()
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
	log.Printf("[WS-Idle-Reclaim] rollout=%d%% idle=%ds eligible=%d reclaimed=%d skipped_busy=%d skipped_context=%d reconnect=%d pending_reconnect=%d",
		snapshot.Percent, snapshot.IdleSeconds, snapshot.Eligible, snapshot.Reclaimed,
		snapshot.SkippedBusy, snapshot.SkippedContext, snapshot.Reconnect, snapshot.PendingReconnects)
}
