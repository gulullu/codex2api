package auth

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/codex2api/cache"
)

const (
	relayCircuitRuntimeCacheNamespace = "relay-circuit-breaker"
	relayCircuitRuntimeCacheTTL       = 24 * time.Hour
	relayCircuitCacheTimeout          = 300 * time.Millisecond

	relayCircuitWeakWindow        = 30 * time.Second
	relayCircuitWeakFailureLimit  = 3
	relayCircuitInitialOpen       = 30 * time.Second
	relayCircuitRecoverySuccesses = 3
)

var relayCircuitReopenBackoffs = [...]time.Duration{
	60 * time.Second,
	120 * time.Second,
	300 * time.Second,
}

// RelayCircuitState is the externally visible state of a Relay account's
// short-lived upstream circuit breaker.
type RelayCircuitState string

const (
	RelayCircuitClosed   RelayCircuitState = "closed"
	RelayCircuitOpen     RelayCircuitState = "open"
	RelayCircuitHalfOpen RelayCircuitState = "half_open"
)

// RelayCircuitPermit identifies one upstream attempt. Callers must acquire a
// permit immediately after Store selects a Relay account and report exactly
// one success or failure with the same value. Generation fences results from
// requests that were already in flight when a newer circuit opened.
type RelayCircuitPermit struct {
	AccountID  int64
	Generation uint64
	LeaseID    uint64
	Probe      bool
	Active     bool
	Guardian   RelayGuardianPermit
}

// RelayCircuitSnapshot is a read-only admin/audit view. It is intentionally
// separate from Account.Status/CooldownReason so Relay server failures cannot
// overwrite the existing 401/429/usage cooldown slot.
type RelayCircuitSnapshot struct {
	AccountID       int64             `json:"account_id"`
	State           RelayCircuitState `json:"state"`
	Generation      uint64            `json:"generation"`
	Reason          string            `json:"reason,omitempty"`
	LastStatusCode  int               `json:"last_status_code,omitempty"`
	OpenedAt        time.Time         `json:"opened_at,omitempty"`
	OpenUntil       time.Time         `json:"open_until,omitempty"`
	LastFailureAt   time.Time         `json:"last_failure_at,omitempty"`
	UpdatedAt       time.Time         `json:"updated_at,omitempty"`
	BackoffLevel    int               `json:"backoff_level"`
	WeakFailures    int               `json:"weak_failures"`
	ProbeInFlight   bool              `json:"probe_in_flight"`
	ProbeSuccesses  int               `json:"probe_successes"`
	RequiredSuccess int               `json:"required_successes"`
}

type relayCircuitRuntimeRecord struct {
	State          RelayCircuitState `json:"state"`
	Generation     uint64            `json:"generation"`
	Reason         string            `json:"reason,omitempty"`
	LastStatusCode int               `json:"last_status_code,omitempty"`
	OpenedAt       time.Time         `json:"opened_at,omitempty"`
	OpenUntil      time.Time         `json:"open_until,omitempty"`
	LastFailureAt  time.Time         `json:"last_failure_at,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at,omitempty"`
	BackoffLevel   int               `json:"backoff_level"`
	ProbeSuccesses int               `json:"probe_successes,omitempty"`
}

type relayCircuitAccountState struct {
	state          RelayCircuitState
	generation     uint64
	revision       uint64
	reason         string
	lastStatusCode int
	openedAt       time.Time
	openUntil      time.Time
	lastFailureAt  time.Time
	updatedAt      time.Time
	backoffLevel   int

	weakFailureTimes []time.Time

	probeInFlight  bool
	probeLeaseID   uint64
	probeSuccesses int
}

type relayCircuitBreaker struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	states    map[int64]*relayCircuitAccountState
	loaded    map[int64]bool
	loading   map[int64]bool
	retryLoad map[int64]time.Time
	permits   map[uint64]RelayCircuitPermit
	nextLease uint64
	cache     cache.TokenCache
	now       func() time.Time
}

func newRelayCircuitBreaker(tc cache.TokenCache) *relayCircuitBreaker {
	return &relayCircuitBreaker{
		states:    make(map[int64]*relayCircuitAccountState),
		loaded:    make(map[int64]bool),
		loading:   make(map[int64]bool),
		retryLoad: make(map[int64]time.Time),
		permits:   make(map[uint64]RelayCircuitPermit),
		cache:     tc,
		now:       time.Now,
	}
}

func (b *relayCircuitBreaker) nowTime() time.Time {
	if b != nil && b.now != nil {
		return b.now()
	}
	return time.Now()
}

func relayCircuitRuntimeKey(accountID int64) string {
	return strconv.FormatInt(accountID, 10)
}

func relayCircuitCacheContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), relayCircuitCacheTimeout)
}

func (b *relayCircuitBreaker) stateLocked(accountID int64) *relayCircuitAccountState {
	state := b.states[accountID]
	if state == nil {
		state = &relayCircuitAccountState{state: RelayCircuitClosed}
		b.states[accountID] = state
	}
	return state
}

// ensureLoaded is called only by startup/reconcile/admin-safe preload paths.
// The cache read stays outside b.mu so request selection can immediately fail
// closed while restoration is in flight instead of waiting behind Redis I/O.
func (b *relayCircuitBreaker) ensureLoaded(accountID int64) {
	if b == nil || accountID == 0 {
		return
	}
	b.mu.Lock()
	if b.loaded[accountID] || b.loading[accountID] {
		b.mu.Unlock()
		return
	}
	now := b.nowTime()
	if retryAt := b.retryLoad[accountID]; retryAt.After(now) {
		b.mu.Unlock()
		return
	}
	if b.cache == nil {
		b.loaded[accountID] = true
		b.mu.Unlock()
		return
	}
	b.loading[accountID] = true
	b.mu.Unlock()

	ctx, cancel := relayCircuitCacheContext()
	payload, ok, err := b.cache.GetRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID))
	cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.loading, accountID)
	if err != nil {
		// A transient cache error must not permanently disable restart fencing.
		// Throttle retries so a cache outage cannot add 300 ms to every scheduler
		// pass for the same account.
		b.retryLoad[accountID] = now.Add(time.Second)
		log.Printf("[Relay circuit account=%d] restore runtime fence failed: %v", accountID, err)
		return
	}
	b.loaded[accountID] = true
	delete(b.retryLoad, accountID)
	if !ok || len(payload) == 0 {
		return
	}
	var record relayCircuitRuntimeRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		log.Printf("[Relay circuit account=%d] decode runtime fence failed: %v", accountID, err)
		return
	}
	if record.State != RelayCircuitOpen && record.State != RelayCircuitHalfOpen {
		return
	}

	state := b.stateLocked(accountID)
	state.state = record.State
	if state.state == RelayCircuitOpen && !record.OpenUntil.After(now) {
		state.state = RelayCircuitHalfOpen
	}
	state.generation = record.Generation
	if state.generation == 0 {
		state.generation = 1
	}
	state.revision++
	state.reason = record.Reason
	state.lastStatusCode = record.LastStatusCode
	state.openedAt = record.OpenedAt
	state.openUntil = record.OpenUntil
	state.lastFailureAt = record.LastFailureAt
	state.updatedAt = record.UpdatedAt
	state.backoffLevel = record.BackoffLevel
	state.probeSuccesses = record.ProbeSuccesses
	state.probeInFlight = false
	state.probeLeaseID = 0
}

func (b *relayCircuitBreaker) selectable(accountID int64) bool {
	if b == nil || accountID == 0 {
		return true
	}
	now := b.nowTime()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded[accountID] && b.cache == nil {
		b.loaded[accountID] = true
	}
	if !b.loaded[accountID] {
		// The restart fence could not be restored yet. Fail closed for this
		// account until the throttled cache retry succeeds.
		return false
	}
	state := b.states[accountID]
	if state == nil || state.state == RelayCircuitClosed {
		return true
	}
	if state.state == RelayCircuitOpen {
		return !state.openUntil.After(now) && !state.probeInFlight
	}
	return !state.probeInFlight
}

func (b *relayCircuitBreaker) begin(accountID int64) (RelayCircuitPermit, bool) {
	if b == nil || accountID == 0 {
		return RelayCircuitPermit{}, false
	}
	now := b.nowTime()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded[accountID] && b.cache == nil {
		b.loaded[accountID] = true
	}
	if !b.loaded[accountID] {
		return RelayCircuitPermit{}, false
	}
	state := b.stateLocked(accountID)
	if state.generation == 0 {
		state.generation = 1
	}

	switch state.state {
	case RelayCircuitOpen:
		if state.openUntil.After(now) {
			return RelayCircuitPermit{}, false
		}
		state.state = RelayCircuitHalfOpen
		state.probeInFlight = false
		state.probeLeaseID = 0
		state.updatedAt = now
		state.revision++
		log.Printf("[Relay circuit account=%d] entering half-open recovery", accountID)
	case RelayCircuitHalfOpen:
		// handled below
	default:
		return b.issuePermitLocked(accountID, state.generation, false), true
	}

	if state.probeInFlight {
		return RelayCircuitPermit{}, false
	}
	permit := b.issuePermitLocked(accountID, state.generation, true)
	state.probeInFlight = true
	state.probeLeaseID = permit.LeaseID
	state.updatedAt = now
	return permit, true
}

func (b *relayCircuitBreaker) issuePermitLocked(accountID int64, generation uint64, probe bool) RelayCircuitPermit {
	b.nextLease++
	if b.nextLease == 0 {
		b.nextLease++
	}
	permit := RelayCircuitPermit{
		AccountID:  accountID,
		Generation: generation,
		LeaseID:    b.nextLease,
		Probe:      probe,
		Active:     true,
	}
	b.permits[permit.LeaseID] = permit
	return permit
}

func (b *relayCircuitBreaker) consumePermitLocked(permit RelayCircuitPermit) bool {
	if !permit.Active || permit.AccountID == 0 || permit.LeaseID == 0 {
		return false
	}
	issued, ok := b.permits[permit.LeaseID]
	if !ok || issued.AccountID != permit.AccountID || issued.Generation != permit.Generation || issued.Probe != permit.Probe {
		return false
	}
	delete(b.permits, permit.LeaseID)
	return true
}

func (b *relayCircuitBreaker) clearAccountPermitsLocked(accountID int64) {
	for leaseID, permit := range b.permits {
		if permit.AccountID == accountID {
			delete(b.permits, leaseID)
		}
	}
}

// IsRelayStrongGatewayFailureStatus is the shared definition used by both the
// breaker and proxy retry policy. Cloudflare's non-standard gateway/origin
// failures must behave like 502/504; otherwise a dead Relay path can remain the
// highest-priority account for minutes.
func IsRelayStrongGatewayFailureStatus(statusCode int) bool {
	return statusCode == 502 || statusCode == 504 ||
		(statusCode >= 520 && statusCode <= 527) || statusCode == 530
}

// IsRelayCircuitFailureStatus reports every HTTP status owned by this breaker.
func IsRelayCircuitFailureStatus(statusCode int) bool {
	return IsRelayStrongGatewayFailureStatus(statusCode) || statusCode == 500 || statusCode == 503
}

func relayCircuitFailure(statusCode int) (strong bool, weak bool) {
	if IsRelayStrongGatewayFailureStatus(statusCode) {
		return true, false
	}
	return false, statusCode == 500 || statusCode == 503
}

func relayCircuitReason(statusCode int) string {
	if statusCode > 0 {
		return "upstream_http_" + strconv.Itoa(statusCode)
	}
	return "upstream_server_failure"
}

func (b *relayCircuitBreaker) openLocked(accountID int64, state *relayCircuitAccountState, now time.Time, statusCode int, recoveryFailure bool) {
	duration := relayCircuitInitialOpen
	if recoveryFailure {
		idx := state.backoffLevel
		if idx < 0 {
			idx = 0
		}
		if idx >= len(relayCircuitReopenBackoffs) {
			idx = len(relayCircuitReopenBackoffs) - 1
		}
		duration = relayCircuitReopenBackoffs[idx]
		if state.backoffLevel < len(relayCircuitReopenBackoffs) {
			state.backoffLevel++
		}
	} else {
		state.backoffLevel = 0
	}
	state.state = RelayCircuitOpen
	b.clearAccountPermitsLocked(accountID)
	state.generation++
	if state.generation == 0 {
		state.generation = 1
	}
	state.revision++
	state.reason = relayCircuitReason(statusCode)
	state.lastStatusCode = statusCode
	state.openedAt = now
	state.openUntil = now.Add(duration)
	state.lastFailureAt = now
	state.updatedAt = now
	state.weakFailureTimes = nil
	state.probeInFlight = false
	state.probeLeaseID = 0
	state.probeSuccesses = 0
	log.Printf("[Relay circuit account=%d] opened after HTTP %d; recovery_failure=%t open_until=%s generation=%d", accountID, statusCode, recoveryFailure, state.openUntil.Format(time.RFC3339), state.generation)
}

func (b *relayCircuitBreaker) reportFailure(permit RelayCircuitPermit, statusCode int) bool {
	strong, weak := relayCircuitFailure(statusCode)
	if b == nil || !permit.Active || permit.AccountID == 0 || (!strong && !weak) {
		return false
	}
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	persist := false

	b.mu.Lock()
	if !b.loaded[permit.AccountID] {
		b.mu.Unlock()
		return false
	}
	state := b.stateLocked(permit.AccountID)
	if !b.consumePermitLocked(permit) {
		b.mu.Unlock()
		return false
	}
	if permit.Generation != state.generation {
		b.mu.Unlock()
		return false
	}
	if permit.Probe {
		if state.state != RelayCircuitHalfOpen || !state.probeInFlight || state.probeLeaseID != permit.LeaseID {
			b.mu.Unlock()
			return false
		}
		b.openLocked(permit.AccountID, state, now, statusCode, true)
		revision, record = state.revision, relayCircuitRecordFromState(state)
		persist = true
		b.mu.Unlock()
		b.persistIfCurrent(permit.AccountID, revision, record, false)
		return true
	}
	if state.state != RelayCircuitClosed {
		b.mu.Unlock()
		return false
	}

	if strong {
		b.openLocked(permit.AccountID, state, now, statusCode, false)
		revision, record = state.revision, relayCircuitRecordFromState(state)
		persist = true
	} else {
		cutoff := now.Add(-relayCircuitWeakWindow)
		kept := state.weakFailureTimes[:0]
		for _, failedAt := range state.weakFailureTimes {
			if !failedAt.Before(cutoff) {
				kept = append(kept, failedAt)
			}
		}
		state.weakFailureTimes = append(kept, now)
		state.lastFailureAt = now
		state.lastStatusCode = statusCode
		state.reason = relayCircuitReason(statusCode)
		state.updatedAt = now
		if len(state.weakFailureTimes) >= relayCircuitWeakFailureLimit {
			b.openLocked(permit.AccountID, state, now, statusCode, false)
			revision, record = state.revision, relayCircuitRecordFromState(state)
			persist = true
		}
	}
	b.mu.Unlock()
	if persist {
		b.persistIfCurrent(permit.AccountID, revision, record, false)
	}
	return persist
}

func (b *relayCircuitBreaker) reportSuccess(permit RelayCircuitPermit) bool {
	if b == nil || !permit.Active || permit.AccountID == 0 {
		return false
	}
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	var closeCircuit bool
	var persist bool

	b.mu.Lock()
	if !b.loaded[permit.AccountID] {
		b.mu.Unlock()
		return false
	}
	state := b.stateLocked(permit.AccountID)
	if !b.consumePermitLocked(permit) {
		b.mu.Unlock()
		return false
	}
	if permit.Generation != state.generation {
		b.mu.Unlock()
		return false
	}
	if !permit.Probe {
		// Normal successes do not reset the 30-second weak-failure window, and
		// cannot close a circuit opened by a newer in-flight failure.
		b.mu.Unlock()
		return false
	}
	if state.state != RelayCircuitHalfOpen || !state.probeInFlight || state.probeLeaseID != permit.LeaseID {
		b.mu.Unlock()
		return false
	}

	state.probeInFlight = false
	state.probeLeaseID = 0
	state.probeSuccesses++
	state.updatedAt = now
	state.revision++
	if state.probeSuccesses >= relayCircuitRecoverySuccesses {
		state.state = RelayCircuitClosed
		state.generation++
		if state.generation == 0 {
			state.generation = 1
		}
		state.reason = ""
		state.lastStatusCode = 0
		state.openedAt = time.Time{}
		state.openUntil = time.Time{}
		state.backoffLevel = 0
		state.weakFailureTimes = nil
		state.probeSuccesses = 0
		b.clearAccountPermitsLocked(permit.AccountID)
		closeCircuit = true
	} else {
		record = relayCircuitRecordFromState(state)
		persist = true
	}
	revision = state.revision
	b.mu.Unlock()

	if closeCircuit {
		b.persistIfCurrent(permit.AccountID, revision, relayCircuitRuntimeRecord{}, true)
		log.Printf("[Relay circuit account=%d] closed after %d successful recovery probes", permit.AccountID, relayCircuitRecoverySuccesses)
		return true
	}
	if persist {
		b.persistIfCurrent(permit.AccountID, revision, record, false)
		log.Printf("[Relay circuit account=%d] recovery probe succeeded (%d/%d)", permit.AccountID, record.ProbeSuccesses, relayCircuitRecoverySuccesses)
	}
	return false
}

func (b *relayCircuitBreaker) abandon(permit RelayCircuitPermit) bool {
	if b == nil || !permit.Active || permit.AccountID == 0 {
		return false
	}
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord

	b.mu.Lock()
	if !b.loaded[permit.AccountID] {
		b.mu.Unlock()
		return false
	}
	state := b.stateLocked(permit.AccountID)
	if !b.consumePermitLocked(permit) {
		b.mu.Unlock()
		return false
	}
	if !permit.Probe {
		b.mu.Unlock()
		return true
	}
	if permit.Generation != state.generation ||
		state.state != RelayCircuitHalfOpen ||
		!state.probeInFlight ||
		state.probeLeaseID != permit.LeaseID {
		b.mu.Unlock()
		return false
	}
	state.probeInFlight = false
	state.probeLeaseID = 0
	state.updatedAt = now
	state.revision++
	revision, record = state.revision, relayCircuitRecordFromState(state)
	b.mu.Unlock()
	b.persistIfCurrent(permit.AccountID, revision, record, false)
	return true
}

func relayCircuitRecordFromState(state *relayCircuitAccountState) relayCircuitRuntimeRecord {
	if state == nil {
		return relayCircuitRuntimeRecord{}
	}
	return relayCircuitRuntimeRecord{
		State:          state.state,
		Generation:     state.generation,
		Reason:         state.reason,
		LastStatusCode: state.lastStatusCode,
		OpenedAt:       state.openedAt,
		OpenUntil:      state.openUntil,
		LastFailureAt:  state.lastFailureAt,
		UpdatedAt:      state.updatedAt,
		BackoffLevel:   state.backoffLevel,
		ProbeSuccesses: state.probeSuccesses,
	}
}

// persistIfCurrent serializes cache writes and discards stale actions by
// revision. The cache is only a restart fence; it is never used as a live CAS.
func (b *relayCircuitBreaker) persistIfCurrent(accountID int64, revision uint64, record relayCircuitRuntimeRecord, deleteRecord bool) {
	if b == nil || b.cache == nil || accountID == 0 {
		return
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	b.mu.Lock()
	state := b.states[accountID]
	current := state != nil && state.revision == revision
	b.mu.Unlock()
	if !current {
		return
	}
	ctx, cancel := relayCircuitCacheContext()
	defer cancel()
	if deleteRecord {
		if err := b.cache.DeleteRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID)); err != nil {
			log.Printf("[Relay circuit account=%d] delete runtime fence failed: %v", accountID, err)
		}
		return
	}
	payload, err := json.Marshal(record)
	if err != nil {
		log.Printf("[Relay circuit account=%d] encode runtime fence failed: %v", accountID, err)
		return
	}
	if err := b.cache.SetRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID), payload, relayCircuitRuntimeCacheTTL); err != nil {
		log.Printf("[Relay circuit account=%d] persist runtime fence failed: %v", accountID, err)
	}
}

func relayCircuitSnapshotFromState(accountID int64, state *relayCircuitAccountState) RelayCircuitSnapshot {
	snapshot := RelayCircuitSnapshot{
		AccountID:       accountID,
		State:           RelayCircuitClosed,
		RequiredSuccess: relayCircuitRecoverySuccesses,
	}
	if state == nil {
		return snapshot
	}
	snapshot.State = state.state
	snapshot.Generation = state.generation
	snapshot.Reason = state.reason
	snapshot.LastStatusCode = state.lastStatusCode
	snapshot.OpenedAt = state.openedAt
	snapshot.OpenUntil = state.openUntil
	snapshot.LastFailureAt = state.lastFailureAt
	snapshot.UpdatedAt = state.updatedAt
	snapshot.BackoffLevel = state.backoffLevel
	snapshot.WeakFailures = len(state.weakFailureTimes)
	snapshot.ProbeInFlight = state.probeInFlight
	snapshot.ProbeSuccesses = state.probeSuccesses
	return snapshot
}

func (b *relayCircuitBreaker) snapshot(accountID int64) RelayCircuitSnapshot {
	if b == nil || accountID == 0 {
		return relayCircuitSnapshotFromState(accountID, nil)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded[accountID] && b.cache == nil {
		b.loaded[accountID] = true
	}
	if !b.loaded[accountID] {
		return RelayCircuitSnapshot{
			AccountID:       accountID,
			State:           RelayCircuitOpen,
			Reason:          "runtime_fence_restore_pending",
			OpenUntil:       b.retryLoad[accountID],
			RequiredSuccess: relayCircuitRecoverySuccesses,
		}
	}
	return relayCircuitSnapshotFromState(accountID, b.states[accountID])
}

func (b *relayCircuitBreaker) snapshots() []RelayCircuitSnapshot {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	result := make([]RelayCircuitSnapshot, 0, len(b.states))
	for accountID, state := range b.states {
		result = append(result, relayCircuitSnapshotFromState(accountID, state))
	}
	b.mu.Unlock()
	sort.Slice(result, func(i, j int) bool { return result[i].AccountID < result[j].AccountID })
	return result
}

func (s *Store) relayCircuitManager() *relayCircuitBreaker {
	if s == nil {
		return nil
	}
	s.relayCircuitOnce.Do(func() {
		if s.relayCircuit == nil {
			s.relayCircuit = newRelayCircuitBreaker(s.tokenCache)
		}
	})
	return s.relayCircuit
}

// RelayCircuitSelectable is a scheduler fence. It is checked before account
// priority, health tier, score, skip-warm behavior, and concurrency. A newly
// expired open circuit becomes selectable for exactly one permit; callers must
// still call BeginRelayCircuitRequest after selection.
func (s *Store) RelayCircuitSelectable(account *Account) bool {
	if s == nil || account == nil {
		return false
	}
	if !s.isConfiguredRelayCircuitAccount(account) {
		return true
	}
	if !s.RelayGuardianSelectable(account) {
		return false
	}
	return s.relayCircuitManager().selectable(account.DBID)
}

func (s *Store) isConfiguredRelayCircuitAccount(account *Account) bool {
	if s == nil || account == nil || !account.IsOpenAIResponsesAPI() {
		return false
	}
	cfg := s.GetCybRelayConfig()
	return cfg.Enabled && cfg.GroupID > 0 && account.HasGroupID(cfg.GroupID)
}

// BeginRelayCircuitRequest acquires the attempt generation and, in half-open,
// the process-wide single recovery-probe lease. A false result means the
// caller must Release the selected account and choose another one.
func (s *Store) BeginRelayCircuitRequest(account *Account) (RelayCircuitPermit, bool) {
	if !s.isConfiguredRelayCircuitAccount(account) {
		return RelayCircuitPermit{}, false
	}
	permit, ok := s.relayCircuitManager().begin(account.DBID)
	if !ok {
		return RelayCircuitPermit{}, false
	}
	guardian, guardianOK := s.BeginRelayGuardianRequest(account)
	if !guardianOK {
		s.relayCircuitManager().abandon(permit)
		return RelayCircuitPermit{}, false
	}
	permit.Guardian = guardian
	return permit, true
}

// ReportRelayCircuitFailure records only the Relay server statuses owned by
// this breaker: gateway failures (502/504, Cloudflare 520-527/530) open
// immediately; 500/503 open after 3 failures in 30s.
// It returns true when this report transitions the circuit to open.
func (s *Store) ReportRelayCircuitFailure(permit RelayCircuitPermit, statusCode int) bool {
	if s == nil {
		return false
	}
	s.ReportRelayGuardianFailure(permit.Guardian, statusCode)
	return s.relayCircuitManager().reportFailure(permit, statusCode)
}

// ReportRelayCircuitSuccess advances a valid half-open probe. It returns true
// only when the third consecutive probe closes the circuit.
func (s *Store) ReportRelayCircuitSuccess(permit RelayCircuitPermit) bool {
	if s == nil {
		return false
	}
	s.ReportRelayGuardianSuccess(permit.Guardian)
	return s.relayCircuitManager().reportSuccess(permit)
}

// AbandonRelayCircuitRequest releases a half-open lease without counting it as
// success or failure. Handlers should defer this after Begin and then report a
// terminal outcome; the abandon call becomes a no-op after a valid report. It
// prevents client cancellation or an unexpected local exit from wedging the
// single recovery-probe slot indefinitely.
func (s *Store) AbandonRelayCircuitRequest(permit RelayCircuitPermit) bool {
	if s == nil {
		return false
	}
	s.AbandonRelayGuardianRequest(permit.Guardian)
	return s.relayCircuitManager().abandon(permit)
}

func (s *Store) RelayCircuitSnapshot(accountID int64) RelayCircuitSnapshot {
	if s == nil {
		return relayCircuitSnapshotFromState(accountID, nil)
	}
	return s.relayCircuitManager().snapshot(accountID)
}

func (s *Store) RelayCircuitSnapshots() []RelayCircuitSnapshot {
	if s == nil {
		return nil
	}
	return s.relayCircuitManager().snapshots()
}
