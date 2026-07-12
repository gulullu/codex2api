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
	nextLease uint64
	cache     cache.TokenCache
	now       func() time.Time
}

func newRelayCircuitBreaker(tc cache.TokenCache) *relayCircuitBreaker {
	return &relayCircuitBreaker{
		states: make(map[int64]*relayCircuitAccountState),
		loaded: make(map[int64]bool),
		cache:  tc,
		now:    time.Now,
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

// ensureLoaded performs a single best-effort cache read per account. The lock
// deliberately remains held during this one-time read: after a process restart
// no concurrent request may slip through before an existing open fence has
// been restored. Redis is not the concurrency authority because TokenCache has
// no compare-and-swap primitive; the confirmed production topology is one
// scheduler process, and the in-process mutex remains authoritative.
func (b *relayCircuitBreaker) ensureLoaded(accountID int64) {
	if b == nil || accountID == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loaded[accountID] {
		return
	}
	b.loaded[accountID] = true
	if b.cache == nil {
		return
	}

	ctx, cancel := relayCircuitCacheContext()
	defer cancel()
	payload, ok, err := b.cache.GetRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID))
	if err != nil {
		log.Printf("[Relay circuit account=%d] restore runtime fence failed: %v", accountID, err)
		return
	}
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

	now := b.nowTime()
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
	b.ensureLoaded(accountID)
	now := b.nowTime()
	b.mu.Lock()
	defer b.mu.Unlock()
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
	case RelayCircuitHalfOpen:
		// handled below
	default:
		return RelayCircuitPermit{
			AccountID:  accountID,
			Generation: state.generation,
			Active:     true,
		}, true
	}

	if state.probeInFlight {
		return RelayCircuitPermit{}, false
	}
	b.nextLease++
	if b.nextLease == 0 {
		b.nextLease++
	}
	state.probeInFlight = true
	state.probeLeaseID = b.nextLease
	state.updatedAt = now
	return RelayCircuitPermit{
		AccountID:  accountID,
		Generation: state.generation,
		LeaseID:    state.probeLeaseID,
		Probe:      true,
		Active:     true,
	}, true
}

func relayCircuitFailure(statusCode int) (strong bool, weak bool) {
	switch statusCode {
	case 502, 504:
		return true, false
	case 500, 503:
		return false, true
	default:
		return false, false
	}
}

func relayCircuitReason(statusCode int) string {
	if statusCode > 0 {
		return "upstream_http_" + strconv.Itoa(statusCode)
	}
	return "upstream_server_failure"
}

func (b *relayCircuitBreaker) openLocked(state *relayCircuitAccountState, now time.Time, statusCode int, recoveryFailure bool) {
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
}

func (b *relayCircuitBreaker) reportFailure(permit RelayCircuitPermit, statusCode int) bool {
	strong, weak := relayCircuitFailure(statusCode)
	if b == nil || !permit.Active || permit.AccountID == 0 || (!strong && !weak) {
		return false
	}
	b.ensureLoaded(permit.AccountID)
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	persist := false

	b.mu.Lock()
	state := b.stateLocked(permit.AccountID)
	if permit.Generation != state.generation {
		b.mu.Unlock()
		return false
	}
	if permit.Probe {
		if state.state != RelayCircuitHalfOpen || !state.probeInFlight || state.probeLeaseID != permit.LeaseID {
			b.mu.Unlock()
			return false
		}
		b.openLocked(state, now, statusCode, true)
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
		b.openLocked(state, now, statusCode, false)
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
			b.openLocked(state, now, statusCode, false)
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
	b.ensureLoaded(permit.AccountID)
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	var closeCircuit bool
	var persist bool

	b.mu.Lock()
	state := b.stateLocked(permit.AccountID)
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
		closeCircuit = true
	} else {
		record = relayCircuitRecordFromState(state)
		persist = true
	}
	revision = state.revision
	b.mu.Unlock()

	if closeCircuit {
		b.persistIfCurrent(permit.AccountID, revision, relayCircuitRuntimeRecord{}, true)
		return true
	}
	if persist {
		b.persistIfCurrent(permit.AccountID, revision, record, false)
	}
	return false
}

func (b *relayCircuitBreaker) abandon(permit RelayCircuitPermit) bool {
	if b == nil || !permit.Active || !permit.Probe || permit.AccountID == 0 {
		return false
	}
	b.ensureLoaded(permit.AccountID)
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord

	b.mu.Lock()
	state := b.stateLocked(permit.AccountID)
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
	if !account.IsOpenAIResponsesAPI() {
		return true
	}
	return s.relayCircuitManager().selectable(account.DBID)
}

// BeginRelayCircuitRequest acquires the attempt generation and, in half-open,
// the process-wide single recovery-probe lease. A false result means the
// caller must Release the selected account and choose another one.
func (s *Store) BeginRelayCircuitRequest(account *Account) (RelayCircuitPermit, bool) {
	if s == nil || account == nil || !account.IsOpenAIResponsesAPI() {
		return RelayCircuitPermit{}, false
	}
	return s.relayCircuitManager().begin(account.DBID)
}

// ReportRelayCircuitFailure records only the Relay server statuses owned by
// this breaker: 502/504 open immediately; 500/503 open after 3 failures in 30s.
// It returns true when this report transitions the circuit to open.
func (s *Store) ReportRelayCircuitFailure(permit RelayCircuitPermit, statusCode int) bool {
	if s == nil {
		return false
	}
	return s.relayCircuitManager().reportFailure(permit, statusCode)
}

// ReportRelayCircuitSuccess advances a valid half-open probe. It returns true
// only when the third consecutive probe closes the circuit.
func (s *Store) ReportRelayCircuitSuccess(permit RelayCircuitPermit) bool {
	if s == nil {
		return false
	}
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
