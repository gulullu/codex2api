package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/cache"
)

const (
	relayCircuitRuntimeCacheNamespace = "relay-circuit-breaker"
	relayCircuitRuntimeCacheTTL       = 24 * time.Hour
	relayCircuitCacheTimeout          = 300 * time.Millisecond

	relayCircuitStrongWindow             = 5 * time.Second
	relayCircuitStrongFailureLimit       = 3
	relayCircuitStrongPostSuspectLimit   = 2
	relayCircuitWeakWindow               = 30 * time.Second
	relayCircuitWeakFailureLimit         = 5
	relayCircuitWeakFailureRatePercent   = 50
	relayCircuitInitialOpen              = 10 * time.Second
	relayCircuitRecoverySuccesses        = 2
	relayCircuitProbationMaxInFlight     = 3
	relayCircuitSuspectAdmissionPercent  = 25
	relayCircuitSuspectAdmissionMin      = 2
	relayCircuitSuspectAdmissionMax      = 8
	relayCircuitLastResortAdmissionLimit = 2
	relayCircuitMaxWeakObservations      = 16384

	// RelayCircuitTransportFailureStatus is an internal, audit-only status for
	// an upstream connection/TLS/read failure that produced no HTTP response.
	// Proxy handlers must never send it downstream; user-facing mapping remains
	// 502. It shares the strong quorum with gateway/origin failures.
	RelayCircuitTransportFailureStatus = 598
)

var relayCircuitReopenBackoffs = [...]time.Duration{
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
	300 * time.Second,
}

// RelayCircuitState is the externally visible state of a Relay account's
// short-lived upstream circuit breaker.
type RelayCircuitState string

const (
	RelayCircuitClosed    RelayCircuitState = "closed"
	RelayCircuitSuspect   RelayCircuitState = "suspect"
	RelayCircuitOpen      RelayCircuitState = "open"
	RelayCircuitProbation RelayCircuitState = "probation"
	// RelayCircuitHalfOpen is accepted only for runtime records written by rb11.
	// New code publishes probation, which admits up to three concurrent recovery
	// requests instead of serializing the entire front door behind one probe.
	RelayCircuitHalfOpen RelayCircuitState = "half_open"
)

// RelayCircuitPermit identifies one upstream attempt. Callers must acquire a
// permit immediately after Store selects a Relay account and report exactly
// one success or failure with the same value. Generation fences results from
// requests that were already in flight when a newer circuit opened.
type RelayCircuitPermit struct {
	AccountID        int64
	Generation       uint64
	LeaseID          uint64
	LogicalRequestID string
	EvidenceEpoch    uint64
	AdmissionLimit   int
	Probe            bool
	Active           bool
	limited          bool
	Guardian         RelayGuardianPermit
}

// RelayCircuitSnapshot is a read-only admin/audit view. It is intentionally
// separate from Account.Status/CooldownReason so Relay server failures cannot
// overwrite the existing 401/429/usage cooldown slot.
type RelayCircuitSnapshot struct {
	AccountID           int64             `json:"account_id"`
	State               RelayCircuitState `json:"state"`
	Generation          uint64            `json:"generation"`
	Reason              string            `json:"reason,omitempty"`
	LastStatusCode      int               `json:"last_status_code,omitempty"`
	OpenedAt            time.Time         `json:"opened_at,omitempty"`
	OpenUntil           time.Time         `json:"open_until,omitempty"`
	LastFailureAt       time.Time         `json:"last_failure_at,omitempty"`
	UpdatedAt           time.Time         `json:"updated_at,omitempty"`
	BackoffLevel        int               `json:"backoff_level"`
	WeakFailures        int               `json:"weak_failures"`
	WeakSamples         int               `json:"weak_samples"`
	StrongFailures      int               `json:"strong_failures"`
	PostSuspectFailures int               `json:"post_suspect_failures"`
	ProbeInFlight       bool              `json:"probe_in_flight"`
	ProbeSuccesses      int               `json:"probe_successes"`
	RequiredSuccess     int               `json:"required_successes"`
	AdmissionLimit      int               `json:"admission_limit"`
	// InFlight is the current suspect/probation admission cohort. Total
	// physical account concurrency remains Account.ActiveRequests.
	InFlight      int    `json:"in_flight"`
	LastResort    bool   `json:"last_resort"`
	EvidenceEpoch uint64 `json:"evidence_epoch"`
	// confirmedStrongCycleToken is process-local evidence that a strong gateway
	// failure cohort reached the breaker's confirmation boundary. It is kept out
	// of JSON/runtime persistence deliberately: a restart must collect fresh
	// evidence and Guardian cold-start protection owns that boundary.
	confirmedStrongCycleToken uint64
}

type relayCircuitRuntimeRecord struct {
	State          RelayCircuitState `json:"state"`
	Generation     uint64            `json:"generation"`
	Reason         string            `json:"reason,omitempty"`
	LastStatusCode int               `json:"last_status_code,omitempty"`
	OpenedAt       time.Time         `json:"opened_at,omitempty"`
	OpenUntil      time.Time         `json:"open_until,omitempty"`
	LastFailureAt  time.Time         `json:"last_failure_at,omitempty"`
	SuspectAt      time.Time         `json:"suspect_at,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at,omitempty"`
	BackoffLevel   int               `json:"backoff_level"`
	ProbeSuccesses int               `json:"probe_successes,omitempty"`
	AdmissionLimit int               `json:"admission_limit,omitempty"`
	LastResort     bool              `json:"last_resort,omitempty"`
	EvidenceEpoch  uint64            `json:"evidence_epoch,omitempty"`
	// IdentityFingerprint binds a persisted breaker decision to the actual
	// Relay front door configuration without storing credentials in plaintext.
	IdentityFingerprint string `json:"identity_fingerprint,omitempty"`
}

type relayCircuitStrongEvidence struct {
	at               time.Time
	logicalRequestID string
	evidenceEpoch    uint64
}

type relayCircuitWeakObservation struct {
	at               time.Time
	logicalRequestID string
	failure          bool
}

type relayCircuitAccountState struct {
	state               RelayCircuitState
	generation          uint64
	revision            uint64
	reason              string
	lastStatusCode      int
	openedAt            time.Time
	openUntil           time.Time
	lastFailureAt       time.Time
	suspectAt           time.Time
	updatedAt           time.Time
	backoffLevel        int
	evidenceEpoch       uint64
	admissionLimit      int
	inFlight            int
	limitedInFlight     int
	lastResort          bool
	identityFingerprint string
	// confirmedStrongCycleToken advances only through confirmFailureLocked for
	// a strong gateway status. The general generation also changes for scheduler
	// state transitions such as pool-invariant last-resort promotion, so it must
	// not be used as proof of an independent confirmed failure cycle.
	confirmedStrongCycleToken uint64

	strongEvidence      []relayCircuitStrongEvidence
	weakObservations    []relayCircuitWeakObservation
	weakObservationHead int
	weakSeen            map[string]time.Time

	probeInFlight  bool
	probeLeaseID   uint64
	probeSuccesses int
}

type relayCircuitIssuedPermit struct {
	permit     RelayCircuitPermit
	poolFilter AccountFilter
}

type relayCircuitBreaker struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	states    map[int64]*relayCircuitAccountState
	loaded    map[int64]bool
	loading   map[int64]uint64
	retryLoad map[int64]time.Time
	permits   map[uint64]relayCircuitIssuedPermit
	nextLease uint64
	nextLoad  uint64
	cache     cache.TokenCache
	now       func() time.Time
}

func newRelayCircuitBreaker(tc cache.TokenCache) *relayCircuitBreaker {
	return &relayCircuitBreaker{
		states:    make(map[int64]*relayCircuitAccountState),
		loaded:    make(map[int64]bool),
		loading:   make(map[int64]uint64),
		retryLoad: make(map[int64]time.Time),
		permits:   make(map[uint64]relayCircuitIssuedPermit),
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

// relayCircuitAccountIdentityFingerprint changes only when the upstream
// transport identity changes. Operator-facing renames and model-list edits do
// not erase valid health evidence, while endpoint/key/proxy/header changes do.
// Only the SHA-256 digest is persisted; credentials never enter logs or cache
// records in plaintext.
func relayCircuitAccountIdentityFingerprint(account *Account) string {
	if account == nil {
		return ""
	}
	account.mu.RLock()
	parts := []string{
		strings.ToLower(strings.TrimSpace(account.UpstreamType)),
		strings.TrimRight(strings.TrimSpace(account.BaseURL), "/"),
		strings.TrimSpace(account.APIKey),
		strings.TrimSpace(account.ProxyURL),
		NormalizeCodexClientMetadataMode(account.CodexClientMetadataMode),
	}
	headerParts := make([]string, 0, len(account.CustomHeaders))
	for key, value := range account.CustomHeaders {
		headerParts = append(headerParts, strings.ToLower(strings.TrimSpace(key))+"="+strings.TrimSpace(value))
	}
	account.mu.RUnlock()
	sort.Strings(headerParts)
	parts = append(parts, headerParts...)
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// forgetAccountRuntime is the membership/config-identity boundary fence. It
// serializes with persistence, removes old permits, advances both revision and
// generation, and deletes (or safely overwrites) the restart fence. Late
// completions from the old front can therefore neither mutate memory nor
// resurrect the old record in Redis.
func (b *relayCircuitBreaker) forgetAccountRuntime(accountID int64, identityFingerprint string) {
	if b == nil || accountID <= 0 {
		return
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	now := b.nowTime()
	b.mu.Lock()
	oldRevision := uint64(0)
	nextGeneration := uint64(1)
	confirmedStrongCycleToken := uint64(0)
	if old := b.states[accountID]; old != nil {
		oldRevision = old.revision
		nextGeneration = old.generation + 1
		// Guardian intentionally retains history across some breaker-only
		// boundaries (for example delete/re-add of the same DB id). Preserve the
		// process-local token so a later confirmed cycle cannot reuse an already
		// observed value and disappear from that retained history.
		confirmedStrongCycleToken = old.confirmedStrongCycleToken
		if nextGeneration == 0 {
			nextGeneration = 1
		}
	}
	for leaseID, issued := range b.permits {
		if issued.permit.AccountID == accountID {
			delete(b.permits, leaseID)
		}
	}
	state := &relayCircuitAccountState{
		state:                     RelayCircuitClosed,
		generation:                nextGeneration,
		revision:                  oldRevision + 1,
		updatedAt:                 now,
		identityFingerprint:       identityFingerprint,
		confirmedStrongCycleToken: confirmedStrongCycleToken,
		weakSeen:                  make(map[string]time.Time),
	}
	if state.revision == 0 {
		state.revision = 1
	}
	b.states[accountID] = state
	b.loaded[accountID] = true
	delete(b.loading, accountID)
	delete(b.retryLoad, accountID)
	// Capture the immutable fallback before releasing b.mu. Requests admitted
	// after this reset may immediately mutate the newly published state while
	// the cache delete is still in flight.
	tombstone := relayCircuitRecordFromState(state)
	b.mu.Unlock()

	if b.cache == nil {
		return
	}
	ctx, cancel := relayCircuitCacheContext()
	err := b.cache.DeleteRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID))
	cancel()
	if err == nil {
		return
	}
	// If delete fails, a durable closed tombstone is safer than leaving the
	// stale open/last-resort record available to the next process.
	payload, marshalErr := json.Marshal(tombstone)
	if marshalErr == nil {
		ctx, cancel = relayCircuitCacheContext()
		setErr := b.cache.SetRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID), payload, relayCircuitRuntimeCacheTTL)
		cancel()
		if setErr == nil {
			return
		}
		log.Printf("[Relay circuit account=%d] reset runtime fence failed: delete=%v; overwrite=%v", accountID, err, setErr)
		return
	}
	log.Printf("[Relay circuit account=%d] reset runtime fence failed: delete=%v; encode=%v", accountID, err, marshalErr)
}

func (b *relayCircuitBreaker) stateLocked(accountID int64) *relayCircuitAccountState {
	state := b.states[accountID]
	if state == nil {
		state = &relayCircuitAccountState{state: RelayCircuitClosed, weakSeen: make(map[string]time.Time)}
		b.states[accountID] = state
	} else if state.weakSeen == nil {
		state.weakSeen = make(map[string]time.Time)
	}
	return state
}

func relayCircuitSuspectAdmissionLimit(normalLimit int) int {
	limit := (normalLimit*relayCircuitSuspectAdmissionPercent + 99) / 100
	if limit < relayCircuitSuspectAdmissionMin {
		limit = relayCircuitSuspectAdmissionMin
	}
	if limit > relayCircuitSuspectAdmissionMax {
		limit = relayCircuitSuspectAdmissionMax
	}
	return limit
}

func relayCircuitLogicalEvidenceID(permit RelayCircuitPermit) string {
	if id := strings.TrimSpace(permit.LogicalRequestID); id != "" {
		return id
	}
	return "lease:" + strconv.FormatUint(permit.LeaseID, 10)
}

func (b *relayCircuitBreaker) advanceTimeLocked(state *relayCircuitAccountState, now time.Time) {
	if state == nil {
		return
	}
	if state.state == RelayCircuitHalfOpen {
		state.state = RelayCircuitProbation
		state.admissionLimit = relayCircuitProbationMaxInFlight
		if state.probeInFlight && state.limitedInFlight == 0 {
			state.limitedInFlight = 1
		}
	}
	if state.state == RelayCircuitOpen && !state.openUntil.After(now) {
		state.state = RelayCircuitProbation
		state.admissionLimit = relayCircuitProbationMaxInFlight
		state.limitedInFlight = 0
		state.probeInFlight = false
		state.updatedAt = now
		state.revision++
	}
	suspectAt := state.suspectAt
	if suspectAt.IsZero() {
		suspectAt = state.lastFailureAt
	}
	if state.state == RelayCircuitSuspect && !state.lastResort && !suspectAt.IsZero() && now.Sub(suspectAt) > relayCircuitStrongWindow {
		b.closeSuspectLocked(state, now)
	}
}

func (b *relayCircuitBreaker) closeSuspectLocked(state *relayCircuitAccountState, now time.Time) {
	if state == nil {
		return
	}
	state.state = RelayCircuitClosed
	state.reason = ""
	state.lastStatusCode = 0
	state.openedAt = time.Time{}
	state.openUntil = time.Time{}
	state.suspectAt = time.Time{}
	state.strongEvidence = nil
	state.admissionLimit = 0
	state.limitedInFlight = 0
	state.lastResort = false
	state.probeSuccesses = 0
	state.updatedAt = now
	state.generation++
	if state.generation == 0 {
		state.generation = 1
	}
	state.revision++
}

func (b *relayCircuitBreaker) enterSuspectLocked(state *relayCircuitAccountState, now time.Time, statusCode, admissionLimit int) {
	if state == nil {
		return
	}
	state.state = RelayCircuitSuspect
	state.evidenceEpoch++
	if state.evidenceEpoch == 0 {
		state.evidenceEpoch = 1
	}
	state.reason = relayCircuitReason(statusCode)
	state.lastStatusCode = statusCode
	state.lastFailureAt = now
	state.suspectAt = now
	state.updatedAt = now
	state.strongEvidence = nil
	state.admissionLimit = admissionLimit
	state.limitedInFlight = 0
	if state.admissionLimit <= 0 {
		state.admissionLimit = relayCircuitSuspectAdmissionMin
	}
	state.lastResort = false
	state.probeSuccesses = 0
	state.revision++
}

func (b *relayCircuitBreaker) pruneStrongEvidenceLocked(state *relayCircuitAccountState, now time.Time) {
	if state == nil || len(state.strongEvidence) == 0 {
		return
	}
	cutoff := now.Add(-relayCircuitStrongWindow)
	kept := state.strongEvidence[:0]
	for _, evidence := range state.strongEvidence {
		if !evidence.at.Before(cutoff) {
			kept = append(kept, evidence)
		}
	}
	state.strongEvidence = kept
}

func (b *relayCircuitBreaker) addStrongEvidenceLocked(state *relayCircuitAccountState, permit RelayCircuitPermit, now time.Time) {
	if state == nil {
		return
	}
	b.pruneStrongEvidenceLocked(state, now)
	id := relayCircuitLogicalEvidenceID(permit)
	for _, evidence := range state.strongEvidence {
		if evidence.logicalRequestID == id {
			return
		}
	}
	state.strongEvidence = append(state.strongEvidence, relayCircuitStrongEvidence{
		at: now, logicalRequestID: id, evidenceEpoch: permit.EvidenceEpoch,
	})
}

func relayCircuitStrongCounts(state *relayCircuitAccountState) (total, postSuspect int) {
	if state == nil {
		return 0, 0
	}
	for _, evidence := range state.strongEvidence {
		total++
		if evidence.evidenceEpoch == state.evidenceEpoch {
			postSuspect++
		}
	}
	return total, postSuspect
}

func (b *relayCircuitBreaker) pruneWeakObservationsLocked(state *relayCircuitAccountState, now time.Time) {
	if state == nil {
		return
	}
	cutoff := now.Add(-relayCircuitWeakWindow)
	for state.weakObservationHead < len(state.weakObservations) && state.weakObservations[state.weakObservationHead].at.Before(cutoff) {
		old := state.weakObservations[state.weakObservationHead]
		if seenAt, ok := state.weakSeen[old.logicalRequestID]; ok && seenAt.Equal(old.at) {
			delete(state.weakSeen, old.logicalRequestID)
		}
		state.weakObservationHead++
	}
	if state.weakObservationHead > 1024 && state.weakObservationHead*2 > len(state.weakObservations) {
		state.weakObservations = append([]relayCircuitWeakObservation(nil), state.weakObservations[state.weakObservationHead:]...)
		state.weakObservationHead = 0
	}
}

func (b *relayCircuitBreaker) addWeakObservationLocked(state *relayCircuitAccountState, permit RelayCircuitPermit, now time.Time, failure bool) {
	if state == nil {
		return
	}
	b.pruneWeakObservationsLocked(state, now)
	id := relayCircuitLogicalEvidenceID(permit)
	if _, exists := state.weakSeen[id]; exists {
		return
	}
	for len(state.weakObservations)-state.weakObservationHead >= relayCircuitMaxWeakObservations {
		old := state.weakObservations[state.weakObservationHead]
		delete(state.weakSeen, old.logicalRequestID)
		state.weakObservationHead++
	}
	observation := relayCircuitWeakObservation{at: now, logicalRequestID: id, failure: failure}
	state.weakObservations = append(state.weakObservations, observation)
	state.weakSeen[id] = now
}

func relayCircuitWeakCounts(state *relayCircuitAccountState) (samples, failures int) {
	if state == nil {
		return 0, 0
	}
	for i := state.weakObservationHead; i < len(state.weakObservations); i++ {
		samples++
		if state.weakObservations[i].failure {
			failures++
		}
	}
	return samples, failures
}

// ensureLoaded is called only by startup/reconcile/admin-safe preload paths.
// The cache read stays outside b.mu so request selection can immediately fail
// closed while restoration is in flight instead of waiting behind Redis I/O.
func (b *relayCircuitBreaker) ensureLoaded(accountID int64) {
	b.ensureLoadedWithIdentity(accountID, "")
}

func (b *relayCircuitBreaker) ensureLoadedForAccount(account *Account) {
	if account == nil {
		return
	}
	b.ensureLoadedWithIdentity(account.DBID, relayCircuitAccountIdentityFingerprint(account))
}

func (b *relayCircuitBreaker) ensureLoadedWithIdentity(accountID int64, identityFingerprint string) {
	if b == nil || accountID == 0 {
		return
	}
	b.mu.Lock()
	if b.loaded[accountID] {
		state := b.stateLocked(accountID)
		if identityFingerprint != "" && state.identityFingerprint == "" {
			state.identityFingerprint = identityFingerprint
		}
		identityChanged := identityFingerprint != "" && state.identityFingerprint != "" &&
			state.identityFingerprint != identityFingerprint
		b.mu.Unlock()
		if identityChanged {
			b.forgetAccountRuntime(accountID, identityFingerprint)
		}
		return
	}
	if b.loading[accountID] != 0 {
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
		b.stateLocked(accountID).identityFingerprint = identityFingerprint
		b.mu.Unlock()
		return
	}
	b.nextLoad++
	if b.nextLoad == 0 {
		b.nextLoad++
	}
	loadToken := b.nextLoad
	b.loading[accountID] = loadToken
	b.mu.Unlock()

	ctx, cancel := relayCircuitCacheContext()
	payload, ok, err := b.cache.GetRuntime(ctx, relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(accountID))
	cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	// A membership/config reset invalidates an in-flight restore. Its old cache
	// result must never revive a stale open/last-resort state after the reset.
	if b.loading[accountID] != loadToken {
		return
	}
	delete(b.loading, accountID)
	if err != nil {
		// A transient cache error must not permanently disable restart fencing.
		// Throttle retries so a cache outage cannot add 300 ms to every scheduler
		// pass for the same account.
		b.retryLoad[accountID] = now.Add(time.Second)
		log.Printf("[Relay circuit account=%d] restore runtime fence failed: %v", accountID, err)
		return
	}
	if !ok || len(payload) == 0 {
		b.loaded[accountID] = true
		b.stateLocked(accountID).identityFingerprint = identityFingerprint
		delete(b.retryLoad, accountID)
		return
	}
	var record relayCircuitRuntimeRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		b.retryLoad[accountID] = now.Add(5 * time.Second)
		log.Printf("[Relay circuit account=%d] decode runtime fence failed: %v", accountID, err)
		return
	}
	if identityFingerprint != "" && record.IdentityFingerprint != "" && record.IdentityFingerprint != identityFingerprint {
		b.loaded[accountID] = true
		delete(b.retryLoad, accountID)
		state := b.stateLocked(accountID)
		oldRevision := state.revision
		confirmedStrongCycleToken := state.confirmedStrongCycleToken
		*state = relayCircuitAccountState{
			state:                     RelayCircuitClosed,
			generation:                record.Generation + 1,
			revision:                  oldRevision + 1,
			updatedAt:                 now,
			identityFingerprint:       identityFingerprint,
			confirmedStrongCycleToken: confirmedStrongCycleToken,
			weakSeen:                  make(map[string]time.Time),
		}
		if state.generation == 0 {
			state.generation = 1
		}
		if state.revision == 0 {
			state.revision = 1
		}
		revision := state.revision
		go b.persistIfCurrent(accountID, revision, relayCircuitRuntimeRecord{}, true)
		return
	}
	if record.State == RelayCircuitClosed {
		b.loaded[accountID] = true
		b.stateLocked(accountID).identityFingerprint = identityFingerprint
		delete(b.retryLoad, accountID)
		return
	}
	if record.State != RelayCircuitOpen && record.State != RelayCircuitHalfOpen && record.State != RelayCircuitProbation && record.State != RelayCircuitSuspect {
		b.retryLoad[accountID] = now.Add(5 * time.Second)
		log.Printf("[Relay circuit account=%d] invalid runtime fence state %q", accountID, record.State)
		return
	}
	b.loaded[accountID] = true
	delete(b.retryLoad, accountID)

	state := b.stateLocked(accountID)
	state.identityFingerprint = identityFingerprint
	if state.identityFingerprint == "" {
		state.identityFingerprint = record.IdentityFingerprint
	}
	state.state = record.State
	// Durable last-resort is encoded as legacy half_open for rollback safety,
	// but rb12 must restore its original suspect semantics (one newly admitted
	// success clears it). Ordinary legacy half_open still becomes probation.
	if record.LastResort {
		state.state = RelayCircuitSuspect
	}
	// A suspect record contains no durable per-request evidence and must never
	// revive as a restriction after restart. Old half_open records are upgraded
	// to the bounded-concurrency probation state.
	discardRuntimeRecord := state.state == RelayCircuitSuspect && !record.LastResort
	if discardRuntimeRecord {
		state.state = RelayCircuitClosed
	}
	if state.state == RelayCircuitHalfOpen || (state.state == RelayCircuitOpen && !record.OpenUntil.After(now)) {
		state.state = RelayCircuitProbation
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
	state.suspectAt = record.SuspectAt
	state.updatedAt = record.UpdatedAt
	state.backoffLevel = record.BackoffLevel
	state.probeSuccesses = record.ProbeSuccesses
	state.admissionLimit = record.AdmissionLimit
	state.lastResort = record.LastResort
	state.evidenceEpoch = record.EvidenceEpoch
	if state.state == RelayCircuitClosed {
		state.reason = ""
		state.lastStatusCode = 0
		state.admissionLimit = 0
		state.lastResort = false
	}
	if state.state == RelayCircuitProbation {
		state.admissionLimit = relayCircuitProbationMaxInFlight
	}
	if state.lastResort {
		state.admissionLimit = relayCircuitLastResortAdmissionLimit
	}
	state.probeInFlight = false
	state.probeLeaseID = 0
	state.inFlight = 0
	state.limitedInFlight = 0
	if state.state == RelayCircuitProbation && state.probeSuccesses >= relayCircuitRecoverySuccesses {
		discardRuntimeRecord = b.closeProbationIfReadyLocked(state, now)
	}
	if discardRuntimeRecord {
		// Delete non-durable suspect records and already-satisfied legacy recovery
		// records after releasing b.mu. The revision fence prevents this cleanup
		// from racing a newer confirmed-open persistence action.
		revision := state.revision
		go b.persistIfCurrent(accountID, revision, relayCircuitRuntimeRecord{}, true)
	}
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
	state := b.stateLocked(accountID)
	b.advanceTimeLocked(state, now)
	if b.closeProbationIfReadyLocked(state, now) {
		revision := state.revision
		go b.persistIfCurrent(accountID, revision, relayCircuitRuntimeRecord{}, true)
	}
	switch state.state {
	case RelayCircuitOpen:
		return false
	case RelayCircuitSuspect, RelayCircuitProbation:
		limit := state.admissionLimit
		if state.lastResort {
			limit = relayCircuitLastResortAdmissionLimit
		}
		return limit > 0 && state.limitedInFlight < limit
	default:
		return true
	}
}

func (b *relayCircuitBreaker) begin(accountID int64) (RelayCircuitPermit, bool) {
	return b.beginWithEvidence(accountID, "", relayCircuitSuspectAdmissionMax*4)
}

func (b *relayCircuitBreaker) beginWithEvidence(accountID int64, logicalRequestID string, normalLimit int) (RelayCircuitPermit, bool) {
	return b.beginWithEvidenceAndFilter(accountID, logicalRequestID, normalLimit, nil)
}

func (b *relayCircuitBreaker) beginWithEvidenceAndFilter(accountID int64, logicalRequestID string, normalLimit int, poolFilter AccountFilter) (RelayCircuitPermit, bool) {
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
	b.advanceTimeLocked(state, now)
	if b.closeProbationIfReadyLocked(state, now) {
		revision := state.revision
		go b.persistIfCurrent(accountID, revision, relayCircuitRuntimeRecord{}, true)
	}
	if state.generation == 0 {
		state.generation = 1
	}

	switch state.state {
	case RelayCircuitOpen:
		return RelayCircuitPermit{}, false
	case RelayCircuitSuspect, RelayCircuitProbation:
		limit := state.admissionLimit
		if state.lastResort {
			limit = relayCircuitLastResortAdmissionLimit
		}
		if limit <= 0 || state.limitedInFlight >= limit {
			return RelayCircuitPermit{}, false
		}
		probe := state.state == RelayCircuitProbation
		permit := b.issuePermitLocked(accountID, state.generation, logicalRequestID, state.evidenceEpoch, limit, probe, true, poolFilter)
		state.inFlight++
		state.limitedInFlight++
		state.probeInFlight = probe && state.limitedInFlight > 0
		state.updatedAt = now
		return permit, true
	default:
		limit := relayCircuitSuspectAdmissionLimit(normalLimit)
		permit := b.issuePermitLocked(accountID, state.generation, logicalRequestID, state.evidenceEpoch, limit, false, false, poolFilter)
		state.inFlight++
		return permit, true
	}
}

func (b *relayCircuitBreaker) issuePermitLocked(accountID int64, generation uint64, logicalRequestID string, evidenceEpoch uint64, admissionLimit int, probe, limited bool, poolFilter AccountFilter) RelayCircuitPermit {
	b.nextLease++
	if b.nextLease == 0 {
		b.nextLease++
	}
	permit := RelayCircuitPermit{
		AccountID:        accountID,
		Generation:       generation,
		LeaseID:          b.nextLease,
		LogicalRequestID: strings.TrimSpace(logicalRequestID),
		EvidenceEpoch:    evidenceEpoch,
		AdmissionLimit:   admissionLimit,
		Probe:            probe,
		Active:           true,
		limited:          limited,
	}
	b.permits[permit.LeaseID] = relayCircuitIssuedPermit{permit: permit, poolFilter: poolFilter}
	return permit
}

// permitPoolFilter returns the filter captured by the server-issued permit,
// never a caller-supplied copy. ReportRelayCircuitFailure uses it to decide
// whether another front door can serve the same model and Relay traffic class
// before fully opening the current one. Session-owner affinity is deliberately
// excluded: a non-replayable continuation cannot be rescued in the current
// logical request, while isolating its repeatedly failing owner protects other
// traffic that the healthy peer can serve.
func (b *relayCircuitBreaker) permitPoolFilter(permit RelayCircuitPermit) (AccountFilter, bool) {
	if b == nil || !permit.Active || permit.AccountID == 0 || permit.LeaseID == 0 {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	issued, ok := b.permits[permit.LeaseID]
	if !ok || issued.permit.AccountID != permit.AccountID || issued.permit.Generation != permit.Generation || issued.permit.Probe != permit.Probe {
		return nil, false
	}
	return issued.poolFilter, true
}

func (b *relayCircuitBreaker) consumePermitLocked(permit RelayCircuitPermit) (RelayCircuitPermit, bool) {
	if !permit.Active || permit.AccountID == 0 || permit.LeaseID == 0 {
		return RelayCircuitPermit{}, false
	}
	issuedRecord, ok := b.permits[permit.LeaseID]
	if !ok || issuedRecord.permit.AccountID != permit.AccountID || issuedRecord.permit.Generation != permit.Generation || issuedRecord.permit.Probe != permit.Probe {
		return RelayCircuitPermit{}, false
	}
	delete(b.permits, permit.LeaseID)
	issued := issuedRecord.permit
	if state := b.states[permit.AccountID]; state != nil {
		if state.inFlight > 0 {
			state.inFlight--
		}
		if issued.limited && issued.Generation == state.generation && state.limitedInFlight > 0 {
			state.limitedInFlight--
		}
		state.probeInFlight = (state.state == RelayCircuitProbation || state.state == RelayCircuitHalfOpen) && state.limitedInFlight > 0
	}
	return issued, true
}

// IsRelayStrongGatewayFailureStatus is the shared definition used by both the
// breaker and proxy retry policy. Cloudflare's non-standard gateway/origin
// failures must behave like 502/504; otherwise a dead Relay path can remain the
// highest-priority account for minutes.
func IsRelayStrongGatewayFailureStatus(statusCode int) bool {
	return statusCode == RelayCircuitTransportFailureStatus || statusCode == 502 || statusCode == 504 ||
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
	if statusCode == RelayCircuitTransportFailureStatus {
		return "upstream_transport_failure"
	}
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
	state.suspectAt = time.Time{}
	state.updatedAt = now
	state.weakObservations = nil
	state.weakObservationHead = 0
	state.weakSeen = make(map[string]time.Time)
	state.strongEvidence = nil
	state.admissionLimit = 0
	state.limitedInFlight = 0
	state.lastResort = false
	state.probeInFlight = false
	state.probeLeaseID = 0
	state.probeSuccesses = 0
	log.Printf("[Relay circuit account=%d] opened after HTTP %d; recovery_failure=%t open_until=%s generation=%d", accountID, statusCode, recoveryFailure, state.openUntil.Format(time.RFC3339), state.generation)
}

func (b *relayCircuitBreaker) hasOtherHealthyFrontLocked(accountID int64, poolAccountIDs []int64, now time.Time) bool {
	for _, otherID := range poolAccountIDs {
		if otherID == 0 || otherID == accountID || !b.loaded[otherID] {
			continue
		}
		other := b.stateLocked(otherID)
		b.advanceTimeLocked(other, now)
		if other.state == RelayCircuitClosed {
			return true
		}
		if other.state == RelayCircuitSuspect && !other.lastResort &&
			other.admissionLimit > 0 && other.limitedInFlight < other.admissionLimit {
			return true
		}
	}
	return false
}

func (b *relayCircuitBreaker) activateLastResortLocked(accountID int64, state *relayCircuitAccountState, now time.Time, statusCode int) {
	state.state = RelayCircuitSuspect
	state.generation++
	if state.generation == 0 {
		state.generation = 1
	}
	state.evidenceEpoch++
	if state.evidenceEpoch == 0 {
		state.evidenceEpoch = 1
	}
	state.revision++
	state.reason = relayCircuitReason(statusCode) + "_last_resort"
	state.lastStatusCode = statusCode
	state.lastFailureAt = now
	state.suspectAt = now
	state.updatedAt = now
	state.openedAt = time.Time{}
	state.openUntil = time.Time{}
	state.strongEvidence = nil
	state.admissionLimit = relayCircuitLastResortAdmissionLimit
	state.limitedInFlight = 0
	state.lastResort = true
	state.probeSuccesses = 0
	log.Printf("[Relay circuit account=%d] retained as pool last-resort after HTTP %d; admission_limit=%d generation=%d", accountID, statusCode, state.admissionLimit, state.generation)
}

func (b *relayCircuitBreaker) confirmFailureLocked(accountID int64, state *relayCircuitAccountState, poolAccountIDs []int64, now time.Time, statusCode int, recoveryFailure bool) bool {
	// A single probation/half-open failure is enough to restore the transport
	// fence, but it is not a second independently confirmed strong cohort. Only
	// the ordinary strong-quorum path advances Guardian's cycle identity.
	if IsRelayStrongGatewayFailureStatus(statusCode) && !recoveryFailure {
		state.confirmedStrongCycleToken++
		if state.confirmedStrongCycleToken == 0 {
			state.confirmedStrongCycleToken = 1
		}
	}
	if poolAccountIDs != nil && !b.hasOtherHealthyFrontLocked(accountID, poolAccountIDs, now) {
		b.activateLastResortLocked(accountID, state, now, statusCode)
		return false
	}
	b.openLocked(accountID, state, now, statusCode, recoveryFailure)
	return true
}

func (b *relayCircuitBreaker) reportFailure(permit RelayCircuitPermit, statusCode int) bool {
	return b.reportFailureWithPool(permit, statusCode, nil)
}

func (b *relayCircuitBreaker) reportFailureWithPool(permit RelayCircuitPermit, statusCode int, poolAccountIDs []int64) bool {
	strong, weak := relayCircuitFailure(statusCode)
	if b == nil || !permit.Active || permit.AccountID == 0 || (!strong && !weak) {
		return false
	}
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	persist := false
	opened := false

	b.mu.Lock()
	if !b.loaded[permit.AccountID] {
		b.mu.Unlock()
		return false
	}
	state := b.stateLocked(permit.AccountID)
	issuedPermit, consumed := b.consumePermitLocked(permit)
	if !consumed {
		b.mu.Unlock()
		return false
	}
	permit = issuedPermit
	if permit.Generation != state.generation {
		nextGeneration := permit.Generation + 1
		if nextGeneration == 0 {
			nextGeneration = 1
		}
		lateProbationFailure := permit.Probe && state.generation == nextGeneration &&
			(state.state == RelayCircuitClosed || state.state == RelayCircuitSuspect)
		lateSuspectFailure := strong && permit.limited && !permit.Probe && state.generation == nextGeneration &&
			(state.state == RelayCircuitClosed || state.state == RelayCircuitSuspect)
		lateWeakFailure := weak && permit.limited && !permit.Probe && state.generation == nextGeneration &&
			(state.state == RelayCircuitClosed || state.state == RelayCircuitSuspect)
		if lateProbationFailure {
			opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, true)
			revision, record = state.revision, relayCircuitRecordFromState(state)
			persist = true
		} else if lateSuspectFailure {
			// A success from a suspect cohort closes that generation, but other
			// already-issued requests can still fail afterwards. Treat those late
			// failures as evidence for a fresh suspect cycle instead of silently
			// discarding them. Their old evidence epoch means they cannot satisfy
			// the post-suspect quorum by themselves.
			if state.state == RelayCircuitClosed {
				b.enterSuspectLocked(state, now, statusCode, permit.AdmissionLimit)
			}
			b.addStrongEvidenceLocked(state, permit, now)
			state.lastFailureAt = now
			state.lastStatusCode = statusCode
			state.reason = relayCircuitReason(statusCode)
			state.updatedAt = now
			state.revision++
			total, postSuspect := relayCircuitStrongCounts(state)
			if total >= relayCircuitStrongFailureLimit && postSuspect >= relayCircuitStrongPostSuspectLimit {
				opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, false)
			}
			revision, record = state.revision, relayCircuitRecordFromState(state)
			persist = opened || record.LastResort
		} else if lateWeakFailure {
			// A success can close a suspect generation before the rest of that
			// bounded cohort completes. Keep canonical late 500/503 outcomes in
			// the rolling weak-failure window; otherwise completion order could
			// erase a genuinely unhealthy 5xx majority. The one-generation fence,
			// limited flag and consumed lease prevent stale or duplicate evidence.
			b.addWeakObservationLocked(state, permit, now, true)
			samples, failures := relayCircuitWeakCounts(state)
			if failures >= relayCircuitWeakFailureLimit && failures*100 >= samples*relayCircuitWeakFailureRatePercent {
				opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, false)
				revision, record = state.revision, relayCircuitRecordFromState(state)
				persist = opened || record.LastResort
			}
		}
		b.mu.Unlock()
		if persist {
			b.persistIfCurrent(permit.AccountID, revision, record, false)
		}
		return opened
	}
	b.advanceTimeLocked(state, now)
	if state.state == RelayCircuitOpen {
		b.mu.Unlock()
		return false
	}

	if state.state == RelayCircuitProbation || state.state == RelayCircuitHalfOpen {
		opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, true)
		revision, record = state.revision, relayCircuitRecordFromState(state)
		persist = true
	} else if strong {
		if state.state == RelayCircuitClosed {
			b.enterSuspectLocked(state, now, statusCode, permit.AdmissionLimit)
		}
		b.addStrongEvidenceLocked(state, permit, now)
		state.lastFailureAt = now
		state.lastStatusCode = statusCode
		state.reason = relayCircuitReason(statusCode)
		state.updatedAt = now
		state.revision++
		total, postSuspect := relayCircuitStrongCounts(state)
		if total >= relayCircuitStrongFailureLimit && postSuspect >= relayCircuitStrongPostSuspectLimit {
			opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, false)
		}
		revision, record = state.revision, relayCircuitRecordFromState(state)
		persist = true
	} else if weak {
		b.addWeakObservationLocked(state, permit, now, true)
		samples, failures := relayCircuitWeakCounts(state)
		if failures >= relayCircuitWeakFailureLimit && failures*100 >= samples*relayCircuitWeakFailureRatePercent {
			opened = b.confirmFailureLocked(permit.AccountID, state, poolAccountIDs, now, statusCode, false)
			revision, record = state.revision, relayCircuitRecordFromState(state)
			persist = true
		}
	}
	b.mu.Unlock()
	if persist && (record.State != RelayCircuitSuspect || record.LastResort) {
		// Ordinary suspect evidence remains process-local: without its
		// per-logical-request observations a restart cannot reconstruct the
		// decision, and avoiding cache writes keeps the retry hot path bounded. A
		// confirmed last-resort cap is durable so restart cannot turn a known
		// failing sole front door back into an unrestricted one.
		b.persistIfCurrent(permit.AccountID, revision, record, false)
	}
	return opened
}

func (b *relayCircuitBreaker) closeProbationIfReadyLocked(state *relayCircuitAccountState, now time.Time) bool {
	if state == nil || state.state != RelayCircuitProbation ||
		state.probeSuccesses < relayCircuitRecoverySuccesses {
		return false
	}
	state.state = RelayCircuitClosed
	state.generation++
	if state.generation == 0 {
		state.generation = 1
	}
	state.revision++
	state.reason = ""
	state.lastStatusCode = 0
	state.openedAt = time.Time{}
	state.openUntil = time.Time{}
	state.suspectAt = time.Time{}
	state.updatedAt = now
	state.backoffLevel = 0
	state.strongEvidence = nil
	state.weakObservations = nil
	state.weakObservationHead = 0
	state.weakSeen = make(map[string]time.Time)
	state.admissionLimit = 0
	state.limitedInFlight = 0
	state.lastResort = false
	state.probeInFlight = false
	state.probeLeaseID = 0
	state.probeSuccesses = 0
	return true
}

func (b *relayCircuitBreaker) reportSuccess(permit RelayCircuitPermit) bool {
	if b == nil || !permit.Active || permit.AccountID == 0 {
		return false
	}
	now := b.nowTime()
	var revision uint64
	var record relayCircuitRuntimeRecord
	var closeCircuit bool
	var probationClosed bool
	var deleteRuntimeRecord bool
	var persist bool

	b.mu.Lock()
	if !b.loaded[permit.AccountID] {
		b.mu.Unlock()
		return false
	}
	state := b.stateLocked(permit.AccountID)
	issuedPermit, consumed := b.consumePermitLocked(permit)
	if !consumed {
		b.mu.Unlock()
		return false
	}
	permit = issuedPermit
	if permit.Generation != state.generation {
		nextGeneration := permit.Generation + 1
		if nextGeneration == 0 {
			nextGeneration = 1
		}
		lateSuspectSuccess := permit.limited && !permit.Probe && state.generation == nextGeneration &&
			(state.state == RelayCircuitClosed || state.state == RelayCircuitSuspect)
		if lateSuspectSuccess {
			// Preserve the denominator paired with late weak failures. This does
			// not clear a fresh suspect cycle because the permit belongs to the
			// prior evidence epoch.
			b.addWeakObservationLocked(state, permit, now, false)
		}
		probationClosed = b.closeProbationIfReadyLocked(state, now)
		revision = state.revision
		b.mu.Unlock()
		if probationClosed {
			b.persistIfCurrent(permit.AccountID, revision, relayCircuitRuntimeRecord{}, true)
		}
		return probationClosed
	}
	b.advanceTimeLocked(state, now)
	if state.state == RelayCircuitOpen {
		b.mu.Unlock()
		return false
	}

	if state.state == RelayCircuitProbation || state.state == RelayCircuitHalfOpen {
		state.probeSuccesses++
		state.updatedAt = now
		state.revision++
	} else {
		b.addWeakObservationLocked(state, permit, now, false)
		if state.state == RelayCircuitSuspect && permit.EvidenceEpoch == state.evidenceEpoch {
			deleteRuntimeRecord = state.lastResort
			b.closeSuspectLocked(state, now)
			closeCircuit = true
		}
	}
	if b.closeProbationIfReadyLocked(state, now) {
		closeCircuit = true
		probationClosed = true
		deleteRuntimeRecord = true
	} else if state.state == RelayCircuitProbation {
		record = relayCircuitRecordFromState(state)
		persist = true
	}
	revision = state.revision
	b.mu.Unlock()

	if closeCircuit {
		if deleteRuntimeRecord {
			b.persistIfCurrent(permit.AccountID, revision, relayCircuitRuntimeRecord{}, true)
		}
		if probationClosed {
			log.Printf("[Relay circuit account=%d] closed after %d successful probation requests", permit.AccountID, relayCircuitRecoverySuccesses)
		} else {
			log.Printf("[Relay circuit account=%d] suspect cleared by a newly admitted successful request", permit.AccountID)
		}
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
	issuedPermit, consumed := b.consumePermitLocked(permit)
	if !consumed {
		b.mu.Unlock()
		return false
	}
	permit = issuedPermit
	if b.closeProbationIfReadyLocked(state, now) {
		revision = state.revision
		b.mu.Unlock()
		b.persistIfCurrent(permit.AccountID, revision, relayCircuitRuntimeRecord{}, true)
		return true
	}
	if !permit.Probe {
		b.mu.Unlock()
		return true
	}
	if permit.Generation != state.generation ||
		(state.state != RelayCircuitHalfOpen && state.state != RelayCircuitProbation) {
		b.mu.Unlock()
		return false
	}
	state.probeInFlight = state.limitedInFlight > 0
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
	// Keep the Redis wire state readable by the pre-rb12 rollback image. That
	// version accepts only open/half_open and would fail-closed for 24 hours on
	// the new probation or durable last-resort suspect values. rb12 upgrades the
	// legacy half_open value back to probation and still reads LastResort.
	wireState := state.state
	if wireState == RelayCircuitProbation || (wireState == RelayCircuitSuspect && state.lastResort) {
		wireState = RelayCircuitHalfOpen
	}
	return relayCircuitRuntimeRecord{
		State:               wireState,
		Generation:          state.generation,
		Reason:              state.reason,
		LastStatusCode:      state.lastStatusCode,
		OpenedAt:            state.openedAt,
		OpenUntil:           state.openUntil,
		LastFailureAt:       state.lastFailureAt,
		SuspectAt:           state.suspectAt,
		UpdatedAt:           state.updatedAt,
		BackoffLevel:        state.backoffLevel,
		ProbeSuccesses:      state.probeSuccesses,
		AdmissionLimit:      state.admissionLimit,
		LastResort:          state.lastResort,
		EvidenceEpoch:       state.evidenceEpoch,
		IdentityFingerprint: state.identityFingerprint,
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
	snapshot.WeakSamples, snapshot.WeakFailures = relayCircuitWeakCounts(state)
	snapshot.StrongFailures, snapshot.PostSuspectFailures = relayCircuitStrongCounts(state)
	snapshot.ProbeInFlight = state.probeInFlight || ((state.state == RelayCircuitProbation || state.state == RelayCircuitHalfOpen) && state.limitedInFlight > 0)
	snapshot.ProbeSuccesses = state.probeSuccesses
	snapshot.AdmissionLimit = state.admissionLimit
	snapshot.InFlight = state.limitedInFlight
	snapshot.LastResort = state.lastResort
	snapshot.EvidenceEpoch = state.evidenceEpoch
	snapshot.confirmedStrongCycleToken = state.confirmedStrongCycleToken
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
	state := b.stateLocked(accountID)
	b.advanceTimeLocked(state, b.nowTime())
	b.pruneStrongEvidenceLocked(state, b.nowTime())
	b.pruneWeakObservationsLocked(state, b.nowTime())
	return relayCircuitSnapshotFromState(accountID, state)
}

func (b *relayCircuitBreaker) snapshots() []RelayCircuitSnapshot {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	result := make([]RelayCircuitSnapshot, 0, len(b.states))
	now := b.nowTime()
	for accountID, state := range b.states {
		b.advanceTimeLocked(state, now)
		b.pruneStrongEvidenceLocked(state, now)
		b.pruneWeakObservationsLocked(state, now)
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

// relayCircuitConfigChanged invalidates every state that could belong to the
// old or new Relay scope. Circuit cache keys are account-scoped, so a group
// change must not let an old group's open/last-resort state leak into the new
// routing authority.
func (s *Store) relayCircuitConfigChanged(previous, current CybRelayConfig, accounts []*Account) {
	if s == nil {
		return
	}
	breaker := s.relayCircuitManager()
	ids := make(map[int64]string)
	breaker.mu.Lock()
	for accountID := range breaker.states {
		ids[accountID] = ""
	}
	breaker.mu.Unlock()
	for _, account := range accounts {
		if account == nil || !account.IsOpenAIResponsesAPI() {
			continue
		}
		if (previous.GroupID > 0 && account.HasGroupID(previous.GroupID)) ||
			(current.GroupID > 0 && account.HasGroupID(current.GroupID)) {
			ids[account.DBID] = relayCircuitAccountIdentityFingerprint(account)
		}
	}
	for accountID, identityFingerprint := range ids {
		if account := s.FindByID(accountID); account != nil {
			account.setRelayCircuitLastResort(false)
		}
		breaker.forgetAccountRuntime(accountID, identityFingerprint)
	}
}

// RelayCircuitSelectable is a scheduler fence checked before account priority,
// health tier, score, skip-warm behavior, and concurrency. Suspect accounts use
// a bounded admission limit, confirmed-open accounts are excluded, and expired
// opens enter a three-request probation window. Callers must still acquire a
// permit with BeginRelayCircuitRequest after selection.
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
	breaker := s.relayCircuitManager()
	selectable := breaker.selectable(account.DBID)
	account.setRelayCircuitLastResort(breaker.snapshot(account.DBID).LastResort)
	return selectable
}

func (s *Store) isConfiguredRelayCircuitAccount(account *Account) bool {
	if s == nil || account == nil || !account.IsOpenAIResponsesAPI() {
		return false
	}
	cfg := s.GetCybRelayConfig()
	return cfg.Enabled && cfg.GroupID > 0 && account.HasGroupID(cfg.GroupID)
}

// BeginRelayCircuitRequest acquires an attempt permit fenced by circuit
// generation. Suspect and probation states apply their bounded concurrent
// admission limits. A false result means the caller must release the selected
// account and choose another one.
func (s *Store) BeginRelayCircuitRequest(account *Account) (RelayCircuitPermit, bool) {
	return s.BeginRelayCircuitRequestForLogicalRequest(account, "")
}

func (s *Store) BeginRelayCircuitRequestForLogicalRequest(account *Account, logicalRequestID string) (RelayCircuitPermit, bool) {
	return s.BeginRelayCircuitRequestForLogicalRequestWithFilter(account, logicalRequestID, nil)
}

func (s *Store) BeginRelayCircuitRequestForLogicalRequestWithFilter(account *Account, logicalRequestID string, poolFilter AccountFilter) (RelayCircuitPermit, bool) {
	if s == nil || account == nil {
		return RelayCircuitPermit{}, false
	}
	// Linearize membership with RemoveAccount/RemoveAccounts. A scheduler may
	// have selected an Account pointer immediately before an admin/reconcile
	// replacement of the same DB ID. Without the pointer-identity check, that old
	// object could acquire a permit from the replacement membership generation
	// and later mutate the replacement's breaker state.
	s.mu.RLock()
	if s.lookupByIDLocked(account.DBID) != account || !s.isConfiguredRelayCircuitAccount(account) {
		s.mu.RUnlock()
		return RelayCircuitPermit{}, false
	}
	_, _, _, normalLimit := account.schedulerSnapshot(int64(s.GetMaxConcurrency()))
	permit, ok := s.relayCircuitManager().beginWithEvidenceAndFilter(account.DBID, logicalRequestID, int(normalLimit), poolFilter)
	if !ok {
		s.mu.RUnlock()
		return RelayCircuitPermit{}, false
	}
	guardian, guardianOK := s.BeginRelayGuardianRequest(account)
	s.mu.RUnlock()
	if !guardianOK {
		s.relayCircuitManager().abandon(permit)
		return RelayCircuitPermit{}, false
	}
	permit.Guardian = guardian
	return permit, true
}

func (s *Store) relayCircuitHealthyPoolAccountIDs(poolFilter AccountFilter) []int64 {
	if s == nil {
		return nil
	}
	accounts := s.configuredRelayGuardianAccounts()
	ids := make([]int64, 0, len(accounts))
	breaker := s.relayCircuitManager()
	baseLimit := s.GetMaxConcurrency()
	for _, account := range accounts {
		if account == nil || !relayGuardianManualEnabled(account) || account.RuntimeStatus() != "active" ||
			!account.IsAvailable() || !s.relayGuardianManager().normalCapacity(account) {
			continue
		}
		if poolFilter != nil && !poolFilter(account) {
			continue
		}
		_, _, _, limit := account.schedulerSnapshot(int64(baseLimit))
		if limit <= 0 || account.GetActiveRequests() >= limit {
			continue
		}
		breaker.ensureLoaded(account.DBID)
		ids = append(ids, account.DBID)
	}
	return ids
}

type relayCircuitRequestCandidate struct {
	account  *Account
	priority int64
	excluded bool
}

// EnsureRelayCircuitRequestPoolInvariant repairs the request-scoped availability
// invariant after the scheduler found no eligible Relay account. It never
// changes account status, Disabled, DispatchPaused, group membership, Guardian
// state, or request eligibility. If every eligible current member is circuit
// open, exactly one per request qualification class is conservatively promoted
// to a durable cap-2 last-resort. Selection excludes are deliberately not part
// of that class: excluding its current last-resort for one retry must not grow
// emergency admission to cap 2*N. Manual/runtime/Guardian/poolFilter
// ineligibility does remove an account from the class.
//
// The return value means a scheduler re-selection can be useful: either an
// eligible, non-excluded last-resort already has breaker admission room, or
// this call created one. A non-excluded normal closed/suspect/probation
// candidate suppresses promotion even if it is momentarily saturated; ordinary
// scheduling remains authoritative.
func (s *Store) EnsureRelayCircuitRequestPoolInvariant(poolFilter AccountFilter, exclude map[int64]bool) bool {
	if s == nil {
		return false
	}
	breaker := s.relayCircuitManager()
	candidates := make([]relayCircuitRequestCandidate, 0)
	for _, account := range s.configuredRelayGuardianAccounts() {
		if account == nil || !relayGuardianManualEnabled(account) || account.RuntimeStatus() != "active" ||
			!account.IsAvailable() {
			continue
		}
		if poolFilter != nil && !poolFilter(account) {
			continue
		}
		if !s.RelayGuardianSelectable(account) {
			continue
		}
		breaker.ensureLoadedForAccount(account)
		candidates = append(candidates, relayCircuitRequestCandidate{
			account:  account,
			priority: account.schedulerPriority(),
			excluded: exclude != nil && exclude[account.DBID],
		})
	}
	if len(candidates) == 0 {
		return false
	}

	// Keep the membership pointer stable through the breaker decision. The
	// request filters were intentionally evaluated before taking s.mu because an
	// AccountFilter is caller supplied and may consult Store state itself.
	s.mu.RLock()
	valid := candidates[:0]
	for _, candidate := range candidates {
		account := candidate.account
		if s.lookupByIDLocked(account.DBID) != account ||
			!s.isConfiguredRelayCircuitAccount(account) ||
			!relayGuardianManualEnabled(account) || account.RuntimeStatus() != "active" ||
			!account.IsAvailable() {
			continue
		}
		valid = append(valid, candidate)
	}
	if len(valid) == 0 {
		s.mu.RUnlock()
		return false
	}

	now := breaker.nowTime()
	hasExistingLastResort := false
	existingLastResortAvailable := false
	hasNormalCandidate := false
	var promote *relayCircuitRequestCandidate
	var promoteState *relayCircuitAccountState

	breaker.mu.Lock()
	for i := range valid {
		candidate := &valid[i]
		if !breaker.loaded[candidate.account.DBID] {
			continue
		}
		state := breaker.stateLocked(candidate.account.DBID)
		breaker.advanceTimeLocked(state, now)
		candidate.account.setRelayCircuitLastResort(state.lastResort)
		switch state.state {
		case RelayCircuitClosed, RelayCircuitProbation, RelayCircuitHalfOpen:
			if !candidate.excluded {
				hasNormalCandidate = true
			}
		case RelayCircuitSuspect:
			if state.lastResort {
				// Selection excludes are scoped to one attempt. They must not hide
				// an existing last-resort in the same request qualification class;
				// otherwise each retry can promote another open front and inflate
				// emergency admission from cap 2 to cap 2*N.
				hasExistingLastResort = true
				if !candidate.excluded && state.admissionLimit > 0 && state.limitedInFlight < relayCircuitLastResortAdmissionLimit {
					existingLastResortAvailable = true
				}
			} else if !candidate.excluded {
				hasNormalCandidate = true
			}
		case RelayCircuitOpen:
			if !candidate.excluded && (promote == nil || relayCircuitRequestPromotionPreferred(candidate, state, promote, promoteState)) {
				promote = candidate
				promoteState = state
			}
		default:
			// Unknown state is never a reason to relax another circuit.
			if !candidate.excluded {
				hasNormalCandidate = true
			}
		}
	}

	if hasExistingLastResort {
		breaker.mu.Unlock()
		s.mu.RUnlock()
		return existingLastResortAvailable
	}
	if hasNormalCandidate || promote == nil || promoteState == nil {
		breaker.mu.Unlock()
		s.mu.RUnlock()
		return false
	}

	statusCode := promoteState.lastStatusCode
	if statusCode == 0 {
		statusCode = 502
	}
	breaker.activateLastResortLocked(promote.account.DBID, promoteState, now, statusCode)
	revision := promoteState.revision
	record := relayCircuitRecordFromState(promoteState)
	breaker.mu.Unlock()
	s.mu.RUnlock()

	promote.account.setRelayCircuitLastResort(true)
	breaker.persistIfCurrent(promote.account.DBID, revision, record, false)
	return true
}

func relayCircuitRequestPromotionPreferred(candidate *relayCircuitRequestCandidate, state *relayCircuitAccountState, current *relayCircuitRequestCandidate, currentState *relayCircuitAccountState) bool {
	if candidate == nil || candidate.account == nil || state == nil {
		return false
	}
	if current == nil || current.account == nil || currentState == nil {
		return true
	}
	// Prefer the circuit nearest its normal recovery window, then preserve the
	// official scheduler priority and finally use DB ID for deterministic races.
	if !state.openUntil.Equal(currentState.openUntil) {
		if state.openUntil.IsZero() {
			return false
		}
		if currentState.openUntil.IsZero() {
			return true
		}
		return state.openUntil.Before(currentState.openUntil)
	}
	if candidate.priority != current.priority {
		return candidate.priority > current.priority
	}
	return candidate.account.DBID < current.account.DBID
}

// ReportRelayCircuitFailure records only Relay server statuses owned by this
// breaker. A first strong gateway failure enters suspect; opening requires
// three distinct logical failures in five seconds, including two from permits
// issued after suspect began. HTTP 500/503 require five failures and a 50%
// failure rate in the 30-second observation window.
// It returns true when this report transitions the circuit to open.
func (s *Store) ReportRelayCircuitFailure(permit RelayCircuitPermit, statusCode int) bool {
	if s == nil {
		return false
	}
	s.ReportRelayGuardianFailure(permit.Guardian, statusCode)
	breaker := s.relayCircuitManager()
	poolFilter, valid := breaker.permitPoolFilter(permit)
	if !valid {
		return false
	}
	opened := breaker.reportFailureWithPool(permit, statusCode, s.relayCircuitHealthyPoolAccountIDs(poolFilter))
	if account := s.FindByID(permit.AccountID); account != nil {
		account.setRelayCircuitLastResort(breaker.snapshot(permit.AccountID).LastResort)
	}
	return opened
}

// ReportRelayCircuitSuccess clears suspect on a successful newly admitted
// request, or advances probation. It returns true when the circuit becomes
// closed; probation closes after two successful requests.
func (s *Store) ReportRelayCircuitSuccess(permit RelayCircuitPermit) bool {
	if s == nil {
		return false
	}
	s.ReportRelayGuardianSuccess(permit.Guardian)
	breaker := s.relayCircuitManager()
	closed := breaker.reportSuccess(permit)
	if account := s.FindByID(permit.AccountID); account != nil {
		account.setRelayCircuitLastResort(breaker.snapshot(permit.AccountID).LastResort)
	}
	return closed
}

// AbandonRelayCircuitRequest releases a permit without counting it as success
// or failure. Handlers should defer this after Begin and then report a terminal
// outcome; the abandon call becomes a no-op after a valid report. This prevents
// cancellation or a local exit from consuming bounded admission indefinitely.
func (s *Store) AbandonRelayCircuitRequest(permit RelayCircuitPermit) bool {
	if s == nil {
		return false
	}
	s.AbandonRelayGuardianRequest(permit.Guardian)
	breaker := s.relayCircuitManager()
	released := breaker.abandon(permit)
	if account := s.FindByID(permit.AccountID); account != nil {
		account.setRelayCircuitLastResort(breaker.snapshot(permit.AccountID).LastResort)
	}
	return released
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
