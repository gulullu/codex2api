package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codex2api/cache"
	"github.com/codex2api/database"
)

var relayGuardianScopeEpochFallback atomic.Uint64

func newRelayGuardianScopeEpoch() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), relayGuardianScopeEpochFallback.Add(1))
}

const (
	relayGuardianRuntimeNamespace     = "relay-health-guardian"
	relayGuardianRuntimeSchemaVersion = 2
	relayGuardianRuntimeTTL           = 7 * 24 * time.Hour
	relayGuardianCacheTimeout         = 300 * time.Millisecond
	relayGuardianDBTimeout            = 3 * time.Second
	RelayGuardianScanInterval         = 60 * time.Second

	relayGuardianInitialQuarantine    = 30 * time.Minute
	relayGuardianProbationStage       = 10 * time.Minute
	relayGuardianProbationSuccesses   = 20
	relayGuardianWeakConfirmations    = 2
	relayGuardianStrongCycleWindow    = 10 * time.Minute
	relayGuardianPeerSuccessFreshness = 10 * time.Minute
	// A new process or execution scope must observe one complete initial
	// quarantine + two-stage probation window before it can remove a front door
	// for a long Guardian quarantine. The fast circuit remains authoritative
	// during this availability-first cold start.
	relayGuardianColdStartGuard = relayGuardianInitialQuarantine + 2*relayGuardianProbationStage
	// Config changes clear every affected Redis scope under one shared deadline.
	// The old implementation paid a fresh timeout per account and could make an
	// online transition scale linearly with pool size.
	relayGuardianConfigTransitionTimeout = 2 * relayGuardianCacheTimeout
)

const (
	RelayGuardianEventWouldQuarantine = "would_quarantine"
	RelayGuardianEventQuarantine      = "quarantine"
	RelayGuardianEventHalfOpen        = "half_open"
	RelayGuardianEventProbation       = "probation"
	RelayGuardianEventRecovered       = "recovered"
	RelayGuardianEventRelease         = "release"
	RelayGuardianEventBypass          = "bypass"
	RelayGuardianEventBypassExpired   = "bypass_expired"
	RelayGuardianEventLastResort      = "last_resort"
	RelayGuardianEventPoolWide        = "pool_wide"
	RelayGuardianEventSummary         = "summary"
	RelayGuardianEventAudit           = "audit"
)

var relayGuardianReopenDurations = [...]time.Duration{
	30 * time.Minute,
	60 * time.Minute,
	120 * time.Minute,
}

type RelayGuardianMode string

const (
	RelayGuardianOff     RelayGuardianMode = "off"
	RelayGuardianMonitor RelayGuardianMode = "monitor"
	RelayGuardianEnforce RelayGuardianMode = "enforce"
)

func NormalizeRelayGuardianMode(mode string) RelayGuardianMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case string(RelayGuardianMonitor):
		return RelayGuardianMonitor
	case string(RelayGuardianEnforce):
		return RelayGuardianEnforce
	default:
		return RelayGuardianOff
	}
}

type RelayGuardianState string

const (
	RelayGuardianHealthy         RelayGuardianState = "healthy"
	RelayGuardianSuspect         RelayGuardianState = "suspect"
	RelayGuardianWouldQuarantine RelayGuardianState = "would_quarantine"
	RelayGuardianQuarantined     RelayGuardianState = "quarantined"
	RelayGuardianHalfOpen        RelayGuardianState = "half_open"
	RelayGuardianProbation       RelayGuardianState = "probation"
	RelayGuardianTemporaryBypass RelayGuardianState = "temporary_bypass"
	RelayGuardianManualDisabled  RelayGuardianState = "manual_disabled"
)

type relayGuardianFailure struct {
	At               time.Time `json:"at"`
	LogicalRequestID string    `json:"logical_request_id"`
	StatusCode       int       `json:"status_code"`
	UserVisible      bool      `json:"user_visible"`
	StrongGateway    bool      `json:"strong_gateway"`
	AttemptOnly      bool      `json:"attempt_only,omitempty"`
	Recovery         bool      `json:"recovery,omitempty"`
}

type relayGuardianRuntimeRecord struct {
	SchemaVersion                   int                    `json:"schema_version,omitempty"`
	Mode                            RelayGuardianMode      `json:"mode,omitempty"`
	ScopeGroupID                    int64                  `json:"scope_group_id,omitempty"`
	ScopeEpoch                      string                 `json:"scope_epoch,omitempty"`
	State                           RelayGuardianState     `json:"state"`
	Generation                      uint64                 `json:"generation"`
	Reason                          string                 `json:"reason,omitempty"`
	TriggerSource                   string                 `json:"trigger_source,omitempty"`
	WindowSeconds                   int                    `json:"window_seconds,omitempty"`
	QuarantineUntil                 time.Time              `json:"quarantine_until,omitempty"`
	BackoffLevel                    int                    `json:"backoff_level"`
	ProbationPercent                int                    `json:"probation_percent,omitempty"`
	ProbationSuccesses              int                    `json:"probation_successes,omitempty"`
	ProbationStartedAt              time.Time              `json:"probation_started_at,omitempty"`
	TemporaryBypassUntil            time.Time              `json:"temporary_bypass_until,omitempty"`
	BypassReturnState               RelayGuardianState     `json:"bypass_return_state,omitempty"`
	LastResort                      bool                   `json:"last_resort,omitempty"`
	LastResortCap                   int                    `json:"last_resort_cap,omitempty"`
	LastResortLevel                 int                    `json:"last_resort_level,omitempty"`
	LastResortFailureID             string                 `json:"last_resort_failure_id,omitempty"`
	ShadowAction                    string                 `json:"shadow_action,omitempty"`
	HealthySince                    time.Time              `json:"healthy_since,omitempty"`
	PoolWideReportedAt              time.Time              `json:"pool_wide_reported_at,omitempty"`
	Failures                        []relayGuardianFailure `json:"failures,omitempty"`
	SeenStrong                      map[string]time.Time   `json:"seen_strong,omitempty"`
	SeenFinal                       map[string]time.Time   `json:"seen_final,omitempty"`
	LastFailureAt                   time.Time              `json:"last_failure_at,omitempty"`
	LastActionAt                    time.Time              `json:"last_action_at,omitempty"`
	LastScanAt                      time.Time              `json:"last_scan_at,omitempty"`
	ReliabilityObservedAt           time.Time              `json:"reliability_observed_at,omitempty"`
	ReliabilityTotal                int                    `json:"reliability_total,omitempty"`
	ReliabilityFailures             int                    `json:"reliability_failures,omitempty"`
	ReliabilityWindowSeconds        int                    `json:"reliability_window_seconds,omitempty"`
	FailureRatePercent              float64                `json:"failure_rate_percent,omitempty"`
	FailureRateLowerBoundPercent    float64                `json:"failure_rate_lower_bound_percent,omitempty"`
	ReliabilityLatestFailureRowID   int64                  `json:"reliability_latest_failure_row_id,omitempty"`
	WeakCandidateTrigger            string                 `json:"weak_candidate_trigger,omitempty"`
	WeakCandidateLatestFailureRowID int64                  `json:"weak_candidate_latest_failure_row_id,omitempty"`
	WeakCandidateSince              time.Time              `json:"weak_candidate_since,omitempty"`
	WeakConfirmationCount           int                    `json:"weak_confirmation_count,omitempty"`
	StrongCircuitCycleToken         uint64                 `json:"strong_circuit_cycle_token,omitempty"`
	StrongCircuitCycleCount         int                    `json:"strong_circuit_cycle_count,omitempty"`
	StrongCircuitCycleStartedAt     time.Time              `json:"strong_circuit_cycle_started_at,omitempty"`
	StrongCircuitCycleLastAt        time.Time              `json:"strong_circuit_cycle_last_at,omitempty"`
	UpdatedAt                       time.Time              `json:"updated_at,omitempty"`
}

type relayGuardianAccountState struct {
	relayGuardianRuntimeRecord
	revision            uint64
	halfOpenInFlight    bool
	halfOpenLeaseID     uint64
	halfOpenSuccesses   int
	probationAttemptSeq uint64
	permits             map[uint64]RelayGuardianPermit
}

type relayGuardianCapacitySample struct {
	At     time.Time
	Active int64
}

type relayGuardianCapacityAccount struct {
	account                *Account
	manual                 bool
	available              bool
	active                 int64
	limit                  int64
	lastCanonicalSuccessAt time.Time
	circuit                RelayCircuitSnapshot
}

type relayGuardianReliabilitySnapshot struct {
	AccountID             int64
	ObservedAt            time.Time
	Total10m              int
	Failures10m           int
	LatestFailureRowID10m int64
	Total60m              int
	Failures60m           int
	LatestFailureRowID60m int64
}

type relayGuardianWeakDecision struct {
	Trigger            string
	Window             time.Duration
	Total              int
	Failures           int
	LatestFailureRowID int64
	Rate               float64
	LowerBound         float64
	Catastrophic       bool
}

type relayHealthGuardian struct {
	store                         *Store
	cache                         cache.TokenCache
	db                            *database.DB
	mu                            sync.Mutex
	loadMu                        sync.Mutex
	persistMu                     sync.Mutex
	states                        map[int64]*relayGuardianAccountState
	loaded                        map[int64]bool
	loading                       map[int64]bool
	retryLoad                     map[int64]time.Time
	nextLease                     uint64
	heartbeat                     time.Time
	lastScan                      time.Time
	lastNewQuarantine             time.Time
	lastShadowQuarantine          time.Time
	lastShadowQuarantineAccountID int64
	incidentEpoch                 time.Time
	lastSummary                   time.Time
	lastAudit                     time.Time
	scanInFlight                  bool
	reliabilityInFlight           bool
	lastReliabilityQuery          time.Time
	lastReliabilitySuccess        time.Time
	lastReliabilityError          time.Time
	reliabilityFailureSince       time.Time
	reliabilityConsecutiveErrors  int
	scopeEpoch                    string
	scopeEpochGroupID             int64
	coldStartUntil                time.Time
	configTransitionTimeout       time.Duration
	poolWideUntil                 time.Time
	poolEvents                    map[string]time.Time
	capacitySamples               []relayGuardianCapacitySample
	now                           func() time.Time
	replayLockedHook              func() // deterministic test synchronization; nil in production
}

type RelayGuardianPermit struct {
	AccountID  int64
	Generation uint64
	LeaseID    uint64
	HalfOpen   bool
	Probation  bool
	Active     bool
}

type RelayGuardianObservation struct {
	AccountID           int64
	LogicalRequestID    string
	StatusCode          int
	UpstreamErrorKind   string
	ErrorMessage        string
	RouteClass          string
	RouteSource         string
	RouteGroupID        int64
	UpstreamAccountType string
	AttemptOnly         bool
	ObservedAt          time.Time
}

type RelayGuardianAccountSnapshot struct {
	AccountID                    int64              `json:"account_id"`
	AccountName                  string             `json:"account_name"`
	ManualEnabled                bool               `json:"manual_enabled"`
	State                        RelayGuardianState `json:"state"`
	EffectiveSchedulable         bool               `json:"effective_schedulable"`
	Reason                       string             `json:"reason,omitempty"`
	TriggerSource                string             `json:"trigger_source,omitempty"`
	Generation                   uint64             `json:"generation"`
	WindowSeconds                int                `json:"window_seconds,omitempty"`
	FailureCount                 int                `json:"failure_count"`
	UserVisibleFailures          int                `json:"user_visible_failures"`
	StrongGatewayFailures        int                `json:"strong_gateway_failures"`
	WouldQuarantine              bool               `json:"would_quarantine"`
	QuarantineUntil              *time.Time         `json:"quarantine_until,omitempty"`
	BackoffLevel                 int                `json:"backoff_level"`
	LastResort                   bool               `json:"last_resort"`
	LastResortCap                int                `json:"last_resort_cap"`
	ShadowAction                 string             `json:"shadow_action,omitempty"`
	ProbationPercent             int                `json:"probation_percent"`
	ProbationSuccesses           int                `json:"probation_successes"`
	ProbationRequiredSuccesses   int                `json:"probation_required_successes"`
	LastFailureAt                *time.Time         `json:"last_failure_at,omitempty"`
	LastActionAt                 *time.Time         `json:"last_action_at,omitempty"`
	LastScanAt                   *time.Time         `json:"last_scan_at,omitempty"`
	CircuitState                 RelayCircuitState  `json:"circuit_state"`
	CircuitOpenUntil             *time.Time         `json:"circuit_open_until,omitempty"`
	CircuitProbeSuccesses        int                `json:"circuit_probe_successes"`
	CircuitRequiredSuccesses     int                `json:"circuit_required_successes"`
	ReliabilityTotal             int                `json:"reliability_total"`
	ReliabilityFailures          int                `json:"reliability_failures"`
	ReliabilityWindowSeconds     int                `json:"reliability_window_seconds"`
	FailureRatePercent           float64            `json:"failure_rate_percent"`
	FailureRateLowerBoundPercent float64            `json:"failure_rate_lower_bound_percent"`
	WeakConfirmationCount        int                `json:"weak_confirmation_count"`
	WeakConfirmationRequired     int                `json:"weak_confirmation_required"`
	StrongCircuitCycleCount      int                `json:"strong_circuit_cycle_count"`
	LastCanonicalSuccessAt       *time.Time         `json:"last_canonical_success_at,omitempty"`
}

type RelayGuardianStatus struct {
	Enabled                      bool                           `json:"enabled"`
	Mode                         RelayGuardianMode              `json:"mode"`
	GeneratedAt                  time.Time                      `json:"generated_at"`
	HeartbeatAt                  *time.Time                     `json:"heartbeat_at,omitempty"`
	ScanIntervalSeconds          int                            `json:"scan_interval_seconds"`
	ReliabilityQueryStatus       string                         `json:"reliability_query_status"`
	ReliabilityConsecutiveErrors int                            `json:"reliability_consecutive_errors"`
	ReliabilityLastSuccessAt     *time.Time                     `json:"reliability_last_success_at,omitempty"`
	ReliabilityLastErrorAt       *time.Time                     `json:"reliability_last_error_at,omitempty"`
	ColdStartActive              bool                           `json:"cold_start_active"`
	ColdStartUntil               *time.Time                     `json:"cold_start_until,omitempty"`
	Accounts                     []RelayGuardianAccountSnapshot `json:"accounts"`
}

type RelayGuardianHealthSummary struct {
	Enabled             bool              `json:"enabled"`
	Mode                RelayGuardianMode `json:"mode"`
	Status              string            `json:"status"`
	HeartbeatAt         *time.Time        `json:"heartbeat_at,omitempty"`
	ScanIntervalSeconds int               `json:"scan_interval_seconds"`
	ColdStartActive     bool              `json:"cold_start_active"`
	ColdStartUntil      *time.Time        `json:"cold_start_until,omitempty"`
	Reasons             []string          `json:"reasons,omitempty"`
}

type RelayGuardianRelaySummary struct {
	GroupID                 int64 `json:"group_id"`
	Configured              int   `json:"configured"`
	Enabled                 int   `json:"enabled"`
	Schedulable             int   `json:"schedulable"`
	NormalSchedulable       int   `json:"normal_schedulable"`
	Suspect                 int   `json:"suspect"`
	RecoveryOnly            int   `json:"recovery_only"`
	CircuitOpen             int   `json:"circuit_open"`
	EffectiveAvailableSlots int64 `json:"effective_available_slots"`
	LastResort              int   `json:"last_resort"`
	Quarantined             int   `json:"quarantined"`
	Probation               int   `json:"probation"`
	Degraded                int   `json:"degraded"`
}

var ErrRelayGuardianStaleGeneration = errors.New("relay guardian generation changed")
var ErrRelayGuardianNotEnforcing = errors.New("relay guardian is not in enforce mode")
var ErrRelayGuardianInvalidState = errors.New("relay guardian action is not allowed in current state")
var ErrRelayGuardianRuntimeUnavailable = errors.New("relay guardian runtime state is unavailable")

func newRelayHealthGuardian(store *Store) *relayHealthGuardian {
	now := time.Now()
	groupID := store.GetCybRelayConfig().GroupID
	// Availability-first boot fence: Guardian weak isolation/recovery state is
	// intentionally reset after a process restart. The independent strong
	// circuit breaker still restores/rebuilds its own transport protection.
	// A random process-cycle token also makes this safe under clock rollback.
	return &relayHealthGuardian{
		store:                   store,
		cache:                   store.tokenCache,
		db:                      store.db,
		states:                  make(map[int64]*relayGuardianAccountState),
		loaded:                  make(map[int64]bool),
		loading:                 make(map[int64]bool),
		retryLoad:               make(map[int64]time.Time),
		poolEvents:              make(map[string]time.Time),
		now:                     time.Now,
		incidentEpoch:           now,
		scopeEpoch:              newRelayGuardianScopeEpoch(),
		scopeEpochGroupID:       groupID,
		coldStartUntil:          now.Add(relayGuardianColdStartGuard),
		configTransitionTimeout: relayGuardianConfigTransitionTimeout,
	}
}

func (g *relayHealthGuardian) transitionMode(current RelayGuardianMode) {
	if g == nil {
		return
	}
	// Serialize mode boundaries with both restore and persistence. In
	// particular, an account whose first cache read failed may not be present in
	// g.states yet; resetting only loaded states would let its old enforce-mode
	// quarantine reappear after E -> M -> E.
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	previous := g.store.GetRelayGuardianMode()
	if previous == current {
		return
	}
	now := g.nowTime()
	nextScopeEpoch := newRelayGuardianScopeEpoch()
	accounts := g.store.configuredRelayGuardianAccounts()
	groupID := g.store.GetCybRelayConfig().GroupID
	byID := make(map[int64]*Account, len(accounts))
	for _, account := range accounts {
		byID[account.DBID] = account
		relayGuardianSchedulingHint(account, false, 0, 0)
	}
	records := make(map[int64]relayGuardianRuntimeRecord, len(accounts))
	g.mu.Lock()
	// Publish the new mode only after all outer fences are held. Any request
	// that observes it must then wait on g.mu until the old evidence is reset.
	g.store.relayGuardianMode.Store(string(current))
	g.incidentEpoch = now
	g.coldStartUntil = now.Add(relayGuardianColdStartGuard)
	g.scopeEpoch = nextScopeEpoch
	g.scopeEpochGroupID = groupID
	g.lastScan = now
	g.lastNewQuarantine = time.Time{}
	g.lastShadowQuarantine = time.Time{}
	g.lastShadowQuarantineAccountID = 0
	g.poolWideUntil = time.Time{}
	g.poolEvents = make(map[string]time.Time)
	g.capacitySamples = nil
	g.lastSummary = time.Time{}
	g.lastAudit = time.Time{}
	g.lastReliabilityQuery = time.Time{}
	g.reliabilityInFlight = false
	g.lastReliabilitySuccess = time.Time{}
	g.lastReliabilityError = time.Time{}
	g.reliabilityFailureSince = time.Time{}
	g.reliabilityConsecutiveErrors = 0
	// Preserve the old behavior for any already-known state, then explicitly
	// materialize every configured account so cache failures cannot keep it in
	// an unknown state across the mode fence.
	for accountID, state := range g.states {
		if state == nil {
			continue
		}
		g.resetForModeLocked(state, current, now)
		relayGuardianSchedulingHint(byID[accountID], false, 0, 0)
		state.revision++
		state.UpdatedAt = now
		records[accountID] = cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
	}
	for accountID := range byID {
		state := g.states[accountID]
		if state == nil {
			state = &relayGuardianAccountState{permits: make(map[uint64]RelayGuardianPermit)}
			g.states[accountID] = state
			g.resetForModeLocked(state, current, now)
			state.revision++
			state.UpdatedAt = now
			records[accountID] = cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
		}
	}
	g.loaded = make(map[int64]bool, len(byID))
	for accountID := range byID {
		g.loaded[accountID] = true
	}
	g.loading = make(map[int64]bool)
	g.retryLoad = make(map[int64]time.Time)
	g.mu.Unlock()

	if g.cache == nil {
		return
	}
	for accountID, record := range records {
		if groupID <= 0 || record.ScopeGroupID != groupID {
			continue
		}
		payload, err := json.Marshal(record)
		if err != nil {
			continue
		}
		ctx, cancel := relayGuardianCacheContext()
		err = g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID), payload, relayGuardianRuntimeTTL)
		cancel()
		if err != nil {
			// The in-memory state remains authoritatively loaded and every
			// reconcile persists it again; never reload the stale cache record.
			log.Printf("[Relay guardian account=%d] persist mode transition failed: %v", accountID, err)
		}
	}
}

func (g *relayHealthGuardian) transitionConfig(current CybRelayConfig, accounts []*Account) {
	if g == nil {
		return
	}
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	previous := g.store.GetCybRelayConfig()
	if previous.Enabled == current.Enabled && previous.GroupID == current.GroupID {
		g.store.cybRelayConfig.Store(current)
		return
	}
	now := g.nowTime()
	nextScopeEpoch := newRelayGuardianScopeEpoch()
	ids := make(map[int64]struct{}, len(accounts))
	for _, account := range accounts {
		if account == nil {
			continue
		}
		relayGuardianSchedulingHint(account, false, 0, 0)
		account.relayGuardianCanonicalSuccessAt.Store(0)
		if account.IsOpenAIResponsesAPI() &&
			((previous.GroupID > 0 && account.HasGroupID(previous.GroupID)) ||
				(current.GroupID > 0 && account.HasGroupID(current.GroupID))) {
			ids[account.DBID] = struct{}{}
		}
	}
	g.mu.Lock()
	for accountID := range g.states {
		ids[accountID] = struct{}{}
	}
	// Publish the new scope while g.mu is held. A request that observes the new
	// group then blocks until the old states, permits and hints are gone.
	g.store.cybRelayConfig.Store(current)
	g.states = make(map[int64]*relayGuardianAccountState)
	g.loaded = make(map[int64]bool)
	g.loading = make(map[int64]bool)
	g.retryLoad = make(map[int64]time.Time)
	g.incidentEpoch = now
	g.coldStartUntil = now.Add(relayGuardianColdStartGuard)
	g.scopeEpoch = nextScopeEpoch
	g.scopeEpochGroupID = current.GroupID
	// The entry clear above can race with a replay that already passed its
	// membership check and is waiting for g.mu. Clear again while publishing the
	// scope boundary so no old-group last-resort/probation hint can survive it.
	for _, account := range accounts {
		relayGuardianSchedulingHint(account, false, 0, 0)
	}
	g.lastScan = now
	g.lastNewQuarantine = time.Time{}
	g.lastShadowQuarantine = time.Time{}
	g.lastShadowQuarantineAccountID = 0
	g.poolWideUntil = time.Time{}
	g.poolEvents = make(map[string]time.Time)
	g.capacitySamples = nil
	g.lastSummary = time.Time{}
	g.lastAudit = time.Time{}
	g.lastReliabilityQuery = time.Time{}
	g.reliabilityInFlight = false
	g.lastReliabilitySuccess = time.Time{}
	g.lastReliabilityError = time.Time{}
	g.reliabilityFailureSince = time.Time{}
	g.reliabilityConsecutiveErrors = 0
	g.mu.Unlock()
	if g.cache == nil {
		return
	}
	groups := make(map[int64]struct{}, 2)
	if previous.GroupID > 0 {
		groups[previous.GroupID] = struct{}{}
	}
	if current.GroupID > 0 {
		groups[current.GroupID] = struct{}{}
	}
	g.clearConfigRuntimeScopesBounded(ids, groups, now)
}

// clearConfigRuntimeScopesBounded runs after the in-memory scope fence has
// already been published and while transitionConfig still owns loadMu and
// persistMu. Every key shares one total deadline, so pool size cannot multiply
// the Redis timeout. Any key left behind is harmless: its old scope epoch is
// rejected by ensureLoaded, and the freshly published in-memory scope remains
// authoritative for this process.
func (g *relayHealthGuardian) clearConfigRuntimeScopesBounded(ids, groups map[int64]struct{}, now time.Time) {
	if g == nil || g.cache == nil || len(ids) == 0 || len(groups) == 0 {
		return
	}
	timeout := g.configTransitionTimeout
	if timeout <= 0 {
		timeout = relayGuardianConfigTransitionTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	incomplete := false
outer:
	for accountID := range ids {
		for groupID := range groups {
			if ctx.Err() != nil {
				incomplete = true
				break outer
			}
			err := g.cache.DeleteRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID))
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				incomplete = true
				break outer
			}
			record := relayGuardianRuntimeRecord{SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: g.store.GetRelayGuardianMode(), ScopeGroupID: groupID, ScopeEpoch: g.scopeEpoch, State: RelayGuardianHealthy, Generation: 1, UpdatedAt: now}
			payload, marshalErr := json.Marshal(record)
			if marshalErr != nil {
				log.Printf("[Relay guardian account=%d] encode config tombstone failed: %v", accountID, marshalErr)
				continue
			}
			if setErr := g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID), payload, relayGuardianRuntimeTTL); setErr != nil {
				if ctx.Err() != nil {
					incomplete = true
					break outer
				}
				log.Printf("[Relay guardian account=%d] clear old scope failed: delete=%v; healthy overwrite=%v", accountID, err, setErr)
			}
		}
	}
	if incomplete {
		log.Printf("Relay guardian config cache cleanup reached shared deadline after %s; stale records remain epoch-fenced", timeout)
	}
}

func (g *relayHealthGuardian) resetForModeLocked(state *relayGuardianAccountState, mode RelayGuardianMode, now time.Time) {
	if state == nil {
		return
	}
	state.SchemaVersion = relayGuardianRuntimeSchemaVersion
	state.Mode = mode
	state.ScopeGroupID = g.store.GetCybRelayConfig().GroupID
	state.ScopeEpoch = g.scopeEpoch
	state.State = RelayGuardianHealthy
	state.Generation++
	state.Reason = "mode_transition"
	state.TriggerSource = ""
	state.WindowSeconds = 0
	state.QuarantineUntil = time.Time{}
	state.BackoffLevel = 0
	state.ProbationPercent = 0
	state.ProbationSuccesses = 0
	state.ProbationStartedAt = time.Time{}
	state.TemporaryBypassUntil = time.Time{}
	state.BypassReturnState = ""
	state.LastResort = false
	state.LastResortCap = 0
	state.LastResortLevel = 0
	state.LastResortFailureID = ""
	state.ShadowAction = ""
	state.HealthySince = time.Time{}
	state.PoolWideReportedAt = time.Time{}
	state.Failures = nil
	state.SeenStrong = make(map[string]time.Time)
	state.SeenFinal = make(map[string]time.Time)
	state.LastFailureAt = time.Time{}
	state.ReliabilityObservedAt = time.Time{}
	state.ReliabilityTotal = 0
	state.ReliabilityFailures = 0
	state.ReliabilityWindowSeconds = 0
	state.FailureRatePercent = 0
	state.FailureRateLowerBoundPercent = 0
	state.ReliabilityLatestFailureRowID = 0
	state.WeakCandidateTrigger = ""
	state.WeakCandidateLatestFailureRowID = 0
	state.WeakCandidateSince = time.Time{}
	state.WeakConfirmationCount = 0
	state.StrongCircuitCycleToken = 0
	state.StrongCircuitCycleCount = 0
	state.StrongCircuitCycleStartedAt = time.Time{}
	state.StrongCircuitCycleLastAt = time.Time{}
	state.LastActionAt = now
	state.halfOpenInFlight = false
	state.halfOpenLeaseID = 0
	state.halfOpenSuccesses = 0
	state.probationAttemptSeq = 0
	state.permits = make(map[uint64]RelayGuardianPermit)
}

func (g *relayHealthGuardian) nowTime() time.Time {
	if g != nil && g.now != nil {
		return g.now()
	}
	return time.Now()
}

func (g *relayHealthGuardian) stateLocked(accountID int64) *relayGuardianAccountState {
	state := g.states[accountID]
	if state == nil {
		state = &relayGuardianAccountState{relayGuardianRuntimeRecord: relayGuardianRuntimeRecord{SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: g.store.GetRelayGuardianMode(), ScopeGroupID: g.store.GetCybRelayConfig().GroupID, ScopeEpoch: g.scopeEpoch, State: RelayGuardianHealthy, Generation: 1}, permits: make(map[uint64]RelayGuardianPermit)}
		g.states[accountID] = state
	}
	if state.State == "" {
		state.State = RelayGuardianHealthy
	}
	if state.Generation == 0 {
		state.Generation = 1
	}
	if state.SchemaVersion == 0 {
		state.SchemaVersion = relayGuardianRuntimeSchemaVersion
	}
	if state.Mode == "" {
		state.Mode = g.store.GetRelayGuardianMode()
	}
	if state.SeenStrong == nil {
		state.SeenStrong = make(map[string]time.Time)
	}
	if state.SeenFinal == nil {
		state.SeenFinal = make(map[string]time.Time)
	}
	if state.permits == nil {
		state.permits = make(map[uint64]RelayGuardianPermit)
	}
	return state
}

func relayGuardianCacheContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), relayGuardianCacheTimeout)
}

func relayGuardianTimePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func relayGuardianManualEnabled(account *Account) bool {
	return account != nil && atomic.LoadInt32(&account.Disabled) == 0 && atomic.LoadInt32(&account.DispatchPaused) == 0
}

func relayGuardianRecordCanonicalSuccess(account *Account, at time.Time) {
	if account == nil || at.IsZero() {
		return
	}
	next := at.UnixNano()
	for {
		current := account.relayGuardianCanonicalSuccessAt.Load()
		if current >= next {
			return
		}
		if account.relayGuardianCanonicalSuccessAt.CompareAndSwap(current, next) {
			return
		}
	}
}

func relayGuardianCanonicalSuccessAt(account *Account) time.Time {
	if account == nil {
		return time.Time{}
	}
	value := account.relayGuardianCanonicalSuccessAt.Load()
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

func (g *relayHealthGuardian) coldStartActiveLocked(now time.Time) bool {
	return g != nil && g.coldStartUntil.After(now)
}

func relayGuardianRuntimeKey(groupID, accountID int64) string {
	return fmt.Sprintf("group:%d:account:%d", groupID, accountID)
}

// relayGuardianSchedulingHint is the single adapter between the Guardian state
// machine and the scheduler's atomic runtime hint.
func relayGuardianSchedulingHint(account *Account, lastResort bool, hardCap int64, percent int) {
	if account == nil {
		return
	}
	if !lastResort && hardCap <= 0 && percent <= 0 {
		account.clearRelayGuardianSchedulingHint()
		return
	}
	account.setRelayGuardianSchedulingHint(lastResort, hardCap, percent)
}

func relayGuardianLastResortCap(level int) int {
	switch {
	case level <= 1:
		return 5
	case level == 2:
		return 3
	default:
		return 1
	}
}

func relayGuardianApplySchedulingHint(account *Account, state *relayGuardianAccountState) {
	if account == nil || state == nil || !relayGuardianManualEnabled(account) {
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	if state.LastResort {
		relayGuardianSchedulingHint(account, true, int64(state.LastResortCap), 0)
		return
	}
	if state.State == RelayGuardianProbation {
		percent := state.ProbationPercent
		if percent != 50 {
			percent = 10
		}
		relayGuardianSchedulingHint(account, false, 0, percent)
		return
	}
	relayGuardianSchedulingHint(account, false, 0, 0)
}

// replaySchedulingHint re-derives the runtime-only scheduler overlay from the
// already loaded Guardian state. It never performs cache or database I/O and is
// safe for account enable/replacement hooks after their Store locks are gone.
func (g *relayHealthGuardian) replaySchedulingHint(account *Account) {
	if g == nil || account == nil || g.store.GetRelayGuardianMode() != RelayGuardianEnforce ||
		!g.store.isConfiguredRelayCircuitAccount(account) || !relayGuardianManualEnabled(account) {
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.replayLockedHook != nil {
		g.replayLockedHook()
	}
	if !g.loaded[account.DBID] {
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	relayGuardianApplySchedulingHint(account, g.states[account.DBID])
}

// preloadAndReplay is for startup/reconcile/admin update paths only. Request
// selection and attempt paths must remain memory-only.
func (g *relayHealthGuardian) preloadAndReplay(account *Account) {
	if g == nil || account == nil {
		return
	}
	g.ensureLoaded(account.DBID)
	g.replaySchedulingHint(account)
}

// forgetAccountRuntime is the membership-boundary fence. It serializes with
// both cache restore and persistence so an in-flight old revision cannot
// recreate the state after the account has left the Relay group.
func (g *relayHealthGuardian) forgetAccountRuntime(account *Account, groupID int64) {
	if g == nil || account == nil {
		return
	}
	account.relayGuardianCanonicalSuccessAt.Store(0)
	relayGuardianSchedulingHint(account, false, 0, 0)
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	now := g.nowTime()
	g.mu.Lock()
	oldRevision := uint64(0)
	if state := g.states[account.DBID]; state != nil {
		oldRevision = state.revision
	}
	delete(g.states, account.DBID)
	delete(g.loaded, account.DBID)
	delete(g.loading, account.DBID)
	delete(g.retryLoad, account.DBID)
	// A replay may have passed its membership check before the entry clear and
	// then waited for g.mu. Clearing inside the state-deletion boundary makes
	// the leave authoritative regardless of that ordering.
	relayGuardianSchedulingHint(account, false, 0, 0)
	// Do not let the fallback scanner replay rows from the membership that
	// just ended if the account is immediately added back.
	g.incidentEpoch = now
	g.coldStartUntil = now.Add(relayGuardianColdStartGuard)
	g.lastScan = now
	g.mu.Unlock()
	cacheFenced := g.cache == nil || groupID <= 0
	var err error
	if !cacheFenced {
		ctx, cancel := relayGuardianCacheContext()
		err = g.cache.DeleteRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, account.DBID))
		cancel()
		if err == nil {
			cacheFenced = true
		} else {
			// A failed delete must not leave a known-bad quarantine/probation
			// record behind. Best-effort overwrite it with a healthy tombstone.
			record := relayGuardianRuntimeRecord{
				SchemaVersion: relayGuardianRuntimeSchemaVersion,
				Mode:          g.store.GetRelayGuardianMode(),
				ScopeGroupID:  groupID,
				ScopeEpoch:    g.scopeEpoch,
				State:         RelayGuardianHealthy,
				Generation:    1,
				UpdatedAt:     now,
			}
			payload, marshalErr := json.Marshal(record)
			if marshalErr == nil {
				ctx, cancel = relayGuardianCacheContext()
				setErr := g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, account.DBID), payload, relayGuardianRuntimeTTL)
				cancel()
				if setErr == nil {
					cacheFenced = true
				} else {
					err = fmt.Errorf("delete failed: %v; healthy overwrite failed: %w", err, setErr)
				}
			}
		}
	}
	// Every membership leave needs an in-process tombstone. A successful cache
	// delete is not enough: an immediate rejoin can create revision 1 while an
	// old revision-1 persist is still queued on persistMu.
	g.mu.Lock()
	state := g.stateLocked(account.DBID)
	g.resetForModeLocked(state, g.store.GetRelayGuardianMode(), now)
	state.Reason = "membership_transition"
	relayGuardianSchedulingHint(account, false, 0, 0)
	// Revisions from the membership that just ended may still be queued on
	// persistMu. Never recycle their numbers: otherwise an old asynchronous
	// persist can pass the equality fence after this fresh state is materialized
	// and recreate the quarantine we just invalidated.
	state.revision = oldRevision + 1
	if state.revision == 0 {
		state.revision = 1
	}
	g.loaded[account.DBID] = true
	delete(g.loading, account.DBID)
	delete(g.retryLoad, account.DBID)
	g.mu.Unlock()
	if !cacheFenced {
		log.Printf("[Relay guardian account=%d] invalidate removed account state failed: %v", account.DBID, err)
	}
}

func (g *relayHealthGuardian) ensureLoaded(accountID int64) {
	if g == nil || accountID <= 0 {
		return
	}
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	now := g.nowTime()
	groupID := g.store.GetCybRelayConfig().GroupID
	g.mu.Lock()
	if g.scopeEpochGroupID != groupID {
		g.scopeEpoch = newRelayGuardianScopeEpoch()
		g.scopeEpochGroupID = groupID
	}
	if g.loaded[accountID] || g.loading[accountID] || g.retryLoad[accountID].After(now) {
		g.mu.Unlock()
		return
	}
	if g.cache == nil {
		g.loaded[accountID] = true
		g.mu.Unlock()
		return
	}
	g.loading[accountID] = true
	g.mu.Unlock()
	account := g.store.FindByID(accountID)
	ctx, cancel := relayGuardianCacheContext()
	payload, ok, err := g.cache.GetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID))
	cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.loading, accountID)
	if err != nil {
		g.retryLoad[accountID] = now.Add(time.Second)
		log.Printf("[Relay guardian account=%d] restore runtime state failed: %v", accountID, err)
		return
	}
	if !ok || len(payload) == 0 {
		g.loaded[accountID] = true
		delete(g.retryLoad, accountID)
		return
	}
	var record relayGuardianRuntimeRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		g.retryLoad[accountID] = now.Add(5 * time.Second)
		log.Printf("[Relay guardian account=%d] decode runtime state failed: %v", accountID, err)
		return
	}
	g.loaded[accountID] = true
	delete(g.retryLoad, accountID)
	state := g.stateLocked(accountID)
	state.relayGuardianRuntimeRecord = record
	currentMode := g.store.GetRelayGuardianMode()
	if state.SchemaVersion != relayGuardianRuntimeSchemaVersion || state.Mode != currentMode || state.ScopeGroupID != groupID ||
		state.ScopeEpoch == "" || state.ScopeEpoch != g.scopeEpoch {
		g.resetForModeLocked(state, currentMode, now)
		relayGuardianSchedulingHint(account, false, 0, 0)
		g.incidentEpoch = now
		g.coldStartUntil = now.Add(relayGuardianColdStartGuard)
		g.lastScan = now
	}
	state.revision++
	state.halfOpenInFlight = false
	state.halfOpenLeaseID = 0
	state.permits = make(map[uint64]RelayGuardianPermit)
	g.trimLocked(state, now)
	// Runtime records written before LastResortFailureID existed already
	// consumed their latest incident. Seed the marker during restore so the
	// first reconcile cannot replay that historical row as a fresh escalation.
	if state.LastResort && state.LastResortFailureID == "" {
		state.LastResortFailureID = relayGuardianLatestFailureID(state)
	}
	if currentMode != RelayGuardianOff {
		if until := relayGuardianRestoredPoolUntil(state, now); until.After(g.poolWideUntil) {
			g.poolWideUntil = until
		}
	}
	relayGuardianApplySchedulingHint(account, state)
}

func (g *relayHealthGuardian) persist(accountID int64, revision uint64, record relayGuardianRuntimeRecord) {
	if g == nil || g.cache == nil || accountID <= 0 {
		return
	}
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	g.mu.Lock()
	state := g.states[accountID]
	current := state != nil && state.revision == revision && record.ScopeEpoch != "" && record.ScopeEpoch == g.scopeEpoch
	g.mu.Unlock()
	if !current {
		return
	}
	if record.Mode != g.store.GetRelayGuardianMode() || record.ScopeGroupID <= 0 || record.ScopeGroupID != g.store.GetCybRelayConfig().GroupID {
		return
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	ctx, cancel := relayGuardianCacheContext()
	defer cancel()
	if err := g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(record.ScopeGroupID, accountID), payload, relayGuardianRuntimeTTL); err != nil {
		log.Printf("[Relay guardian account=%d] persist runtime state failed: %v", accountID, err)
	}
}

func (g *relayHealthGuardian) persistState(accountID int64, state *relayGuardianAccountState) {
	if state == nil {
		return
	}
	state.revision++
	state.SchemaVersion = relayGuardianRuntimeSchemaVersion
	state.UpdatedAt = g.nowTime()
	state.Mode = g.store.GetRelayGuardianMode()
	state.ScopeGroupID = g.store.GetCybRelayConfig().GroupID
	state.ScopeEpoch = g.scopeEpoch
	revision := state.revision
	record := cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
	go g.persist(accountID, revision, record)
}

func cloneRelayGuardianRuntimeRecord(record relayGuardianRuntimeRecord) relayGuardianRuntimeRecord {
	cloned := record
	cloned.Failures = append([]relayGuardianFailure(nil), record.Failures...)
	cloned.SeenStrong = make(map[string]time.Time, len(record.SeenStrong))
	for key, value := range record.SeenStrong {
		cloned.SeenStrong[key] = value
	}
	cloned.SeenFinal = make(map[string]time.Time, len(record.SeenFinal))
	for key, value := range record.SeenFinal {
		cloned.SeenFinal[key] = value
	}
	return cloned
}

func (g *relayHealthGuardian) trimLocked(state *relayGuardianAccountState, now time.Time) {
	if state == nil {
		return
	}
	cutoff := now.Add(-60 * time.Minute)
	kept := state.Failures[:0]
	for _, failure := range state.Failures {
		if !failure.At.Before(cutoff) {
			kept = append(kept, failure)
		}
	}
	state.Failures = kept
	for key, at := range state.SeenStrong {
		if at.Before(cutoff) {
			delete(state.SeenStrong, key)
		}
	}
	for key, at := range state.SeenFinal {
		if at.Before(cutoff) {
			delete(state.SeenFinal, key)
		}
	}
}

func relayGuardianAttributable(obs RelayGuardianObservation) bool {
	if obs.StatusCode < 500 || obs.StatusCode > 599 {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(obs.UpstreamErrorKind))
	message := strings.ToLower(obs.ErrorMessage)
	for _, excluded := range []string{"cyber_policy", "content_policy", "client", "cancel", "rate_limit", "usage_limit", "usage limit", "concurrency_limit", "concurrency limit", "bad_request"} {
		if strings.Contains(kind, excluded) || strings.Contains(message, excluded) {
			return false
		}
	}
	return true
}

func relayGuardianLocalWebsocketContention(obs RelayGuardianObservation) bool {
	switch strings.ToLower(strings.TrimSpace(obs.UpstreamErrorKind)) {
	case "websocket_busy_session", "websocket_local_capacity", "websocket_continuation_unavailable":
		return true
	default:
		return false
	}
}

func relayGuardianSharedCapacityLimited(obs RelayGuardianObservation) bool {
	kind := strings.ToLower(strings.TrimSpace(obs.UpstreamErrorKind))
	for _, marker := range []string{"rate_limit", "usage_limit", "concurrency_limit"} {
		if strings.Contains(kind, marker) {
			return true
		}
	}
	message := strings.ToLower(strings.TrimSpace(obs.ErrorMessage))
	for _, phrase := range []string{"rate limit exceeded", "usage limit exceeded", "concurrency limit exceeded"} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

func (g *relayHealthGuardian) observe(obs RelayGuardianObservation) {
	if g == nil || obs.AccountID <= 0 {
		return
	}
	mode := g.store.GetRelayGuardianMode()
	if mode == RelayGuardianOff {
		return
	}
	logicalID := strings.TrimSpace(obs.LogicalRequestID)
	if logicalID == "" {
		return
	}
	// A busy session or exhausted local WS slot is gateway-local contention,
	// not evidence that the selected Relay front door is unhealthy. Exclude it
	// before strong 502/504 classification, which intentionally ignores generic
	// message-based suppressions for real gateway failures.
	if relayGuardianLocalWebsocketContention(obs) {
		return
	}
	// A downstream shared-user quota or concurrency ceiling can be wrapped by
	// an intermediate gateway as 502. It is capacity evidence for the normal
	// account cooldown/scheduler, not proof that the Relay front door is broken.
	if relayGuardianSharedCapacityLimited(obs) {
		return
	}
	account := g.store.FindByID(obs.AccountID)
	if account == nil || !g.store.isConfiguredRelayCircuitAccount(account) {
		return
	}
	if !relayGuardianManualEnabled(account) {
		return
	}
	cfg := g.store.GetCybRelayConfig()
	if obs.RouteClass != "cyb_relay" || obs.RouteGroupID != cfg.GroupID || !strings.EqualFold(obs.UpstreamAccountType, UpstreamOpenAIResponses) {
		return
	}
	observedAt := obs.ObservedAt
	if observedAt.IsZero() {
		observedAt = g.nowTime()
	}
	if obs.StatusCode >= 200 && obs.StatusCode <= 399 && !obs.AttemptOnly && !strings.EqualFold(strings.TrimSpace(obs.RouteSource), "probe") {
		relayGuardianRecordCanonicalSuccess(account, observedAt)
		return
	}
	strong := IsRelayStrongGatewayFailureStatus(obs.StatusCode)
	weakAttributable := relayGuardianAttributable(obs)
	// Transport status is authoritative for the fast breaker. A misleading
	// upstream error string (for example one containing "client") must never
	// suppress a real 502/504-class gateway failure.
	if !strong && !weakAttributable {
		return
	}
	now := g.nowTime()
	userVisible := weakAttributable && !strong && !obs.AttemptOnly && !strings.EqualFold(strings.TrimSpace(obs.RouteSource), "probe")
	if !strong && !userVisible {
		return
	}

	accounts := g.store.configuredRelayGuardianAccounts()
	capacity := g.capacityInputs(accounts)
	g.mu.Lock()
	if !g.loaded[obs.AccountID] && g.cache == nil {
		g.loaded[obs.AccountID] = true
	}
	if !g.loaded[obs.AccountID] {
		g.mu.Unlock()
		return
	}
	if observedAt.Before(g.incidentEpoch) || mode != g.store.GetRelayGuardianMode() || cfg.GroupID != g.store.GetCybRelayConfig().GroupID {
		g.mu.Unlock()
		return
	}
	state := g.stateLocked(obs.AccountID)
	g.trimLocked(state, now)
	state.HealthySince = time.Time{}
	added := false
	if strong {
		if _, duplicate := state.SeenStrong[logicalID]; !duplicate {
			state.SeenStrong[logicalID] = observedAt
			state.Failures = append(state.Failures, relayGuardianFailure{At: observedAt, LogicalRequestID: logicalID, StatusCode: obs.StatusCode, StrongGateway: true, AttemptOnly: obs.AttemptOnly})
			added = true
		}
	}
	if userVisible {
		if _, duplicate := state.SeenFinal[logicalID]; !duplicate {
			state.SeenFinal[logicalID] = observedAt
			state.Failures = append(state.Failures, relayGuardianFailure{At: observedAt, LogicalRequestID: logicalID, StatusCode: obs.StatusCode, UserVisible: true})
			added = true
		}
	}
	if !added {
		g.mu.Unlock()
		return
	}
	state.LastFailureAt = observedAt
	trigger, window, finals, gateways := g.triggerLocked(obs.AccountID, state, now)
	if trigger == "" {
		if state.State != RelayGuardianWouldQuarantine && state.ShadowAction == "" && !state.LastResort {
			if gateways >= 3 {
				state.Reason = "strong_gateway_waiting_for_confirmed_breaker_cycle"
				state.TriggerSource = "strong_gateway_unconfirmed_3_in_5m"
				state.WindowSeconds = int((5 * time.Minute) / time.Second)
			} else {
				state.Reason = "upstream_http_" + strconv.Itoa(obs.StatusCode)
			}
		}
		if state.State == RelayGuardianHealthy {
			state.State = RelayGuardianSuspect
		}
		g.persistState(obs.AccountID, state)
		g.mu.Unlock()
		return
	}
	g.applyTriggerLocked(account, state, accounts, capacity, trigger, window, finals, gateways, now)
	g.mu.Unlock()
}

func (g *relayHealthGuardian) noteConfirmedCircuitCycleLocked(accountID int64, state *relayGuardianAccountState, now time.Time) {
	if g == nil || state == nil || accountID <= 0 {
		return
	}
	snapshot := g.store.RelayCircuitSnapshot(accountID)
	if snapshot.confirmedStrongCycleToken == 0 || (snapshot.State != RelayCircuitOpen && !snapshot.LastResort) ||
		!IsRelayStrongGatewayFailureStatus(snapshot.LastStatusCode) {
		return
	}
	if snapshot.confirmedStrongCycleToken == state.StrongCircuitCycleToken {
		return
	}
	if state.StrongCircuitCycleStartedAt.IsZero() || now.Before(state.StrongCircuitCycleStartedAt) || now.Sub(state.StrongCircuitCycleStartedAt) > relayGuardianStrongCycleWindow {
		state.StrongCircuitCycleCount = 1
		state.StrongCircuitCycleStartedAt = now
	} else {
		state.StrongCircuitCycleCount++
	}
	state.StrongCircuitCycleToken = snapshot.confirmedStrongCycleToken
	state.StrongCircuitCycleLastAt = now
}

// clearStrongCircuitCycleWindowLocked expires the rolling two-cycle window but
// deliberately preserves the last observed breaker token. The token is a
// process-epoch deduplication watermark: clearing it on recovery or window
// expiry would allow fresh raw observations to count the same old confirmed
// breaker cycle again. Mode/config/membership epoch resets replace or fully
// reset the Guardian state and clear the watermark separately.
func (g *relayHealthGuardian) clearStrongCircuitCycleWindowLocked(state *relayGuardianAccountState) {
	if state == nil {
		return
	}
	state.StrongCircuitCycleCount = 0
	state.StrongCircuitCycleStartedAt = time.Time{}
	state.StrongCircuitCycleLastAt = time.Time{}
}

func (g *relayHealthGuardian) triggerLocked(accountID int64, state *relayGuardianAccountState, now time.Time) (string, time.Duration, int, int) {
	count := func(window time.Duration, userVisible, strong bool) int {
		cutoff := now.Add(-window)
		seen := make(map[string]struct{})
		for _, f := range state.Failures {
			if f.At.Before(cutoff) || (userVisible && !f.UserVisible) || (strong && !f.StrongGateway) {
				continue
			}
			seen[f.LogicalRequestID] = struct{}{}
		}
		return len(seen)
	}
	strong5 := count(5*time.Minute, false, true)
	final5 := count(5*time.Minute, true, false)
	if strong5 >= 3 {
		g.noteConfirmedCircuitCycleLocked(accountID, state, now)
		if state.StrongCircuitCycleCount >= 2 && !state.StrongCircuitCycleLastAt.IsZero() && now.Sub(state.StrongCircuitCycleLastAt) <= relayGuardianStrongCycleWindow {
			return "strong_breaker_2_cycles_in_10m", relayGuardianStrongCycleWindow, final5, strong5
		}
	}
	if !state.StrongCircuitCycleLastAt.IsZero() && (now.Before(state.StrongCircuitCycleLastAt) || now.Sub(state.StrongCircuitCycleLastAt) > relayGuardianStrongCycleWindow) {
		g.clearStrongCircuitCycleWindowLocked(state)
	}
	return "", 0, final5, strong5
}

func relayGuardianWilsonLowerBound(failures, total int) float64 {
	if failures <= 0 || total <= 0 || failures > total {
		return 0
	}
	z := 1.959963984540054
	n := float64(total)
	p := float64(failures) / n
	z2 := z * z
	return (p + z2/(2*n) - z*math.Sqrt((p*(1-p)+z2/(4*n))/n)) / (1 + z2/n)
}

func relayGuardianWeakReliabilityDecision(snapshot relayGuardianReliabilitySnapshot) relayGuardianWeakDecision {
	decision := func(trigger string, window time.Duration, total, failures int, latest int64, catastrophic bool) relayGuardianWeakDecision {
		rate := 0.0
		if total > 0 {
			rate = float64(failures) / float64(total)
		}
		return relayGuardianWeakDecision{Trigger: trigger, Window: window, Total: total, Failures: failures,
			LatestFailureRowID: latest, Rate: rate, LowerBound: relayGuardianWilsonLowerBound(failures, total), Catastrophic: catastrophic}
	}
	rate10 := 0.0
	if snapshot.Total10m > 0 {
		rate10 = float64(snapshot.Failures10m) / float64(snapshot.Total10m)
	}
	if snapshot.Failures10m >= 10 && rate10 >= 0.20 {
		return decision("weak_reliability_catastrophic_10m", 10*time.Minute, snapshot.Total10m, snapshot.Failures10m, snapshot.LatestFailureRowID10m, true)
	}
	if snapshot.Failures10m >= 2 && relayGuardianWilsonLowerBound(snapshot.Failures10m, snapshot.Total10m) > 0.01 {
		return decision("weak_reliability_10m", 10*time.Minute, snapshot.Total10m, snapshot.Failures10m, snapshot.LatestFailureRowID10m, false)
	}
	if snapshot.Failures60m >= 4 && snapshot.Failures10m > 0 && relayGuardianWilsonLowerBound(snapshot.Failures60m, snapshot.Total60m) > 0.01 {
		return decision("weak_reliability_60m", 60*time.Minute, snapshot.Total60m, snapshot.Failures60m, snapshot.LatestFailureRowID60m, false)
	}
	return relayGuardianWeakDecision{}
}

func (g *relayHealthGuardian) resetWeakCandidateLocked(state *relayGuardianAccountState) {
	if state == nil {
		return
	}
	state.WeakCandidateTrigger = ""
	state.WeakCandidateLatestFailureRowID = 0
	state.WeakCandidateSince = time.Time{}
	state.WeakConfirmationCount = 0
}

func (g *relayHealthGuardian) applyReliabilityLocked(account *Account, state *relayGuardianAccountState, accounts []*Account,
	capacity []relayGuardianCapacityAccount, snapshot relayGuardianReliabilitySnapshot, now time.Time) bool {
	if state == nil || snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.Before(g.incidentEpoch) ||
		now.Sub(snapshot.ObservedAt) > 2*RelayGuardianScanInterval || snapshot.ObservedAt.After(now.Add(RelayGuardianScanInterval)) {
		return false
	}
	decision := relayGuardianWeakReliabilityDecision(snapshot)
	state.ReliabilityObservedAt = snapshot.ObservedAt
	if decision.Trigger == "" {
		state.ReliabilityTotal = snapshot.Total10m
		state.ReliabilityFailures = snapshot.Failures10m
		state.ReliabilityWindowSeconds = int((10 * time.Minute) / time.Second)
		state.FailureRatePercent = 0
		if snapshot.Total10m > 0 {
			state.FailureRatePercent = 100 * float64(snapshot.Failures10m) / float64(snapshot.Total10m)
		}
		state.FailureRateLowerBoundPercent = 100 * relayGuardianWilsonLowerBound(snapshot.Failures10m, snapshot.Total10m)
		state.ReliabilityLatestFailureRowID = snapshot.LatestFailureRowID10m
		hadCandidate := state.WeakConfirmationCount > 0 || state.WeakCandidateTrigger != ""
		g.resetWeakCandidateLocked(state)
		clearWeakExplanation := !state.LastResort && (hadCandidate || strings.HasPrefix(state.TriggerSource, "weak_reliability_"))
		if clearWeakExplanation {
			state.TriggerSource = ""
			state.WindowSeconds = 0
			state.Reason = "weak_reliability_below_threshold"
		}
		return false
	}
	state.ReliabilityTotal = decision.Total
	state.ReliabilityFailures = decision.Failures
	state.ReliabilityWindowSeconds = int(decision.Window / time.Second)
	state.FailureRatePercent = 100 * decision.Rate
	state.FailureRateLowerBoundPercent = 100 * decision.LowerBound
	state.ReliabilityLatestFailureRowID = decision.LatestFailureRowID
	if decision.Catastrophic {
		g.resetWeakCandidateLocked(state)
		g.applyTriggerLocked(account, state, accounts, capacity, decision.Trigger, decision.Window, decision.Failures, 0, now)
		return true
	}
	// Do not demote a still-active strong action merely because the DB also has
	// weak evidence. The handoff to weak confirmation starts only after the hot
	// 5-minute trigger has actually expired.
	oldNonWeakAction := (state.State == RelayGuardianWouldQuarantine || state.ShadowAction != "" || state.LastResort) &&
		!strings.HasPrefix(state.TriggerSource, "weak_reliability_")
	if oldNonWeakAction {
		if activeTrigger, _, _, _ := g.triggerLocked(account.DBID, state, now); activeTrigger != "" {
			g.resetWeakCandidateLocked(state)
			return true
		}
	}
	state.WindowSeconds = int(decision.Window / time.Second)
	// A pending weak candidate is only valid across adjacent successful scans.
	// Never let a stale 1/2 survive a scheduler pause, a missed reconcile or a
	// database outage and turn one fresh failure into a confirmed incident.
	if state.WeakConfirmationCount > 0 && state.WeakConfirmationCount < relayGuardianWeakConfirmations &&
		(state.WeakCandidateSince.IsZero() || now.Before(state.WeakCandidateSince) || now.Sub(state.WeakCandidateSince) > 2*RelayGuardianScanInterval) {
		g.resetWeakCandidateLocked(state)
	}
	// A confirmed weak incident remains confirmed when the statistically best
	// window changes between 10m and 60m. Re-run the action/capacity decision
	// immediately instead of creating a second confirmation cycle.
	confirmedWeak := state.WeakConfirmationCount >= relayGuardianWeakConfirmations && strings.HasPrefix(state.WeakCandidateTrigger, "weak_reliability_")
	if confirmedWeak {
		state.WeakCandidateTrigger = decision.Trigger
		state.WeakCandidateLatestFailureRowID = decision.LatestFailureRowID
		g.applyTriggerLocked(account, state, accounts, capacity, decision.Trigger, decision.Window, decision.Failures, 0, now)
		return true
	}
	// Monitor conclusions are reversible shadows. Once their strong/pool signal
	// has expired, a current weak signal must be allowed to start its own two-scan
	// confirmation instead of inheriting the old would-quarantine action.
	if g.store.GetRelayGuardianMode() == RelayGuardianMonitor && (state.State == RelayGuardianWouldQuarantine || state.ShadowAction != "") {
		state.State = RelayGuardianSuspect
		state.ShadowAction = ""
	}
	if state.WeakCandidateTrigger != decision.Trigger || state.WeakConfirmationCount == 0 {
		state.WeakCandidateTrigger = decision.Trigger
		state.WeakCandidateLatestFailureRowID = decision.LatestFailureRowID
		state.WeakCandidateSince = now
		state.WeakConfirmationCount = 1
		state.State = RelayGuardianSuspect
		state.Reason = "weak_reliability_confirming"
		state.TriggerSource = decision.Trigger
		g.persistState(account.DBID, state)
		return true
	}
	if now.Sub(state.WeakCandidateSince) >= RelayGuardianScanInterval && decision.LatestFailureRowID > state.WeakCandidateLatestFailureRowID {
		state.WeakCandidateLatestFailureRowID = decision.LatestFailureRowID
		if state.WeakConfirmationCount < relayGuardianWeakConfirmations {
			state.WeakConfirmationCount++
		}
	}
	if state.WeakConfirmationCount < relayGuardianWeakConfirmations {
		g.persistState(account.DBID, state)
		return true
	}
	g.applyTriggerLocked(account, state, accounts, capacity, decision.Trigger, decision.Window, decision.Failures, 0, now)
	return true
}

func (g *relayHealthGuardian) poolGuardLocked(accounts []*Account, candidateID int64, trigger string, triggerWindow time.Duration, now time.Time) bool {
	// Once a correlated pool incident is established, keep every trigger inside
	// that incident on the pool-safe path until the longest contributing trigger
	// window has elapsed. This also prevents a later single transport failure
	// from combining with already-classified pool evidence and decaying into an
	// account quarantine. The deadline is only set when correlation is observed;
	// reconcile calls never slide it forward.
	if g.poolWideUntil.After(now) {
		return true
	}
	enabled := make([]*Account, 0, len(accounts))
	for _, account := range accounts {
		if relayGuardianManualEnabled(account) {
			enabled = append(enabled, account)
		}
	}
	if len(enabled) < 2 {
		return false
	}
	candidateSignatures := relayGuardianCandidatePoolSignatures(g.states[candidateID], trigger, now)
	if len(candidateSignatures) == 0 {
		return false
	}
	var candidateSignature relayGuardianPoolFailureSignature
	affected := 0
	for _, signature := range candidateSignatures {
		matched := 0
		for _, account := range enabled {
			state := g.states[account.DBID]
			if state != nil && relayGuardianStateHasPoolSignature(state, signature, now) {
				matched++
			}
		}
		if matched >= 2 && matched*2 >= len(enabled) && matched > affected {
			candidateSignature = signature
			affected = matched
		}
	}
	if affected == 0 {
		return false
	}
	window := candidateSignature.window
	if triggerWindow > window {
		window = triggerWindow
	}
	g.poolWideUntil = now.Add(window)
	windowStart := now.UTC().Truncate(window)
	windowID := windowStart.Format(time.RFC3339) + "/" + window.String()
	eventKey := candidateSignature.key() + ":" + windowID
	for key, at := range g.poolEvents {
		if now.Sub(at) > 2*time.Hour {
			delete(g.poolEvents, key)
		}
	}
	if _, duplicate := g.poolEvents[eventKey]; !duplicate {
		g.poolEvents[eventKey] = now
		if state := g.states[candidateID]; state != nil {
			state.PoolWideReportedAt = now
		}
		g.recordSystemEvent(now, RelayGuardianEventPoolWide, "pool_wide_failure_guard", trigger, map[string]any{
			"signature": candidateSignature.key(), "affected": affected, "enabled": len(enabled), "window_id": windowID,
			"protected_until": g.poolWideUntil, "signature_window_seconds": int(candidateSignature.window / time.Second), "trigger_window_seconds": int(triggerWindow / time.Second),
		})
	}
	return true
}

func relayGuardianTriggerCategory(trigger string) string {
	switch {
	case strings.HasPrefix(trigger, "user_visible_"), strings.HasPrefix(trigger, "weak_reliability_"):
		return "user_visible"
	case strings.HasPrefix(trigger, "strong_gateway_"), strings.HasPrefix(trigger, "strong_breaker_"):
		return "strong_gateway"
	case strings.HasPrefix(trigger, "recovery_"):
		return "recovery"
	default:
		return trigger
	}
}

func relayGuardianTriggerWindow(trigger string) time.Duration {
	switch {
	case strings.Contains(trigger, "60m"):
		return 60 * time.Minute
	case strings.Contains(trigger, "10m"):
		return 10 * time.Minute
	case strings.HasPrefix(trigger, "strong_gateway_"), strings.HasPrefix(trigger, "strong_breaker_"), strings.HasPrefix(trigger, "recovery_"):
		return 5 * time.Minute
	default:
		return 0
	}
}

func relayGuardianRestoredPoolUntil(state *relayGuardianAccountState, now time.Time) time.Time {
	if state == nil || state.PoolWideReportedAt.IsZero() || state.Reason != "pool_wide_failure_guard" {
		return time.Time{}
	}
	window := time.Duration(state.WindowSeconds) * time.Second
	if minimum := relayGuardianTriggerWindow(state.TriggerSource); minimum > window {
		window = minimum
	}
	if window < 5*time.Minute {
		window = 5 * time.Minute
	}
	until := state.PoolWideReportedAt.Add(window)
	if !until.After(now) {
		return time.Time{}
	}
	return until
}

type relayGuardianPoolFailureSignature struct {
	category   string
	statusCode int
	window     time.Duration
}

func (signature relayGuardianPoolFailureSignature) key() string {
	if signature.category == "" || signature.statusCode == 0 {
		return ""
	}
	return signature.category + ":" + strconv.Itoa(signature.statusCode)
}

func relayGuardianCandidatePoolSignatures(state *relayGuardianAccountState, trigger string, now time.Time) []relayGuardianPoolFailureSignature {
	if state == nil || trigger == "" {
		return nil
	}
	category := relayGuardianTriggerCategory(trigger)
	window := 10 * time.Minute
	if category == "strong_gateway" || category == "recovery" {
		window = 5 * time.Minute
	}
	if strings.Contains(trigger, "60m") {
		window = 60 * time.Minute
	}
	cutoff := now.Add(-window)
	seen := make(map[string]struct{})
	result := make([]relayGuardianPoolFailureSignature, 0)
	for index := len(state.Failures) - 1; index >= 0; index-- {
		failure := state.Failures[index]
		if failure.At.Before(cutoff) {
			continue
		}
		matches := (category == "user_visible" && failure.UserVisible) ||
			(category == "strong_gateway" && failure.StrongGateway) ||
			(category == "recovery" && failure.Recovery)
		if !matches {
			continue
		}
		signature := relayGuardianPoolFailureSignature{category: category, statusCode: failure.StatusCode, window: window}
		if IsRelayStrongGatewayFailureStatus(failure.StatusCode) {
			if failure.At.Before(now.Add(-5 * time.Minute)) {
				continue
			}
			signature.category = "strong_gateway"
			signature.window = 5 * time.Minute
		}
		if _, duplicate := seen[signature.key()]; duplicate {
			continue
		}
		seen[signature.key()] = struct{}{}
		result = append(result, signature)
	}
	return result
}

func relayGuardianStateHasPoolSignature(state *relayGuardianAccountState, signature relayGuardianPoolFailureSignature, now time.Time) bool {
	if state == nil || signature.key() == "" || signature.window <= 0 {
		return false
	}
	cutoff := now.Add(-signature.window)
	for index := len(state.Failures) - 1; index >= 0; index-- {
		failure := state.Failures[index]
		if failure.At.Before(cutoff) {
			continue
		}
		if failure.StatusCode != signature.statusCode {
			continue
		}
		switch signature.category {
		case "strong_gateway":
			if failure.StrongGateway {
				return true
			}
		case "user_visible":
			if failure.UserVisible {
				return true
			}
		case "recovery":
			if failure.Recovery {
				return true
			}
		}
	}
	return false
}

func (g *relayHealthGuardian) capacityInputs(accounts []*Account) []relayGuardianCapacityAccount {
	base := atomic.LoadInt64(&g.store.maxConcurrency)
	result := make([]relayGuardianCapacityAccount, 0, len(accounts))
	for _, account := range accounts {
		if account == nil {
			continue
		}
		_, _, _, limit := account.schedulerSnapshot(base)
		result = append(result, relayGuardianCapacityAccount{
			account: account, manual: relayGuardianManualEnabled(account), available: account.IsAvailable(),
			active: account.GetActiveRequests(), limit: limit, lastCanonicalSuccessAt: relayGuardianCanonicalSuccessAt(account),
			circuit: g.store.RelayCircuitSnapshot(account.DBID),
		})
	}
	return result
}

func (g *relayHealthGuardian) capacityAllowsLocked(accounts []relayGuardianCapacityAccount, candidateID int64, now time.Time) (bool, string) {
	otherHealthy := 0
	staleHealthy := 0
	var remaining int64
	for _, input := range accounts {
		account := input.account
		if account.DBID == candidateID || !input.manual || !input.available {
			continue
		}
		state := g.states[account.DBID]
		if g.cache != nil && !g.loaded[account.DBID] {
			continue
		}
		guardianState := RelayGuardianHealthy
		if state != nil {
			guardianState = state.State
		}
		if guardianState != RelayGuardianHealthy && guardianState != RelayGuardianProbation {
			continue
		}
		if input.circuit.State == RelayCircuitOpen {
			continue
		}
		if input.lastCanonicalSuccessAt.IsZero() || input.lastCanonicalSuccessAt.After(now.Add(RelayGuardianScanInterval)) || now.Sub(input.lastCanonicalSuccessAt) > relayGuardianPeerSuccessFreshness {
			if guardianState == RelayGuardianHealthy && input.circuit.State == RelayCircuitClosed {
				staleHealthy++
			}
			continue
		}
		limit := input.limit
		if guardianState == RelayGuardianProbation {
			percent := state.ProbationPercent
			if percent != 50 {
				percent = 10
			}
			limit = limit * int64(percent) / 100
			if limit < 1 {
				limit = 1
			}
		}
		if input.circuit.State == RelayCircuitHalfOpen && limit > 1 {
			limit = 1
		}
		if input.circuit.State == RelayCircuitHalfOpen && input.circuit.ProbeInFlight {
			continue
		}
		active := input.active
		if limit > active {
			remaining += limit - active
		}
		if guardianState == RelayGuardianHealthy && input.circuit.State == RelayCircuitClosed {
			otherHealthy++
		}
	}
	if otherHealthy == 0 {
		if staleHealthy > 0 {
			return false, "peer_canonical_success_stale"
		}
		return false, "last_available_relay"
	}
	if !g.capacityWarmLocked(now) {
		return false, "capacity_warmup"
	}
	required := g.requiredCapacityLocked(now)
	if remaining < required {
		return false, "insufficient_remaining_capacity"
	}
	return true, ""
}

func (g *relayHealthGuardian) capacityWarmLocked(now time.Time) bool {
	g.requiredCapacityLocked(now)
	if len(g.capacitySamples) < 3 {
		return false
	}
	oldest := g.capacitySamples[0].At
	newest := oldest
	for _, sample := range g.capacitySamples[1:] {
		if sample.At.Before(oldest) {
			oldest = sample.At
		}
		if sample.At.After(newest) {
			newest = sample.At
		}
	}
	return newest.Sub(oldest) >= 2*RelayGuardianScanInterval
}

func (g *relayHealthGuardian) requiredCapacityLocked(now time.Time) int64 {
	cutoff := now.Add(-15 * time.Minute)
	values := make([]int64, 0, len(g.capacitySamples))
	kept := g.capacitySamples[:0]
	for _, sample := range g.capacitySamples {
		if sample.At.Before(cutoff) {
			continue
		}
		kept = append(kept, sample)
		values = append(values, sample.Active)
	}
	g.capacitySamples = kept
	if len(values) == 0 {
		return 1
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	idx := int(math.Ceil(float64(len(values))*0.95)) - 1
	if idx < 0 {
		idx = 0
	}
	return int64(math.Max(1, math.Ceil(float64(values[idx])*1.3)))
}

func (g *relayHealthGuardian) applyTriggerLocked(account *Account, state *relayGuardianAccountState, accounts []*Account, capacity []relayGuardianCapacityAccount, trigger string, window time.Duration, finals, gateways int, now time.Time) {
	mode := g.store.GetRelayGuardianMode()
	state.TriggerSource = trigger
	state.WindowSeconds = int(window / time.Second)
	if mode == RelayGuardianMonitor {
		previousAction := state.ShadowAction
		shadowAction := "quarantine"
		shadowReason := "shadow_quarantine"
		switch {
		case g.poolGuardLocked(accounts, account.DBID, trigger, window, now):
			shadowAction, shadowReason = "pool_alert", "pool_wide_failure_guard"
		case g.coldStartActiveLocked(now):
			shadowAction, shadowReason = "last_resort", "cold_start_guard"
		case !g.lastShadowQuarantine.IsZero() && now.Sub(g.lastShadowQuarantine) < RelayGuardianScanInterval && g.lastShadowQuarantineAccountID != account.DBID:
			shadowAction, shadowReason = "last_resort", "one_quarantine_per_scan_guard"
		default:
			if ok, reason := g.capacityAllowsLocked(capacity, account.DBID, now); !ok {
				shadowAction, shadowReason = "last_resort", reason
			}
		}
		if shadowAction == "quarantine" && previousAction != "quarantine" {
			g.lastShadowQuarantine = now
			g.lastShadowQuarantineAccountID = account.DBID
		}
		// Reason may legitimately vary as capacity warms or pool evidence ages.
		// The operator-visible shadow conclusion is the action; do not turn a
		// reason-only refresh into a new generation and duplicate event.
		changed := state.State != RelayGuardianWouldQuarantine || previousAction != shadowAction
		state.ShadowAction = shadowAction
		state.Reason = shadowReason
		if changed {
			from := state.State
			state.State = RelayGuardianWouldQuarantine
			state.Generation++
			state.LastActionAt = now
			g.recordEventLocked(account, RelayGuardianEventWouldQuarantine, from, state, "guardian", trigger, window, finals, gateways, 0)
		}
		g.persistState(account.DBID, state)
		return
	}
	state.ShadowAction = ""
	if mode != RelayGuardianEnforce || state.State == RelayGuardianQuarantined || state.State == RelayGuardianHalfOpen || state.State == RelayGuardianTemporaryBypass {
		g.persistState(account.DBID, state)
		return
	}
	if g.poolGuardLocked(accounts, account.DBID, trigger, window, now) {
		g.activateLastResortLocked(account, state, "pool_wide_failure_guard", trigger, window, finals, gateways, now)
		return
	}
	if g.coldStartActiveLocked(now) {
		g.activateLastResortLocked(account, state, "cold_start_guard", trigger, window, finals, gateways, now)
		return
	}
	if !g.lastNewQuarantine.IsZero() && now.Sub(g.lastNewQuarantine) < RelayGuardianScanInterval {
		g.activateLastResortLocked(account, state, "one_quarantine_per_scan_guard", trigger, window, finals, gateways, now)
		return
	}
	if ok, reason := g.capacityAllowsLocked(capacity, account.DBID, now); !ok {
		g.activateLastResortLocked(account, state, reason, trigger, window, finals, gateways, now)
		return
	}
	g.quarantineLocked(account, state, trigger, window, finals, gateways, now, false)
}

func (g *relayHealthGuardian) activateLastResortLocked(account *Account, state *relayGuardianAccountState, reason, trigger string, window time.Duration, finals, gateways int, now time.Time) {
	if account == nil || state == nil {
		return
	}
	from := state.State
	activated := false
	failureID := relayGuardianLatestFailureID(state)
	newCycle := !state.LastResort
	newFailure := failureID != "" && failureID != state.LastResortFailureID
	scanAdvanced := state.LastActionAt.IsZero() || now.Sub(state.LastActionAt) >= RelayGuardianScanInterval
	if newCycle || (newFailure && scanAdvanced) {
		state.LastResortLevel++
		if state.LastResortLevel < 1 {
			state.LastResortLevel = 1
		}
		state.Generation++
		state.LastActionAt = now
		activated = true
	}
	// Always consume the latest deduplicated failure ID. If several rows from
	// one scan arrive inside the 60s fence, they may update the diagnosis but
	// cannot be replayed by a later reconcile to raise the level again.
	if newFailure || newCycle {
		state.LastResortFailureID = failureID
	}
	state.State = RelayGuardianSuspect
	state.ShadowAction = ""
	state.LastResort = true
	state.LastResortCap = relayGuardianLastResortCap(state.LastResortLevel)
	state.Reason = reason
	state.TriggerSource = trigger
	state.WindowSeconds = int(window / time.Second)
	state.QuarantineUntil = time.Time{}
	state.ProbationPercent = 0
	state.ProbationSuccesses = 0
	state.ProbationStartedAt = time.Time{}
	state.halfOpenInFlight = false
	state.halfOpenLeaseID = 0
	state.permits = make(map[uint64]RelayGuardianPermit)
	relayGuardianSchedulingHint(account, true, int64(state.LastResortCap), 0)
	g.persistState(account.DBID, state)
	if from != state.State || activated {
		g.recordEventLocked(account, RelayGuardianEventLastResort, from, state, "guardian", trigger, window, finals, gateways, 0)
	}
}

func relayGuardianLatestFailureID(state *relayGuardianAccountState) string {
	if state == nil {
		return ""
	}
	for index := len(state.Failures) - 1; index >= 0; index-- {
		if logicalID := strings.TrimSpace(state.Failures[index].LogicalRequestID); logicalID != "" {
			return logicalID
		}
	}
	return ""
}

func (g *relayHealthGuardian) quarantineLocked(account *Account, state *relayGuardianAccountState, trigger string, window time.Duration, finals, gateways int, now time.Time, recoveryFailure bool) {
	from := state.State
	idx := state.BackoffLevel
	if idx < 0 {
		idx = 0
	}
	if idx >= len(relayGuardianReopenDurations) {
		idx = len(relayGuardianReopenDurations) - 1
	}
	duration := relayGuardianReopenDurations[idx]
	if recoveryFailure && state.BackoffLevel < len(relayGuardianReopenDurations)-1 {
		state.BackoffLevel++
		duration = relayGuardianReopenDurations[state.BackoffLevel]
	}
	state.State = RelayGuardianQuarantined
	state.ShadowAction = ""
	state.LastResort = false
	state.LastResortCap = 0
	state.LastResortFailureID = ""
	state.Generation++
	state.QuarantineUntil = now.Add(duration)
	state.LastActionAt = now
	state.TriggerSource = trigger
	state.WindowSeconds = int(window / time.Second)
	state.halfOpenInFlight = false
	state.halfOpenLeaseID = 0
	state.halfOpenSuccesses = 0
	state.ProbationPercent = 0
	state.ProbationSuccesses = 0
	state.ProbationStartedAt = time.Time{}
	state.permits = make(map[uint64]RelayGuardianPermit)
	relayGuardianSchedulingHint(account, false, 0, 0)
	g.lastNewQuarantine = now
	// The quarantine event must retain the confirmation evidence that caused
	// this transition. Clear the candidate only after the event value has been
	// assembled so no 2/2 fence can leak into recovery or the next incident.
	g.recordEventLocked(account, RelayGuardianEventQuarantine, from, state, "guardian", trigger, window, finals, gateways, duration)
	g.resetWeakCandidateLocked(state)
	g.persistState(account.DBID, state)
	log.Printf("[Relay guardian account=%d] quarantined for %s trigger=%s generation=%d", account.DBID, duration, trigger, state.Generation)
}

func (g *relayHealthGuardian) recordEventLocked(account *Account, eventType string, from RelayGuardianState, state *relayGuardianAccountState, actor, trigger string, window time.Duration, finals, gateways int, quarantine time.Duration) {
	if g.db == nil || account == nil || state == nil {
		return
	}
	eventTime := state.LastActionAt
	if eventTime.IsZero() {
		eventTime = g.nowTime()
	}
	effectiveWindow := window
	if effectiveWindow <= 0 && state.WindowSeconds > 0 {
		effectiveWindow = time.Duration(state.WindowSeconds) * time.Second
	}
	if effectiveWindow <= 0 {
		effectiveWindow = 10 * time.Minute
	}
	cutoff := eventTime.Add(-effectiveWindow)
	logical := make([]string, 0, len(state.Failures))
	seen := make(map[string]struct{})
	for _, f := range state.Failures {
		if f.At.Before(cutoff) || f.At.After(eventTime) {
			continue
		}
		if _, ok := seen[f.LogicalRequestID]; ok {
			continue
		}
		seen[f.LogicalRequestID] = struct{}{}
		logical = append(logical, f.LogicalRequestID)
	}
	failureCount := len(logical)
	if finals > failureCount {
		failureCount = finals
	}
	if gateways > failureCount {
		failureCount = gateways
	}
	if len(logical) > 20 {
		logical = logical[len(logical)-20:]
	}
	windowID := ""
	if window > 0 {
		windowID = eventTime.UTC().Truncate(window).Format(time.RFC3339) + "/" + window.String()
	}
	event := database.RelayGuardianEvent{
		CreatedAt: eventTime, AccountID: account.DBID, AccountName: account.DisplayName(), EventType: eventType,
		FromState: string(from), ToState: string(state.State), Actor: actor,
		Reason: state.Reason, TriggerSource: trigger, WindowSeconds: int(window / time.Second),
		FailureCount: failureCount, UserVisibleFailures: finals, StrongGatewayFailures: gateways,
		QuarantineSeconds: int(quarantine / time.Second), Generation: state.Generation,
		LogicalRequestIDs: logical,
		Details: map[string]any{"mode": g.store.GetRelayGuardianMode(), "probation_percent": state.ProbationPercent,
			"shadow_action": state.ShadowAction, "quarantine_until": state.QuarantineUntil, "event_time": eventTime, "window_id": windowID,
			"reliability_total": state.ReliabilityTotal, "reliability_failures": state.ReliabilityFailures,
			"reliability_window_seconds": state.ReliabilityWindowSeconds, "failure_rate_percent": state.FailureRatePercent,
			"failure_rate_lower_bound_percent": state.FailureRateLowerBoundPercent,
			"weak_confirmation_count":          state.WeakConfirmationCount, "weak_confirmation_required": relayGuardianWeakConfirmations},
	}
	g.recordEvent(event)
}

func (g *relayHealthGuardian) recordSystemEvent(eventTime time.Time, eventType, reason, trigger string, details map[string]any) {
	if g == nil || g.db == nil {
		return
	}
	if eventTime.IsZero() {
		eventTime = g.nowTime()
	}
	if details == nil {
		details = make(map[string]any)
	}
	details["mode"] = g.store.GetRelayGuardianMode()
	details["event_time"] = eventTime
	g.recordEvent(database.RelayGuardianEvent{CreatedAt: eventTime, EventType: eventType, Actor: "system", Reason: reason, TriggerSource: trigger, Details: details})
}

func (g *relayHealthGuardian) recordEvent(event database.RelayGuardianEvent) {
	if g == nil || g.db == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := g.db.InsertRelayGuardianEvent(ctx, &event); err != nil {
			log.Printf("insert Relay guardian event failed: %v", err)
		}
	}()
}

func (g *relayHealthGuardian) advanceTimeLocked(account *Account, state *relayGuardianAccountState, now time.Time) bool {
	if state.State == RelayGuardianTemporaryBypass && !state.TemporaryBypassUntil.After(now) {
		from := state.State
		if state.QuarantineUntil.After(now) {
			state.State = RelayGuardianQuarantined
		} else {
			state.State = RelayGuardianHalfOpen
		}
		state.Generation++
		state.LastActionAt = now
		g.resetWeakCandidateLocked(state)
		relayGuardianSchedulingHint(account, false, 0, 0)
		g.persistState(account.DBID, state)
		g.recordEventLocked(account, RelayGuardianEventBypassExpired, from, state, "system", state.TriggerSource, time.Duration(state.WindowSeconds)*time.Second, 0, 0, 0)
		return true
	}
	if state.State == RelayGuardianQuarantined && !state.QuarantineUntil.After(now) {
		from := state.State
		state.State = RelayGuardianHalfOpen
		state.Generation++
		state.halfOpenInFlight = false
		state.halfOpenSuccesses = 0
		state.LastActionAt = now
		g.resetWeakCandidateLocked(state)
		relayGuardianSchedulingHint(account, false, 0, 0)
		g.persistState(account.DBID, state)
		g.recordEventLocked(account, RelayGuardianEventHalfOpen, from, state, "system", state.TriggerSource, time.Duration(state.WindowSeconds)*time.Second, 0, 0, 0)
		return true
	}
	return false
}

func (g *relayHealthGuardian) selectable(account *Account) bool {
	if g == nil || account == nil || g.store.GetRelayGuardianMode() != RelayGuardianEnforce {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[account.DBID] && g.cache == nil {
		g.loaded[account.DBID] = true
	}
	if !g.loaded[account.DBID] {
		return false
	}
	state := g.stateLocked(account.DBID)
	g.advanceTimeLocked(account, state, g.nowTime())
	switch state.State {
	case RelayGuardianQuarantined:
		return false
	case RelayGuardianHalfOpen:
		return !state.halfOpenInFlight
	default:
		return true
	}
}

// normalCapacity reports whether Guardian considers an account stable pool
// capacity. Recovery-only entrances are intentionally stricter than
// selectable: half-open, probation, temporary bypass and last-resort traffic
// may serve bounded requests, but they must not be used as proof that another
// failing Relay front door can be removed safely.
func (g *relayHealthGuardian) normalCapacity(account *Account) bool {
	if g == nil || account == nil || g.store.GetRelayGuardianMode() != RelayGuardianEnforce {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[account.DBID] && g.cache == nil {
		g.loaded[account.DBID] = true
	}
	if !g.loaded[account.DBID] {
		return false
	}
	state := g.stateLocked(account.DBID)
	g.advanceTimeLocked(account, state, g.nowTime())
	if state.LastResort {
		return false
	}
	switch state.State {
	case RelayGuardianHealthy, RelayGuardianSuspect:
		return true
	default:
		return false
	}
}

func (g *relayHealthGuardian) begin(account *Account) (RelayGuardianPermit, bool) {
	if g == nil || account == nil || g.store.GetRelayGuardianMode() != RelayGuardianEnforce {
		return RelayGuardianPermit{}, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[account.DBID] && g.cache == nil {
		g.loaded[account.DBID] = true
	}
	if !g.loaded[account.DBID] {
		return RelayGuardianPermit{}, false
	}
	state := g.stateLocked(account.DBID)
	g.advanceTimeLocked(account, state, g.nowTime())
	if state.State == RelayGuardianQuarantined {
		return RelayGuardianPermit{}, false
	}
	if state.State != RelayGuardianHalfOpen && state.State != RelayGuardianProbation {
		return RelayGuardianPermit{}, true
	}
	if state.State == RelayGuardianHalfOpen && state.halfOpenInFlight {
		return RelayGuardianPermit{}, false
	}
	g.nextLease++
	if g.nextLease == 0 {
		g.nextLease++
	}
	permit := RelayGuardianPermit{AccountID: account.DBID, Generation: state.Generation, LeaseID: g.nextLease, HalfOpen: state.State == RelayGuardianHalfOpen, Probation: state.State == RelayGuardianProbation, Active: true}
	state.permits[permit.LeaseID] = permit
	if permit.HalfOpen {
		state.halfOpenInFlight = true
		state.halfOpenLeaseID = permit.LeaseID
	}
	return permit, true
}

func (g *relayHealthGuardian) consumePermitLocked(state *relayGuardianAccountState, permit RelayGuardianPermit) bool {
	if state == nil || !permit.Active {
		return false
	}
	issued, ok := state.permits[permit.LeaseID]
	if !ok || issued.Generation != permit.Generation || issued.AccountID != permit.AccountID {
		return false
	}
	delete(state.permits, permit.LeaseID)
	return true
}

func (g *relayHealthGuardian) finishFailure(permit RelayGuardianPermit, statusCode int) {
	if g == nil || !permit.Active || !relayGuardianAttributable(RelayGuardianObservation{StatusCode: statusCode}) {
		return
	}
	account := g.store.FindByID(permit.AccountID)
	if account == nil {
		return
	}
	accounts := g.store.configuredRelayGuardianAccounts()
	capacity := g.capacityInputs(accounts)
	g.mu.Lock()
	if !g.loaded[permit.AccountID] {
		g.mu.Unlock()
		return
	}
	state := g.stateLocked(permit.AccountID)
	if !g.consumePermitLocked(state, permit) || state.Generation != permit.Generation {
		g.mu.Unlock()
		return
	}
	now := g.nowTime()
	trigger := "recovery_failure_" + strconv.Itoa(statusCode)
	state.Failures = append(state.Failures, relayGuardianFailure{At: now, LogicalRequestID: fmt.Sprintf("recovery-%d", permit.LeaseID), StatusCode: statusCode, Recovery: true})
	state.LastFailureAt = now
	g.trimLocked(state, now)
	state.Reason = "recovery_upstream_http_" + strconv.Itoa(statusCode)
	state.HealthySince = time.Time{}
	plannedBackoff := state.BackoffLevel
	if plannedBackoff < len(relayGuardianReopenDurations)-1 {
		plannedBackoff++
	}
	if g.poolGuardLocked(accounts, account.DBID, trigger, 5*time.Minute, now) {
		state.BackoffLevel = plannedBackoff
		g.activateLastResortLocked(account, state, "pool_wide_failure_guard", trigger, 5*time.Minute, 0, 0, now)
		g.mu.Unlock()
		return
	}
	if !g.lastNewQuarantine.IsZero() && now.Sub(g.lastNewQuarantine) < RelayGuardianScanInterval {
		state.BackoffLevel = plannedBackoff
		g.activateLastResortLocked(account, state, "one_quarantine_per_scan_guard", trigger, 5*time.Minute, 0, 0, now)
		g.mu.Unlock()
		return
	}
	if ok, reason := g.capacityAllowsLocked(capacity, account.DBID, now); !ok {
		state.BackoffLevel = plannedBackoff
		g.activateLastResortLocked(account, state, reason, trigger, 5*time.Minute, 0, 0, now)
		g.mu.Unlock()
		return
	}
	g.quarantineLocked(account, state, trigger, 5*time.Minute, 0, 0, now, true)
	g.mu.Unlock()
}

func (g *relayHealthGuardian) finishSuccess(permit RelayGuardianPermit) {
	if g == nil || !permit.Active {
		return
	}
	account := g.store.FindByID(permit.AccountID)
	if account == nil {
		return
	}
	g.mu.Lock()
	if !g.loaded[permit.AccountID] {
		g.mu.Unlock()
		return
	}
	state := g.stateLocked(permit.AccountID)
	if !g.consumePermitLocked(state, permit) || state.Generation != permit.Generation {
		g.mu.Unlock()
		return
	}
	now := g.nowTime()
	from := state.State
	if permit.HalfOpen && state.State == RelayGuardianHalfOpen {
		state.halfOpenInFlight = false
		state.halfOpenLeaseID = 0
		state.halfOpenSuccesses++
		if state.halfOpenSuccesses >= 3 {
			state.State = RelayGuardianProbation
			state.Generation++
			state.ProbationPercent = 10
			state.ProbationSuccesses = 0
			state.ProbationStartedAt = now
			state.LastActionAt = now
			state.permits = make(map[uint64]RelayGuardianPermit)
			relayGuardianSchedulingHint(account, false, 0, 10)
			g.recordEventLocked(account, RelayGuardianEventProbation, from, state, "system", state.TriggerSource, 0, 0, 0, 0)
		}
		g.persistState(account.DBID, state)
		g.mu.Unlock()
		return
	}
	if permit.Probation && state.State == RelayGuardianProbation {
		state.ProbationSuccesses++
		if state.ProbationSuccesses >= relayGuardianProbationSuccesses && now.Sub(state.ProbationStartedAt) >= relayGuardianProbationStage {
			if state.ProbationPercent <= 10 {
				state.Generation++
				state.ProbationPercent = 50
				state.ProbationSuccesses = 0
				state.ProbationStartedAt = now
				state.LastActionAt = now
				state.permits = make(map[uint64]RelayGuardianPermit)
				relayGuardianSchedulingHint(account, false, 0, 50)
				g.recordEventLocked(account, RelayGuardianEventProbation, from, state, "system", state.TriggerSource, 0, 0, 0, 0)
			} else {
				state.State = RelayGuardianHealthy
				state.Generation++
				state.Reason = ""
				state.TriggerSource = ""
				state.WindowSeconds = 0
				state.QuarantineUntil = time.Time{}
				state.ProbationPercent = 0
				state.ProbationSuccesses = 0
				state.ProbationStartedAt = time.Time{}
				state.LastActionAt = now
				state.HealthySince = now
				state.Failures = nil
				state.SeenStrong = make(map[string]time.Time)
				state.SeenFinal = make(map[string]time.Time)
				state.permits = make(map[uint64]RelayGuardianPermit)
				g.resetWeakCandidateLocked(state)
				g.clearStrongCircuitCycleWindowLocked(state)
				relayGuardianSchedulingHint(account, false, 0, 0)
				g.recordEventLocked(account, RelayGuardianEventRecovered, from, state, "system", "probation_complete", 0, 0, 0, 0)
			}
		}
		g.persistState(account.DBID, state)
	}
	g.mu.Unlock()
}

func (g *relayHealthGuardian) abandon(permit RelayGuardianPermit) {
	if g == nil || !permit.Active {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[permit.AccountID] {
		return
	}
	state := g.stateLocked(permit.AccountID)
	if !g.consumePermitLocked(state, permit) {
		return
	}
	if permit.HalfOpen && state.halfOpenLeaseID == permit.LeaseID {
		state.halfOpenInFlight = false
		state.halfOpenLeaseID = 0
		g.persistState(permit.AccountID, state)
	}
}

func (g *relayHealthGuardian) sampleCapacityLocked(accounts []*Account, now time.Time) {
	var active int64
	for _, account := range accounts {
		active += account.GetActiveRequests()
	}
	g.capacitySamples = append(g.capacitySamples, relayGuardianCapacitySample{At: now, Active: active})
	g.requiredCapacityLocked(now)
}

func (g *relayHealthGuardian) ageStateLocked(account *Account, state *relayGuardianAccountState, now time.Time) {
	if state == nil {
		return
	}
	switch state.State {
	case RelayGuardianQuarantined, RelayGuardianHalfOpen, RelayGuardianProbation, RelayGuardianTemporaryBypass:
		return
	}
	if len(state.Failures) > 0 {
		clearedAction := state.State == RelayGuardianWouldQuarantine || state.ShadowAction != ""
		clearedUnconfirmedStrong := strings.HasPrefix(state.TriggerSource, "strong_gateway_unconfirmed_")
		state.ShadowAction = ""
		state.HealthySince = time.Time{}
		if state.State == RelayGuardianHealthy || state.State == RelayGuardianWouldQuarantine {
			state.State = RelayGuardianSuspect
		}
		if !state.LastResort {
			state.TriggerSource = ""
			state.WindowSeconds = 0
			if clearedAction || clearedUnconfirmedStrong {
				state.Reason = "recent_failure_observed"
			}
		}
		return
	}
	state.State = RelayGuardianHealthy
	state.Reason = ""
	state.TriggerSource = ""
	state.WindowSeconds = 0
	state.LastResort = false
	state.LastResortCap = 0
	state.LastResortFailureID = ""
	state.ShadowAction = ""
	g.resetWeakCandidateLocked(state)
	g.clearStrongCircuitCycleWindowLocked(state)
	if state.HealthySince.IsZero() {
		state.HealthySince = now
	}
	relayGuardianSchedulingHint(account, false, 0, 0)
	if now.Sub(state.HealthySince) >= 24*time.Hour {
		state.BackoffLevel = 0
		state.LastResortLevel = 0
	}
}

func (g *relayHealthGuardian) summaryDetailsLocked(accounts []*Account, now time.Time) map[string]any {
	counts := map[string]int{"configured": len(accounts)}
	for _, account := range accounts {
		if !relayGuardianManualEnabled(account) {
			counts["manual_disabled"]++
			continue
		}
		if !g.loaded[account.DBID] {
			counts["unknown"]++
			continue
		}
		state := g.states[account.DBID]
		if state == nil {
			counts[string(RelayGuardianHealthy)]++
			continue
		}
		counts[string(state.State)]++
		if state.LastResort {
			counts["last_resort"]++
		}
		if state.ShadowAction != "" {
			counts["shadow_"+state.ShadowAction]++
		}
	}
	return map[string]any{"counts": counts, "window_id": now.UTC().Truncate(5*time.Minute).Format(time.RFC3339) + "/5m"}
}

func (g *relayHealthGuardian) loadReliability(ctx context.Context, groupID int64, incidentEpoch, now time.Time) (map[int64]relayGuardianReliabilitySnapshot, error) {
	if g == nil || g.db == nil || groupID <= 0 {
		return nil, nil
	}
	// Leave a two-minute maturity gap so a retry/fallback chain has time to
	// append its terminal row before weak reliability evaluates it. The strong
	// gateway breaker remains entirely on the real-time observation path.
	matureEnd := now.Add(-2 * time.Minute)
	if !matureEnd.After(incidentEpoch) {
		return map[int64]relayGuardianReliabilitySnapshot{}, nil
	}
	start := matureEnd.Add(-60 * time.Minute)
	if start.Before(incidentEpoch) {
		start = incidentEpoch
	}
	if !matureEnd.After(start) {
		return map[int64]relayGuardianReliabilitySnapshot{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, relayGuardianDBTimeout)
	defer cancel()
	rows, err := g.db.ListRelayGuardianReliability(queryCtx, groupID, start, matureEnd.Add(-10*time.Minute), matureEnd, now)
	if err != nil {
		return nil, err
	}
	result := make(map[int64]relayGuardianReliabilitySnapshot, len(rows))
	for _, row := range rows {
		result[row.AccountID] = relayGuardianReliabilitySnapshot{
			AccountID: row.AccountID, ObservedAt: now,
			Total10m: row.Total10m, Failures10m: row.Failures10m, LatestFailureRowID10m: row.LatestFailureRowID10m,
			Total60m: row.Total60m, Failures60m: row.Failures60m, LatestFailureRowID60m: row.LatestFailureRowID60m,
		}
	}
	return result, nil
}

func (g *relayHealthGuardian) reconcile(ctx context.Context) {
	if g == nil {
		return
	}
	now := g.nowTime()
	mode := g.store.GetRelayGuardianMode()
	groupID := g.store.GetCybRelayConfig().GroupID
	g.mu.Lock()
	epochForReliability := g.incidentEpoch
	queryReliability := g.db != nil && mode != RelayGuardianOff && !g.reliabilityInFlight &&
		(g.lastReliabilityQuery.IsZero() || now.Sub(g.lastReliabilityQuery) >= RelayGuardianScanInterval)
	if queryReliability {
		g.reliabilityInFlight = true
		g.lastReliabilityQuery = now
	}
	g.mu.Unlock()
	var reliability map[int64]relayGuardianReliabilitySnapshot
	reliabilityOK := false
	if queryReliability {
		var reliabilityErr error
		reliability, reliabilityErr = g.loadReliability(ctx, groupID, epochForReliability, now)
		g.mu.Lock()
		scopeMatches := g.incidentEpoch.Equal(epochForReliability) && g.store.GetRelayGuardianMode() == mode && g.store.GetCybRelayConfig().GroupID == groupID
		g.reliabilityInFlight = false
		if scopeMatches && reliabilityErr != nil {
			if g.reliabilityConsecutiveErrors == 0 {
				g.reliabilityFailureSince = now
			}
			g.reliabilityConsecutiveErrors++
			g.lastReliabilityError = now
			// Two confirmations must come from adjacent successful DB scans. A
			// query gap invalidates every pending 1/2 candidate, while already
			// confirmed actions remain untouched.
			for accountID, state := range g.states {
				if state != nil && state.WeakConfirmationCount > 0 && state.WeakConfirmationCount < relayGuardianWeakConfirmations {
					g.resetWeakCandidateLocked(state)
					g.persistState(accountID, state)
				}
			}
		} else if scopeMatches {
			g.reliabilityConsecutiveErrors = 0
			g.reliabilityFailureSince = time.Time{}
			g.lastReliabilitySuccess = now
		}
		g.mu.Unlock()
		if reliabilityErr != nil {
			log.Printf("Relay guardian reliability aggregation failed; weak quarantine suppressed: %v", reliabilityErr)
		} else if scopeMatches {
			reliabilityOK = true
		}
	}
	allAccounts := g.store.Accounts()
	allByID := make(map[int64]*Account, len(allAccounts))
	for _, account := range allAccounts {
		if account != nil {
			allByID[account.DBID] = account
		}
	}
	accounts := g.store.configuredRelayGuardianAccounts()
	currentIDs := make(map[int64]struct{}, len(accounts))
	for _, account := range accounts {
		currentIDs[account.DBID] = struct{}{}
	}
	for _, account := range accounts {
		g.store.relayCircuitManager().ensureLoaded(account.DBID)
		g.ensureLoaded(account.DBID)
	}
	capacity := g.capacityInputs(accounts)
	removedIDs := make([]int64, 0)
	g.mu.Lock()
	g.heartbeat = now
	g.sampleCapacityLocked(accounts, now)
	for accountID := range g.states {
		if _, current := currentIDs[accountID]; current {
			continue
		}
		removedIDs = append(removedIDs, accountID)
		relayGuardianSchedulingHint(allByID[accountID], false, 0, 0)
		delete(g.states, accountID)
		delete(g.loaded, accountID)
		delete(g.loading, accountID)
		delete(g.retryLoad, accountID)
	}
	for _, account := range accounts {
		if !g.loaded[account.DBID] {
			continue
		}
		state := g.stateLocked(account.DBID)
		state.LastScanAt = now
		g.trimLocked(state, now)
		g.advanceTimeLocked(account, state, now)
		if !relayGuardianManualEnabled(account) {
			if state.WeakConfirmationCount > 0 && state.WeakConfirmationCount < relayGuardianWeakConfirmations {
				g.resetWeakCandidateLocked(state)
			}
			relayGuardianSchedulingHint(account, false, 0, 0)
			g.ageStateLocked(account, state, now)
			g.persistState(account.DBID, state)
			continue
		}
		// Manual re-enable and same-DBID Account replacement both create a
		// zero-valued Account hint. Re-derive it every reconcile from the
		// authoritative in-memory state before making further transitions.
		relayGuardianApplySchedulingHint(account, state)
		eligibleForTrigger := state.State != RelayGuardianQuarantined && state.State != RelayGuardianHalfOpen && state.State != RelayGuardianProbation && state.State != RelayGuardianTemporaryBypass
		if mode != RelayGuardianOff && eligibleForTrigger {
			trigger, window, finals, gateways := g.triggerLocked(account.DBID, state, now)
			if trigger != "" {
				g.applyTriggerLocked(account, state, accounts, capacity, trigger, window, finals, gateways, now)
				continue
			}
			if reliabilityOK {
				snapshot := reliability[account.DBID]
				snapshot.AccountID = account.DBID
				snapshot.ObservedAt = now
				if g.applyReliabilityLocked(account, state, accounts, capacity, snapshot, now) {
					continue
				}
			}
		}
		if reliabilityOK && !eligibleForTrigger {
			// Keep operator-facing reliability metrics current during quarantine
			// and recovery without allowing the weak path to change those states.
			snapshot := reliability[account.DBID]
			snapshot.ObservedAt = now
			decision := relayGuardianWeakReliabilityDecision(snapshot)
			state.ReliabilityObservedAt = now
			if decision.Trigger != "" {
				state.ReliabilityTotal, state.ReliabilityFailures = decision.Total, decision.Failures
				state.ReliabilityWindowSeconds = int(decision.Window / time.Second)
				state.FailureRatePercent, state.FailureRateLowerBoundPercent = 100*decision.Rate, 100*decision.LowerBound
				state.ReliabilityLatestFailureRowID = decision.LatestFailureRowID
			} else {
				state.ReliabilityTotal, state.ReliabilityFailures = snapshot.Total10m, snapshot.Failures10m
				state.ReliabilityWindowSeconds = int((10 * time.Minute) / time.Second)
				state.FailureRatePercent = 0
				if snapshot.Total10m > 0 {
					state.FailureRatePercent = 100 * float64(snapshot.Failures10m) / float64(snapshot.Total10m)
				}
				state.FailureRateLowerBoundPercent = 100 * relayGuardianWilsonLowerBound(snapshot.Failures10m, snapshot.Total10m)
				state.ReliabilityLatestFailureRowID = snapshot.LatestFailureRowID10m
			}
		}
		g.ageStateLocked(account, state, now)
		g.persistState(account.DBID, state)
	}
	summaryDue := g.db != nil && (g.lastSummary.IsZero() || now.Sub(g.lastSummary) >= 5*time.Minute)
	var summary map[string]any
	if summaryDue {
		g.lastSummary = now
		summary = g.summaryDetailsLocked(accounts, now)
	}
	epoch := g.incidentEpoch
	end := now.Add(-2 * time.Minute)
	start := g.lastScan
	if start.IsZero() || start.Before(epoch) {
		start = epoch
	}
	auditDue := g.lastAudit.IsZero() || now.Sub(g.lastAudit) >= time.Hour
	doScan := g.db != nil && mode != RelayGuardianOff && !g.scanInFlight && end.After(start)
	if doScan {
		g.scanInFlight = true
	}
	g.mu.Unlock()
	for _, accountID := range removedIDs {
		if g.cache == nil || groupID <= 0 {
			break
		}
		cacheCtx, cancel := relayGuardianCacheContext()
		err := g.cache.DeleteRuntime(cacheCtx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID))
		cancel()
		if err != nil {
			log.Printf("[Relay guardian account=%d] clear removed account state failed: %v", accountID, err)
		}
	}
	if summaryDue {
		g.recordSystemEvent(now, RelayGuardianEventSummary, "periodic_summary", "5m", summary)
	}
	if !doScan {
		return
	}
	count, scanErr := g.scanUsageFallback(ctx, groupID, mode, epoch, start, end)
	auditCount := 0
	var auditErr error
	if scanErr == nil && auditDue {
		auditStart := now.Add(-time.Hour)
		if auditStart.Before(epoch) {
			auditStart = epoch
		}
		if end.After(auditStart) {
			auditCount, auditErr = g.scanUsageFallback(ctx, groupID, mode, epoch, auditStart, end)
		}
	}
	g.mu.Lock()
	if g.incidentEpoch.Equal(epoch) && g.store.GetRelayGuardianMode() == mode && g.store.GetCybRelayConfig().GroupID == groupID {
		if scanErr == nil && end.After(g.lastScan) {
			g.lastScan = end
		}
		if scanErr == nil && auditDue && auditErr == nil {
			g.lastAudit = now
		}
	}
	g.scanInFlight = false
	g.mu.Unlock()
	if scanErr != nil {
		log.Printf("Relay guardian fallback scan failed without watermark advance: %v", scanErr)
		return
	}
	if auditDue && auditErr == nil {
		g.recordSystemEvent(now, RelayGuardianEventAudit, "hourly_full_audit", "1h", map[string]any{"incremental_rows": count, "audit_rows": auditCount, "window_id": now.UTC().Truncate(time.Hour).Format(time.RFC3339) + "/1h"})
		if deleted, err := g.db.DeleteRelayGuardianEventsBefore(ctx, now.Add(-90*24*time.Hour)); err != nil {
			log.Printf("Relay guardian event retention cleanup failed: %v", err)
		} else if deleted > 0 {
			log.Printf("Relay guardian event retention removed %d rows", deleted)
		}
	} else if auditErr != nil {
		log.Printf("Relay guardian hourly audit failed: %v", auditErr)
	}
}

func (g *relayHealthGuardian) scanUsageFallback(ctx context.Context, groupID int64, mode RelayGuardianMode, incidentEpoch, start, end time.Time) (int, error) {
	if !end.After(start) {
		return 0, nil
	}
	rows, err := g.db.ListRelayGuardianUsage(ctx, groupID, start, end, 100000)
	if err != nil {
		return 0, err
	}
	if len(rows) >= 100000 {
		return 0, errors.New("relay guardian fallback result reached safety limit")
	}
	lastLogicalRow := make(map[string]int64, len(rows))
	for _, row := range rows {
		if row.LogicalRequestID != "" && row.ID > lastLogicalRow[row.LogicalRequestID] {
			lastLogicalRow[row.LogicalRequestID] = row.ID
		}
	}
	for _, row := range rows {
		if row.CreatedAt.Before(incidentEpoch) {
			continue
		}
		g.mu.Lock()
		scopeMatches := g.incidentEpoch.Equal(incidentEpoch)
		g.mu.Unlock()
		if !scopeMatches || g.store.GetRelayGuardianMode() != mode || g.store.GetCybRelayConfig().GroupID != groupID {
			return 0, errors.New("relay guardian scope changed during fallback scan")
		}
		attemptOnly := row.GuardianAttemptOnly || lastLogicalRow[row.LogicalRequestID] != row.ID
		obs := RelayGuardianObservation{AccountID: row.AccountID, LogicalRequestID: row.LogicalRequestID, StatusCode: row.StatusCode, UpstreamErrorKind: row.UpstreamErrorKind, ErrorMessage: row.ErrorMessage, RouteClass: row.RouteClass, RouteSource: row.RouteSource, RouteGroupID: row.RouteGroupID, UpstreamAccountType: row.UpstreamAccountType, AttemptOnly: attemptOnly, ObservedAt: row.CreatedAt}
		g.observe(obs)
	}
	return len(rows), nil
}

func (g *relayHealthGuardian) release(accountID int64, generation uint64) error {
	if g.store.GetRelayGuardianMode() != RelayGuardianEnforce {
		return ErrRelayGuardianNotEnforcing
	}
	account := g.store.FindByID(accountID)
	if account == nil {
		return database.ErrRelayGuardianAccountNotFound
	}
	g.ensureLoaded(accountID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[accountID] {
		return ErrRelayGuardianRuntimeUnavailable
	}
	state := g.stateLocked(accountID)
	if state.Generation != generation {
		return ErrRelayGuardianStaleGeneration
	}
	if state.State != RelayGuardianQuarantined {
		return ErrRelayGuardianInvalidState
	}
	if !relayGuardianManualEnabled(account) {
		return ErrRelayGuardianInvalidState
	}
	from := state.State
	state.State = RelayGuardianHalfOpen
	state.Generation++
	state.QuarantineUntil = g.nowTime()
	state.halfOpenInFlight = false
	state.halfOpenSuccesses = 0
	state.LastActionAt = g.nowTime()
	state.permits = make(map[uint64]RelayGuardianPermit)
	g.resetWeakCandidateLocked(state)
	relayGuardianSchedulingHint(account, false, 0, 0)
	g.persistState(accountID, state)
	g.recordEventLocked(account, RelayGuardianEventRelease, from, state, "admin", "manual_release", 0, 0, 0, 0)
	return nil
}

func (g *relayHealthGuardian) temporaryBypass(accountID int64, generation uint64, minutes int) error {
	if g.store.GetRelayGuardianMode() != RelayGuardianEnforce {
		return ErrRelayGuardianNotEnforcing
	}
	if minutes < 1 {
		minutes = 1
	}
	if minutes > 60 {
		minutes = 60
	}
	account := g.store.FindByID(accountID)
	if account == nil {
		return database.ErrRelayGuardianAccountNotFound
	}
	g.ensureLoaded(accountID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.loaded[accountID] {
		return ErrRelayGuardianRuntimeUnavailable
	}
	state := g.stateLocked(accountID)
	if state.Generation != generation {
		return ErrRelayGuardianStaleGeneration
	}
	if !relayGuardianManualEnabled(account) {
		return ErrRelayGuardianInvalidState
	}
	if state.State != RelayGuardianQuarantined && state.State != RelayGuardianHalfOpen && state.State != RelayGuardianProbation {
		return ErrRelayGuardianInvalidState
	}
	from := state.State
	state.BypassReturnState = from
	state.State = RelayGuardianTemporaryBypass
	state.Generation++
	state.TemporaryBypassUntil = g.nowTime().Add(time.Duration(minutes) * time.Minute)
	state.LastActionAt = g.nowTime()
	state.halfOpenInFlight = false
	state.halfOpenLeaseID = 0
	state.permits = make(map[uint64]RelayGuardianPermit)
	relayGuardianSchedulingHint(account, false, 0, 0)
	g.persistState(accountID, state)
	g.recordEventLocked(account, RelayGuardianEventBypass, from, state, "admin", "temporary_bypass", 0, 0, 0, time.Duration(minutes)*time.Minute)
	return nil
}

func (g *relayHealthGuardian) status() RelayGuardianStatus {
	now := g.nowTime()
	result := RelayGuardianStatus{Enabled: g.store.GetRelayGuardianMode() != RelayGuardianOff, Mode: g.store.GetRelayGuardianMode(), GeneratedAt: now, ScanIntervalSeconds: int(RelayGuardianScanInterval / time.Second), ReliabilityQueryStatus: "pending"}
	g.mu.Lock()
	result.HeartbeatAt = relayGuardianTimePtr(g.heartbeat)
	result.ReliabilityConsecutiveErrors = g.reliabilityConsecutiveErrors
	result.ReliabilityLastSuccessAt = relayGuardianTimePtr(g.lastReliabilitySuccess)
	result.ReliabilityLastErrorAt = relayGuardianTimePtr(g.lastReliabilityError)
	result.ColdStartActive = g.coldStartActiveLocked(now)
	result.ColdStartUntil = relayGuardianTimePtr(g.coldStartUntil)
	if !result.Enabled {
		result.ReliabilityQueryStatus = "disabled"
	} else if g.reliabilityConsecutiveErrors > 0 {
		result.ReliabilityQueryStatus = "retrying"
		if g.reliabilityConsecutiveErrors >= 3 || (!g.reliabilityFailureSince.IsZero() && now.Sub(g.reliabilityFailureSince) >= 3*RelayGuardianScanInterval) {
			result.ReliabilityQueryStatus = "degraded"
		}
	} else if !g.lastReliabilitySuccess.IsZero() {
		result.ReliabilityQueryStatus = "ok"
	}
	g.mu.Unlock()
	for _, account := range g.store.configuredRelayGuardianAccounts() {
		g.ensureLoaded(account.DBID)
		g.mu.Lock()
		if !g.loaded[account.DBID] {
			manual := relayGuardianManualEnabled(account)
			displayState := RelayGuardianSuspect
			if !manual {
				displayState = RelayGuardianManualDisabled
			}
			snapshot := RelayGuardianAccountSnapshot{AccountID: account.DBID, AccountName: account.DisplayName(), ManualEnabled: manual, State: displayState, EffectiveSchedulable: manual && account.IsAvailable() && g.store.GetRelayGuardianMode() != RelayGuardianEnforce, Reason: "runtime_state_unavailable", ProbationRequiredSuccesses: relayGuardianProbationSuccesses, WeakConfirmationRequired: relayGuardianWeakConfirmations, LastCanonicalSuccessAt: relayGuardianTimePtr(relayGuardianCanonicalSuccessAt(account))}
			g.mu.Unlock()
			result.Accounts = append(result.Accounts, g.decorateCircuitSnapshot(snapshot, now))
			continue
		}
		state := g.stateLocked(account.DBID)
		g.trimLocked(state, now)
		failureIDs := make(map[string]struct{})
		finalIDs := make(map[string]struct{})
		strongIDs := make(map[string]struct{})
		countWindow := 60 * time.Minute
		if state.WindowSeconds > 0 {
			countWindow = time.Duration(state.WindowSeconds) * time.Second
			if countWindow > 60*time.Minute {
				countWindow = 60 * time.Minute
			}
		}
		countCutoff := now.Add(-countWindow)
		strongCutoff := now.Add(-5 * time.Minute)
		for _, f := range state.Failures {
			if f.StrongGateway && !f.At.Before(strongCutoff) {
				strongIDs[f.LogicalRequestID] = struct{}{}
			}
			if f.At.Before(countCutoff) {
				continue
			}
			failureIDs[f.LogicalRequestID] = struct{}{}
			if f.UserVisible {
				finalIDs[f.LogicalRequestID] = struct{}{}
			}
		}
		manual := relayGuardianManualEnabled(account)
		displayState := state.State
		if !manual {
			displayState = RelayGuardianManualDisabled
		}
		effective := manual && account.IsAvailable() && displayState != RelayGuardianQuarantined && (displayState != RelayGuardianHalfOpen || !state.halfOpenInFlight)
		snapshot := RelayGuardianAccountSnapshot{AccountID: account.DBID, AccountName: account.DisplayName(), ManualEnabled: manual, State: displayState, EffectiveSchedulable: effective, Reason: state.Reason, TriggerSource: state.TriggerSource, Generation: state.Generation, WindowSeconds: state.WindowSeconds, FailureCount: len(failureIDs), UserVisibleFailures: len(finalIDs), StrongGatewayFailures: len(strongIDs), WouldQuarantine: state.State == RelayGuardianWouldQuarantine, QuarantineUntil: relayGuardianTimePtr(state.QuarantineUntil), BackoffLevel: state.BackoffLevel, LastResort: state.LastResort, LastResortCap: state.LastResortCap, ShadowAction: state.ShadowAction, ProbationPercent: state.ProbationPercent, ProbationSuccesses: state.ProbationSuccesses, ProbationRequiredSuccesses: relayGuardianProbationSuccesses, LastFailureAt: relayGuardianTimePtr(state.LastFailureAt), LastActionAt: relayGuardianTimePtr(state.LastActionAt), LastScanAt: relayGuardianTimePtr(state.LastScanAt), ReliabilityTotal: state.ReliabilityTotal, ReliabilityFailures: state.ReliabilityFailures, ReliabilityWindowSeconds: state.ReliabilityWindowSeconds, FailureRatePercent: state.FailureRatePercent, FailureRateLowerBoundPercent: state.FailureRateLowerBoundPercent, WeakConfirmationCount: state.WeakConfirmationCount, WeakConfirmationRequired: relayGuardianWeakConfirmations, StrongCircuitCycleCount: state.StrongCircuitCycleCount, LastCanonicalSuccessAt: relayGuardianTimePtr(relayGuardianCanonicalSuccessAt(account))}
		g.mu.Unlock()
		result.Accounts = append(result.Accounts, g.decorateCircuitSnapshot(snapshot, now))
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].AccountID < result.Accounts[j].AccountID })
	return result
}

func (g *relayHealthGuardian) decorateCircuitSnapshot(snapshot RelayGuardianAccountSnapshot, now time.Time) RelayGuardianAccountSnapshot {
	circuit := g.store.RelayCircuitSnapshot(snapshot.AccountID)
	snapshot.CircuitState = circuit.State
	snapshot.CircuitOpenUntil = relayGuardianTimePtr(circuit.OpenUntil)
	snapshot.CircuitProbeSuccesses = circuit.ProbeSuccesses
	snapshot.CircuitRequiredSuccesses = circuit.RequiredSuccess
	if circuit.State == RelayCircuitOpen && (circuit.OpenUntil.IsZero() || circuit.OpenUntil.After(now)) {
		snapshot.EffectiveSchedulable = false
	}
	if circuit.State == RelayCircuitHalfOpen && circuit.ProbeInFlight {
		snapshot.EffectiveSchedulable = false
	}
	return snapshot
}

func (s *Store) configuredRelayGuardianAccounts() []*Account {
	if s == nil {
		return nil
	}
	cfg := s.GetCybRelayConfig()
	if !cfg.Enabled || cfg.GroupID <= 0 {
		return nil
	}
	accounts := s.Accounts()
	result := make([]*Account, 0, len(accounts))
	for _, account := range accounts {
		if account != nil && account.IsOpenAIResponsesAPI() && account.HasGroupID(cfg.GroupID) {
			result = append(result, account)
		}
	}
	return result
}

// preloadRelayRuntimeAccount is used only after startup or an account/admin
// mutation, never from scheduler selection. It restores both runtime fences,
// then replays the Guardian scheduler overlay onto the current Account object.
func (s *Store) preloadRelayRuntimeAccount(account *Account) {
	if s == nil || account == nil {
		return
	}
	if !s.isConfiguredRelayCircuitAccount(account) {
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	s.relayCircuitManager().ensureLoadedForAccount(account)
	account.setRelayCircuitLastResort(s.relayCircuitManager().snapshot(account.DBID).LastResort)
	s.relayGuardianManager().preloadAndReplay(account)
}

// relayRuntimeAccountIdentityChanged starts a fresh health epoch after an
// operator changes the actual Relay front door. A display-name edit does not
// call this path. Both breaker and Guardian are reset so old endpoint evidence
// cannot penalize replacement credentials or a replacement gateway.
func (s *Store) relayRuntimeAccountIdentityChanged(account *Account) {
	if s == nil || account == nil || !s.isConfiguredRelayCircuitAccount(account) {
		return
	}
	account.setRelayCircuitLastResort(false)
	s.relayCircuitManager().forgetAccountRuntime(account.DBID, relayCircuitAccountIdentityFingerprint(account))
	s.relayGuardianManager().forgetAccountRuntime(account, s.GetCybRelayConfig().GroupID)
	s.preloadRelayRuntimeAccount(account)
}

func (s *Store) relayGuardianAccountAvailabilityChanged(account *Account) {
	if account == nil {
		return
	}
	if !relayGuardianManualEnabled(account) {
		// Manual disable always wins immediately; the Guardian state remains so
		// an explicit re-enable can safely replay its probation/last-resort cap.
		account.relayGuardianCanonicalSuccessAt.Store(0)
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	s.preloadRelayRuntimeAccount(account)
}

func (s *Store) relayGuardianAccountMembershipChanged(account *Account, wasRelay, isRelay bool) {
	if account == nil || wasRelay == isRelay {
		return
	}
	// Breaker permits and restart fences are scoped to one membership epoch,
	// just like Guardian state. Reset before either leaving or joining so a late
	// completion from the old membership cannot cross the boundary.
	account.setRelayCircuitLastResort(false)
	s.relayCircuitManager().forgetAccountRuntime(account.DBID, relayCircuitAccountIdentityFingerprint(account))
	if !isRelay {
		// The hint lives on Account, not on a group bucket, so it must be cleared
		// synchronously before another group can schedule this account. Drop the
		// authoritative state too, so immediate leave/rejoin starts healthy.
		s.relayGuardianManager().forgetAccountRuntime(account, s.GetCybRelayConfig().GroupID)
		return
	}
	// A join is a new membership epoch. Delete any stale runtime key left by
	// an older process/config cycle before loading the new healthy state.
	s.relayGuardianManager().forgetAccountRuntime(account, s.GetCybRelayConfig().GroupID)
	s.preloadRelayRuntimeAccount(account)
}

func (s *Store) relayGuardianManager() *relayHealthGuardian {
	if s == nil {
		return nil
	}
	s.relayGuardianOnce.Do(func() {
		if s.relayGuardian == nil {
			s.relayGuardian = newRelayHealthGuardian(s)
		}
	})
	return s.relayGuardian
}

func (s *Store) SetRelayGuardianMode(mode string) {
	if s == nil {
		return
	}
	normalized := NormalizeRelayGuardianMode(mode)
	if s.relayGuardian == nil {
		s.relayGuardianMode.Store(string(normalized))
		return
	}
	s.relayGuardian.transitionMode(normalized)
}
func (s *Store) GetRelayGuardianMode() RelayGuardianMode {
	if s == nil {
		return RelayGuardianOff
	}
	if raw, ok := s.relayGuardianMode.Load().(string); ok {
		return NormalizeRelayGuardianMode(raw)
	}
	return RelayGuardianOff
}

func (s *Store) RelayGuardianSelectable(account *Account) bool {
	if s == nil || account == nil || !s.isConfiguredRelayCircuitAccount(account) {
		return true
	}
	return s.relayGuardianManager().selectable(account)
}
func (s *Store) BeginRelayGuardianRequest(account *Account) (RelayGuardianPermit, bool) {
	if s == nil || account == nil || !s.isConfiguredRelayCircuitAccount(account) {
		return RelayGuardianPermit{}, true
	}
	return s.relayGuardianManager().begin(account)
}
func (s *Store) ReportRelayGuardianFailure(permit RelayGuardianPermit, status int) {
	if s != nil {
		s.relayGuardianManager().finishFailure(permit, status)
	}
}
func (s *Store) ReportRelayGuardianSuccess(permit RelayGuardianPermit) {
	if s != nil {
		s.relayGuardianManager().finishSuccess(permit)
	}
}
func (s *Store) AbandonRelayGuardianRequest(permit RelayGuardianPermit) {
	if s != nil {
		s.relayGuardianManager().abandon(permit)
	}
}

func (s *Store) ObserveRelayGuardianUsage(input *database.UsageLogInput) {
	if s == nil || input == nil {
		return
	}
	s.relayGuardianManager().observe(RelayGuardianObservation{AccountID: input.AccountID, LogicalRequestID: input.LogicalRequestID, StatusCode: input.StatusCode, UpstreamErrorKind: input.UpstreamErrorKind, ErrorMessage: input.ErrorMessage, RouteClass: input.RouteClass, RouteSource: input.RouteSource, RouteGroupID: input.RouteGroupID, UpstreamAccountType: input.UpstreamAccountType, AttemptOnly: input.GuardianAttemptOnly})
}
func (s *Store) RelayGuardianReconcile(ctx context.Context) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	s.relayGuardianManager().reconcile(ctx)
}
func (s *Store) RelayGuardianStatus() RelayGuardianStatus {
	if s == nil {
		return RelayGuardianStatus{Mode: RelayGuardianOff, GeneratedAt: time.Now(), ScanIntervalSeconds: 60}
	}
	return s.relayGuardianManager().status()
}
func (s *Store) RelayGuardianAccountStatus(accountID int64) (RelayGuardianAccountSnapshot, bool) {
	for _, account := range s.RelayGuardianStatus().Accounts {
		if account.AccountID == accountID {
			return account, true
		}
	}
	return RelayGuardianAccountSnapshot{}, false
}
func (s *Store) ReleaseRelayGuardian(accountID int64, generation uint64) error {
	return s.relayGuardianManager().release(accountID, generation)
}
func (s *Store) TemporaryBypassRelayGuardian(accountID int64, generation uint64, minutes int) error {
	return s.relayGuardianManager().temporaryBypass(accountID, generation, minutes)
}

func (s *Store) RelayGuardianHealth() (RelayGuardianHealthSummary, RelayGuardianRelaySummary) {
	mode := s.GetRelayGuardianMode()
	now := time.Now()
	health := RelayGuardianHealthSummary{Enabled: mode != RelayGuardianOff, Mode: mode, Status: "disabled", ScanIntervalSeconds: int(RelayGuardianScanInterval / time.Second)}
	type guardianLocal struct {
		loaded           bool
		state            RelayGuardianState
		until            time.Time
		bypassUntil      time.Time
		probe            bool
		probationPercent int
		lastResort       bool
	}
	guardianStates := make(map[int64]guardianLocal)
	poolWide := false
	reliabilityDBDegraded := false
	if guardian := s.relayGuardianManager(); guardian != nil {
		reliabilityNow := guardian.nowTime()
		guardian.mu.Lock()
		health.HeartbeatAt = relayGuardianTimePtr(guardian.heartbeat)
		health.ColdStartActive = guardian.coldStartActiveLocked(reliabilityNow)
		health.ColdStartUntil = relayGuardianTimePtr(guardian.coldStartUntil)
		poolWide = guardian.poolWideUntil.After(now)
		reliabilityDBDegraded = guardian.reliabilityConsecutiveErrors >= 3 ||
			(!guardian.reliabilityFailureSince.IsZero() && reliabilityNow.Sub(guardian.reliabilityFailureSince) >= 3*RelayGuardianScanInterval)
		for accountID, loaded := range guardian.loaded {
			guardianStates[accountID] = guardianLocal{loaded: loaded || guardian.cache == nil, state: RelayGuardianHealthy}
		}
		for accountID, state := range guardian.states {
			guardianStates[accountID] = guardianLocal{
				loaded: guardian.loaded[accountID] || guardian.cache == nil, state: state.State,
				until: state.QuarantineUntil, bypassUntil: state.TemporaryBypassUntil,
				probe: state.halfOpenInFlight, probationPercent: state.ProbationPercent,
				lastResort: state.LastResort,
			}
		}
		guardian.mu.Unlock()
	}
	reasonSet := make(map[string]struct{})
	addReason := func(reason string) {
		if reason != "" {
			reasonSet[reason] = struct{}{}
		}
	}
	if health.Enabled {
		health.Status = "ok"
		if health.HeartbeatAt == nil || now.Sub(*health.HeartbeatAt) > 2*RelayGuardianScanInterval {
			addReason("guardian_heartbeat_stale")
		}
		if poolWide {
			addReason("pool_wide_failure")
		}
		if reliabilityDBDegraded {
			addReason("guardian_reliability_db_unavailable")
		}
	}

	accounts := s.configuredRelayGuardianAccounts()
	relay := RelayGuardianRelaySummary{GroupID: s.GetCybRelayConfig().GroupID, Configured: len(accounts)}
	for _, account := range accounts {
		manual := relayGuardianManualEnabled(account)
		if !manual {
			continue
		}
		relay.Enabled++
		accountDegraded := false
		guardianState, knownGuardian := guardianStates[account.DBID]
		guardianEnforcing := mode == RelayGuardianEnforce
		guardianShadowWarning := mode == RelayGuardianMonitor && guardianState.state == RelayGuardianWouldQuarantine
		guardianNonNormal := false
		guardianRecoveryOnly := false
		guardianRecoveryCap := int64(0)
		guardianBypassActive := false
		if guardianEnforcing {
			switch guardianState.state {
			case RelayGuardianQuarantined:
				relay.Quarantined++
				guardianNonNormal = true
				if !guardianState.until.After(now) {
					// The next scheduler touch advances an expired quarantine to
					// single-request half-open. Until that happens it is recovery
					// capacity, never normal capacity.
					guardianRecoveryOnly = true
					guardianRecoveryCap = 1
				}
			case RelayGuardianHalfOpen:
				relay.Quarantined++
				guardianNonNormal = true
				guardianRecoveryOnly = true
				guardianRecoveryCap = 1
			case RelayGuardianProbation:
				relay.Probation++
				guardianNonNormal = true
				guardianRecoveryOnly = true
			case RelayGuardianTemporaryBypass:
				guardianNonNormal = true
				guardianBypassActive = guardianState.bypassUntil.After(now)
				if guardianBypassActive {
					guardianRecoveryOnly = true
				} else if !guardianState.until.After(now) {
					// An expired bypass returns to half-open on the next touch.
					guardianRecoveryOnly = true
					guardianRecoveryCap = 1
				}
			}
		}
		// A weak failure merely places an account in suspect/candidate state.
		// It remains schedulable and must not make /health fail (the watchdog is
		// intentionally strict). Only an actionable Guardian state degrades it.
		if guardianShadowWarning || guardianNonNormal || (guardianEnforcing && guardianState.lastResort) {
			accountDegraded = true
			addReason("relay_account_degraded")
		}
		if guardianEnforcing && guardianState.state == RelayGuardianTemporaryBypass {
			addReason("relay_guardian_temporary_bypass")
		}
		if guardianRecoveryOnly {
			addReason("relay_guardian_recovery_only")
		}
		schedulable := account.IsAvailable()
		normalSchedulable := schedulable
		if guardianNonNormal {
			normalSchedulable = false
		}
		guardianUnknown := guardianEnforcing && (!knownGuardian || !guardianState.loaded)
		guardianBlocked := false
		recoveryOnly := guardianRecoveryOnly
		if mode != RelayGuardianOff && guardianUnknown {
			accountDegraded = true
			normalSchedulable = false
			addReason("guardian_runtime_state_unavailable")
		}
		if mode == RelayGuardianEnforce {
			if guardianUnknown {
				schedulable = false
				guardianBlocked = true
			}
			if guardianState.state == RelayGuardianQuarantined {
				schedulable = false
				guardianBlocked = guardianState.until.After(now)
			}
			if guardianState.state == RelayGuardianHalfOpen || guardianState.state == RelayGuardianProbation {
				schedulable = false
			}
			if guardianState.state == RelayGuardianTemporaryBypass && !guardianBypassActive {
				schedulable = false
				guardianBlocked = guardianState.until.After(now)
			}
		}

		circuit := s.RelayCircuitSnapshot(account.DBID)
		circuitUnknown := circuit.Reason == "runtime_fence_restore_pending"
		if circuitUnknown {
			accountDegraded = true
			addReason("circuit_runtime_state_unavailable")
			schedulable = false
			normalSchedulable = false
		}

		switch circuit.State {
		case RelayCircuitOpen:
			relay.CircuitOpen++
			accountDegraded = true
			addReason("relay_circuit_open")
			schedulable = false
			normalSchedulable = false
		case RelayCircuitHalfOpen, RelayCircuitProbation:
			recoveryOnly = true
			accountDegraded = true
			addReason("relay_circuit_recovery_only")
			// A recovery-only entrance deliberately admits a bounded proving
			// request. It is not stable business capacity and must never keep
			// sub2 standby accounts closed.
			schedulable = false
			normalSchedulable = false
		case RelayCircuitSuspect:
			relay.Suspect++
			accountDegraded = true
			normalSchedulable = false
			addReason("relay_circuit_suspect")
		}
		if recoveryOnly {
			// Guardian and circuit recovery can overlap for one account; the
			// account contributes one recovery-only entrance, never two.
			relay.RecoveryOnly++
		}

		lastResort := (guardianEnforcing && guardianState.lastResort) || circuit.LastResort
		if lastResort {
			relay.LastResort++
			normalSchedulable = false
			accountDegraded = true
			addReason("relay_last_resort")
		}

		// Total account concurrency and the current breaker cohort are separate
		// budgets. ActiveRequests includes every generation, while circuit.InFlight
		// contains only the current bounded suspect/probation cohort. Subtract each
		// from its own cap before taking the smaller remaining budget.
		dynamicLimit := account.GetDynamicConcurrencyLimit()
		guardianLimit := dynamicLimit
		if guardianEnforcing {
			guardianLimit = account.relayGuardianConcurrencyLimit(dynamicLimit)
		}
		if mode == RelayGuardianEnforce && guardianState.state == RelayGuardianProbation {
			percent := guardianState.probationPercent
			if percent != 50 {
				percent = 10
			}
			probationLimit := (dynamicLimit*int64(percent) + 99) / 100
			if dynamicLimit > 0 && probationLimit < 1 {
				probationLimit = 1
			}
			if probationLimit < guardianLimit {
				guardianLimit = probationLimit
			}
		}
		if mode == RelayGuardianEnforce && guardianRecoveryCap > 0 && guardianRecoveryCap < guardianLimit {
			guardianLimit = guardianRecoveryCap
		}
		if mode == RelayGuardianEnforce && guardianRecoveryCap > 0 && guardianState.probe {
			guardianLimit = 0
		}
		available := guardianLimit - atomic.LoadInt64(&account.ActiveRequests)
		if available < 0 {
			available = 0
		}
		if circuit.AdmissionLimit > 0 {
			boundedAvailable := int64(circuit.AdmissionLimit) - int64(circuit.InFlight)
			if boundedAvailable < 0 {
				boundedAvailable = 0
			}
			if boundedAvailable < available {
				available = boundedAvailable
			}
		}
		if !account.IsAvailable() || guardianBlocked || circuit.State == RelayCircuitOpen || circuitUnknown {
			available = 0
		}
		if available > 0 {
			relay.EffectiveAvailableSlots += available
		} else if circuit.State == RelayCircuitSuspect {
			// Suspect remains schedulable only while its bounded admission
			// window has a real slot. A nominal entrance at capacity is not
			// usable failover capacity.
			schedulable = false
		}
		if accountDegraded {
			relay.Degraded++
		}
		if schedulable {
			relay.Schedulable++
		}
		if normalSchedulable && circuit.State == RelayCircuitClosed && !lastResort {
			relay.NormalSchedulable++
		}
	}
	if health.Enabled && relay.Enabled > 0 && relay.NormalSchedulable == 0 {
		addReason("relay_capacity_unavailable")
	}
	if health.Enabled && len(reasonSet) > 0 {
		health.Status = "degraded"
	}
	for reason := range reasonSet {
		health.Reasons = append(health.Reasons, reason)
	}
	sort.Strings(health.Reasons)
	return health, relay
}
