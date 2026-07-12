package auth

import (
	"context"
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

const (
	relayGuardianRuntimeNamespace = "relay-health-guardian"
	relayGuardianRuntimeTTL       = 7 * 24 * time.Hour
	relayGuardianCacheTimeout     = 300 * time.Millisecond
	RelayGuardianScanInterval     = 60 * time.Second

	relayGuardianInitialQuarantine  = 30 * time.Minute
	relayGuardianProbationStage     = 10 * time.Minute
	relayGuardianProbationSuccesses = 20
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
	Recovery         bool      `json:"recovery,omitempty"`
}

type relayGuardianRuntimeRecord struct {
	Mode                 RelayGuardianMode      `json:"mode,omitempty"`
	ScopeGroupID         int64                  `json:"scope_group_id,omitempty"`
	State                RelayGuardianState     `json:"state"`
	Generation           uint64                 `json:"generation"`
	Reason               string                 `json:"reason,omitempty"`
	TriggerSource        string                 `json:"trigger_source,omitempty"`
	WindowSeconds        int                    `json:"window_seconds,omitempty"`
	QuarantineUntil      time.Time              `json:"quarantine_until,omitempty"`
	BackoffLevel         int                    `json:"backoff_level"`
	ProbationPercent     int                    `json:"probation_percent,omitempty"`
	ProbationSuccesses   int                    `json:"probation_successes,omitempty"`
	ProbationStartedAt   time.Time              `json:"probation_started_at,omitempty"`
	TemporaryBypassUntil time.Time              `json:"temporary_bypass_until,omitempty"`
	BypassReturnState    RelayGuardianState     `json:"bypass_return_state,omitempty"`
	LastResort           bool                   `json:"last_resort,omitempty"`
	LastResortCap        int                    `json:"last_resort_cap,omitempty"`
	LastResortLevel      int                    `json:"last_resort_level,omitempty"`
	LastResortFailureID  string                 `json:"last_resort_failure_id,omitempty"`
	ShadowAction         string                 `json:"shadow_action,omitempty"`
	HealthySince         time.Time              `json:"healthy_since,omitempty"`
	PoolWideReportedAt   time.Time              `json:"pool_wide_reported_at,omitempty"`
	Failures             []relayGuardianFailure `json:"failures,omitempty"`
	SeenStrong           map[string]time.Time   `json:"seen_strong,omitempty"`
	SeenFinal            map[string]time.Time   `json:"seen_final,omitempty"`
	LastFailureAt        time.Time              `json:"last_failure_at,omitempty"`
	LastActionAt         time.Time              `json:"last_action_at,omitempty"`
	LastScanAt           time.Time              `json:"last_scan_at,omitempty"`
	UpdatedAt            time.Time              `json:"updated_at,omitempty"`
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
	account   *Account
	manual    bool
	available bool
	active    int64
	limit     int64
	circuit   RelayCircuitSnapshot
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
	poolWideUntil                 time.Time
	poolEvents                    map[string]time.Time
	capacitySamples               []relayGuardianCapacitySample
	now                           func() time.Time
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
	AccountID                  int64              `json:"account_id"`
	AccountName                string             `json:"account_name"`
	ManualEnabled              bool               `json:"manual_enabled"`
	State                      RelayGuardianState `json:"state"`
	EffectiveSchedulable       bool               `json:"effective_schedulable"`
	Reason                     string             `json:"reason,omitempty"`
	TriggerSource              string             `json:"trigger_source,omitempty"`
	Generation                 uint64             `json:"generation"`
	WindowSeconds              int                `json:"window_seconds,omitempty"`
	FailureCount               int                `json:"failure_count"`
	UserVisibleFailures        int                `json:"user_visible_failures"`
	StrongGatewayFailures      int                `json:"strong_gateway_failures"`
	WouldQuarantine            bool               `json:"would_quarantine"`
	QuarantineUntil            *time.Time         `json:"quarantine_until,omitempty"`
	BackoffLevel               int                `json:"backoff_level"`
	LastResort                 bool               `json:"last_resort"`
	LastResortCap              int                `json:"last_resort_cap"`
	ShadowAction               string             `json:"shadow_action,omitempty"`
	ProbationPercent           int                `json:"probation_percent"`
	ProbationSuccesses         int                `json:"probation_successes"`
	ProbationRequiredSuccesses int                `json:"probation_required_successes"`
	LastFailureAt              *time.Time         `json:"last_failure_at,omitempty"`
	LastActionAt               *time.Time         `json:"last_action_at,omitempty"`
	LastScanAt                 *time.Time         `json:"last_scan_at,omitempty"`
	CircuitState               RelayCircuitState  `json:"circuit_state"`
	CircuitOpenUntil           *time.Time         `json:"circuit_open_until,omitempty"`
	CircuitProbeSuccesses      int                `json:"circuit_probe_successes"`
	CircuitRequiredSuccesses   int                `json:"circuit_required_successes"`
}

type RelayGuardianStatus struct {
	Enabled             bool                           `json:"enabled"`
	Mode                RelayGuardianMode              `json:"mode"`
	GeneratedAt         time.Time                      `json:"generated_at"`
	HeartbeatAt         *time.Time                     `json:"heartbeat_at,omitempty"`
	ScanIntervalSeconds int                            `json:"scan_interval_seconds"`
	Accounts            []RelayGuardianAccountSnapshot `json:"accounts"`
}

type RelayGuardianHealthSummary struct {
	Enabled             bool              `json:"enabled"`
	Mode                RelayGuardianMode `json:"mode"`
	Status              string            `json:"status"`
	HeartbeatAt         *time.Time        `json:"heartbeat_at,omitempty"`
	ScanIntervalSeconds int               `json:"scan_interval_seconds"`
	Reasons             []string          `json:"reasons,omitempty"`
}

type RelayGuardianRelaySummary struct {
	Configured  int `json:"configured"`
	Enabled     int `json:"enabled"`
	Schedulable int `json:"schedulable"`
	Quarantined int `json:"quarantined"`
	Probation   int `json:"probation"`
	Degraded    int `json:"degraded"`
}

var ErrRelayGuardianStaleGeneration = errors.New("relay guardian generation changed")
var ErrRelayGuardianNotEnforcing = errors.New("relay guardian is not in enforce mode")
var ErrRelayGuardianInvalidState = errors.New("relay guardian action is not allowed in current state")
var ErrRelayGuardianRuntimeUnavailable = errors.New("relay guardian runtime state is unavailable")

func newRelayHealthGuardian(store *Store) *relayHealthGuardian {
	return &relayHealthGuardian{
		store:         store,
		cache:         store.tokenCache,
		db:            store.db,
		states:        make(map[int64]*relayGuardianAccountState),
		loaded:        make(map[int64]bool),
		loading:       make(map[int64]bool),
		retryLoad:     make(map[int64]time.Time),
		poolEvents:    make(map[string]time.Time),
		now:           time.Now,
		incidentEpoch: time.Now(),
	}
}

func (g *relayHealthGuardian) modeChanged(previous, current RelayGuardianMode) {
	if g == nil {
		return
	}
	now := g.nowTime()
	accounts := g.store.configuredRelayGuardianAccounts()
	byID := make(map[int64]*Account, len(accounts))
	for _, account := range accounts {
		byID[account.DBID] = account
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.incidentEpoch = now
	g.lastScan = now
	g.lastNewQuarantine = time.Time{}
	g.lastShadowQuarantine = time.Time{}
	g.lastShadowQuarantineAccountID = 0
	g.poolWideUntil = time.Time{}
	g.poolEvents = make(map[string]time.Time)
	g.capacitySamples = nil
	g.lastSummary = time.Time{}
	g.lastAudit = time.Time{}
	for accountID, state := range g.states {
		if state == nil {
			continue
		}
		g.resetForModeLocked(state, current, now)
		relayGuardianSchedulingHint(byID[accountID], false, 0, 0)
		g.persistState(accountID, state)
	}
}

func (g *relayHealthGuardian) relayConfigChanged(previous, current CybRelayConfig, accounts []*Account) {
	if g == nil || (previous.Enabled == current.Enabled && previous.GroupID == current.GroupID) {
		return
	}
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	now := g.nowTime()
	ids := make(map[int64]struct{}, len(accounts))
	for _, account := range accounts {
		if account == nil {
			continue
		}
		relayGuardianSchedulingHint(account, false, 0, 0)
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
	g.states = make(map[int64]*relayGuardianAccountState)
	g.loaded = make(map[int64]bool)
	g.loading = make(map[int64]bool)
	g.retryLoad = make(map[int64]time.Time)
	g.incidentEpoch = now
	g.lastScan = now
	g.lastNewQuarantine = time.Time{}
	g.lastShadowQuarantine = time.Time{}
	g.lastShadowQuarantineAccountID = 0
	g.poolWideUntil = time.Time{}
	g.poolEvents = make(map[string]time.Time)
	g.capacitySamples = nil
	g.lastSummary = time.Time{}
	g.lastAudit = time.Time{}
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
	for accountID := range ids {
		for groupID := range groups {
			ctx, cancel := relayGuardianCacheContext()
			err := g.cache.DeleteRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID))
			cancel()
			if err != nil {
				record := relayGuardianRuntimeRecord{Mode: g.store.GetRelayGuardianMode(), ScopeGroupID: groupID, State: RelayGuardianHealthy, Generation: 1, UpdatedAt: now}
				payload, marshalErr := json.Marshal(record)
				if marshalErr == nil {
					ctx, cancel = relayGuardianCacheContext()
					setErr := g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, accountID), payload, relayGuardianRuntimeTTL)
					cancel()
					if setErr == nil {
						continue
					}
					err = fmt.Errorf("delete failed: %v; healthy overwrite failed: %w", err, setErr)
				}
				log.Printf("[Relay guardian account=%d] clear old scope failed: %v", accountID, err)
			}
		}
	}
}

func (g *relayHealthGuardian) resetForModeLocked(state *relayGuardianAccountState, mode RelayGuardianMode, now time.Time) {
	if state == nil {
		return
	}
	state.Mode = mode
	state.ScopeGroupID = g.store.GetCybRelayConfig().GroupID
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
		state = &relayGuardianAccountState{relayGuardianRuntimeRecord: relayGuardianRuntimeRecord{State: RelayGuardianHealthy, Generation: 1}, permits: make(map[uint64]RelayGuardianPermit)}
		g.states[accountID] = state
	}
	if state.State == "" {
		state.State = RelayGuardianHealthy
	}
	if state.Generation == 0 {
		state.Generation = 1
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
	relayGuardianSchedulingHint(account, false, 0, 0)
	g.loadMu.Lock()
	defer g.loadMu.Unlock()
	g.persistMu.Lock()
	defer g.persistMu.Unlock()
	now := g.nowTime()
	g.mu.Lock()
	delete(g.states, account.DBID)
	delete(g.loaded, account.DBID)
	delete(g.loading, account.DBID)
	delete(g.retryLoad, account.DBID)
	// Do not let the fallback scanner replay rows from the membership that
	// just ended if the account is immediately added back.
	g.incidentEpoch = now
	g.lastScan = now
	g.mu.Unlock()
	if g.cache == nil || groupID <= 0 {
		return
	}
	ctx, cancel := relayGuardianCacheContext()
	err := g.cache.DeleteRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, account.DBID))
	cancel()
	if err == nil {
		return
	}
	// A failed delete must not leave a known-bad quarantine/probation record
	// behind. Best-effort overwrite it with an explicit healthy tombstone.
	record := relayGuardianRuntimeRecord{
		Mode:         g.store.GetRelayGuardianMode(),
		ScopeGroupID: groupID,
		State:        RelayGuardianHealthy,
		Generation:   1,
		UpdatedAt:    now,
	}
	payload, marshalErr := json.Marshal(record)
	if marshalErr == nil {
		ctx, cancel = relayGuardianCacheContext()
		setErr := g.cache.SetRuntime(ctx, relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(groupID, account.DBID), payload, relayGuardianRuntimeTTL)
		cancel()
		if setErr == nil {
			return
		}
		err = fmt.Errorf("delete failed: %v; healthy overwrite failed: %w", err, setErr)
	}
	log.Printf("[Relay guardian account=%d] invalidate removed account state failed: %v", account.DBID, err)
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
	if state.Mode != currentMode || state.ScopeGroupID != groupID {
		g.resetForModeLocked(state, currentMode, now)
		relayGuardianSchedulingHint(account, false, 0, 0)
		g.incidentEpoch = now
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
	current := state != nil && state.revision == revision
	g.mu.Unlock()
	if !current {
		return
	}
	if record.ScopeGroupID <= 0 || record.ScopeGroupID != g.store.GetCybRelayConfig().GroupID {
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
	state.UpdatedAt = g.nowTime()
	state.Mode = g.store.GetRelayGuardianMode()
	state.ScopeGroupID = g.store.GetCybRelayConfig().GroupID
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
	for _, excluded := range []string{"cyber_policy", "content_policy", "client", "cancel", "rate_limit", "bad_request"} {
		if strings.Contains(kind, excluded) || strings.Contains(message, excluded) {
			return false
		}
	}
	return true
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
	if !relayGuardianAttributable(obs) {
		return
	}
	observedAt := obs.ObservedAt
	if observedAt.IsZero() {
		observedAt = g.nowTime()
	}
	now := g.nowTime()
	strong := IsRelayStrongGatewayFailureStatus(obs.StatusCode)
	userVisible := !obs.AttemptOnly && !strings.EqualFold(strings.TrimSpace(obs.RouteSource), "probe")
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
			state.Failures = append(state.Failures, relayGuardianFailure{At: observedAt, LogicalRequestID: logicalID, StatusCode: obs.StatusCode, StrongGateway: true})
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
	state.Reason = "upstream_http_" + strconv.Itoa(obs.StatusCode)
	trigger, window, finals, gateways := g.triggerLocked(state, now)
	if trigger == "" {
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

func (g *relayHealthGuardian) triggerLocked(state *relayGuardianAccountState, now time.Time) (string, time.Duration, int, int) {
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
	final10 := count(10*time.Minute, true, false)
	strong5 := count(5*time.Minute, false, true)
	final60 := count(60*time.Minute, true, false)
	switch {
	case final10 >= 2:
		return "user_visible_2_in_10m", 10 * time.Minute, final10, strong5
	case strong5 >= 3:
		return "strong_gateway_3_in_5m", 5 * time.Minute, final10, strong5
	case final60 >= 4:
		return "user_visible_4_in_60m", 60 * time.Minute, final60, strong5
	default:
		return "", 0, final10, strong5
	}
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
	case strings.HasPrefix(trigger, "user_visible_"):
		return "user_visible"
	case strings.HasPrefix(trigger, "strong_gateway_"):
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
	case strings.HasPrefix(trigger, "strong_gateway_"), strings.HasPrefix(trigger, "recovery_"):
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
			active: account.GetActiveRequests(), limit: limit, circuit: g.store.RelayCircuitSnapshot(account.DBID),
		})
	}
	return result
}

func (g *relayHealthGuardian) capacityAllowsLocked(accounts []relayGuardianCapacityAccount, candidateID int64, now time.Time) (bool, string) {
	otherHealthy := 0
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
		changed := state.State != RelayGuardianWouldQuarantine || previousAction != shadowAction || state.Reason != shadowReason
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
	g.persistState(account.DBID, state)
	g.recordEventLocked(account, RelayGuardianEventQuarantine, from, state, "guardian", trigger, window, finals, gateways, duration)
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
		FailureCount: len(logical), UserVisibleFailures: finals, StrongGatewayFailures: gateways,
		QuarantineSeconds: int(quarantine / time.Second), Generation: state.Generation,
		LogicalRequestIDs: logical,
		Details:           map[string]any{"mode": g.store.GetRelayGuardianMode(), "probation_percent": state.ProbationPercent, "shadow_action": state.ShadowAction, "quarantine_until": state.QuarantineUntil, "event_time": eventTime, "window_id": windowID},
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
		state.ShadowAction = ""
		state.HealthySince = time.Time{}
		if state.State == RelayGuardianHealthy || state.State == RelayGuardianWouldQuarantine {
			state.State = RelayGuardianSuspect
		}
		if !state.LastResort {
			state.TriggerSource = ""
			state.WindowSeconds = 0
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

func (g *relayHealthGuardian) reconcile(ctx context.Context) {
	if g == nil {
		return
	}
	now := g.nowTime()
	mode := g.store.GetRelayGuardianMode()
	groupID := g.store.GetCybRelayConfig().GroupID
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
			relayGuardianSchedulingHint(account, false, 0, 0)
			g.ageStateLocked(account, state, now)
			g.persistState(account.DBID, state)
			continue
		}
		// Manual re-enable and same-DBID Account replacement both create a
		// zero-valued Account hint. Re-derive it every reconcile from the
		// authoritative in-memory state before making further transitions.
		relayGuardianApplySchedulingHint(account, state)
		if mode == RelayGuardianEnforce && state.State != RelayGuardianQuarantined && state.State != RelayGuardianHalfOpen && state.State != RelayGuardianProbation && state.State != RelayGuardianTemporaryBypass {
			trigger, window, finals, gateways := g.triggerLocked(state, now)
			if trigger != "" {
				g.applyTriggerLocked(account, state, accounts, capacity, trigger, window, finals, gateways, now)
				continue
			}
		}
		if mode == RelayGuardianMonitor {
			trigger, window, finals, gateways := g.triggerLocked(state, now)
			if trigger != "" {
				g.applyTriggerLocked(account, state, accounts, capacity, trigger, window, finals, gateways, now)
				continue
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
	result := RelayGuardianStatus{Enabled: g.store.GetRelayGuardianMode() != RelayGuardianOff, Mode: g.store.GetRelayGuardianMode(), GeneratedAt: now, ScanIntervalSeconds: int(RelayGuardianScanInterval / time.Second)}
	g.mu.Lock()
	result.HeartbeatAt = relayGuardianTimePtr(g.heartbeat)
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
			snapshot := RelayGuardianAccountSnapshot{AccountID: account.DBID, AccountName: account.DisplayName(), ManualEnabled: manual, State: displayState, EffectiveSchedulable: manual && account.IsAvailable() && g.store.GetRelayGuardianMode() != RelayGuardianEnforce, Reason: "runtime_state_unavailable", ProbationRequiredSuccesses: relayGuardianProbationSuccesses}
			g.mu.Unlock()
			result.Accounts = append(result.Accounts, g.decorateCircuitSnapshot(snapshot, now))
			continue
		}
		state := g.stateLocked(account.DBID)
		g.trimLocked(state, now)
		failureIDs := make(map[string]struct{})
		finalIDs := make(map[string]struct{})
		strongIDs := make(map[string]struct{})
		for _, f := range state.Failures {
			failureIDs[f.LogicalRequestID] = struct{}{}
			if f.UserVisible {
				finalIDs[f.LogicalRequestID] = struct{}{}
			}
			if f.StrongGateway {
				strongIDs[f.LogicalRequestID] = struct{}{}
			}
		}
		manual := relayGuardianManualEnabled(account)
		displayState := state.State
		if !manual {
			displayState = RelayGuardianManualDisabled
		}
		effective := manual && account.IsAvailable() && displayState != RelayGuardianQuarantined && (displayState != RelayGuardianHalfOpen || !state.halfOpenInFlight)
		snapshot := RelayGuardianAccountSnapshot{AccountID: account.DBID, AccountName: account.DisplayName(), ManualEnabled: manual, State: displayState, EffectiveSchedulable: effective, Reason: state.Reason, TriggerSource: state.TriggerSource, Generation: state.Generation, WindowSeconds: state.WindowSeconds, FailureCount: len(failureIDs), UserVisibleFailures: len(finalIDs), StrongGatewayFailures: len(strongIDs), WouldQuarantine: state.State == RelayGuardianWouldQuarantine, QuarantineUntil: relayGuardianTimePtr(state.QuarantineUntil), BackoffLevel: state.BackoffLevel, LastResort: state.LastResort, LastResortCap: state.LastResortCap, ShadowAction: state.ShadowAction, ProbationPercent: state.ProbationPercent, ProbationSuccesses: state.ProbationSuccesses, ProbationRequiredSuccesses: relayGuardianProbationSuccesses, LastFailureAt: relayGuardianTimePtr(state.LastFailureAt), LastActionAt: relayGuardianTimePtr(state.LastActionAt), LastScanAt: relayGuardianTimePtr(state.LastScanAt)}
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
	s.relayCircuitManager().ensureLoaded(account.DBID)
	s.relayGuardianManager().preloadAndReplay(account)
}

func (s *Store) relayGuardianAccountAvailabilityChanged(account *Account) {
	if account == nil {
		return
	}
	if !relayGuardianManualEnabled(account) {
		// Manual disable always wins immediately; the Guardian state remains so
		// an explicit re-enable can safely replay its probation/last-resort cap.
		relayGuardianSchedulingHint(account, false, 0, 0)
		return
	}
	s.preloadRelayRuntimeAccount(account)
}

func (s *Store) relayGuardianAccountMembershipChanged(account *Account, wasRelay, isRelay bool) {
	if account == nil || wasRelay == isRelay {
		return
	}
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
	previous := s.GetRelayGuardianMode()
	s.relayGuardianMode.Store(string(normalized))
	if previous != normalized && s.relayGuardian != nil {
		s.relayGuardian.modeChanged(previous, normalized)
	}
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
		loaded     bool
		state      RelayGuardianState
		until      time.Time
		probe      bool
		lastResort bool
	}
	guardianStates := make(map[int64]guardianLocal)
	poolWide := false
	if guardian := s.relayGuardianManager(); guardian != nil {
		guardian.mu.Lock()
		health.HeartbeatAt = relayGuardianTimePtr(guardian.heartbeat)
		poolWide = guardian.poolWideUntil.After(now)
		for accountID, loaded := range guardian.loaded {
			guardianStates[accountID] = guardianLocal{loaded: loaded || guardian.cache == nil, state: RelayGuardianHealthy}
		}
		for accountID, state := range guardian.states {
			guardianStates[accountID] = guardianLocal{loaded: guardian.loaded[accountID] || guardian.cache == nil, state: state.State, until: state.QuarantineUntil, probe: state.halfOpenInFlight, lastResort: state.LastResort}
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
	}

	type circuitLocal struct {
		loaded bool
		state  RelayCircuitState
		until  time.Time
		probe  bool
	}
	circuitStates := make(map[int64]circuitLocal)
	circuitCacheBacked := false
	if breaker := s.relayCircuitManager(); breaker != nil {
		breaker.mu.Lock()
		circuitCacheBacked = breaker.cache != nil
		for accountID, loaded := range breaker.loaded {
			circuitStates[accountID] = circuitLocal{loaded: loaded || breaker.cache == nil, state: RelayCircuitClosed}
		}
		for accountID, state := range breaker.states {
			circuitStates[accountID] = circuitLocal{loaded: breaker.loaded[accountID] || breaker.cache == nil, state: state.state, until: state.openUntil, probe: state.probeInFlight}
		}
		breaker.mu.Unlock()
	}
	accounts := s.configuredRelayGuardianAccounts()
	relay := RelayGuardianRelaySummary{Configured: len(accounts)}
	for _, account := range accounts {
		manual := relayGuardianManualEnabled(account)
		if !manual {
			continue
		}
		relay.Enabled++
		accountDegraded := false
		guardianState, knownGuardian := guardianStates[account.DBID]
		if guardianState.state == RelayGuardianQuarantined || guardianState.state == RelayGuardianHalfOpen {
			relay.Quarantined++
		}
		if guardianState.state == RelayGuardianProbation {
			relay.Probation++
		}
		if guardianState.state == RelayGuardianSuspect || guardianState.state == RelayGuardianWouldQuarantine || guardianState.lastResort {
			accountDegraded = true
			addReason("relay_account_degraded")
		}
		schedulable := account.IsAvailable()
		guardianUnknown := !knownGuardian || !guardianState.loaded
		if mode != RelayGuardianOff && guardianUnknown {
			accountDegraded = true
			addReason("guardian_runtime_state_unavailable")
		}
		if mode == RelayGuardianEnforce {
			if guardianUnknown {
				schedulable = false
			}
			if guardianState.state == RelayGuardianQuarantined && guardianState.until.After(now) {
				schedulable = false
			}
			if guardianState.state == RelayGuardianHalfOpen && guardianState.probe {
				schedulable = false
			}
		}
		circuitState, knownCircuit := circuitStates[account.DBID]
		if circuitCacheBacked && (!knownCircuit || !circuitState.loaded) {
			accountDegraded = true
			addReason("circuit_runtime_state_unavailable")
			schedulable = false
		}
		if knownCircuit && circuitState.loaded {
			switch circuitState.state {
			case RelayCircuitOpen:
				if circuitState.until.IsZero() || circuitState.until.After(now) {
					accountDegraded = true
					addReason("relay_circuit_open")
					schedulable = false
				}
			case RelayCircuitHalfOpen:
				accountDegraded = true
				addReason("relay_circuit_half_open")
				if circuitState.probe {
					schedulable = false
				}
			}
		}
		if accountDegraded {
			relay.Degraded++
		}
		if schedulable {
			relay.Schedulable++
		}
	}
	if health.Enabled && relay.Enabled > 0 && relay.Schedulable == 0 {
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
