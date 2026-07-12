package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/cache"
	"github.com/codex2api/database"
)

type relayGuardianCountingCache struct {
	cache.TokenCache
	gets atomic.Int64
}

type relayGuardianFailingCache struct {
	cache.TokenCache
	gets atomic.Int64
}

func (c *relayGuardianFailingCache) GetRuntime(context.Context, string, string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return nil, false, errors.New("runtime unavailable")
}

func (c *relayGuardianCountingCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return c.TokenCache.GetRuntime(ctx, namespace, key)
}

func newGuardianTestStore(t *testing.T, mode RelayGuardianMode, clock *relayCircuitTestClock, ids ...int64) (*Store, *relayHealthGuardian) {
	t.Helper()
	accounts := make([]*Account, 0, len(ids))
	byID := make(map[int64]*Account, len(ids))
	for index, id := range ids {
		account := relayCircuitSchedulerAccount(id, int64(100-index))
		account.Email = "relay-" + string(rune('A'+index))
		accounts = append(accounts, account)
		byID[id] = account
	}
	store := &Store{accounts: accounts, accountsByID: byID, sessionBindings: make(map[string]sessionAffinity)}
	atomic.StoreInt64(&store.maxConcurrency, 100)
	store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 7})
	store.SetRelayGuardianMode(string(mode))
	guardian := newRelayHealthGuardian(store)
	guardian.now = clock.Now
	guardian.incidentEpoch = clock.Now()
	guardian.lastScan = clock.Now()
	guardian.capacitySamples = []relayGuardianCapacitySample{
		{At: clock.Now().Add(-2 * RelayGuardianScanInterval)},
		{At: clock.Now().Add(-RelayGuardianScanInterval)},
		{At: clock.Now()},
	}
	store.relayGuardian = guardian
	return store, guardian
}

func guardianObservation(accountID int64, logicalID string, status int, attemptOnly bool, at time.Time) RelayGuardianObservation {
	return RelayGuardianObservation{AccountID: accountID, LogicalRequestID: logicalID, StatusCode: status,
		RouteClass: "cyb_relay", RouteGroupID: 7, UpstreamAccountType: UpstreamOpenAIResponses,
		AttemptOnly: attemptOnly, ObservedAt: at}
}

func TestRelayGuardianAccount51ReplayWouldQuarantineOnSecondVisible500(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50, 53)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	clock.Advance(2*time.Minute + 5*time.Second)
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))

	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianWouldQuarantine || state.TriggerSource != "user_visible_2_in_10m" {
		t.Fatalf("state=%s trigger=%s, want would_quarantine at second visible 500", state.State, state.TriggerSource)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianSingle502AndRecoveredChainDoNotLongQuarantine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53)
	guardian.observe(guardianObservation(50, "chain", 502, true, clock.Now()))
	guardian.observe(guardianObservation(53, "chain", 400, false, clock.Now()))

	guardian.mu.Lock()
	state50 := guardian.stateLocked(50)
	state53 := guardian.stateLocked(53)
	if state50.State != RelayGuardianSuspect || len(state50.SeenStrong) != 1 || len(state50.SeenFinal) != 0 {
		t.Fatalf("50 state=%s strong=%d final=%d", state50.State, len(state50.SeenStrong), len(state50.SeenFinal))
	}
	if state53.State != RelayGuardianHealthy || len(state53.Failures) != 0 {
		t.Fatalf("53 request-side 400 affected Guardian: state=%s failures=%d", state53.State, len(state53.Failures))
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianProbeFailuresOnlyCountStrongGateway(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	for _, logicalID := range []string{"probe-500-a", "probe-500-b"} {
		obs := guardianObservation(51, logicalID, 500, false, clock.Now())
		obs.RouteSource = "probe"
		guardian.observe(obs)
	}
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if len(state.SeenFinal) != 0 || state.State == RelayGuardianWouldQuarantine {
		t.Fatalf("probe 500 counted user-visible: %+v", state)
	}
	guardian.mu.Unlock()
	for _, logicalID := range []string{"probe-502-a", "probe-502-b", "probe-502-c"} {
		obs := guardianObservation(51, logicalID, 502, false, clock.Now())
		obs.RouteSource = "probe"
		guardian.observe(obs)
	}
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	if state.State != RelayGuardianWouldQuarantine || state.TriggerSource != "strong_gateway_3_in_5m" || len(state.SeenFinal) != 0 {
		t.Fatalf("probe gateway classification=%+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianDeduplicatesLogicalRequestPerAccount(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	obs := guardianObservation(51, "duplicate", 500, false, clock.Now())
	guardian.observe(obs)
	guardian.observe(obs)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if len(state.SeenFinal) != 1 || state.State == RelayGuardianWouldQuarantine {
		t.Fatalf("duplicate counted twice: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianManualDisabledAlwaysWins(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	atomic.StoreInt32(&store.accountsByID[51].Disabled, 1)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	status, ok := store.RelayGuardianAccountStatus(51)
	if !ok || status.State != RelayGuardianManualDisabled || status.EffectiveSchedulable {
		t.Fatalf("manual disabled status=%+v", status)
	}
	if err := store.TemporaryBypassRelayGuardian(51, status.Generation, 5); !errors.Is(err, ErrRelayGuardianInvalidState) {
		t.Fatalf("bypass disabled err=%v", err)
	}
}

func TestRelayGuardianCapacityProtectsLastAccount(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State == RelayGuardianQuarantined || state.Reason != "last_available_relay" {
		t.Fatalf("last Relay was quarantined: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianPoolWideCategoryGuard(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 50, 51, 53)
	for i := 0; i < 3; i++ {
		guardian.observe(guardianObservation(50, "a-"+string(rune('0'+i)), 502, true, clock.Now()))
	}
	clock.Advance(61 * time.Second)
	for i := 0; i < 3; i++ {
		guardian.observe(guardianObservation(51, "b-"+string(rune('0'+i)), 502, true, clock.Now()))
	}
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State == RelayGuardianQuarantined || state.Reason != "pool_wide_failure_guard" {
		t.Fatalf("pool guard did not hold second account: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianReleaseAndBypassValidateStateAndGeneration(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	if err := store.ReleaseRelayGuardian(51, 1); !errors.Is(err, ErrRelayGuardianInvalidState) {
		t.Fatalf("healthy release err=%v", err)
	}
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	status, _ := store.RelayGuardianAccountStatus(51)
	if status.State != RelayGuardianQuarantined {
		t.Fatalf("state=%s", status.State)
	}
	if err := store.ReleaseRelayGuardian(51, status.Generation-1); !errors.Is(err, ErrRelayGuardianStaleGeneration) {
		t.Fatalf("stale release err=%v", err)
	}
	if err := store.TemporaryBypassRelayGuardian(51, status.Generation, 5); err != nil {
		t.Fatalf("bypass: %v", err)
	}
	after, _ := store.RelayGuardianAccountStatus(51)
	if after.State != RelayGuardianTemporaryBypass || after.Generation == status.Generation {
		t.Fatalf("bypass status=%+v", after)
	}
}

func TestRelayGuardianModeTransitionDoesNotEnforceOldMonitorIncident(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	guardian.poolWideUntil = clock.Now().Add(time.Hour)
	guardian.poolEvents["old"] = clock.Now()
	guardian.mu.Unlock()
	store.SetRelayGuardianMode(string(RelayGuardianEnforce))
	guardian.observe(guardianObservation(51, "late-old-mode", 500, false, clock.Now().Add(-time.Second)))
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianHealthy || len(state.Failures) != 0 || !guardian.poolWideUntil.IsZero() || len(guardian.poolEvents) != 0 {
		t.Fatalf("old monitor incident survived enforce transition: state=%+v pool_until=%s pool_events=%v", state, guardian.poolWideUntil, guardian.poolEvents)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianRedisRestartRestoresQuarantine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	store.relayCircuitManager().ensureLoaded(51)
	store.relayCircuitManager().ensureLoaded(50)
	guardian.ensureLoaded(51)
	guardian.ensureLoaded(50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	setupState := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
	setupRevision := guardian.stateLocked(51).revision
	guardian.mu.Unlock()
	if setupState.State != RelayGuardianQuarantined {
		t.Fatalf("setup did not quarantine: state=%+v revision=%d epoch=%s now=%s", setupState, setupRevision, guardian.incidentEpoch, clock.Now())
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		payload, ok, _ := tokenCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
		var persisted relayGuardianRuntimeRecord
		if ok && json.Unmarshal(payload, &persisted) == nil && persisted.State == RelayGuardianQuarantined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guardian state was not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}

	store2, guardian2 := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store2.tokenCache = tokenCache
	guardian2.cache = tokenCache
	guardian2.ensureLoaded(51)
	if guardian2.selectable(store2.accountsByID[51]) {
		t.Fatal("quarantined account became selectable after restart")
	}
}

func TestRelayGuardianRedisRestartRestoresPoolIncidentProtection(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	for _, accountID := range []int64{50, 53, 51} {
		guardian.ensureLoaded(accountID)
	}

	guardian.observe(guardianObservation(50, "peer-a", 524, false, clock.Now()))
	clock.Advance(30 * time.Second)
	guardian.observe(guardianObservation(50, "peer-b", 524, false, clock.Now()))
	clock.Advance(3 * time.Minute)
	guardian.observe(guardianObservation(53, "candidate-a", 524, false, clock.Now()))
	clock.Advance(30 * time.Second)
	guardian.observe(guardianObservation(53, "candidate-b", 524, false, clock.Now()))

	guardian.mu.Lock()
	wantUntil := guardian.poolWideUntil
	guardian.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		payload, ok, _ := tokenCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 53))
		var persisted relayGuardianRuntimeRecord
		if ok && json.Unmarshal(payload, &persisted) == nil && !persisted.PoolWideReportedAt.IsZero() && persisted.Reason == "pool_wide_failure_guard" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pool incident state was not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}

	store2, guardian2 := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
	store2.tokenCache = tokenCache
	guardian2.cache = tokenCache
	for _, accountID := range []int64{50, 53, 51} {
		store2.relayCircuitManager().ensureLoaded(accountID)
		guardian2.ensureLoaded(accountID)
	}
	guardian2.mu.Lock()
	gotUntil := guardian2.poolWideUntil
	guardian2.mu.Unlock()
	if !gotUntil.Equal(wantUntil) {
		t.Fatalf("restored pool deadline=%s want=%s", gotUntil, wantUntil)
	}

	clock.Advance(2 * time.Minute)
	guardian2.observe(guardianObservation(53, "later-transport", 598, false, clock.Now()))
	status, ok := store2.RelayGuardianAccountStatus(53)
	if !ok || status.State == RelayGuardianQuarantined || status.ShadowAction != "pool_alert" || status.Reason != "pool_wide_failure_guard" {
		t.Fatalf("restart lost pool protection: %+v ok=%t", status, ok)
	}

	clock.Advance(11 * time.Minute)
	guardian2.mu.Lock()
	guardian2.capacitySamples = []relayGuardianCapacitySample{
		{At: clock.Now().Add(-2 * RelayGuardianScanInterval)},
		{At: clock.Now().Add(-RelayGuardianScanInterval)},
		{At: clock.Now()},
	}
	guardian2.mu.Unlock()
	guardian2.observe(guardianObservation(53, "independent-a", 500, false, clock.Now()))
	clock.Advance(time.Second)
	guardian2.observe(guardianObservation(53, "independent-b", 500, false, clock.Now()))
	status, ok = store2.RelayGuardianAccountStatus(53)
	if !ok || status.State != RelayGuardianWouldQuarantine || status.ShadowAction != "quarantine" || status.Reason != "shadow_quarantine" {
		t.Fatalf("new incident remained protected after restored deadline: %+v ok=%t", status, ok)
	}
}

func TestRelayGuardianRedisOldModeClearsAllExecutionState(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	record := relayGuardianRuntimeRecord{Mode: RelayGuardianMonitor, State: RelayGuardianQuarantined, Generation: 7, QuarantineUntil: clock.Now().Add(time.Hour), BackoffLevel: 2, ProbationPercent: 50, ProbationSuccesses: 19, ProbationStartedAt: clock.Now(), TemporaryBypassUntil: clock.Now().Add(time.Minute), BypassReturnState: RelayGuardianQuarantined, Failures: []relayGuardianFailure{{At: clock.Now(), LogicalRequestID: "old", UserVisible: true}}, SeenFinal: map[string]time.Time{"old": clock.Now()}}
	payload, _ := json.Marshal(record)
	if err := tokenCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	guardian.ensureLoaded(51)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	defer guardian.mu.Unlock()
	if state.State != RelayGuardianHealthy || state.Mode != RelayGuardianEnforce || state.BackoffLevel != 0 || !state.QuarantineUntil.IsZero() || state.ProbationPercent != 0 || state.ProbationSuccesses != 0 || !state.ProbationStartedAt.IsZero() || !state.TemporaryBypassUntil.IsZero() || state.BypassReturnState != "" || len(state.Failures) != 0 || len(state.SeenFinal) != 0 || state.halfOpenSuccesses != 0 {
		t.Fatalf("old mode execution state leaked: %+v", state)
	}
}

func TestRelayGuardianStatusOmitsZeroTimes(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, _ := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	payload, err := json.Marshal(store.RelayGuardianStatus())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "0001-01-01") {
		t.Fatalf("zero time leaked into JSON: %s", payload)
	}
	health, relay := store.RelayGuardianHealth()
	healthPayload, err := json.Marshal(map[string]any{"guardian": health, "relay": relay})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(healthPayload), "0001-01-01") {
		t.Fatalf("zero time leaked into health JSON: %s", healthPayload)
	}
}

func TestRelayGuardianHealthReportsCorruptCircuitRuntimeAsUnavailable(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(4)
	defer tokenCache.Close()
	if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(51), json.RawMessage(`{"state":`), time.Hour); err != nil {
		t.Fatal(err)
	}
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	guardian.ensureLoaded(51)
	store.relayCircuit = newRelayCircuitBreaker(tokenCache)
	store.relayCircuit.now = clock.Now
	store.relayCircuit.ensureLoaded(51)

	health, relay := store.RelayGuardianHealth()
	if relay.Enabled != 1 || relay.Schedulable != 0 || relay.Degraded != 1 {
		t.Fatalf("relay summary=%+v", relay)
	}
	if !containsString(health.Reasons, "circuit_runtime_state_unavailable") {
		t.Fatalf("health did not report corrupt circuit runtime: %+v", health)
	}
}

func TestRelayGuardianHealthReportsCircuitRecoveryWithoutDoubleCounting(t *testing.T) {
	tests := []struct {
		name             string
		state            RelayCircuitState
		openUntil        time.Time
		probe            bool
		guardianDegraded bool
		wantSchedulable  int
		wantDegraded     int
		wantReason       string
	}{
		{name: "active_open", state: RelayCircuitOpen, openUntil: time.Now().Add(time.Minute), wantDegraded: 1, wantReason: "relay_circuit_open"},
		{name: "expired_open_probe_available", state: RelayCircuitOpen, openUntil: time.Now().Add(-time.Minute), wantSchedulable: 1},
		{name: "half_open_available", state: RelayCircuitHalfOpen, wantSchedulable: 1, wantDegraded: 1, wantReason: "relay_circuit_half_open"},
		{name: "half_open_probe_in_flight", state: RelayCircuitHalfOpen, probe: true, wantDegraded: 1, wantReason: "relay_circuit_half_open"},
		{name: "guardian_and_circuit_degraded_once", state: RelayCircuitOpen, openUntil: time.Now().Add(time.Minute), guardianDegraded: true, wantDegraded: 1, wantReason: "relay_circuit_open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
			guardian.mu.Lock()
			guardian.loaded[51] = true
			if tt.guardianDegraded {
				guardian.stateLocked(51).State = RelayGuardianSuspect
			}
			guardian.mu.Unlock()
			breaker := newRelayCircuitBreaker(nil)
			breaker.mu.Lock()
			breaker.loaded[51] = true
			state := breaker.stateLocked(51)
			state.state = tt.state
			state.openUntil = tt.openUntil
			state.probeInFlight = tt.probe
			breaker.mu.Unlock()
			store.relayCircuit = breaker

			health, relay := store.RelayGuardianHealth()
			if relay.Schedulable != tt.wantSchedulable || relay.Degraded != tt.wantDegraded {
				t.Fatalf("relay summary=%+v", relay)
			}
			if tt.wantReason != "" && !containsString(health.Reasons, tt.wantReason) {
				t.Fatalf("health=%+v missing %q", health, tt.wantReason)
			}
		})
	}
}

func TestRelayGuardianStatusNeverLeaksAccountCredentials(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, _ := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
	store.accountsByID[51].Email = "https://user:super-secret@relay.example/v1?api_key=secret"
	store.accountsByID[51].BaseURL = "https://other:password@relay.example/v1?token=hidden"
	store.accountsByID[51].APIKey = "sk-should-never-appear"
	payload, err := json.Marshal(store.RelayGuardianStatus())
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, secret := range []string{"super-secret", "api_key", "password", "token=hidden", "sk-should-never-appear"} {
		if strings.Contains(text, secret) {
			t.Fatalf("status leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"account_name":"relay-51"`) {
		t.Fatalf("masked account label missing: %s", text)
	}
}

func TestRelayGuardianHealthDoesNotReadRuntimeCache(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	counting := &relayGuardianCountingCache{TokenCache: baseCache}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = counting
	guardian.cache = counting
	store.RelayGuardianHealth()
	if got := counting.gets.Load(); got != 0 {
		t.Fatalf("health performed %d runtime cache reads", got)
	}
}

func TestRelayGuardianStatusOnlyListsCurrentRelayGroup(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, _ := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	outside := relayCircuitSchedulerAccount(99, 999)
	outside.GroupIDs = []int64{9}
	store.accounts = append(store.accounts, outside)
	store.accountsByID[99] = outside
	status := store.RelayGuardianStatus()
	if len(status.Accounts) != 2 {
		t.Fatalf("accounts=%v", status.Accounts)
	}
	for _, account := range status.Accounts {
		if account.AccountID == 99 {
			t.Fatal("outside-group account leaked into Guardian status")
		}
	}
}

func TestRelayGuardianRecoveryStateMachine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	clock.Advance(31 * time.Minute)
	if !guardian.selectable(store.accountsByID[51]) {
		t.Fatal("expired quarantine did not enter half-open")
	}
	first, ok := guardian.begin(store.accountsByID[51])
	if !ok || !first.HalfOpen {
		t.Fatal("first half-open lease missing")
	}
	if _, ok := guardian.begin(store.accountsByID[51]); ok {
		t.Fatal("second concurrent half-open lease was allowed")
	}
	guardian.finishSuccess(first)
	for i := 0; i < 2; i++ {
		permit, ok := guardian.begin(store.accountsByID[51])
		if !ok {
			t.Fatal("next half-open probe denied")
		}
		guardian.finishSuccess(permit)
	}
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianProbation || state.ProbationPercent != 10 {
		t.Fatalf("after probes: %+v", state)
	}
	guardian.mu.Unlock()

	advanceProbation := func() {
		clock.Advance(10 * time.Minute)
		successes := 0
		for attempts := 0; attempts < 400 && successes < relayGuardianProbationSuccesses; attempts++ {
			permit, ok := guardian.begin(store.accountsByID[51])
			if !ok {
				continue
			}
			guardian.finishSuccess(permit)
			successes++
		}
		if successes != relayGuardianProbationSuccesses {
			t.Fatalf("probation successes=%d", successes)
		}
	}
	advanceProbation()
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	if state.State != RelayGuardianProbation || state.ProbationPercent != 50 {
		t.Fatalf("after 10%%: %+v", state)
	}
	guardian.mu.Unlock()
	advanceProbation()
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	if state.State != RelayGuardianHealthy {
		t.Fatalf("after 50%%: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianProbationFailureReopensWithBackoff(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	clock.Advance(31 * time.Minute)
	for i := 0; i < 3; i++ {
		permit, ok := guardian.begin(store.accountsByID[51])
		if !ok {
			t.Fatal("half-open probe denied")
		}
		guardian.finishSuccess(permit)
	}
	var probation RelayGuardianPermit
	for attempts := 0; attempts < 20; attempts++ {
		if permit, ok := guardian.begin(store.accountsByID[51]); ok {
			probation = permit
			break
		}
	}
	if !probation.Active || !probation.Probation {
		t.Fatal("probation permit missing")
	}
	guardian.mu.Lock()
	guardian.capacitySamples = []relayGuardianCapacitySample{
		{At: clock.Now().Add(-2 * RelayGuardianScanInterval)},
		{At: clock.Now().Add(-RelayGuardianScanInterval)},
		{At: clock.Now()},
	}
	guardian.mu.Unlock()
	guardian.finishFailure(probation, 500)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	defer guardian.mu.Unlock()
	if state.State != RelayGuardianQuarantined || state.BackoffLevel != 1 || state.QuarantineUntil.Sub(clock.Now()) != time.Hour {
		t.Fatalf("failure did not reopen with 60m backoff: %+v", state)
	}
}

func TestRelayGuardianHalfOpenNonAttributableOutcomesReleaseLease(t *testing.T) {
	for _, statusCode := range []int{400, 429, 499} {
		t.Run(string(rune(statusCode)), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
			guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
			guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
			clock.Advance(31 * time.Minute)
			permit, ok := guardian.begin(store.accountsByID[51])
			if !ok {
				t.Fatal("half-open permit denied")
			}
			guardian.finishFailure(permit, statusCode)
			guardian.abandon(permit)
			if _, ok := guardian.begin(store.accountsByID[51]); !ok {
				t.Fatalf("status %d leaked half-open lease", statusCode)
			}
		})
	}
}

func TestRelayGuardianDispatchPausedAlwaysWins(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	atomic.StoreInt32(&store.accountsByID[51].DispatchPaused, 1)
	guardian.observe(guardianObservation(51, "paused-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "paused-2", 500, false, clock.Now()))
	status, ok := store.RelayGuardianAccountStatus(51)
	if !ok || status.State != RelayGuardianManualDisabled || status.ManualEnabled || status.EffectiveSchedulable {
		t.Fatalf("dispatch-paused account was not manual-disabled: %+v", status)
	}
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	old := guardian.stateLocked(51)
	old.State = RelayGuardianQuarantined
	old.QuarantineUntil = clock.Now().Add(time.Hour)
	guardian.mu.Unlock()
	_, relay := store.RelayGuardianHealth()
	if relay.Quarantined != 0 || relay.Probation != 0 || relay.Degraded != 0 {
		t.Fatalf("manual-disabled old state polluted health: %+v", relay)
	}
}

func TestRelayGuardianRuntimeLoadFailureIsUnknownFailClosedAndHealthHasNoIO(t *testing.T) {
	clock := newRelayCircuitTestClock()
	base := cache.NewMemory(10)
	defer base.Close()
	failing := &relayGuardianFailingCache{TokenCache: base}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = failing
	guardian.cache = failing
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	if guardian.loaded[51] || guardian.states[51] != nil {
		t.Fatalf("load failure created runtime state: loaded=%v state=%+v", guardian.loaded[51], guardian.states[51])
	}
	guardian.mu.Unlock()
	status, ok := store.RelayGuardianAccountStatus(51)
	if !ok || status.State != RelayGuardianSuspect || status.Reason != "runtime_state_unavailable" || status.EffectiveSchedulable {
		t.Fatalf("unknown runtime status=%+v", status)
	}
	before := failing.gets.Load()
	health, relay := store.RelayGuardianHealth()
	if after := failing.gets.Load(); after != before {
		t.Fatalf("health performed cache IO: before=%d after=%d", before, after)
	}
	if health.Status != "degraded" || relay.Degraded == 0 {
		t.Fatalf("health=%+v relay=%+v", health, relay)
	}
}

func TestRelayGuardianMonitorRuntimeUnknownIsDegradedButDoesNotFenceTraffic(t *testing.T) {
	clock := newRelayCircuitTestClock()
	base := cache.NewMemory(10)
	defer base.Close()
	failing := &relayGuardianFailingCache{TokenCache: base}
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	store.tokenCache = failing
	guardian.cache = failing
	// This case isolates Guardian monitor semantics. The Relay circuit has its own
	// fail-closed runtime fence and is covered independently below.
	store.relayCircuit = newRelayCircuitBreaker(nil)
	guardian.reconcile(context.Background())
	before := failing.gets.Load()
	health, relay := store.RelayGuardianHealth()
	if failing.gets.Load() != before {
		t.Fatal("monitor health performed runtime cache IO")
	}
	if health.Status != "degraded" || !containsString(health.Reasons, "guardian_runtime_state_unavailable") || relay.Degraded == 0 || relay.Schedulable != relay.Enabled {
		t.Fatalf("monitor unknown health=%+v relay=%+v", health, relay)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRelayGuardianCorruptRuntimeRemainsUnknownFailClosed(t *testing.T) {
	clock := newRelayCircuitTestClock()
	base := cache.NewMemory(10)
	defer base.Close()
	if err := base.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), json.RawMessage(`{"state":`), time.Hour); err != nil {
		t.Fatal(err)
	}
	counting := &relayGuardianCountingCache{TokenCache: base}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = counting
	guardian.cache = counting
	guardian.ensureLoaded(51)
	guardian.mu.Lock()
	if guardian.loaded[51] || guardian.states[51] != nil || !guardian.retryLoad[51].After(clock.Now()) {
		t.Fatalf("corrupt state was accepted: loaded=%v state=%+v retry=%s", guardian.loaded[51], guardian.states[51], guardian.retryLoad[51])
	}
	guardian.mu.Unlock()
	status, _ := store.RelayGuardianAccountStatus(51)
	if status.Reason != "runtime_state_unavailable" || status.EffectiveSchedulable {
		t.Fatalf("corrupt runtime status=%+v", status)
	}
	before := counting.gets.Load()
	health, _ := store.RelayGuardianHealth()
	if counting.gets.Load() != before || health.Status != "degraded" {
		t.Fatalf("health cache IO/status: before=%d after=%d health=%+v", before, counting.gets.Load(), health)
	}
}

func TestRelayGuardianFallbackFailureDoesNotAdvanceWatermark(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	guardian.db = db
	guardian.mu.Lock()
	guardian.incidentEpoch = clock.Now().Add(-10 * time.Minute)
	guardian.lastScan = clock.Now().Add(-8 * time.Minute)
	want := guardian.lastScan
	guardian.mu.Unlock()
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	if !guardian.lastScan.Equal(want) || guardian.scanInFlight {
		t.Fatalf("failed query advanced/stuck watermark: last=%s want=%s in_flight=%v", guardian.lastScan, want, guardian.scanInFlight)
	}
}

func TestRelayGuardianFallbackHonorsEpochAndOnlyLastLogicalRowIsFinal(t *testing.T) {
	clock := newRelayCircuitTestClock()
	path := filepath.Join(t.TempDir(), "fallback.db")
	db, err := database.New("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	epoch := clock.Now()
	insert := func(at time.Time, accountID int64, logical string, status int) {
		t.Helper()
		_, insertErr := raw.Exec(`INSERT INTO usage_logs (created_at,account_id,logical_request_id,status_code,route_class,route_source,route_group_id,upstream_account_type,guardian_attempt_only) VALUES (?,?,?,?, 'cyb_relay','direct',7,'openai_responses',false)`, at, accountID, logical, status)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	insert(epoch.Add(-time.Minute), 51, "old-a", 500)
	insert(epoch.Add(-30*time.Second), 51, "old-b", 500)
	insert(epoch.Add(time.Minute), 50, "retry-chain", 502)
	insert(epoch.Add(2*time.Minute), 53, "retry-chain", 200)
	insert(epoch.Add(3*time.Minute), 51, "new-a", 500)
	insert(epoch.Add(4*time.Minute), 51, "new-b", 500)
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50, 53)
	guardian.db = db
	guardian.incidentEpoch = epoch
	clock.Advance(5 * time.Minute)
	if _, err := guardian.scanUsageFallback(context.Background(), 7, RelayGuardianEnforce, epoch, epoch.Add(-2*time.Minute), clock.Now()); err != nil {
		t.Fatal(err)
	}
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	state51 := guardian.stateLocked(51)
	if state51.State != RelayGuardianQuarantined || len(state51.SeenFinal) != 2 {
		t.Fatalf("post-epoch finals=%+v", state51)
	}
	if _, leaked := state51.SeenFinal["old-a"]; leaked {
		t.Fatalf("pre-epoch row replayed: %+v", state51.SeenFinal)
	}
	state50 := guardian.stateLocked(50)
	if len(state50.SeenFinal) != 0 || len(state50.SeenStrong) != 1 {
		t.Fatalf("retry attempt misclassified final: %+v", state50)
	}
	if state53 := guardian.stateLocked(53); len(state53.Failures) != 0 {
		t.Fatalf("successful terminal row affected Guardian: %+v", state53)
	}
}

func TestRelayGuardianSuspectWouldAgeAndBackoffNeeds24HealthyHours(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	guardian.observe(guardianObservation(51, "age-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "age-2", 500, false, clock.Now()))
	clock.Advance(11 * time.Minute)
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianSuspect {
		t.Fatalf("would state skipped suspect aging: %+v", state)
	}
	guardian.mu.Unlock()
	clock.Advance(50 * time.Minute)
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	if state.State != RelayGuardianHealthy || state.LastResort || state.HealthySince.IsZero() {
		t.Fatalf("expired incident did not recover: %+v", state)
	}
	state.BackoffLevel = 2
	guardian.mu.Unlock()
	clock.Advance(23 * time.Hour)
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	if state.BackoffLevel != 2 {
		t.Fatalf("backoff cleared before 24h: %+v", state)
	}
	guardian.mu.Unlock()
	clock.Advance(61 * time.Minute)
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	if state.BackoffLevel != 0 {
		t.Fatalf("backoff not cleared after 24h healthy: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianProbationBeginNeverRejectsAfterSchedulerAcquire(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	state := guardian.stateLocked(51)
	state.State = RelayGuardianProbation
	state.ProbationPercent = 10
	guardian.mu.Unlock()
	for index := 0; index < 25; index++ {
		permit, ok := guardian.begin(store.accountsByID[51])
		if !ok || !permit.Probation {
			t.Fatalf("probation begin rejected acquired request at %d: permit=%+v", index, permit)
		}
		guardian.abandon(permit)
	}
}

func TestRelayGuardianCapacityRequiresAnotherHealthyClosedRelay(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.mu.Lock()
	guardian.loaded[50] = true
	other := guardian.stateLocked(50)
	other.State = RelayGuardianProbation
	other.ProbationPercent = 50
	guardian.mu.Unlock()
	guardian.observe(guardianObservation(51, "capacity-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "capacity-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State == RelayGuardianQuarantined || !state.LastResort || state.Reason != "last_available_relay" {
		t.Fatalf("recovering peer counted healthy: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianCapacityDoesNotCountCircuitHalfOpenAsHealthy(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	breaker.loaded[50] = true
	circuitState := breaker.stateLocked(50)
	circuitState.state = RelayCircuitHalfOpen
	breaker.mu.Unlock()
	guardian.observe(guardianObservation(51, "half-capacity-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "half-capacity-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State == RelayGuardianQuarantined || !state.LastResort || state.Reason != "last_available_relay" {
		t.Fatalf("half-open circuit counted healthy: %+v", state)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianRecoveryFailuresCannotQuarantineLastRelay(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	guardian.db = db
	makePermit := func(accountID int64, lease uint64) RelayGuardianPermit {
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		guardian.loaded[accountID] = true
		state := guardian.stateLocked(accountID)
		state.State = RelayGuardianProbation
		state.ProbationPercent = 10
		permit := RelayGuardianPermit{AccountID: accountID, Generation: state.Generation, LeaseID: lease, Probation: true, Active: true}
		state.permits[lease] = permit
		return permit
	}
	guardian.finishFailure(makePermit(51, 101), 500)
	guardian.mu.Lock()
	if guardian.stateLocked(51).State != RelayGuardianQuarantined {
		t.Fatalf("first recovery failure should quarantine with healthy peer: %+v", guardian.stateLocked(51))
	}
	guardian.mu.Unlock()
	guardian.finishFailure(makePermit(50, 102), 500)
	guardian.mu.Lock()
	last := guardian.stateLocked(50)
	if last.State == RelayGuardianQuarantined || !last.LastResort || last.LastResortCap != 5 || last.Reason != "pool_wide_failure_guard" {
		t.Fatalf("last Relay was not held as capped pool-wide last-resort: %+v", last)
	}
	guardian.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		page, listErr := db.ListRelayGuardianEvents(context.Background(), 1, 20, time.Time{}, time.Time{})
		if listErr != nil {
			t.Fatal(listErr)
		}
		found := false
		for _, event := range page.Items {
			if event.EventType == RelayGuardianEventPoolWide && event.TriggerSource == "recovery_failure_500" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery pool-wide event missing: %+v", page.Items)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = store
}

func TestRelayGuardianProductionReplayFixture(t *testing.T) {
	type replayRow struct {
		account         int64
		offset          time.Duration
		status          int
		routeSource     string
		errorKind       string
		logicalRelation string
		attemptOnly     bool
	}
	replay := func(t *testing.T, ids []int64, rows []replayRow) (*Store, *relayHealthGuardian) {
		t.Helper()
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, ids...)
		var elapsed time.Duration
		for _, row := range rows {
			if row.offset > elapsed {
				clock.Advance(row.offset - elapsed)
				elapsed = row.offset
			}
			obs := guardianObservation(row.account, row.logicalRelation, row.status, row.attemptOnly, clock.Now())
			obs.RouteSource = row.routeSource
			obs.UpstreamErrorKind = row.errorKind
			guardian.observe(obs)
		}
		return store, guardian
	}
	t.Run("account51_midday_502_burst", func(t *testing.T) {
		_, guardian := replay(t, []int64{51, 50, 53}, []replayRow{
			{51, 0, 502, "direct", "gateway", "burst-a", true}, {51, time.Minute, 502, "direct", "gateway", "burst-b", true}, {51, 2 * time.Minute, 502, "direct", "gateway", "burst-c", true},
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		if state := guardian.stateLocked(51); state.State != RelayGuardianQuarantined {
			t.Fatalf("502 burst not quarantined: %+v", state)
		}
	})
	t.Run("account50_only_available_two_500", func(t *testing.T) {
		_, guardian := replay(t, []int64{50}, []replayRow{
			{50, 0, 500, "direct", "server", "visible-a", false}, {50, 2 * time.Minute, 500, "direct", "server", "visible-b", false},
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		if state := guardian.stateLocked(50); state.State == RelayGuardianQuarantined || !state.LastResort || state.LastResortCap != 5 {
			t.Fatalf("only Relay not kept last-resort: %+v", state)
		}
	})
	t.Run("shared_524_window_is_pool_wide", func(t *testing.T) {
		_, guardian := replay(t, []int64{50, 53, 51}, []replayRow{
			{50, 0, 524, "direct", "gateway", "shared-a", true}, {53, 30 * time.Second, 524, "direct", "gateway", "shared-a", true},
			{50, time.Minute, 524, "direct", "gateway", "shared-b", true}, {53, 90 * time.Second, 524, "direct", "gateway", "shared-b", true},
			{53, 2 * time.Minute, 524, "direct", "gateway", "only-53", true},
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		for _, accountID := range []int64{50, 53} {
			if state := guardian.stateLocked(accountID); state.State == RelayGuardianQuarantined {
				t.Fatalf("pool-wide account %d hard-quarantined: %+v", accountID, state)
			}
		}
		if state := guardian.stateLocked(53); state.Reason != "pool_wide_failure_guard" || !state.LastResort {
			t.Fatalf("pool-wide guard missing: %+v", state)
		}
	})
}

func TestRelayGuardianMonitorShadowDecisionsMatchEnforceGuards(t *testing.T) {
	t.Run("burst_shadow_quarantine", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50, 53)
		for _, logical := range []string{"burst-a", "burst-b", "burst-c"} {
			guardian.observe(guardianObservation(51, logical, 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.State != RelayGuardianWouldQuarantine || state.ShadowAction != "quarantine" || state.Reason != "shadow_quarantine" {
			t.Fatalf("shadow quarantine=%+v", state)
		}
	})
	t.Run("only_relay_shadow_last_resort", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50)
		guardian.observe(guardianObservation(50, "only-a", 500, false, clock.Now()))
		guardian.observe(guardianObservation(50, "only-b", 500, false, clock.Now()))
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(50)
		if state.State != RelayGuardianWouldQuarantine || state.ShadowAction != "last_resort" || state.Reason != "last_available_relay" {
			t.Fatalf("shadow last-resort=%+v", state)
		}
	})
	t.Run("shared_524_shadow_pool_alert", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		clock.mu.Lock()
		clock.now = time.Now().UTC().Truncate(time.Second)
		clock.mu.Unlock()
		store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
		guardian.observe(guardianObservation(50, "shared-a", 524, true, clock.Now()))
		guardian.observe(guardianObservation(53, "shared-a", 524, true, clock.Now()))
		guardian.observe(guardianObservation(50, "shared-b", 524, true, clock.Now()))
		guardian.observe(guardianObservation(53, "shared-b", 524, true, clock.Now()))
		guardian.observe(guardianObservation(53, "only-53", 524, true, clock.Now()))
		guardian.mu.Lock()
		state := guardian.stateLocked(53)
		if state.State != RelayGuardianWouldQuarantine || state.ShadowAction != "pool_alert" || state.Reason != "pool_wide_failure_guard" || !guardian.poolWideUntil.After(clock.Now()) {
			guardian.mu.Unlock()
			t.Fatalf("shadow pool=%+v until=%s", state, guardian.poolWideUntil)
		}
		guardian.mu.Unlock()
		health, _ := store.RelayGuardianHealth()
		if !containsString(health.Reasons, "pool_wide_failure") {
			t.Fatalf("pool-wide health not degraded: %+v", health)
		}
	})
}

func TestRelayGuardianPoolIncidentProtectionDoesNotDecayIntoAccountQuarantine(t *testing.T) {
	for _, mode := range []RelayGuardianMode{RelayGuardianMonitor, RelayGuardianEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, mode, clock, 50, 53, 51)

			guardian.observe(guardianObservation(50, "peer-a", 524, false, clock.Now()))
			clock.Advance(30 * time.Second)
			guardian.observe(guardianObservation(50, "peer-b", 524, false, clock.Now()))
			clock.Advance(3 * time.Minute)
			guardian.observe(guardianObservation(53, "candidate-a", 524, false, clock.Now()))
			clock.Advance(30 * time.Second)
			guardian.observe(guardianObservation(53, "candidate-b", 524, false, clock.Now()))

			guardian.mu.Lock()
			incidentUntil := guardian.poolWideUntil
			state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(53).relayGuardianRuntimeRecord)
			guardian.mu.Unlock()
			if state.Reason != "pool_wide_failure_guard" || !incidentUntil.Equal(clock.Now().Add(10*time.Minute)) {
				t.Fatalf("initial pool incident state=%+v until=%s now=%s", state, incidentUntil, clock.Now())
			}

			// The peer 524 evidence leaves the 5m signature window while the
			// candidate's final 524 evidence still occupies the 10m trigger window.
			// A later single 598 must remain part of the pool-safe incident rather
			// than combining with the 524s into an account quarantine.
			clock.Advance(2 * time.Minute)
			guardian.reconcile(context.Background())
			guardian.observe(guardianObservation(53, "later-transport", 598, false, clock.Now()))
			guardian.mu.Lock()
			state = cloneRelayGuardianRuntimeRecord(guardian.stateLocked(53).relayGuardianRuntimeRecord)
			incidentAfterReconcile := guardian.poolWideUntil
			guardian.mu.Unlock()
			if state.State == RelayGuardianQuarantined || state.Reason != "pool_wide_failure_guard" {
				t.Fatalf("pool incident decayed after peer window/598: %+v", state)
			}
			if !incidentAfterReconcile.Equal(incidentUntil) {
				t.Fatalf("reconcile slid pool deadline: before=%s after=%s", incidentUntil, incidentAfterReconcile)
			}

			// After all old pool/transport evidence has expired, a new independent
			// per-account incident is evaluated normally.
			clock.Advance(11 * time.Minute)
			guardian.mu.Lock()
			guardian.capacitySamples = []relayGuardianCapacitySample{
				{At: clock.Now().Add(-2 * RelayGuardianScanInterval)},
				{At: clock.Now().Add(-RelayGuardianScanInterval)},
				{At: clock.Now()},
			}
			guardian.mu.Unlock()
			guardian.observe(guardianObservation(53, "independent-a", 500, false, clock.Now()))
			clock.Advance(time.Second)
			guardian.observe(guardianObservation(53, "independent-b", 500, false, clock.Now()))
			status, ok := store.RelayGuardianAccountStatus(53)
			if !ok {
				t.Fatal("missing account 53 status")
			}
			if mode == RelayGuardianMonitor {
				if status.State != RelayGuardianWouldQuarantine || status.ShadowAction != "quarantine" || status.Reason != "shadow_quarantine" {
					t.Fatalf("new monitor incident remained pool-protected: %+v", status)
				}
			} else if status.State != RelayGuardianQuarantined {
				t.Fatalf("new enforce incident remained pool-protected: %+v", status)
			}
		})
	}
}

func TestRelayGuardianLockOrderRegression(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50, 53)
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for index := 0; index < 200; index++ {
			guardian.reconcile(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		for index := 0; index < 200; index++ {
			store.mu.Lock()
			guardian.mu.Lock()
			guardian.mu.Unlock()
			store.mu.Unlock()
		}
	}()
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("guardian/store lock order deadlocked")
	}
}

func TestRelayGuardianRelayGroupScopeDoesNotInheritOldRuntime(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	record := relayGuardianRuntimeRecord{Mode: RelayGuardianEnforce, ScopeGroupID: 7, State: RelayGuardianQuarantined, Generation: 3, QuarantineUntil: clock.Now().Add(time.Hour)}
	payload, _ := json.Marshal(record)
	if err := tokenCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	if guardian.selectable(store.accountsByID[51]) {
		t.Fatal("setup quarantine was not restored")
	}
	store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 9})
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, ok, _ := tokenCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old Relay group runtime key was not cleared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 7})
	if !guardian.selectable(store.accountsByID[51]) {
		t.Fatal("account inherited quarantine after leaving and rejoining Relay group")
	}
}

func TestRelayGuardianOneScanCanCreateOnlyOneNewQuarantine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50, 53)
	guardian.observe(guardianObservation(51, "first-a", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "first-b", 500, false, clock.Now()))
	for _, logical := range []string{"second-a", "second-b", "second-c"} {
		guardian.observe(guardianObservation(50, logical, 502, true, clock.Now()))
	}
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	if guardian.stateLocked(51).State != RelayGuardianQuarantined {
		t.Fatalf("first candidate not quarantined: %+v", guardian.stateLocked(51))
	}
	second := guardian.stateLocked(50)
	if second.State == RelayGuardianQuarantined || !second.LastResort || second.Reason != "one_quarantine_per_scan_guard" {
		t.Fatalf("second candidate crossed per-scan guard: %+v", second)
	}
}

func TestRelayGuardianPoolCorrelationOutranksOnePerScanGuard(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53)
	for _, logical := range []string{"first-a", "first-b", "first-c"} {
		guardian.observe(guardianObservation(50, logical, 502, true, clock.Now()))
	}
	clock.Advance(30 * time.Second)
	for _, logical := range []string{"second-a", "second-b", "second-c"} {
		guardian.observe(guardianObservation(53, logical, 502, true, clock.Now()))
	}
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	first := guardian.stateLocked(50)
	second := guardian.stateLocked(53)
	if first.ShadowAction != "quarantine" {
		t.Fatalf("first shadow decision=%+v", first)
	}
	if second.ShadowAction != "pool_alert" || second.Reason != "pool_wide_failure_guard" {
		t.Fatalf("pool correlation lost behind per-scan guard: %+v", second)
	}
}

func TestRelayGuardianHotShadowAccountDoesNotRefreshOnePerScanSlot(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
	for _, logical := range []string{"hot-a", "hot-b", "hot-c"} {
		guardian.observe(guardianObservation(50, logical, 502, true, clock.Now()))
	}
	guardian.mu.Lock()
	occupiedAt := guardian.lastShadowQuarantine
	guardian.mu.Unlock()
	clock.Advance(30 * time.Second)
	guardian.observe(guardianObservation(50, "hot-d", 502, true, clock.Now()))
	guardian.mu.Lock()
	hotAt := guardian.lastShadowQuarantine
	hotState := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(50).relayGuardianRuntimeRecord)
	if !hotAt.Equal(occupiedAt) || hotState.ShadowAction != "quarantine" {
		guardian.mu.Unlock()
		t.Fatalf("hot account refreshed/changed slot: at=%s want=%s state=%+v", hotAt, occupiedAt, hotState)
	}
	guardian.mu.Unlock()
	clock.Advance(31 * time.Second)
	for _, logical := range []string{"other-a", "other-b", "other-c"} {
		guardian.observe(guardianObservation(53, logical, 504, true, clock.Now()))
	}
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	other := guardian.stateLocked(53)
	if other.ShadowAction != "quarantine" || other.Reason != "shadow_quarantine" {
		t.Fatalf("expired slot still blocked other account: %+v", other)
	}
}

func TestRelayGuardianEventUsesActionTimeAndMaskedAccountName(t *testing.T) {
	clock := newRelayCircuitTestClock()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.db = db
	observed := clock.Now().Add(-2 * time.Minute)
	guardian.incidentEpoch = observed.Add(-time.Second)
	guardian.observe(guardianObservation(51, "event-a", 500, false, observed))
	guardian.observe(guardianObservation(51, "event-b", 500, false, observed.Add(time.Minute)))
	deadline := time.Now().Add(2 * time.Second)
	for {
		page, listErr := db.ListRelayGuardianEvents(context.Background(), 1, 20, time.Time{}, time.Time{})
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, event := range page.Items {
			if event.EventType != RelayGuardianEventQuarantine {
				continue
			}
			if event.AccountName != "relay-51" {
				t.Fatalf("event leaked account name: %+v", event)
			}
			if !event.CreatedAt.Equal(clock.Now()) {
				t.Fatalf("action time=%s want current=%s (observed=%s)", event.CreatedAt, clock.Now(), observed)
			}
			guardian.mu.Lock()
			until := guardian.stateLocked(51).QuarantineUntil
			guardian.mu.Unlock()
			if until.Sub(clock.Now()) != 30*time.Minute {
				t.Fatalf("quarantine used observation time: until=%s", until)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("quarantine event not persisted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayGuardianPeriodicSummaryAndHourlyAuditAreDebounced(t *testing.T) {
	clock := newRelayCircuitTestClock()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	guardian.db = db
	guardian.mu.Lock()
	guardian.incidentEpoch = clock.Now().Add(-10 * time.Minute)
	guardian.lastScan = guardian.incidentEpoch
	guardian.mu.Unlock()
	guardian.reconcile(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for {
		page, listErr := db.ListRelayGuardianEvents(context.Background(), 1, 20, time.Time{}, time.Time{})
		if listErr != nil {
			t.Fatal(listErr)
		}
		seen := map[string]int{}
		for _, event := range page.Items {
			seen[event.EventType]++
		}
		if seen[RelayGuardianEventSummary] == 1 && seen[RelayGuardianEventAudit] == 1 {
			guardian.reconcile(context.Background())
			time.Sleep(50 * time.Millisecond)
			after, _ := db.ListRelayGuardianEvents(context.Background(), 1, 20, time.Time{}, time.Time{})
			counts := map[string]int{}
			for _, event := range after.Items {
				counts[event.EventType]++
			}
			if counts[RelayGuardianEventSummary] != 1 || counts[RelayGuardianEventAudit] != 1 {
				t.Fatalf("periodic events not debounced: %v", counts)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("periodic events missing: %v", seen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
