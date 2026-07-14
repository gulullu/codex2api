package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
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

type relayGuardianBlockingSetCache struct {
	cache.TokenCache
	once          sync.Once
	entered       chan struct{}
	release       chan struct{}
	ignoreContext bool
}

type relayGuardianBlockingDeleteCache struct {
	cache.TokenCache
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type relayGuardianFailingSetCache struct {
	cache.TokenCache
	sets atomic.Int64
}

type relayGuardianFailingMutationCache struct {
	cache.TokenCache
	gets    atomic.Int64
	sets    atomic.Int64
	deletes atomic.Int64
}

type relayGuardianMembershipABACache struct {
	cache.TokenCache
	deleteOnce    sync.Once
	deleteEntered chan struct{}
	deleteRelease chan struct{}
	sets          atomic.Int64
	deletes       atomic.Int64
}

type relayGuardianMembershipMutationCache struct {
	cache.TokenCache
	failDelete  bool
	failHealthy bool
	gets        atomic.Int64
	sets        atomic.Int64
	deletes     atomic.Int64
}

func (c *relayGuardianFailingCache) GetRuntime(context.Context, string, string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return nil, false, errors.New("runtime unavailable")
}

func (c *relayGuardianCountingCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return c.TokenCache.GetRuntime(ctx, namespace, key)
}

func (c *relayGuardianBlockingSetCache) SetRuntime(ctx context.Context, namespace, key string, value json.RawMessage, ttl time.Duration) error {
	block := false
	c.once.Do(func() {
		block = true
		close(c.entered)
	})
	if block {
		if c.ignoreContext {
			<-c.release
		} else {
			select {
			case <-c.release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return c.TokenCache.SetRuntime(ctx, namespace, key, value, ttl)
}

func (c *relayGuardianBlockingDeleteCache) DeleteRuntime(ctx context.Context, namespace, key string) error {
	block := false
	c.once.Do(func() {
		block = true
		close(c.entered)
	})
	if block {
		select {
		case <-c.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.TokenCache.DeleteRuntime(ctx, namespace, key)
}

func (c *relayGuardianFailingSetCache) SetRuntime(context.Context, string, string, json.RawMessage, time.Duration) error {
	c.sets.Add(1)
	return errors.New("runtime write unavailable")
}

func (c *relayGuardianFailingMutationCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return c.TokenCache.GetRuntime(ctx, namespace, key)
}

func (c *relayGuardianFailingMutationCache) SetRuntime(context.Context, string, string, json.RawMessage, time.Duration) error {
	c.sets.Add(1)
	return errors.New("runtime write unavailable")
}

func (c *relayGuardianFailingMutationCache) DeleteRuntime(context.Context, string, string) error {
	c.deletes.Add(1)
	return errors.New("runtime delete unavailable")
}

func (c *relayGuardianMembershipABACache) DeleteRuntime(ctx context.Context, namespace, key string) error {
	c.deletes.Add(1)
	c.deleteOnce.Do(func() { close(c.deleteEntered) })
	select {
	case <-c.deleteRelease:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.New("runtime delete unavailable")
}

func (c *relayGuardianMembershipABACache) SetRuntime(ctx context.Context, namespace, key string, payload json.RawMessage, ttl time.Duration) error {
	if c.sets.Add(1) == 1 {
		return errors.New("healthy tombstone unavailable")
	}
	return c.TokenCache.SetRuntime(ctx, namespace, key, payload, ttl)
}

func (c *relayGuardianMembershipMutationCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	c.gets.Add(1)
	return c.TokenCache.GetRuntime(ctx, namespace, key)
}

func (c *relayGuardianMembershipMutationCache) DeleteRuntime(ctx context.Context, namespace, key string) error {
	c.deletes.Add(1)
	if c.failDelete {
		return errors.New("runtime delete unavailable")
	}
	return c.TokenCache.DeleteRuntime(ctx, namespace, key)
}

func (c *relayGuardianMembershipMutationCache) SetRuntime(ctx context.Context, namespace, key string, payload json.RawMessage, ttl time.Duration) error {
	if c.sets.Add(1) == 1 && c.failHealthy {
		return errors.New("healthy tombstone unavailable")
	}
	return c.TokenCache.SetRuntime(ctx, namespace, key, payload, ttl)
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
	// Most Guardian tests exercise steady-state policy, not the boot fence.
	// Seed recent canonical success for every peer and age the cold-start guard
	// out explicitly; dedicated tests cover both protections below.
	guardian.coldStartUntil = clock.Now().Add(-time.Second)
	for _, account := range accounts {
		relayGuardianRecordCanonicalSuccess(account, clock.Now())
	}
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

// confirmGuardianWeakForTest drives the downstream guard/state-machine tests
// with a DB-confirmed weak incident. Candidate timing and reliability math are
// covered separately; these older tests are about quarantine, pool and recovery
// behavior after confirmation.
func confirmGuardianWeakForTest(t *testing.T, guardian *relayHealthGuardian, accountID int64) {
	t.Helper()
	now := guardian.nowTime()
	accounts := guardian.store.configuredRelayGuardianAccounts()
	capacity := guardian.capacityInputs(accounts)
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	state := guardian.stateLocked(accountID)
	state.WeakCandidateTrigger = "weak_reliability_10m"
	state.WeakCandidateLatestFailureRowID = 101
	state.WeakCandidateSince = now.Add(-RelayGuardianScanInterval)
	state.WeakConfirmationCount = relayGuardianWeakConfirmations
	state.ReliabilityObservedAt = now
	state.ReliabilityTotal = 2
	state.ReliabilityFailures = 2
	state.ReliabilityWindowSeconds = 600
	state.FailureRatePercent = 100
	state.FailureRateLowerBoundPercent = 100 * relayGuardianWilsonLowerBound(2, 2)
	state.ReliabilityLatestFailureRowID = 101
	guardian.applyTriggerLocked(guardian.store.FindByID(accountID), state, accounts, capacity, "weak_reliability_10m", 10*time.Minute, 2, 0, now)
}

// confirmGuardianStrongBreakerCyclesForTest models a fast-breaker reopen that
// has already proven two independent strong transport cycles. Raw 3-in-5m
// observations are deliberately insufficient for long Guardian isolation.
func confirmGuardianStrongBreakerCyclesForTest(t *testing.T, guardian *relayHealthGuardian, accountID int64) {
	t.Helper()
	now := guardian.nowTime()
	guardian.mu.Lock()
	state := guardian.stateLocked(accountID)
	state.StrongCircuitCycleToken = 1
	state.StrongCircuitCycleCount = 1
	state.StrongCircuitCycleStartedAt = now.Add(-time.Minute)
	state.StrongCircuitCycleLastAt = now.Add(-time.Minute)
	guardian.mu.Unlock()
	setGuardianStrongBreakerOpenForTest(t, guardian, accountID, 2, 1)
}

func setGuardianStrongBreakerOpenForTest(t *testing.T, guardian *relayHealthGuardian, accountID int64, cycleToken uint64, backoff int) {
	setGuardianBreakerOpenForTest(t, guardian, accountID, cycleToken, backoff, http.StatusBadGateway)
}

func setGuardianBreakerOpenForTest(t *testing.T, guardian *relayHealthGuardian, accountID int64, generation uint64, backoff, statusCode int) {
	t.Helper()
	breaker := guardian.store.relayCircuitManager()
	now := guardian.nowTime()
	breaker.mu.Lock()
	breaker.now = guardian.now
	breaker.loaded[accountID] = true
	state := breaker.stateLocked(accountID)
	state.state = RelayCircuitOpen
	if generation == 0 {
		generation = state.generation + 1
	}
	state.generation = generation
	if IsRelayStrongGatewayFailureStatus(statusCode) {
		state.confirmedStrongCycleToken = generation
	}
	state.reason = "test_confirmed_reopen"
	state.lastStatusCode = statusCode
	state.openedAt = now
	state.openUntil = now.Add(30 * time.Minute)
	state.updatedAt = now
	state.backoffLevel = backoff
	breaker.mu.Unlock()
}

func applyGuardianReliabilityForTest(t *testing.T, guardian *relayHealthGuardian, accountID int64, snapshot relayGuardianReliabilitySnapshot) {
	t.Helper()
	accounts := guardian.store.configuredRelayGuardianAccounts()
	capacity := guardian.capacityInputs(accounts)
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	if snapshot.ObservedAt.IsZero() {
		snapshot.ObservedAt = guardian.nowTime()
	}
	guardian.applyReliabilityLocked(guardian.store.FindByID(accountID), guardian.stateLocked(accountID), accounts, capacity, snapshot, guardian.nowTime())
}

func recoverGuardianAccountForTest(t *testing.T, store *Store, guardian *relayHealthGuardian, clock *relayCircuitTestClock, accountID int64) {
	t.Helper()
	account := store.accountsByID[accountID]
	clock.Advance(31 * time.Minute)
	for index := 0; index < 3; index++ {
		permit, ok := guardian.begin(account)
		if !ok || !permit.HalfOpen {
			t.Fatalf("half-open recovery permit %d missing: %+v", index, permit)
		}
		guardian.finishSuccess(permit)
	}
	for stage := 0; stage < 2; stage++ {
		clock.Advance(relayGuardianProbationStage)
		for success := 0; success < relayGuardianProbationSuccesses; success++ {
			permit, ok := guardian.begin(account)
			if !ok || !permit.Probation {
				t.Fatalf("probation stage=%d success=%d permit missing: %+v", stage, success, permit)
			}
			guardian.finishSuccess(permit)
		}
	}
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	if state := guardian.stateLocked(accountID); state.State != RelayGuardianHealthy {
		t.Fatalf("recovery did not finish: %+v", state)
	}
}

func TestRelayGuardianWeakReliabilityThresholdsAndConfirmation(t *testing.T) {
	if relayGuardianTriggerCategory("weak_reliability_10m") != "user_visible" || relayGuardianTriggerCategory("weak_reliability_catastrophic_10m") != "user_visible" || relayGuardianTriggerWindow("weak_reliability_60m") != time.Hour {
		t.Fatal("weak reliability triggers are not mapped into pool correlation windows")
	}
	t.Run("high_volume_noise_does_not_trigger", func(t *testing.T) {
		decision := relayGuardianWeakReliabilityDecision(relayGuardianReliabilitySnapshot{Total10m: 1209, Failures10m: 6, LatestFailureRowID10m: 6})
		if decision.Trigger != "" || relayGuardianWilsonLowerBound(6, 1209) >= 0.01 {
			t.Fatalf("6/1209 triggered weak isolation: %+v lower=%f", decision, relayGuardianWilsonLowerBound(6, 1209))
		}
	})

	t.Run("second_reconcile_requires_new_failure_and_60_seconds", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		first := relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 10, Failures10m: 2, LatestFailureRowID10m: 10, Total60m: 10, Failures60m: 2, LatestFailureRowID60m: 10}
		applyGuardianReliabilityForTest(t, guardian, 51, first)
		guardian.mu.Lock()
		if got := guardian.stateLocked(51).WeakConfirmationCount; got != 1 {
			guardian.mu.Unlock()
			t.Fatalf("first confirmation=%d", got)
		}
		guardian.mu.Unlock()
		first.LatestFailureRowID10m = 11
		first.LatestFailureRowID60m = 11
		applyGuardianReliabilityForTest(t, guardian, 51, first)
		guardian.mu.Lock()
		if got := guardian.stateLocked(51).WeakConfirmationCount; got != 1 {
			guardian.mu.Unlock()
			t.Fatalf("same-interval confirmation=%d, want 1", got)
		}
		guardian.mu.Unlock()
		clock.Advance(RelayGuardianScanInterval)
		first.ObservedAt = clock.Now()
		applyGuardianReliabilityForTest(t, guardian, 51, first)
		guardian.mu.Lock()
		state := guardian.stateLocked(51)
		if state.WeakConfirmationCount != 2 || state.State != RelayGuardianWouldQuarantine || state.TriggerSource != "weak_reliability_10m" {
			guardian.mu.Unlock()
			t.Fatalf("confirmed state=%+v", state)
		}
		guardian.mu.Unlock()
	})

	t.Run("same_failure_id_never_confirms", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		snapshot := relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 7, Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 7}
		applyGuardianReliabilityForTest(t, guardian, 51, snapshot)
		clock.Advance(RelayGuardianScanInterval)
		snapshot.ObservedAt = clock.Now()
		applyGuardianReliabilityForTest(t, guardian, 51, snapshot)
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.WeakConfirmationCount != 1 || state.State == RelayGuardianWouldQuarantine {
			t.Fatalf("unchanged failure confirmed: %+v", state)
		}
	})

	t.Run("stale_pending_candidate_restarts_at_one", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 60,
			Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 60,
		})
		clock.Advance(2*RelayGuardianScanInterval + time.Second)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 61,
			Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 61,
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.WeakConfirmationCount != 1 || state.WeakCandidateLatestFailureRowID != 61 ||
			!state.WeakCandidateSince.Equal(clock.Now()) || state.State == RelayGuardianWouldQuarantine {
			t.Fatalf("stale weak candidate was confirmed instead of restarted: %+v", state)
		}
	})

	t.Run("below_threshold_clears_pending_explanation", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 7, Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 7})
		clock.Advance(RelayGuardianScanInterval)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 1000, Failures10m: 1, LatestFailureRowID10m: 8, Total60m: 1000, Failures60m: 1, LatestFailureRowID60m: 8})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.WeakConfirmationCount != 0 || state.TriggerSource != "" || state.WindowSeconds != 0 || state.Reason != "weak_reliability_below_threshold" || state.ReliabilityWindowSeconds != 600 {
			t.Fatalf("below-threshold state=%+v", state)
		}
	})

	t.Run("catastrophic_is_immediate", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 40, Failures10m: 10, LatestFailureRowID10m: 20, Total60m: 40, Failures60m: 10, LatestFailureRowID60m: 20})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.State != RelayGuardianWouldQuarantine || state.TriggerSource != "weak_reliability_catastrophic_10m" || state.WeakConfirmationCount != 0 {
			t.Fatalf("catastrophic state=%+v", state)
		}
	})

	t.Run("sixty_minute_signal_needs_recent_failure", func(t *testing.T) {
		decision := relayGuardianWeakReliabilityDecision(relayGuardianReliabilitySnapshot{Total10m: 100, Failures10m: 0, Total60m: 100, Failures60m: 4, LatestFailureRowID60m: 4})
		if decision.Trigger != "" {
			t.Fatalf("stale 60m failures triggered: %+v", decision)
		}
	})

	t.Run("monitor_strong_shadow_transitions_to_weak_confirmation", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("strong-to-weak-%d", index), 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		strong := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if strong.State != RelayGuardianWouldQuarantine || strong.ShadowAction != "quarantine" || strong.TriggerSource != "strong_breaker_2_cycles_in_10m" {
			t.Fatalf("strong shadow state=%+v", strong)
		}

		clock.Advance(6 * time.Minute)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 20,
			Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 20,
		})
		guardian.mu.Lock()
		candidate := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if candidate.State != RelayGuardianSuspect || candidate.ShadowAction != "" || candidate.WeakConfirmationCount != 1 ||
			candidate.TriggerSource != "weak_reliability_10m" || candidate.Reason != "weak_reliability_confirming" {
			t.Fatalf("first weak confirmation inherited strong shadow: %+v", candidate)
		}

		clock.Advance(RelayGuardianScanInterval)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 21,
			Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 21,
		})
		guardian.mu.Lock()
		confirmed := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if confirmed.State != RelayGuardianWouldQuarantine || confirmed.ShadowAction != "quarantine" ||
			confirmed.WeakConfirmationCount != relayGuardianWeakConfirmations || confirmed.TriggerSource != "weak_reliability_10m" {
			t.Fatalf("confirmed weak shadow state=%+v", confirmed)
		}
	})

	t.Run("enforce_strong_last_resort_rechecks_capacity_after_weak_confirmation", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
		confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
		guardian.mu.Lock()
		peer := guardian.stateLocked(50)
		peer.State = RelayGuardianProbation
		peer.ProbationPercent = 50
		guardian.mu.Unlock()
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("last-resort-to-weak-%d", index), 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		strong := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if strong.State == RelayGuardianQuarantined || !strong.LastResort || strong.LastResortCap != 5 || strong.TriggerSource != "strong_breaker_2_cycles_in_10m" {
			t.Fatalf("strong last-resort state=%+v", strong)
		}

		clock.Advance(6 * time.Minute)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 30,
			Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 30,
		})
		guardian.mu.Lock()
		candidate := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if !candidate.LastResort || candidate.LastResortCap != 5 || candidate.WeakConfirmationCount != 1 ||
			candidate.TriggerSource != "weak_reliability_10m" || candidate.Reason != "weak_reliability_confirming" {
			t.Fatalf("weak candidate discarded last-resort protection: %+v", candidate)
		}

		guardian.mu.Lock()
		peer = guardian.stateLocked(50)
		peer.State = RelayGuardianHealthy
		peer.ProbationPercent = 0
		guardian.mu.Unlock()
		clock.Advance(RelayGuardianScanInterval)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 31,
			Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 31,
		})
		guardian.mu.Lock()
		confirmed := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if confirmed.State != RelayGuardianQuarantined || confirmed.LastResort || confirmed.LastResortCap != 0 ||
			confirmed.TriggerSource != "weak_reliability_10m" {
			t.Fatalf("confirmed weak incident did not re-evaluate capacity: %+v", confirmed)
		}
	})

	t.Run("confirmed_weak_window_switch_does_not_reconfirm", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 40,
			Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 40,
		})
		clock.Advance(RelayGuardianScanInterval)
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 41,
			Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 41,
		})
		guardian.mu.Lock()
		before := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if before.State != RelayGuardianWouldQuarantine || before.WeakConfirmationCount != relayGuardianWeakConfirmations {
			t.Fatalf("initial weak confirmation state=%+v", before)
		}

		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
			AccountID: 51, ObservedAt: clock.Now(), Total10m: 100, Failures10m: 1, LatestFailureRowID10m: 42,
			Total60m: 10, Failures60m: 4, LatestFailureRowID60m: 50,
		})
		guardian.mu.Lock()
		after := *guardian.stateLocked(51)
		guardian.mu.Unlock()
		if after.State != RelayGuardianWouldQuarantine || after.ShadowAction != "quarantine" ||
			after.WeakConfirmationCount != relayGuardianWeakConfirmations || after.WeakCandidateTrigger != "weak_reliability_60m" ||
			after.TriggerSource != "weak_reliability_60m" || after.WindowSeconds != 3600 || after.Generation != before.Generation {
			t.Fatalf("confirmed weak window switch state=%+v before=%+v", after, before)
		}
	})
}

func TestRelayGuardianStrongPathAndOperatorStatusRegressions(t *testing.T) {
	t.Run("strong_status_ignores_client_text", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		for index := 0; index < 3; index++ {
			obs := guardianObservation(51, fmt.Sprintf("strong-client-%d", index), 502, false, clock.Now())
			obs.UpstreamErrorKind = "client_transport"
			obs.ErrorMessage = "client received gateway error"
			guardian.observe(obs)
		}
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.State != RelayGuardianSuspect || state.ShadowAction != "" || state.TriggerSource != "strong_gateway_unconfirmed_3_in_5m" || len(state.SeenFinal) != 0 {
			t.Fatalf("strong status was suppressed: %+v", state)
		}
	})

	t.Run("same_shadow_does_not_advance_generation", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("shadow-%d", index), 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		generation := guardian.stateLocked(51).Generation
		guardian.mu.Unlock()
		guardian.observe(guardianObservation(51, "shadow-fourth", 502, true, clock.Now()))
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		if got := guardian.stateLocked(51).Generation; got != generation {
			t.Fatalf("same shadow generation=%d want=%d", got, generation)
		}
	})

	t.Run("expired_strong_shadow_has_consistent_suspect_reason", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("expire-strong-%d", index), 502, true, clock.Now()))
		}
		clock.Advance(6 * time.Minute)
		guardian.reconcile(context.Background())
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.State != RelayGuardianSuspect || state.ShadowAction != "" || state.TriggerSource != "" || state.Reason != "recent_failure_observed" {
			t.Fatalf("expired strong shadow state=%+v", state)
		}
	})

	t.Run("confirmed_weak_shadow_survives_later_weak_observation", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		guardian.observe(guardianObservation(51, "weak-shadow-a", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "weak-shadow-b", 500, false, clock.Now()))
		confirmGuardianWeakForTest(t, guardian, 51)
		guardian.mu.Lock()
		before := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		guardian.mu.Unlock()
		guardian.observe(guardianObservation(51, "weak-shadow-c", 500, false, clock.Now()))
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		after := guardian.stateLocked(51)
		if after.Generation != before.Generation || after.Reason != before.Reason || after.ShadowAction != before.ShadowAction {
			t.Fatalf("later weak observation changed confirmed shadow: before=%+v after=%+v", before, after)
		}
	})

	t.Run("weak_candidate_cannot_demote_strong_shadow", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
		confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("strong-before-weak-%d", index), 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		before := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		guardian.mu.Unlock()
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 20, Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 20})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		after := guardian.stateLocked(51)
		if after.State != before.State || after.ShadowAction != before.ShadowAction || after.Reason != before.Reason || after.Generation != before.Generation || after.WeakConfirmationCount != 0 {
			t.Fatalf("weak candidate demoted strong shadow: before=%+v after=%+v", before, after)
		}
	})

	t.Run("below_threshold_does_not_clear_last_resort_strong_reason", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
		confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
		for index := 0; index < 3; index++ {
			guardian.observe(guardianObservation(51, fmt.Sprintf("last-strong-%d", index), 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		before := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		guardian.mu.Unlock()
		applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{AccountID: 51, ObservedAt: clock.Now(), Total10m: 100, Failures10m: 0, Total60m: 100, Failures60m: 0})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		after := guardian.stateLocked(51)
		if !after.LastResort || after.TriggerSource != before.TriggerSource || after.WindowSeconds != before.WindowSeconds || after.Reason != before.Reason {
			t.Fatalf("below-threshold reliability cleared last-resort action: before=%+v after=%+v", before, after)
		}
	})

	t.Run("status_counts_current_state_window", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
		guardian.mu.Lock()
		guardian.loaded[51] = true
		state := guardian.stateLocked(51)
		state.WindowSeconds = 600
		state.ReliabilityTotal = 1209
		state.ReliabilityFailures = 6
		state.ReliabilityWindowSeconds = 600
		state.Failures = []relayGuardianFailure{{At: clock.Now().Add(-20 * time.Minute), LogicalRequestID: "old", UserVisible: true}, {At: clock.Now().Add(-2 * time.Minute), LogicalRequestID: "new", UserVisible: true}}
		guardian.mu.Unlock()
		status, _ := store.RelayGuardianAccountStatus(51)
		if status.FailureCount != 1 || status.UserVisibleFailures != 1 || status.ReliabilityTotal != 1209 || status.ReliabilityFailures != 6 || status.ReliabilityWindowSeconds != 600 {
			t.Fatalf("window counts=%+v", status)
		}
	})

	t.Run("strong_gateway_count_is_always_five_minutes", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
		guardian.mu.Lock()
		guardian.loaded[51] = true
		state := guardian.stateLocked(51)
		state.WindowSeconds = 3600
		state.Failures = []relayGuardianFailure{{At: clock.Now().Add(-20 * time.Minute), LogicalRequestID: "old-strong", StrongGateway: true}, {At: clock.Now().Add(-2 * time.Minute), LogicalRequestID: "new-strong", StrongGateway: true}}
		guardian.mu.Unlock()
		status, _ := store.RelayGuardianAccountStatus(51)
		if status.FailureCount != 2 || status.StrongGatewayFailures != 1 {
			t.Fatalf("strong gateway 5m count=%+v", status)
		}
	})

	t.Run("weak_candidate_does_not_degrade_health", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
		guardian.mu.Lock()
		guardian.loaded[51] = true
		guardian.heartbeat = time.Now()
		state := guardian.stateLocked(51)
		state.State = RelayGuardianSuspect
		state.WeakConfirmationCount = 1
		guardian.mu.Unlock()
		health, relay := store.RelayGuardianHealth()
		if health.Status != "ok" || relay.Degraded != 0 {
			t.Fatalf("weak candidate degraded health: health=%+v relay=%+v", health, relay)
		}
	})
}

func TestRelayGuardianStatusUsesOperatorNameAndTracksHotRename(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, _ := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50)
	if !store.ApplyAccountName(50, "cyb-relay-kedaya-0.1") {
		t.Fatal("ApplyAccountName returned false")
	}
	status := store.RelayGuardianStatus()
	if len(status.Accounts) != 1 || status.Accounts[0].AccountName != "cyb-relay-kedaya-0.1" {
		t.Fatalf("status account name after apply = %+v", status.Accounts)
	}
	store.ApplyAccountName(50, "renamed-relay")
	status = store.RelayGuardianStatus()
	if status.Accounts[0].AccountName != "renamed-relay" {
		t.Fatalf("status account name after hot rename = %q", status.Accounts[0].AccountName)
	}
}

func TestRelayGuardianAccount51ConfirmedWeakReliabilityWouldQuarantine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50, 53)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	clock.Advance(2*time.Minute + 5*time.Second)
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian, 51)

	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianWouldQuarantine || state.TriggerSource != "weak_reliability_10m" {
		t.Fatalf("state=%s trigger=%s, want confirmed weak would_quarantine", state.State, state.TriggerSource)
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

func TestRelayGuardianAbsorbedStrongEvidenceRequiresTwoConfirmedBreakerCycles(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)

	guardian.observe(guardianObservation(51, "visible-final", 502, false, clock.Now()))
	guardian.observe(guardianObservation(51, "absorbed-a", 502, true, clock.Now()))
	guardian.observe(guardianObservation(51, "absorbed-b", 502, true, clock.Now()))
	guardian.mu.Lock()
	raw := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
	guardian.mu.Unlock()
	if raw.State != RelayGuardianSuspect || raw.ShadowAction != "" || raw.StrongCircuitCycleCount != 0 || raw.TriggerSource != "strong_gateway_unconfirmed_3_in_5m" {
		t.Fatalf("mixed final/absorbed evidence became actionable: %+v", raw)
	}

	// A persisted backoff proves there was an older cycle, but not that it was
	// inside this ten-minute Guardian window.
	setGuardianStrongBreakerOpenForTest(t, guardian, 51, 2, 1)
	guardian.observe(guardianObservation(51, "first-cycle-evidence", 502, true, clock.Now()))
	guardian.mu.Lock()
	firstCycle := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
	guardian.mu.Unlock()
	if firstCycle.State != RelayGuardianSuspect || firstCycle.ShadowAction != "" || firstCycle.StrongCircuitCycleCount != 1 {
		t.Fatalf("one confirmed breaker cycle caused long isolation: %+v", firstCycle)
	}

	setGuardianStrongBreakerOpenForTest(t, guardian, 51, 4, 0)
	guardian.observe(guardianObservation(51, "second-cycle-evidence", 502, true, clock.Now()))
	guardian.mu.Lock()
	confirmed := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
	guardian.mu.Unlock()
	if confirmed.State != RelayGuardianWouldQuarantine || confirmed.ShadowAction != "quarantine" ||
		confirmed.StrongCircuitCycleCount != 2 || confirmed.TriggerSource != "strong_breaker_2_cycles_in_10m" {
		t.Fatalf("two confirmed breaker cycles did not unlock shadow isolation: %+v", confirmed)
	}
}

func TestRelayGuardianPoolInvariantPromotionDoesNotCreateConfirmedStrongCycle(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	primary := store.FindByID(51)
	fallback := store.FindByID(50)
	breaker := store.relayCircuitManager()
	breaker.now = clock.Now
	breaker.ensureLoadedForAccount(primary)
	breaker.ensureLoadedForAccount(fallback)

	for index := 1; index <= relayCircuitStrongFailureLimit; index++ {
		logicalID := "confirmed-cycle-" + strconv.Itoa(index)
		permit := relayCircuitBeginEvidence(t, breaker, primary.ID(), logicalID)
		opened := breaker.reportFailureWithPool(permit, http.StatusBadGateway, []int64{fallback.ID()})
		if opened != (index == relayCircuitStrongFailureLimit) {
			t.Fatalf("strong failure %d opened=%v", index, opened)
		}
		guardian.observe(guardianObservation(primary.ID(), logicalID, http.StatusBadGateway, true, clock.Now()))
	}

	guardian.mu.Lock()
	state := guardian.stateLocked(primary.ID())
	if state.StrongCircuitCycleCount != 1 || state.StrongCircuitCycleToken != 1 {
		guardian.mu.Unlock()
		t.Fatalf("first confirmed cycle state=%+v", state.relayGuardianRuntimeRecord)
	}
	guardian.mu.Unlock()

	if !store.ApplyAccountEnabled(fallback.ID(), false) {
		t.Fatal("pause fallback failed")
	}
	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("pool invariant did not promote the only open front")
	}
	promoted := store.RelayCircuitSnapshot(primary.ID())
	if !promoted.LastResort || promoted.confirmedStrongCycleToken != 1 {
		t.Fatalf("pool promotion changed confirmed cycle identity: %+v token=%d", promoted, promoted.confirmedStrongCycleToken)
	}

	guardian.observe(guardianObservation(primary.ID(), "same-cycle-after-promotion", http.StatusBadGateway, true, clock.Now()))
	guardian.mu.Lock()
	state = guardian.stateLocked(primary.ID())
	for repeat := 0; repeat < 3; repeat++ {
		if trigger, _, _, _ := guardian.triggerLocked(primary.ID(), state, clock.Now()); trigger != "" {
			guardian.mu.Unlock()
			t.Fatalf("same confirmed cycle repetition produced trigger %q", trigger)
		}
	}
	count := state.StrongCircuitCycleCount
	token := state.StrongCircuitCycleToken
	guardian.mu.Unlock()
	if count != 1 || token != 1 {
		t.Fatalf("pool promotion/repeated observe counted a second cycle: count=%d token=%d", count, token)
	}
}

func TestRelayGuardianStrongCycleConfirmationRejectsWeakBreakerGeneration(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)

	for _, logicalID := range []string{"raw-strong-a", "raw-strong-b", "raw-strong-c"} {
		guardian.observe(guardianObservation(51, logicalID, http.StatusBadGateway, true, clock.Now()))
	}

	setGuardianBreakerOpenForTest(t, guardian, 51, 2, 0, http.StatusBadGateway)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	trigger, _, _, _ := guardian.triggerLocked(51, state, clock.Now())
	firstCount := state.StrongCircuitCycleCount
	guardian.mu.Unlock()
	if trigger != "" || firstCount != 1 {
		t.Fatalf("first strong breaker cycle trigger=%q count=%d, want no trigger and count=1", trigger, firstCount)
	}

	// A later breaker generation can be real without being a strong-gateway
	// cycle. It must not turn the earlier absorbed 502 burst into a long
	// Guardian-isolation candidate.
	setGuardianBreakerOpenForTest(t, guardian, 51, 4, 1, http.StatusServiceUnavailable)
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	trigger, _, _, _ = guardian.triggerLocked(51, state, clock.Now())
	weakCount := state.StrongCircuitCycleCount
	weakToken := state.StrongCircuitCycleToken
	guardian.mu.Unlock()
	if trigger != "" || weakCount != 1 || weakToken != 2 {
		t.Fatalf("weak breaker generation trigger=%q count=%d token=%d, want no trigger count=1 token=2", trigger, weakCount, weakToken)
	}

	// A genuinely independent strong reopen in the same ten-minute window still
	// becomes actionable. Missing two generations between scans remains an
	// intentional availability-first false negative, never a false isolation.
	setGuardianBreakerOpenForTest(t, guardian, 51, 5, 1, http.StatusGatewayTimeout)
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	trigger, _, _, _ = guardian.triggerLocked(51, state, clock.Now())
	strongCount := state.StrongCircuitCycleCount
	strongToken := state.StrongCircuitCycleToken
	guardian.mu.Unlock()
	if trigger != "strong_breaker_2_cycles_in_10m" || strongCount != 2 || strongToken != 5 {
		t.Fatalf("second strong breaker cycle trigger=%q count=%d token=%d", trigger, strongCount, strongToken)
	}
}

func TestRelayGuardianStrongCycleWindowExpiryDoesNotRecountOldToken(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	for index := 0; index < relayCircuitStrongFailureLimit; index++ {
		guardian.observe(guardianObservation(51, "old-window-"+strconv.Itoa(index), http.StatusBadGateway, true, clock.Now()))
	}
	setGuardianStrongBreakerOpenForTest(t, guardian, 51, 1, 0)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	trigger, _, _, _ := guardian.triggerLocked(51, state, clock.Now())
	guardian.mu.Unlock()
	if trigger != "" || state.StrongCircuitCycleCount != 1 || state.StrongCircuitCycleToken != 1 {
		t.Fatalf("first cycle trigger=%q state=%+v", trigger, state.relayGuardianRuntimeRecord)
	}

	clock.Advance(relayGuardianStrongCycleWindow + time.Second)
	for index := 0; index < relayCircuitStrongFailureLimit; index++ {
		guardian.observe(guardianObservation(51, "new-raw-same-token-"+strconv.Itoa(index), http.StatusBadGateway, true, clock.Now()))
	}
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	trigger, _, _, _ = guardian.triggerLocked(51, state, clock.Now())
	count := state.StrongCircuitCycleCount
	token := state.StrongCircuitCycleToken
	guardian.mu.Unlock()
	if trigger != "" || count != 0 || token != 1 {
		t.Fatalf("expired window recounted old token: trigger=%q count=%d token=%d", trigger, count, token)
	}
}

func TestRelayGuardianRecoveryPreservesWatermarkAndCountsNewTokenOnce(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	for index := 0; index < relayCircuitStrongFailureLimit; index++ {
		guardian.observe(guardianObservation(51, "before-recovery-"+strconv.Itoa(index), http.StatusBadGateway, true, clock.Now()))
	}
	setGuardianStrongBreakerOpenForTest(t, guardian, 51, 1, 0)
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	guardian.triggerLocked(51, state, clock.Now())
	guardian.clearStrongCircuitCycleWindowLocked(state)
	if state.StrongCircuitCycleToken != 1 {
		guardian.mu.Unlock()
		t.Fatalf("recovery cleared dedup watermark: %+v", state.relayGuardianRuntimeRecord)
	}
	guardian.mu.Unlock()

	setGuardianStrongBreakerOpenForTest(t, guardian, 51, 2, 1)
	for index := 0; index < relayCircuitStrongFailureLimit; index++ {
		guardian.observe(guardianObservation(51, "after-recovery-"+strconv.Itoa(index), http.StatusBadGateway, true, clock.Now()))
	}
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	for repeat := 0; repeat < 3; repeat++ {
		guardian.triggerLocked(51, state, clock.Now())
	}
	count := state.StrongCircuitCycleCount
	token := state.StrongCircuitCycleToken
	guardian.mu.Unlock()
	if count != 1 || token != 2 {
		t.Fatalf("new post-recovery token was not counted exactly once: count=%d token=%d", count, token)
	}
}

func TestRelayGuardianReplacementCapacityRequiresRecentCanonicalSuccess(t *testing.T) {
	t.Run("stale_peer_is_not_replacement_capacity", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
		store.accountsByID[50].relayGuardianCanonicalSuccessAt.Store(0)
		guardian.observe(guardianObservation(51, "candidate-a", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "candidate-b", 500, false, clock.Now()))
		confirmGuardianWeakForTest(t, guardian, 51)
		guardian.mu.Lock()
		state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		guardian.mu.Unlock()
		if state.State == RelayGuardianQuarantined || !state.LastResort || state.Reason != "peer_canonical_success_stale" {
			t.Fatalf("stale peer was counted as proven replacement capacity: %+v", state)
		}
	})

	t.Run("canonical_success_makes_peer_eligible", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
		store.accountsByID[50].relayGuardianCanonicalSuccessAt.Store(0)
		guardian.observe(guardianObservation(50, "peer-canonical-success", 200, false, clock.Now()))
		guardian.observe(guardianObservation(51, "candidate-a", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "candidate-b", 500, false, clock.Now()))
		confirmGuardianWeakForTest(t, guardian, 51)
		guardian.mu.Lock()
		state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		guardian.mu.Unlock()
		if state.State != RelayGuardianQuarantined {
			t.Fatalf("recent canonical peer success did not qualify as replacement capacity: %+v", state)
		}
	})
}

func TestRelayGuardianColdStartGuardIsVisibleAndPreventsLongIsolation(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.mu.Lock()
	guardian.coldStartUntil = clock.Now().Add(relayGuardianColdStartGuard)
	guardian.mu.Unlock()

	status := guardian.status()
	if !status.ColdStartActive || status.ColdStartUntil == nil || !status.ColdStartUntil.Equal(clock.Now().Add(relayGuardianColdStartGuard)) {
		t.Fatalf("status omitted cold-start fence: %+v", status)
	}
	health, _ := store.RelayGuardianHealth()
	if !health.ColdStartActive || health.ColdStartUntil == nil || !health.ColdStartUntil.Equal(*status.ColdStartUntil) {
		t.Fatalf("health omitted cold-start fence: %+v", health)
	}
	if relayGuardianColdStartGuard != relayGuardianInitialQuarantine+2*relayGuardianProbationStage {
		t.Fatalf("cold-start fence=%s want full recovery window", relayGuardianColdStartGuard)
	}

	guardian.observe(guardianObservation(51, "candidate-a", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "candidate-b", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian, 51)
	guardian.mu.Lock()
	state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
	guardian.mu.Unlock()
	if state.State == RelayGuardianQuarantined || !state.LastResort || state.Reason != "cold_start_guard" {
		t.Fatalf("cold-start fence allowed long isolation: %+v", state)
	}
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
	if state.State != RelayGuardianSuspect || state.ShadowAction != "" || state.TriggerSource != "strong_gateway_unconfirmed_3_in_5m" || len(state.SeenFinal) != 0 {
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
	confirmGuardianWeakForTest(t, guardian, 51)
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
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
	for i := 0; i < 3; i++ {
		guardian.observe(guardianObservation(50, "a-"+string(rune('0'+i)), 502, true, clock.Now()))
	}
	clock.Advance(61 * time.Second)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
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

func TestRelayGuardianPoolGuardFindsSharedSignatureBehindNewerSingleFailure(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 50, 53, 51)
	guardian.observe(guardianObservation(50, "peer-shared-524", 524, false, clock.Now()))
	guardian.observe(guardianObservation(53, "candidate-shared-524", 524, false, clock.Now()))
	clock.Advance(time.Minute)
	guardian.observe(guardianObservation(53, "candidate-single-500", 500, false, clock.Now()))
	accounts := guardian.store.configuredRelayGuardianAccounts()
	capacity := guardian.capacityInputs(accounts)

	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	state := guardian.stateLocked(53)
	guardian.applyTriggerLocked(guardian.store.FindByID(53), state, accounts, capacity, "strong_gateway_3_in_5m", 5*time.Minute, 0, 3, clock.Now())
	if state.State == RelayGuardianQuarantined || !state.LastResort || state.Reason != "pool_wide_failure_guard" {
		t.Fatalf("newer single 500 hid shared 524 pool signature: %+v", state)
	}
}

func TestRelayGuardianReleaseAndBypassValidateStateAndGeneration(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	if err := store.ReleaseRelayGuardian(51, 1); !errors.Is(err, ErrRelayGuardianInvalidState) {
		t.Fatalf("healthy release err=%v", err)
	}
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian, 51)
	status, _ := store.RelayGuardianAccountStatus(51)
	if status.State != RelayGuardianQuarantined {
		t.Fatalf("state=%s", status.State)
	}
	if err := store.ReleaseRelayGuardian(51, status.Generation-1); !errors.Is(err, ErrRelayGuardianStaleGeneration) {
		t.Fatalf("stale release err=%v", err)
	}
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	state.WeakCandidateTrigger = "weak_reliability_10m"
	state.WeakCandidateLatestFailureRowID = 120
	state.WeakCandidateSince = clock.Now()
	state.WeakConfirmationCount = 1
	guardian.mu.Unlock()
	if err := store.ReleaseRelayGuardian(51, status.Generation); err != nil {
		t.Fatalf("release: %v", err)
	}
	released, _ := store.RelayGuardianAccountStatus(51)
	if released.State != RelayGuardianHalfOpen || released.WeakConfirmationCount != 0 {
		t.Fatalf("release retained pending weak candidate: %+v", released)
	}
	if err := store.TemporaryBypassRelayGuardian(51, released.Generation, 5); err != nil {
		t.Fatalf("bypass: %v", err)
	}
	after, _ := store.RelayGuardianAccountStatus(51)
	if after.State != RelayGuardianTemporaryBypass || after.Generation == released.Generation {
		t.Fatalf("bypass status=%+v", after)
	}
}

func TestRelayGuardianModeTransitionDoesNotEnforceOldMonitorIncident(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian, 51)
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

func TestRelayGuardianModeFenceCoversConfiguredAccountWhoseInitialCacheReadFailed(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	old := relayGuardianRuntimeRecord{
		SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: RelayGuardianEnforce, ScopeGroupID: 7,
		State: RelayGuardianQuarantined, Generation: 9, QuarantineUntil: clock.Now().Add(time.Hour),
		TriggerSource: "strong_gateway_3_in_5m", WindowSeconds: 300, UpdatedAt: clock.Now(),
	}
	payload, _ := json.Marshal(old)
	if err := baseCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	failing := &relayGuardianFailingCache{TokenCache: baseCache}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache, guardian.cache = failing, failing
	guardian.ensureLoaded(51)
	guardian.mu.Lock()
	initiallyLoaded := guardian.loaded[51]
	guardian.mu.Unlock()
	if initiallyLoaded || failing.gets.Load() != 1 {
		t.Fatalf("initial cache failure did not leave account unloaded: loaded=%v gets=%d", initiallyLoaded, failing.gets.Load())
	}

	guardian.mu.Lock()
	initialScopeEpoch := guardian.scopeEpoch
	guardian.mu.Unlock()
	store.SetRelayGuardianMode(string(RelayGuardianMonitor))
	guardian.mu.Lock()
	monitorScopeEpoch := guardian.scopeEpoch
	guardian.mu.Unlock()
	store.SetRelayGuardianMode(string(RelayGuardianEnforce))
	guardian.mu.Lock()
	enforceScopeEpoch := guardian.scopeEpoch
	guardian.mu.Unlock()
	if initialScopeEpoch == monitorScopeEpoch || monitorScopeEpoch == enforceScopeEpoch || initialScopeEpoch == enforceScopeEpoch {
		t.Fatalf("same-clock mode transitions reused scope epoch: initial=%q monitor=%q enforce=%q", initialScopeEpoch, monitorScopeEpoch, enforceScopeEpoch)
	}
	guardian.ensureLoaded(51)
	guardian.mu.Lock()
	state := *guardian.stateLocked(51)
	loaded := guardian.loaded[51]
	guardian.mu.Unlock()
	if !loaded || state.State != RelayGuardianHealthy || state.Mode != RelayGuardianEnforce || !state.QuarantineUntil.IsZero() || state.Generation == old.Generation {
		t.Fatalf("old enforce quarantine crossed mode fence: loaded=%v state=%+v", loaded, state)
	}
	if failing.gets.Load() != 1 {
		t.Fatalf("mode fence re-read stale cache after failed initial load: gets=%d", failing.gets.Load())
	}
	stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
	if err != nil || !ok {
		t.Fatalf("mode fence cache write missing: ok=%v err=%v", ok, err)
	}
	var persisted relayGuardianRuntimeRecord
	if err := json.Unmarshal(stored, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.State != RelayGuardianHealthy || persisted.Mode != RelayGuardianEnforce || !persisted.QuarantineUntil.IsZero() {
		t.Fatalf("stale quarantine remained in cache: %+v", persisted)
	}
}

func TestRelayGuardianBootEpochRejectsOldStateWhenTransitionPersistenceFails(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	old := relayGuardianRuntimeRecord{
		SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: RelayGuardianEnforce, ScopeGroupID: 7,
		ScopeEpoch: "old-process-cycle", State: RelayGuardianQuarantined, Generation: 9,
		QuarantineUntil: clock.Now().Add(time.Hour), TriggerSource: "strong_gateway_3_in_5m", WindowSeconds: 300,
	}
	payload, _ := json.Marshal(old)
	if err := baseCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	failingSet := &relayGuardianFailingSetCache{TokenCache: baseCache}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache, guardian.cache = failingSet, failingSet
	guardian.ensureLoaded(51)
	store.SetRelayGuardianMode(string(RelayGuardianMonitor))
	store.SetRelayGuardianMode(string(RelayGuardianEnforce))
	if failingSet.sets.Load() < 2 {
		t.Fatalf("transition cache writes did not fail twice: %d", failingSet.sets.Load())
	}
	// The underlying cache still contains the original enforce quarantine.
	stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
	if err != nil || !ok || string(stored) != string(payload) {
		t.Fatalf("test did not preserve stale cache record: ok=%v err=%v", ok, err)
	}

	store2, guardian2 := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store2.tokenCache, guardian2.cache = baseCache, baseCache
	guardian2.ensureLoaded(51)
	guardian2.mu.Lock()
	after := *guardian2.stateLocked(51)
	guardian2.mu.Unlock()
	if after.State != RelayGuardianHealthy || !after.QuarantineUntil.IsZero() || !guardian2.selectable(store2.accountsByID[51]) {
		t.Fatalf("restart revived stale quarantine despite boot epoch: %+v", after)
	}
}

func TestRelayGuardianModeTransitionAtomicallyFencesObserveReconcileAndOldPersist(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	t.Cleanup(func() { _ = baseCache.Close() })
	blocking := &relayGuardianBlockingSetCache{TokenCache: baseCache, entered: make(chan struct{}), release: make(chan struct{}), ignoreContext: true}
	releaseBlocking := func() {
		select {
		case <-blocking.release:
		default:
			close(blocking.release)
		}
	}
	t.Cleanup(releaseBlocking)
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	store.tokenCache, guardian.cache = blocking, blocking
	guardian.ensureLoaded(51)
	guardian.ensureLoaded(50)
	guardian.observe(guardianObservation(51, "atomic-mode-a", 502, true, clock.Now()))
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("old monitor persist did not block")
	}
	guardian.observe(guardianObservation(51, "atomic-mode-b", 502, true, clock.Now()))

	transitionDone := make(chan struct{})
	go func() {
		store.SetRelayGuardianMode(string(RelayGuardianEnforce))
		close(transitionDone)
	}()
	// Wait until transitionMode owns loadMu and is fenced behind the old
	// persist. Reconcile is expected to wait behind that load fence; keeping it
	// synchronous here would make the test itself deadlock before release.
	deadline := time.Now().Add(time.Second)
	for guardian.loadMu.TryLock() {
		guardian.loadMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("mode transition did not acquire load fence")
		}
		time.Sleep(time.Millisecond)
	}
	reconcileDone := make(chan struct{})
	go func() {
		guardian.reconcile(context.Background())
		close(reconcileDone)
	}()
	// An observation already inside the old mode can still finish before the
	// boundary. Its queued write must become stale once transitionMode publishes
	// enforce and resets the state.
	guardian.observe(guardianObservation(51, "atomic-mode-c", 502, true, clock.Now()))
	if mode := store.GetRelayGuardianMode(); mode != RelayGuardianMonitor {
		t.Fatalf("new mode published before persistence fence: %s", mode)
	}
	releaseBlocking()
	select {
	case <-transitionDone:
	case <-time.After(2 * time.Second):
		t.Fatal("mode transition did not finish")
	}
	select {
	case <-reconcileDone:
	case <-time.After(2 * time.Second):
		t.Fatal("reconcile did not resume after mode transition")
	}
	guardian.mu.Lock()
	state := *guardian.stateLocked(51)
	guardian.mu.Unlock()
	if state.State != RelayGuardianHealthy || state.Mode != RelayGuardianEnforce || len(state.Failures) != 0 || state.TriggerSource != "" {
		t.Fatalf("old monitor evidence crossed atomic mode boundary: %+v", state)
	}
	stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
	if err != nil || !ok {
		t.Fatalf("mode transition cache state missing: ok=%v err=%v", ok, err)
	}
	var persisted relayGuardianRuntimeRecord
	if err := json.Unmarshal(stored, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Mode != RelayGuardianEnforce || persisted.State != RelayGuardianHealthy || len(persisted.Failures) != 0 {
		t.Fatalf("old asynchronous persist overwrote mode fence: %+v", persisted)
	}
}

func TestRelayGuardianConfigTransitionFailClosedDuringCacheFence(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	blocking := &relayGuardianBlockingDeleteCache{TokenCache: baseCache, entered: make(chan struct{}), release: make(chan struct{})}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.accountsByID[51].GroupIDs = []int64{7, 8}
	store.tokenCache, guardian.cache = blocking, blocking
	guardian.ensureLoaded(51)
	guardian.ensureLoaded(50)
	guardian.observe(guardianObservation(51, "old-group-evidence", 500, false, clock.Now()))

	transitionDone := make(chan struct{})
	go func() {
		store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
		close(transitionDone)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("config cache invalidation did not block")
	}
	if cfg := store.GetCybRelayConfig(); !cfg.Enabled || cfg.GroupID != 8 {
		t.Fatalf("new config was not published inside fence: %+v", cfg)
	}
	if store.RelayGuardianSelectable(store.accountsByID[51]) {
		t.Fatal("new group was schedulable before its runtime was preloaded")
	}
	obs := guardianObservation(51, "new-group-during-fence", 502, true, clock.Now())
	obs.RouteGroupID = 8
	guardian.observe(obs)
	close(blocking.release)
	select {
	case <-transitionDone:
	case <-time.After(2 * time.Second):
		t.Fatal("config transition did not finish")
	}
	guardian.mu.Lock()
	state := *guardian.stateLocked(51)
	loaded := guardian.loaded[51]
	guardian.mu.Unlock()
	if !loaded || state.State != RelayGuardianHealthy || len(state.Failures) != 0 || state.ScopeGroupID != 8 {
		t.Fatalf("old/new-group evidence crossed config fence: loaded=%v state=%+v", loaded, state)
	}
}

func TestRelayGuardianConfigTransitionCleanupHasOneBoundedDeadline(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	blocking := &relayGuardianBlockingDeleteCache{TokenCache: baseCache, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(blocking.release)
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50, 53, 54, 55, 56)
	for _, account := range store.accounts {
		account.GroupIDs = []int64{7, 8}
	}
	store.tokenCache, guardian.cache = blocking, blocking
	guardian.configTransitionTimeout = 25 * time.Millisecond

	started := time.Now()
	guardian.transitionConfig(CybRelayConfig{Enabled: true, GroupID: 8}, store.accounts)
	elapsed := time.Since(started)
	if elapsed > 250*time.Millisecond {
		t.Fatalf("config cleanup multiplied its timeout by account/key count: %s", elapsed)
	}
	select {
	case <-blocking.entered:
	default:
		t.Fatal("config transition did not attempt bounded cache cleanup")
	}
	if cfg := store.GetCybRelayConfig(); !cfg.Enabled || cfg.GroupID != 8 {
		t.Fatalf("new config fence was not published: %+v", cfg)
	}
	guardian.mu.Lock()
	cold := guardian.coldStartActiveLocked(clock.Now())
	scopeGroupID := guardian.scopeEpochGroupID
	guardian.mu.Unlock()
	if !cold || scopeGroupID != 8 {
		t.Fatalf("new scope was not cold-start fenced: cold=%v group=%d", cold, scopeGroupID)
	}
}

func TestRelayGuardianMembershipRejoinDoesNotReadStaleStateAfterCacheMutationFailure(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.mu.Lock()
	scopeEpoch := guardian.scopeEpoch
	guardian.mu.Unlock()
	stale := relayGuardianRuntimeRecord{
		SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: RelayGuardianEnforce, ScopeGroupID: 7, ScopeEpoch: scopeEpoch,
		State: RelayGuardianQuarantined, Generation: 9, QuarantineUntil: clock.Now().Add(time.Hour),
		WeakCandidateTrigger: "weak_reliability_10m", WeakConfirmationCount: relayGuardianWeakConfirmations,
	}
	payload, _ := json.Marshal(stale)
	if err := baseCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	failing := &relayGuardianFailingMutationCache{TokenCache: baseCache}
	store.tokenCache, guardian.cache = failing, failing
	account := store.accountsByID[51]
	guardian.forgetAccountRuntime(account, 7)
	guardian.preloadAndReplay(account)

	guardian.mu.Lock()
	state := *guardian.stateLocked(51)
	loaded := guardian.loaded[51]
	guardian.mu.Unlock()
	if !loaded || state.State != RelayGuardianHealthy || !state.QuarantineUntil.IsZero() || state.WeakConfirmationCount != 0 || state.ScopeEpoch != scopeEpoch {
		t.Fatalf("membership failure fence state: loaded=%v state=%+v", loaded, state)
	}
	if failing.deletes.Load() != 1 || failing.sets.Load() != 1 || failing.gets.Load() != 0 {
		t.Fatalf("membership mutation calls delete=%d set=%d get=%d", failing.deletes.Load(), failing.sets.Load(), failing.gets.Load())
	}
	stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
	if err != nil || !ok || string(stored) != string(payload) {
		t.Fatalf("test did not preserve stale cache key: ok=%v err=%v", ok, err)
	}
}

func TestRelayGuardianMembershipLeaveClearsHintReplayedAfterEntryClear(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	account := store.accountsByID[51]
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	state.LastResort = true
	state.LastResortCap = 3
	guardian.loaded[51] = true
	replayEntered := make(chan struct{})
	replayRelease := make(chan struct{})
	var hookOnce sync.Once
	guardian.replayLockedHook = func() {
		hookOnce.Do(func() { close(replayEntered) })
		<-replayRelease
	}
	guardian.mu.Unlock()
	relayGuardianSchedulingHint(account, true, 3, 0)

	replayDone := make(chan struct{})
	go func() {
		guardian.replaySchedulingHint(account)
		close(replayDone)
	}()
	select {
	case <-replayEntered:
	case <-time.After(time.Second):
		t.Fatal("replay did not hold the Guardian state lock")
	}
	forgetDone := make(chan struct{})
	go func() {
		guardian.forgetAccountRuntime(account, 7)
		close(forgetDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		hint := account.relayGuardianSchedulingHintSnapshot()
		if !hint.lastResort && hint.hardCap == 0 && hint.percent == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("membership entry clear did not execute")
		}
		time.Sleep(time.Millisecond)
	}
	close(replayRelease)
	select {
	case <-replayDone:
	case <-time.After(time.Second):
		t.Fatal("blocked replay did not finish")
	}
	select {
	case <-forgetDone:
	case <-time.After(time.Second):
		t.Fatal("membership leave did not finish")
	}
	if hint := account.relayGuardianSchedulingHintSnapshot(); hint.lastResort || hint.hardCap != 0 || hint.percent != 0 {
		t.Fatalf("old-state replay survived membership boundary: %+v", hint)
	}
}

func TestRelayGuardianConfigTransitionClearsHintReplayedAfterEntryClear(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	account := store.accountsByID[51]
	account.GroupIDs = []int64{7, 8}
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	state.LastResort = true
	state.LastResortCap = 3
	guardian.loaded[51] = true
	replayEntered := make(chan struct{})
	replayRelease := make(chan struct{})
	var hookOnce sync.Once
	guardian.replayLockedHook = func() {
		hookOnce.Do(func() { close(replayEntered) })
		<-replayRelease
	}
	guardian.mu.Unlock()
	relayGuardianSchedulingHint(account, true, 3, 0)

	replayDone := make(chan struct{})
	go func() {
		guardian.replaySchedulingHint(account)
		close(replayDone)
	}()
	select {
	case <-replayEntered:
	case <-time.After(time.Second):
		t.Fatal("replay did not hold the Guardian state lock")
	}
	transitionDone := make(chan struct{})
	go func() {
		store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
		close(transitionDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		hint := account.relayGuardianSchedulingHintSnapshot()
		if !hint.lastResort && hint.hardCap == 0 && hint.percent == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("config entry clear did not execute")
		}
		time.Sleep(time.Millisecond)
	}
	close(replayRelease)
	select {
	case <-replayDone:
	case <-time.After(time.Second):
		t.Fatal("blocked replay did not finish")
	}
	select {
	case <-transitionDone:
	case <-time.After(time.Second):
		t.Fatal("config transition did not finish")
	}
	if hint := account.relayGuardianSchedulingHintSnapshot(); hint.lastResort || hint.hardCap != 0 || hint.percent != 0 {
		t.Fatalf("old-state replay survived config boundary: %+v", hint)
	}
}

func TestRelayGuardianMembershipFenceRejectsQueuedOldPersistAfterMutationFailure(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	account := store.accountsByID[51]
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	guardian.resetForModeLocked(state, RelayGuardianEnforce, clock.Now())
	state.State = RelayGuardianQuarantined
	state.Generation = 9
	state.QuarantineUntil = clock.Now().Add(time.Hour)
	state.WeakCandidateTrigger = "weak_reliability_10m"
	state.WeakConfirmationCount = relayGuardianWeakConfirmations
	state.SchemaVersion = relayGuardianRuntimeSchemaVersion
	state.Mode = RelayGuardianEnforce
	state.ScopeGroupID = 7
	state.ScopeEpoch = guardian.scopeEpoch
	state.revision = 1
	guardian.loaded[51] = true
	oldRevision := state.revision
	oldRecord := cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
	guardian.mu.Unlock()

	payload, _ := json.Marshal(oldRecord)
	if err := baseCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	guardedCache := &relayGuardianMembershipABACache{
		TokenCache:    baseCache,
		deleteEntered: make(chan struct{}),
		deleteRelease: make(chan struct{}),
	}
	store.tokenCache, guardian.cache = guardedCache, guardedCache
	relayGuardianSchedulingHint(account, true, 3, 0)
	if hint := account.relayGuardianSchedulingHintSnapshot(); !hint.lastResort || hint.hardCap != 3 {
		t.Fatal("test did not install a last-resort scheduling hint")
	}

	forgetDone := make(chan struct{})
	go func() {
		guardian.forgetAccountRuntime(account, 7)
		close(forgetDone)
	}()
	select {
	case <-guardedCache.deleteEntered:
	case <-time.After(time.Second):
		t.Fatal("membership delete did not hold the persistence fence")
	}
	oldPersistDone := make(chan struct{})
	go func() {
		guardian.persist(51, oldRevision, oldRecord)
		close(oldPersistDone)
	}()
	close(guardedCache.deleteRelease)
	select {
	case <-forgetDone:
	case <-time.After(time.Second):
		t.Fatal("membership invalidation did not finish")
	}
	if hint := account.relayGuardianSchedulingHintSnapshot(); hint.lastResort || hint.hardCap != 0 || hint.percent != 0 {
		t.Fatalf("leaving Relay did not clear the account scheduling hint: %+v", hint)
	}
	account.mu.Lock()
	account.GroupIDs = []int64{8}
	account.mu.Unlock()
	if !store.RelayGuardianSelectable(account) {
		t.Fatal("a non-Relay account was blocked by the membership tombstone")
	}
	account.mu.Lock()
	account.GroupIDs = []int64{7}
	account.mu.Unlock()
	// Rejoin immediately while the old asynchronous persist is queued behind
	// the membership fence. The materialized tombstone must prevent a cache read.
	guardian.preloadAndReplay(account)
	select {
	case <-oldPersistDone:
	case <-time.After(time.Second):
		t.Fatal("queued old persist did not finish")
	}
	if guardedCache.deletes.Load() != 1 || guardedCache.sets.Load() != 1 {
		t.Fatalf("old persist escaped membership revision fence: deletes=%d sets=%d", guardedCache.deletes.Load(), guardedCache.sets.Load())
	}
	guardian.mu.Lock()
	state = guardian.stateLocked(51)
	if state.State != RelayGuardianHealthy || state.revision != oldRevision+1 || !guardian.loaded[51] {
		copy := *state
		guardian.mu.Unlock()
		t.Fatalf("membership tombstone not healthy: %+v", copy)
	}
	// Simulate the next successful state flush. This proves the cache converges
	// to healthy after the two membership mutations failed, without allowing the
	// queued old quarantine write to land first.
	guardian.persistState(51, state)
	guardian.mu.Unlock()

	deadline := time.Now().Add(time.Second)
	for {
		stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			var record relayGuardianRuntimeRecord
			if err := json.Unmarshal(stored, &record); err != nil {
				t.Fatal(err)
			}
			if record.State == RelayGuardianHealthy && record.ScopeEpoch == guardian.scopeEpoch {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("healthy membership tombstone did not converge to cache")
		}
		time.Sleep(time.Millisecond)
	}
	if guardedCache.sets.Load() != 2 {
		t.Fatalf("unexpected cache writes after convergence: %d", guardedCache.sets.Load())
	}
}

func TestRelayGuardianMembershipFenceMaterializesTombstoneForEveryDeleteOutcome(t *testing.T) {
	for _, tt := range []struct {
		name               string
		failDelete         bool
		failHealthy        bool
		writesBeforeRejoin int64
	}{
		{name: "delete_succeeds"},
		{name: "delete_fails_healthy_overwrite_succeeds", failDelete: true, writesBeforeRejoin: 1},
		{name: "delete_fails_healthy_overwrite_fails", failDelete: true, failHealthy: true, writesBeforeRejoin: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			baseCache := cache.NewMemory(10)
			defer baseCache.Close()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
			account := store.accountsByID[51]
			guardian.mu.Lock()
			state := guardian.stateLocked(51)
			guardian.resetForModeLocked(state, RelayGuardianEnforce, clock.Now())
			state.State = RelayGuardianQuarantined
			state.Generation = 9
			state.QuarantineUntil = clock.Now().Add(time.Hour)
			state.SchemaVersion = relayGuardianRuntimeSchemaVersion
			state.Mode = RelayGuardianEnforce
			state.ScopeGroupID = 7
			state.ScopeEpoch = guardian.scopeEpoch
			state.revision = 1
			guardian.loaded[51] = true
			oldRevision := state.revision
			oldRecord := cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
			guardian.mu.Unlock()

			payload, _ := json.Marshal(oldRecord)
			if err := baseCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
				t.Fatal(err)
			}
			guardedCache := &relayGuardianMembershipMutationCache{TokenCache: baseCache, failDelete: tt.failDelete, failHealthy: tt.failHealthy}
			store.tokenCache, guardian.cache = guardedCache, guardedCache

			// Model an asynchronous persist that was created by the old membership
			// but has not reached persistMu yet. Release it only after the account
			// immediately rejoins, which deterministically exercises revision ABA.
			oldPersistReady := make(chan struct{})
			oldPersistRelease := make(chan struct{})
			oldPersistDone := make(chan struct{})
			go func() {
				close(oldPersistReady)
				<-oldPersistRelease
				guardian.persist(51, oldRevision, oldRecord)
				close(oldPersistDone)
			}()
			<-oldPersistReady
			guardian.forgetAccountRuntime(account, 7)
			guardian.preloadAndReplay(account)
			// Let the new membership create and persist its first revision before
			// the delayed old persist resumes. Without the tombstone, both would
			// recycle revision 1 after a successful delete.
			guardian.observe(guardianObservation(51, "new-membership-failure", 502, true, clock.Now()))
			expectedAfterNewPersist := tt.writesBeforeRejoin + 1
			deadline := time.Now().Add(time.Second)
			for guardedCache.sets.Load() < expectedAfterNewPersist {
				if time.Now().After(deadline) {
					t.Fatalf("new membership persist missing: sets=%d", guardedCache.sets.Load())
				}
				time.Sleep(time.Millisecond)
			}
			close(oldPersistRelease)
			select {
			case <-oldPersistDone:
			case <-time.After(time.Second):
				t.Fatal("delayed old persist did not finish")
			}

			if guardedCache.deletes.Load() != 1 || guardedCache.sets.Load() != expectedAfterNewPersist || guardedCache.gets.Load() != 0 {
				t.Fatalf("membership fence calls delete=%d set=%d get=%d", guardedCache.deletes.Load(), guardedCache.sets.Load(), guardedCache.gets.Load())
			}
			guardian.mu.Lock()
			state = guardian.stateLocked(51)
			if state.State != RelayGuardianSuspect || state.revision != oldRevision+2 || !guardian.loaded[51] {
				copy := *state
				guardian.mu.Unlock()
				t.Fatalf("membership tombstone not materialized: %+v", copy)
			}
			guardian.resetForModeLocked(state, RelayGuardianEnforce, clock.Now())
			state.Reason = "test_cache_convergence"
			guardian.persistState(51, state)
			guardian.mu.Unlock()

			expectedFinalWrites := expectedAfterNewPersist + 1
			deadline = time.Now().Add(time.Second)
			for {
				stored, ok, err := baseCache.GetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51))
				if err != nil {
					t.Fatal(err)
				}
				if ok {
					var record relayGuardianRuntimeRecord
					if err := json.Unmarshal(stored, &record); err != nil {
						t.Fatal(err)
					}
					if record.State == RelayGuardianHealthy && record.ScopeEpoch == guardian.scopeEpoch && guardedCache.sets.Load() >= expectedFinalWrites {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("healthy tombstone did not converge to cache")
				}
				time.Sleep(time.Millisecond)
			}
			if guardedCache.sets.Load() != expectedFinalWrites {
				t.Fatalf("old persist wrote cache: sets=%d", guardedCache.sets.Load())
			}
		})
	}
}

func TestRelayGuardianPersistRejectsStaleScopeAtSameRevision(t *testing.T) {
	clock := newRelayCircuitTestClock()
	baseCache := cache.NewMemory(10)
	defer baseCache.Close()
	counting := &relayGuardianFailingSetCache{TokenCache: baseCache}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache, guardian.cache = counting, counting
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	guardian.resetForModeLocked(state, RelayGuardianEnforce, clock.Now())
	state.SchemaVersion = relayGuardianRuntimeSchemaVersion
	state.Mode = RelayGuardianEnforce
	state.ScopeGroupID = 7
	state.ScopeEpoch = guardian.scopeEpoch
	state.revision = 11
	revision := state.revision
	current := cloneRelayGuardianRuntimeRecord(state.relayGuardianRuntimeRecord)
	guardian.mu.Unlock()

	oldEpoch := current
	oldEpoch.ScopeEpoch = "previous-process-cycle"
	oldMode := current
	oldMode.Mode = RelayGuardianMonitor
	oldGroup := current
	oldGroup.ScopeGroupID = 8
	for _, record := range []relayGuardianRuntimeRecord{oldEpoch, oldMode, oldGroup} {
		guardian.persist(51, revision, record)
	}
	if counting.sets.Load() != 0 {
		t.Fatalf("stale epoch/mode/group persist reached cache: %d", counting.sets.Load())
	}
	guardian.persist(51, revision, current)
	if counting.sets.Load() != 1 {
		t.Fatalf("current persist did not reach cache: %d", counting.sets.Load())
	}
}

func TestRelayGuardianModeAndConfigTransitionsInvalidateOldRecoveryPermit(t *testing.T) {
	for _, transition := range []string{"mode", "config"} {
		t.Run(transition, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
			if transition == "config" {
				store.accountsByID[51].GroupIDs = []int64{7, 8}
			}
			guardian.mu.Lock()
			state := guardian.stateLocked(51)
			state.State = RelayGuardianHalfOpen
			state.Generation = 7
			state.permits = make(map[uint64]RelayGuardianPermit)
			guardian.mu.Unlock()
			permit, ok := guardian.begin(store.accountsByID[51])
			if !ok || !permit.HalfOpen {
				t.Fatalf("old recovery permit missing: %+v", permit)
			}
			if transition == "mode" {
				store.SetRelayGuardianMode(string(RelayGuardianMonitor))
				store.SetRelayGuardianMode(string(RelayGuardianEnforce))
			} else {
				store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
			}
			guardian.finishFailure(permit, 500)
			guardian.mu.Lock()
			defer guardian.mu.Unlock()
			after := guardian.stateLocked(51)
			if after.State != RelayGuardianHealthy || len(after.Failures) != 0 {
				t.Fatalf("old permit mutated post-transition state: %+v", after)
			}
		})
	}
}

func TestRelayGuardianManualDisableClearsPendingWeakCandidate(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 100,
		Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 100,
	})
	atomic.StoreInt32(&store.accountsByID[51].DispatchPaused, 1)
	clock.Advance(RelayGuardianScanInterval)
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	paused := *guardian.stateLocked(51)
	guardian.mu.Unlock()
	if paused.WeakConfirmationCount != 0 || paused.WeakCandidateTrigger != "" {
		t.Fatalf("manual disable retained pending candidate: %+v", paused)
	}

	atomic.StoreInt32(&store.accountsByID[51].DispatchPaused, 0)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 101,
		Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 101,
	})
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	resumed := guardian.stateLocked(51)
	if resumed.WeakConfirmationCount != 1 || resumed.State == RelayGuardianWouldQuarantine {
		t.Fatalf("resumed account skipped fresh confirmation: %+v", resumed)
	}
}

func TestRelayGuardianBootEpochDoesNotRestoreQuarantine(t *testing.T) {
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
	confirmGuardianWeakForTest(t, guardian, 51)
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
	guardian.mu.Lock()
	delete(guardian.states, 51)
	delete(guardian.loaded, 51)
	guardian.mu.Unlock()
	guardian.ensureLoaded(51)
	if guardian.selectable(store.accountsByID[51]) {
		t.Fatal("same-process scope token failed to restore current quarantine")
	}

	store2, guardian2 := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store2.tokenCache = tokenCache
	guardian2.cache = tokenCache
	guardian2.ensureLoaded(51)
	if !guardian2.selectable(store2.accountsByID[51]) {
		t.Fatal("boot epoch restored a stale Guardian quarantine")
	}
}

func TestRelayGuardianBootEpochDoesNotRestorePoolIncidentProtection(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	for _, accountID := range []int64{50, 53, 51} {
		guardian.ensureLoaded(accountID)
	}
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 53)

	guardian.observe(guardianObservation(50, "peer-a", 524, false, clock.Now()))
	clock.Advance(30 * time.Second)
	guardian.observe(guardianObservation(50, "peer-b", 524, false, clock.Now()))
	guardian.observe(guardianObservation(50, "peer-c", 524, false, clock.Now()))
	clock.Advance(3 * time.Minute)
	guardian.observe(guardianObservation(53, "candidate-a", 524, false, clock.Now()))
	clock.Advance(30 * time.Second)
	guardian.observe(guardianObservation(53, "candidate-b", 524, false, clock.Now()))
	guardian.observe(guardianObservation(53, "candidate-c", 524, false, clock.Now()))

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
	if !gotUntil.IsZero() || wantUntil.IsZero() {
		t.Fatalf("boot epoch restored pool deadline=%s old=%s", gotUntil, wantUntil)
	}

	clock.Advance(relayGuardianColdStartGuard + time.Minute)
	guardian2.mu.Lock()
	guardian2.capacitySamples = []relayGuardianCapacitySample{
		{At: clock.Now().Add(-2 * RelayGuardianScanInterval)},
		{At: clock.Now().Add(-RelayGuardianScanInterval)},
		{At: clock.Now()},
	}
	guardian2.mu.Unlock()
	relayGuardianRecordCanonicalSuccess(store2.accountsByID[50], clock.Now())
	guardian2.observe(guardianObservation(53, "independent-a", 500, false, clock.Now()))
	clock.Advance(time.Second)
	guardian2.observe(guardianObservation(53, "independent-b", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian2, 53)
	status, ok := store2.RelayGuardianAccountStatus(53)
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

func TestRelayGuardianLegacyRuntimeSchemaCannotRestoreOldWeakThreshold(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()
	record := relayGuardianRuntimeRecord{Mode: RelayGuardianMonitor, ScopeGroupID: 7, State: RelayGuardianWouldQuarantine,
		Generation: 9, Reason: "shadow_quarantine", TriggerSource: "user_visible_2_in_10m", WindowSeconds: 600,
		Failures: []relayGuardianFailure{{At: clock.Now(), LogicalRequestID: "legacy", StatusCode: 500, UserVisible: true}}}
	payload, _ := json.Marshal(record)
	if err := tokenCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	store.tokenCache, guardian.cache = tokenCache, tokenCache
	guardian.ensureLoaded(51)
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	state := guardian.stateLocked(51)
	if state.SchemaVersion != relayGuardianRuntimeSchemaVersion || state.State != RelayGuardianHealthy || len(state.Failures) != 0 || state.WeakConfirmationCount != 0 {
		t.Fatalf("legacy runtime survived schema fence: %+v", state)
	}
}

func TestRelayGuardianReliabilityDBFailureCannotTriggerWeakIsolation(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	guardian.db = db
	guardian.incidentEpoch = clock.Now().Add(-10 * time.Minute)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 110,
		Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 110,
	})
	db.Close()
	guardian.observe(guardianObservation(51, "db-fail-a", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "db-fail-b", 500, false, clock.Now()))
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State == RelayGuardianWouldQuarantine || state.State == RelayGuardianQuarantined || state.WeakConfirmationCount != 0 {
		guardian.mu.Unlock()
		t.Fatalf("DB failure triggered weak isolation: %+v", state)
	}
	guardian.heartbeat = time.Now()
	guardian.mu.Unlock()
	status := store.RelayGuardianStatus()
	if status.ReliabilityQueryStatus != "retrying" || status.ReliabilityConsecutiveErrors != 1 {
		t.Fatalf("first DB failure status=%+v", status)
	}
	health, _ := store.RelayGuardianHealth()
	if containsString(health.Reasons, "guardian_reliability_db_unavailable") {
		t.Fatalf("single DB failure degraded health: %+v", health)
	}
	clock.Advance(RelayGuardianScanInterval)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 111,
		Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 111,
	})
	guardian.mu.Lock()
	firstAfterOutage := *guardian.stateLocked(51)
	guardian.mu.Unlock()
	if firstAfterOutage.WeakConfirmationCount != 1 || firstAfterOutage.State == RelayGuardianWouldQuarantine {
		t.Fatalf("first successful snapshot after outage reused pending confirmation: %+v", firstAfterOutage)
	}
	for attempt := 2; attempt <= 3; attempt++ {
		clock.Advance(RelayGuardianScanInterval)
		guardian.reconcile(context.Background())
	}
	status = store.RelayGuardianStatus()
	if status.ReliabilityQueryStatus != "degraded" || status.ReliabilityConsecutiveErrors != 3 {
		t.Fatalf("third DB failure status=%+v", status)
	}
	guardian.mu.Lock()
	guardian.heartbeat = time.Now()
	guardian.mu.Unlock()
	health, _ = store.RelayGuardianHealth()
	if !containsString(health.Reasons, "guardian_reliability_db_unavailable") {
		t.Fatalf("repeated DB failures missing health reason: %+v", health)
	}
}

func TestRelayGuardianReliabilityWaitsForMaturityAfterStartup(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50)
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	guardian.db = db
	rows, err := guardian.loadReliability(context.Background(), 7, clock.Now().Add(-time.Minute), clock.Now())
	if err != nil {
		t.Fatalf("startup maturity should return before querying DB: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("startup maturity rows=%+v", rows)
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
		wantNormal       int
		wantSuspect      int
		wantRecoveryOnly int
		wantCircuitOpen  int
		wantDegraded     int
		wantReason       string
		wantEffective    bool
	}{
		{name: "closed", state: RelayCircuitClosed, wantSchedulable: 1, wantNormal: 1, wantEffective: true},
		{name: "active_open", state: RelayCircuitOpen, openUntil: time.Now().Add(time.Minute), wantCircuitOpen: 1, wantDegraded: 1, wantReason: "relay_circuit_open"},
		{name: "expired_open_is_not_stable_capacity", state: RelayCircuitOpen, openUntil: time.Now().Add(-time.Minute), wantRecoveryOnly: 1, wantDegraded: 1, wantReason: "relay_circuit_recovery_only", wantEffective: true},
		{name: "legacy_half_open_idle_is_recovery_only", state: RelayCircuitHalfOpen, wantRecoveryOnly: 1, wantDegraded: 1, wantReason: "relay_circuit_recovery_only", wantEffective: true},
		{name: "legacy_half_open_probe_in_flight", state: RelayCircuitHalfOpen, probe: true, wantRecoveryOnly: 1, wantDegraded: 1, wantReason: "relay_circuit_recovery_only", wantEffective: true},
		{name: "probation_is_recovery_only", state: RelayCircuitProbation, wantRecoveryOnly: 1, wantDegraded: 1, wantReason: "relay_circuit_recovery_only", wantEffective: true},
		{name: "suspect_has_slots_but_is_not_normal", state: RelayCircuitSuspect, wantSchedulable: 1, wantSuspect: 1, wantDegraded: 1, wantReason: "relay_circuit_suspect", wantEffective: true},
		{name: "guardian_and_circuit_degraded_once", state: RelayCircuitOpen, openUntil: time.Now().Add(time.Minute), guardianDegraded: true, wantCircuitOpen: 1, wantDegraded: 1, wantReason: "relay_circuit_open"},
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
			if relay.GroupID != 7 || relay.Schedulable != tt.wantSchedulable || relay.NormalSchedulable != tt.wantNormal ||
				relay.Suspect != tt.wantSuspect || relay.RecoveryOnly != tt.wantRecoveryOnly ||
				relay.CircuitOpen != tt.wantCircuitOpen || relay.Degraded != tt.wantDegraded {
				t.Fatalf("relay summary=%+v", relay)
			}
			if tt.wantEffective && relay.EffectiveAvailableSlots <= 0 {
				t.Fatalf("relay has no expected effective slots: %+v", relay)
			}
			if tt.wantReason != "" && !containsString(health.Reasons, tt.wantReason) {
				t.Fatalf("health=%+v missing %q", health, tt.wantReason)
			}
		})
	}
}

func TestRelayGuardianHealthGuardianEnforceDistinguishesBlockedAndRecoveryCapacity(t *testing.T) {
	tests := []struct {
		name             string
		state            RelayGuardianState
		until            time.Time
		probe            bool
		wantSlots        int64
		wantRecoveryOnly int
	}{
		{name: "active_quarantine", state: RelayGuardianQuarantined, until: time.Now().Add(time.Minute)},
		{name: "expired_quarantine_becomes_recovery", state: RelayGuardianQuarantined, until: time.Now().Add(-time.Minute), wantSlots: 1, wantRecoveryOnly: 1},
		{name: "half_open_idle", state: RelayGuardianHalfOpen, wantSlots: 1, wantRecoveryOnly: 1},
		{name: "half_open_probe_in_flight", state: RelayGuardianHalfOpen, probe: true, wantRecoveryOnly: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			guardian.mu.Lock()
			guardian.loaded[51] = true
			state := guardian.stateLocked(51)
			state.State = tt.state
			state.QuarantineUntil = tt.until
			state.halfOpenInFlight = tt.probe
			guardian.mu.Unlock()

			_, relay := store.RelayGuardianHealth()
			if relay.Schedulable != 0 || relay.NormalSchedulable != 0 || relay.RecoveryOnly != tt.wantRecoveryOnly ||
				relay.EffectiveAvailableSlots != tt.wantSlots {
				t.Fatalf("Guardian enforce state capacity mismatch: %+v", relay)
			}
		})
	}
}

func TestRelayGuardianHealthCircuitProbationRetainsOnlyBoundedEffectiveSlots(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardian.mu.Unlock()
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	breaker.loaded[51] = true
	state := breaker.stateLocked(51)
	state.state = RelayCircuitProbation
	state.admissionLimit = 3
	breaker.mu.Unlock()

	_, relay := store.RelayGuardianHealth()
	if relay.Schedulable != 0 || relay.NormalSchedulable != 0 || relay.RecoveryOnly != 1 || relay.EffectiveAvailableSlots != 3 {
		t.Fatalf("circuit probation capacity summary=%+v", relay)
	}
}

func TestRelayGuardianHealthHighConcurrencySuspectRetainsBoundedSlots(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardian.mu.Unlock()
	account := store.accountsByID[51]
	atomic.StoreInt64(&account.ActiveRequests, 95)
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	breaker.loaded[51] = true
	state := breaker.stateLocked(51)
	state.state = RelayCircuitSuspect
	state.admissionLimit = 20
	state.inFlight = 0
	state.limitedInFlight = 0
	breaker.mu.Unlock()

	_, relay := store.RelayGuardianHealth()
	if relay.Suspect != 1 || relay.Schedulable != 1 || relay.NormalSchedulable != 0 || relay.EffectiveAvailableSlots != 5 {
		t.Fatalf("high-concurrency suspect lost bounded slots: %+v", relay)
	}
}

func TestRelayGuardianHealthGuardianProbationIsBoundedRecoveryOnly(t *testing.T) {
	for _, percent := range []int{10, 50} {
		t.Run(fmt.Sprintf("percent_%d", percent), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			account := store.accountsByID[51]
			atomic.StoreInt64(&account.ActiveRequests, 3)
			guardian.mu.Lock()
			guardian.loaded[51] = true
			state := guardian.stateLocked(51)
			state.State = RelayGuardianProbation
			state.ProbationPercent = percent
			relayGuardianApplySchedulingHint(account, state)
			guardian.mu.Unlock()

			_, relay := store.RelayGuardianHealth()
			expectedSlots := int64(percent - 3)
			if relay.Probation != 1 || relay.RecoveryOnly != 1 || relay.Schedulable != 0 ||
				relay.NormalSchedulable != 0 || relay.EffectiveAvailableSlots != expectedSlots {
				t.Fatalf("Guardian probation summary=%+v", relay)
			}
		})
	}
}

func TestRelayGuardianHealthTemporaryBypassIsNeverNormalRecoveryProof(t *testing.T) {
	tests := []struct {
		name             string
		bypassUntil      time.Time
		quarantineUntil  time.Time
		wantSchedulable  int
		wantRecoveryOnly int
		wantSlots        int64
	}{
		{name: "active_override", bypassUntil: time.Now().Add(time.Minute), quarantineUntil: time.Now().Add(time.Hour), wantSchedulable: 1, wantRecoveryOnly: 1, wantSlots: 100},
		{name: "expired_returns_to_quarantine", bypassUntil: time.Now().Add(-time.Minute), quarantineUntil: time.Now().Add(time.Hour)},
		{name: "expired_returns_to_half_open", bypassUntil: time.Now().Add(-time.Minute), quarantineUntil: time.Now().Add(-time.Second), wantRecoveryOnly: 1, wantSlots: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			guardian.mu.Lock()
			guardian.loaded[51] = true
			state := guardian.stateLocked(51)
			state.State = RelayGuardianTemporaryBypass
			state.TemporaryBypassUntil = tt.bypassUntil
			state.QuarantineUntil = tt.quarantineUntil
			guardian.mu.Unlock()

			health, relay := store.RelayGuardianHealth()
			if relay.Schedulable != tt.wantSchedulable || relay.NormalSchedulable != 0 ||
				relay.RecoveryOnly != tt.wantRecoveryOnly || relay.EffectiveAvailableSlots != tt.wantSlots || relay.Degraded != 1 {
				t.Fatalf("temporary bypass health summary=%+v", relay)
			}
			if !containsString(health.Reasons, "relay_guardian_temporary_bypass") {
				t.Fatalf("temporary bypass reason missing: %+v", health)
			}
		})
	}
}

func TestRelayGuardianHealthNonEnforceIgnoresStaleExecutionState(t *testing.T) {
	tests := []struct {
		name  string
		mode  RelayGuardianMode
		state RelayGuardianState
	}{
		{name: "off_quarantined", mode: RelayGuardianOff, state: RelayGuardianQuarantined},
		{name: "off_probation", mode: RelayGuardianOff, state: RelayGuardianProbation},
		{name: "monitor_half_open", mode: RelayGuardianMonitor, state: RelayGuardianHalfOpen},
		{name: "monitor_temporary_bypass", mode: RelayGuardianMonitor, state: RelayGuardianTemporaryBypass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, tt.mode, clock, 51)
			account := store.accountsByID[51]
			guardian.mu.Lock()
			guardian.loaded[51] = true
			state := guardian.stateLocked(51)
			state.State = tt.state
			state.QuarantineUntil = clock.Now().Add(time.Hour)
			state.TemporaryBypassUntil = clock.Now().Add(time.Hour)
			state.ProbationPercent = 10
			state.LastResort = true
			state.LastResortCap = 1
			relayGuardianApplySchedulingHint(account, state)
			guardian.mu.Unlock()

			health, relay := store.RelayGuardianHealth()
			if relay.Schedulable != 1 || relay.NormalSchedulable != 1 || relay.RecoveryOnly != 0 ||
				relay.Quarantined != 0 || relay.Probation != 0 || relay.LastResort != 0 || relay.Degraded != 0 ||
				relay.EffectiveAvailableSlots != 100 {
				t.Fatalf("non-enforce stale Guardian state changed capacity: health=%+v relay=%+v", health, relay)
			}
			if containsString(health.Reasons, "relay_guardian_recovery_only") ||
				containsString(health.Reasons, "relay_guardian_temporary_bypass") ||
				containsString(health.Reasons, "relay_last_resort") {
				t.Fatalf("non-enforce stale Guardian reason leaked: %+v", health)
			}
		})
	}
}

func TestRelayGuardianHealthRecoveryOnlyDeduplicatesGuardianAndCircuit(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	account := store.accountsByID[51]
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardianState := guardian.stateLocked(51)
	guardianState.State = RelayGuardianProbation
	guardianState.ProbationPercent = 50
	relayGuardianApplySchedulingHint(account, guardianState)
	guardian.mu.Unlock()
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	breaker.loaded[51] = true
	circuitState := breaker.stateLocked(51)
	circuitState.state = RelayCircuitProbation
	circuitState.admissionLimit = 3
	circuitState.inFlight = 1
	circuitState.limitedInFlight = 1
	breaker.mu.Unlock()

	_, relay := store.RelayGuardianHealth()
	if relay.Probation != 1 || relay.RecoveryOnly != 1 || relay.Schedulable != 0 ||
		relay.NormalSchedulable != 0 || relay.EffectiveAvailableSlots != 2 {
		t.Fatalf("overlapping probation summary=%+v", relay)
	}
}

func TestRelayGuardianHealthCountsLastResortWithoutCallingItNormal(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardian.stateLocked(51).LastResort = true
	guardian.mu.Unlock()

	health, relay := store.RelayGuardianHealth()
	if relay.Schedulable != 1 || relay.NormalSchedulable != 0 || relay.LastResort != 1 || relay.EffectiveAvailableSlots <= 0 {
		t.Fatalf("last-resort capacity summary=%+v", relay)
	}
	if health.Status != "degraded" || !containsString(health.Reasons, "relay_last_resort") {
		t.Fatalf("last-resort health=%+v", health)
	}
}

func TestRelayGuardianHealthDoesNotCountSaturatedSuspectAsSchedulable(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardian.mu.Unlock()
	account := store.accountsByID[51]
	atomic.StoreInt64(&account.ActiveRequests, account.GetDynamicConcurrencyLimit())
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	breaker.loaded[51] = true
	breaker.stateLocked(51).state = RelayCircuitSuspect
	breaker.mu.Unlock()

	_, relay := store.RelayGuardianHealth()
	if relay.Suspect != 1 || relay.Schedulable != 0 || relay.NormalSchedulable != 0 || relay.EffectiveAvailableSlots != 0 {
		t.Fatalf("saturated suspect summary=%+v", relay)
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
	confirmGuardianWeakForTest(t, guardian, 51)
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

func TestRelayGuardianRecoveredAccountRequiresFreshTwoWeakScans(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 70,
		Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 70,
	})
	clock.Advance(RelayGuardianScanInterval)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 5, Failures10m: 3, LatestFailureRowID10m: 71,
		Total60m: 5, Failures60m: 3, LatestFailureRowID60m: 71,
	})
	guardian.mu.Lock()
	quarantined := *guardian.stateLocked(51)
	guardian.mu.Unlock()
	if quarantined.State != RelayGuardianQuarantined || quarantined.WeakConfirmationCount != 0 {
		t.Fatalf("quarantine retained weak confirmation fence: %+v", quarantined)
	}

	recoverGuardianAccountForTest(t, store, guardian, clock, 51)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 6, Failures10m: 2, LatestFailureRowID10m: 80,
		Total60m: 6, Failures60m: 2, LatestFailureRowID60m: 80,
	})
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	firstFresh := guardian.stateLocked(51)
	if firstFresh.WeakConfirmationCount != 1 || firstFresh.State != RelayGuardianSuspect {
		t.Fatalf("recovered account skipped fresh first confirmation: %+v", firstFresh)
	}
}

func TestRelayGuardianStrongQuarantineAfterWeakCandidateDoesNotLeakAcrossRecovery(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 51)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 4, Failures10m: 2, LatestFailureRowID10m: 90,
		Total60m: 4, Failures60m: 2, LatestFailureRowID60m: 90,
	})
	for index := 0; index < 3; index++ {
		guardian.observe(guardianObservation(51, fmt.Sprintf("strong-after-weak-%d", index), 502, true, clock.Now()))
	}
	guardian.mu.Lock()
	quarantined := *guardian.stateLocked(51)
	guardian.mu.Unlock()
	if quarantined.State != RelayGuardianQuarantined || quarantined.TriggerSource != "strong_breaker_2_cycles_in_10m" || quarantined.WeakConfirmationCount != 0 {
		t.Fatalf("strong quarantine retained pending weak candidate: %+v", quarantined)
	}

	recoverGuardianAccountForTest(t, store, guardian, clock, 51)
	applyGuardianReliabilityForTest(t, guardian, 51, relayGuardianReliabilitySnapshot{
		AccountID: 51, ObservedAt: clock.Now(), Total10m: 6, Failures10m: 2, LatestFailureRowID10m: 91,
		Total60m: 6, Failures60m: 2, LatestFailureRowID60m: 91,
	})
	guardian.mu.Lock()
	defer guardian.mu.Unlock()
	firstFresh := guardian.stateLocked(51)
	if firstFresh.WeakConfirmationCount != 1 || firstFresh.State != RelayGuardianSuspect {
		t.Fatalf("post-strong recovery reused old weak candidate: %+v", firstFresh)
	}
}

func TestRelayGuardianProbationFailureReopensWithBackoff(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	guardian.observe(guardianObservation(51, "u-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "u-2", 500, false, clock.Now()))
	confirmGuardianWeakForTest(t, guardian, 51)
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
	relayGuardianRecordCanonicalSuccess(store.accountsByID[50], clock.Now())
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
			confirmGuardianWeakForTest(t, guardian, 51)
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

func TestRelayGuardianMonitorRuntimeUnknownDoesNotDegradeCapacity(t *testing.T) {
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
	if containsString(health.Reasons, "guardian_runtime_state_unavailable") || relay.Degraded != 0 ||
		relay.Schedulable != relay.Enabled || relay.NormalSchedulable != relay.Enabled {
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
	if state51.State != RelayGuardianSuspect || len(state51.SeenFinal) != 2 || state51.WeakConfirmationCount != 0 {
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
	confirmGuardianWeakForTest(t, guardian, 51)
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
	confirmGuardianWeakForTest(t, guardian, 51)
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
	t.Run("account51_absorbed_502_burst_stays_suspect", func(t *testing.T) {
		_, guardian := replay(t, []int64{51, 50, 53}, []replayRow{
			{51, 0, 502, "direct", "gateway", "burst-a", true}, {51, time.Minute, 502, "direct", "gateway", "burst-b", true}, {51, 2 * time.Minute, 502, "direct", "gateway", "burst-c", true},
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		if state := guardian.stateLocked(51); state.State != RelayGuardianSuspect || state.LastResort || state.ShadowAction != "" {
			t.Fatalf("absorbed 502 burst became actionable: %+v", state)
		}
	})
	t.Run("account50_only_available_two_500", func(t *testing.T) {
		_, guardian := replay(t, []int64{50}, []replayRow{
			{50, 0, 500, "direct", "server", "visible-a", false}, {50, 2 * time.Minute, 500, "direct", "server", "visible-b", false},
		})
		confirmGuardianWeakForTest(t, guardian, 50)
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		if state := guardian.stateLocked(50); state.State == RelayGuardianQuarantined || !state.LastResort || state.LastResortCap != 5 {
			t.Fatalf("only Relay not kept last-resort: %+v", state)
		}
	})
	t.Run("shared_absorbed_524_window_stays_observational", func(t *testing.T) {
		_, guardian := replay(t, []int64{50, 53, 51}, []replayRow{
			{50, 0, 524, "direct", "gateway", "shared-a", true}, {53, 30 * time.Second, 524, "direct", "gateway", "shared-a", true},
			{50, time.Minute, 524, "direct", "gateway", "shared-b", true}, {53, 90 * time.Second, 524, "direct", "gateway", "shared-b", true},
			{53, 2 * time.Minute, 524, "direct", "gateway", "only-53", true},
		})
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		for _, accountID := range []int64{50, 53} {
			if state := guardian.stateLocked(accountID); state.State == RelayGuardianQuarantined || state.LastResort || state.ShadowAction != "" {
				t.Fatalf("absorbed shared 524 made account %d actionable: %+v", accountID, state)
			}
		}
	})
}

func TestRelayGuardianMonitorShadowDecisionsMatchEnforceGuards(t *testing.T) {
	t.Run("raw_burst_stays_suspect", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 51, 50, 53)
		for _, logical := range []string{"burst-a", "burst-b", "burst-c"} {
			guardian.observe(guardianObservation(51, logical, 502, true, clock.Now()))
		}
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(51)
		if state.State != RelayGuardianSuspect || state.ShadowAction != "" || state.Reason != "strong_gateway_waiting_for_confirmed_breaker_cycle" {
			t.Fatalf("raw burst became actionable=%+v", state)
		}
	})
	t.Run("only_relay_shadow_last_resort", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		_, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50)
		guardian.observe(guardianObservation(50, "only-a", 500, false, clock.Now()))
		guardian.observe(guardianObservation(50, "only-b", 500, false, clock.Now()))
		confirmGuardianWeakForTest(t, guardian, 50)
		guardian.mu.Lock()
		defer guardian.mu.Unlock()
		state := guardian.stateLocked(50)
		if state.State != RelayGuardianWouldQuarantine || state.ShadowAction != "last_resort" || state.Reason != "last_available_relay" {
			t.Fatalf("shadow last-resort=%+v", state)
		}
	})
	t.Run("shared_524_confirmed_breaker_pool_alert", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		clock.mu.Lock()
		clock.now = time.Now().UTC().Truncate(time.Second)
		clock.mu.Unlock()
		store, guardian := newGuardianTestStore(t, RelayGuardianMonitor, clock, 50, 53, 51)
		confirmGuardianStrongBreakerCyclesForTest(t, guardian, 53)
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
			confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
			confirmGuardianStrongBreakerCyclesForTest(t, guardian, 53)

			guardian.observe(guardianObservation(50, "peer-a", 524, false, clock.Now()))
			clock.Advance(30 * time.Second)
			guardian.observe(guardianObservation(50, "peer-b", 524, false, clock.Now()))
			guardian.observe(guardianObservation(50, "peer-c", 524, false, clock.Now()))
			clock.Advance(3 * time.Minute)
			guardian.observe(guardianObservation(53, "candidate-a", 524, false, clock.Now()))
			clock.Advance(30 * time.Second)
			guardian.observe(guardianObservation(53, "candidate-b", 524, false, clock.Now()))
			guardian.observe(guardianObservation(53, "candidate-c", 524, false, clock.Now()))

			guardian.mu.Lock()
			incidentUntil := guardian.poolWideUntil
			state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(53).relayGuardianRuntimeRecord)
			guardian.mu.Unlock()
			if state.Reason != "pool_wide_failure_guard" || !incidentUntil.Equal(clock.Now().Add(relayGuardianStrongCycleWindow)) {
				t.Fatalf("initial pool incident state=%+v until=%s now=%s", state, incidentUntil, clock.Now())
			}

			// The peer 524 evidence leaves the 5m signature window while the
			// candidate's 524 evidence still occupies the strong 5m trigger window.
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
			relayGuardianRecordCanonicalSuccess(store.accountsByID[51], clock.Now())
			guardian.observe(guardianObservation(53, "independent-a", 500, false, clock.Now()))
			clock.Advance(time.Second)
			guardian.observe(guardianObservation(53, "independent-b", 500, false, clock.Now()))
			confirmGuardianWeakForTest(t, guardian, 53)
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
	record := relayGuardianRuntimeRecord{SchemaVersion: relayGuardianRuntimeSchemaVersion, Mode: RelayGuardianEnforce, ScopeGroupID: 7, State: RelayGuardianQuarantined, Generation: 3, QuarantineUntil: clock.Now().Add(time.Hour)}
	payload, _ := json.Marshal(record)
	if err := tokenCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, 51), payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	guardian.ensureLoaded(51)
	if !guardian.selectable(store.accountsByID[51]) {
		guardian.mu.Lock()
		state := cloneRelayGuardianRuntimeRecord(guardian.stateLocked(51).relayGuardianRuntimeRecord)
		loaded := guardian.loaded[51]
		guardian.mu.Unlock()
		t.Fatalf("boot epoch restored old-group quarantine: loaded=%v state=%+v", loaded, state)
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
	confirmGuardianWeakForTest(t, guardian, 51)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
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
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
	for _, logical := range []string{"first-a", "first-b", "first-c"} {
		guardian.observe(guardianObservation(50, logical, 502, true, clock.Now()))
	}
	clock.Advance(30 * time.Second)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 53)
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
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 50)
	confirmGuardianStrongBreakerCyclesForTest(t, guardian, 53)
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
	confirmGuardianWeakForTest(t, guardian, 51)
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
			runtimeState := *guardian.stateLocked(51)
			guardian.mu.Unlock()
			if runtimeState.QuarantineUntil.Sub(clock.Now()) != 30*time.Minute {
				t.Fatalf("quarantine used observation time: until=%s", runtimeState.QuarantineUntil)
			}
			details, _ := event.Details.(map[string]any)
			if runtimeState.WeakConfirmationCount != 0 || fmt.Sprint(details["weak_confirmation_count"]) != "2" {
				t.Fatalf("weak fence/event evidence mismatch: runtime=%+v event=%+v", runtimeState, event.Details)
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
