package auth

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/cache"
)

func requireRelayGuardianHint(t *testing.T, account *Account, lastResort bool, hardCap int64, percent int) {
	t.Helper()
	hint := account.relayGuardianSchedulingHintSnapshot()
	if hint.lastResort != lastResort || hint.hardCap != hardCap || hint.percent != percent {
		t.Fatalf("scheduler hint=%+v, want lastResort=%v hardCap=%d percent=%d", hint, lastResort, hardCap, percent)
	}
}

func TestRelayGuardianCapacityLastResortEscalatesHintCaps(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	account := store.accountsByID[51]

	for level, cap := range []int64{5, 3, 1} {
		prefix := string(rune('a' + level))
		guardian.observe(guardianObservation(51, prefix+"-1", 500, false, clock.Now()))
		if level == 2 {
			guardian.mu.Lock()
			state := guardian.stateLocked(51)
			if state.LastResortLevel != 3 || state.TriggerSource != "user_visible_4_in_60m" {
				guardian.mu.Unlock()
				t.Fatalf("60m label transition state=%+v, want level 3 without a double jump", state)
			}
			guardian.mu.Unlock()
			// Duplicate logical rows must be ignored before the rule label switches
			// back to the 2/10m signal on the next distinct request.
			guardian.observe(guardianObservation(51, prefix+"-1", 500, false, clock.Now()))
		}
		guardian.observe(guardianObservation(51, prefix+"-2", 500, false, clock.Now()))

		guardian.mu.Lock()
		state := guardian.stateLocked(51)
		if !state.LastResort || state.LastResortLevel != level+1 || int64(state.LastResortCap) != cap || state.Reason != "last_available_relay" {
			guardian.mu.Unlock()
			t.Fatalf("level %d state=%+v, want last-resort cap %d", level+1, state, cap)
		}
		guardian.mu.Unlock()
		requireRelayGuardianHint(t, account, true, cap, 0)
		if effective := account.relayGuardianConcurrencyLimit(100); effective != cap {
			t.Fatalf("level %d effective concurrency=%d, want %d", level+1, effective, cap)
		}
		if level == 2 {
			guardian.reconcile(context.Background())
			clock.Advance(RelayGuardianScanInterval + time.Second)
			guardian.reconcile(context.Background())
			guardian.mu.Lock()
			if got := guardian.stateLocked(51).LastResortLevel; got != 3 {
				guardian.mu.Unlock()
				t.Fatalf("same incident was replayed by reconcile: level=%d, want 3", got)
			}
			guardian.mu.Unlock()
			continue
		}
		clock.Advance(10*time.Minute + time.Second)
	}
}

func TestRelayGuardianRecoveryTransitionsApplyAndClearSchedulerHint(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
	account := store.accountsByID[51]
	guardian.observe(guardianObservation(51, "recovery-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "recovery-2", 500, false, clock.Now()))
	requireRelayGuardianHint(t, account, false, 0, 0)

	clock.Advance(31 * time.Minute)
	if !guardian.selectable(account) {
		t.Fatal("expired quarantine did not enter half-open")
	}
	requireRelayGuardianHint(t, account, false, 0, 0)

	for i := 0; i < 3; i++ {
		permit, ok := guardian.begin(account)
		if !ok || !permit.HalfOpen {
			t.Fatalf("half-open permit %d=%+v ok=%v", i, permit, ok)
		}
		guardian.finishSuccess(permit)
	}
	requireRelayGuardianHint(t, account, false, 0, 10)
	if effective := account.relayGuardianConcurrencyLimit(100); effective != 10 {
		t.Fatalf("10%% probation effective concurrency=%d, want 10", effective)
	}

	advanceProbation := func() {
		t.Helper()
		clock.Advance(relayGuardianProbationStage)
		for i := 0; i < relayGuardianProbationSuccesses; i++ {
			permit, ok := guardian.begin(account)
			if !ok || !permit.Probation {
				t.Fatalf("probation permit %d=%+v ok=%v", i, permit, ok)
			}
			guardian.finishSuccess(permit)
		}
	}
	advanceProbation()
	requireRelayGuardianHint(t, account, false, 0, 50)
	if effective := account.relayGuardianConcurrencyLimit(100); effective != 50 {
		t.Fatalf("50%% probation effective concurrency=%d, want 50", effective)
	}

	advanceProbation()
	guardian.mu.Lock()
	state := guardian.stateLocked(51)
	if state.State != RelayGuardianHealthy {
		guardian.mu.Unlock()
		t.Fatalf("final recovery state=%+v, want healthy", state)
	}
	guardian.mu.Unlock()
	requireRelayGuardianHint(t, account, false, 0, 0)
	if effective := account.relayGuardianConcurrencyLimit(100); effective != 100 {
		t.Fatalf("healthy effective concurrency=%d, want 100", effective)
	}
}

func TestRelayGuardianLifecycleClearsSchedulerHint(t *testing.T) {
	t.Run("mode_off", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
		account := store.accountsByID[51]
		guardian.observe(guardianObservation(51, "off-1", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "off-2", 500, false, clock.Now()))
		requireRelayGuardianHint(t, account, true, 5, 0)
		store.SetRelayGuardianMode(string(RelayGuardianOff))
		requireRelayGuardianHint(t, account, false, 0, 0)
	})

	t.Run("manual_disable", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
		account := store.accountsByID[51]
		guardian.observe(guardianObservation(51, "manual-1", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "manual-2", 500, false, clock.Now()))
		requireRelayGuardianHint(t, account, true, 5, 0)
		atomic.StoreInt32(&account.Disabled, 1)
		guardian.reconcile(context.Background())
		requireRelayGuardianHint(t, account, false, 0, 0)
	})

	t.Run("temporary_bypass", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
		account := store.accountsByID[51]
		guardian.mu.Lock()
		guardian.loaded[51] = true
		state := guardian.stateLocked(51)
		state.State = RelayGuardianProbation
		state.Generation++
		state.ProbationPercent = 10
		relayGuardianApplySchedulingHint(account, state)
		generation := state.Generation
		guardian.mu.Unlock()
		requireRelayGuardianHint(t, account, false, 0, 10)
		if err := store.TemporaryBypassRelayGuardian(51, generation, 5); err != nil {
			t.Fatal(err)
		}
		requireRelayGuardianHint(t, account, false, 0, 0)
	})

	t.Run("group_removal", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
		account := store.accountsByID[51]
		guardian.observe(guardianObservation(51, "group-1", 500, false, clock.Now()))
		guardian.observe(guardianObservation(51, "group-2", 500, false, clock.Now()))
		requireRelayGuardianHint(t, account, true, 5, 0)
		account.mu.Lock()
		account.GroupIDs = nil
		account.mu.Unlock()
		guardian.reconcile(context.Background())
		requireRelayGuardianHint(t, account, false, 0, 0)
		guardian.mu.Lock()
		_, retained := guardian.states[51]
		guardian.mu.Unlock()
		if retained {
			t.Fatal("removed Relay group account retained Guardian runtime state")
		}
	})
}

func TestRelayGuardianRedisRestoreReappliesOrClearsSchedulerHint(t *testing.T) {
	clock := newRelayCircuitTestClock()
	tokenCache := cache.NewMemory(10)
	defer tokenCache.Close()

	records := map[int64]relayGuardianRuntimeRecord{
		51: {
			Mode: RelayGuardianEnforce, ScopeGroupID: 7, State: RelayGuardianSuspect, Generation: 2,
			LastResort: true, LastResortCap: 3, LastResortLevel: 2,
			Reason: "last_available_relay", TriggerSource: "user_visible_2_in_10m", LastActionAt: clock.Now().Add(-10 * time.Minute),
			Failures: []relayGuardianFailure{
				{At: clock.Now(), LogicalRequestID: "restored-1", StatusCode: 500, UserVisible: true},
				{At: clock.Now(), LogicalRequestID: "restored-2", StatusCode: 500, UserVisible: true},
			},
			SeenFinal: map[string]time.Time{"restored-1": clock.Now(), "restored-2": clock.Now()},
		},
		50: {Mode: RelayGuardianEnforce, ScopeGroupID: 7, State: RelayGuardianProbation, Generation: 4, ProbationPercent: 50, ProbationStartedAt: clock.Now()},
		53: {Mode: RelayGuardianEnforce, ScopeGroupID: 7, State: RelayGuardianQuarantined, Generation: 6, QuarantineUntil: clock.Now().Add(time.Hour)},
	}
	for accountID, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := tokenCache.SetRuntime(context.Background(), relayGuardianRuntimeNamespace, relayGuardianRuntimeKey(7, accountID), payload, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50, 53)
	store.tokenCache = tokenCache
	guardian.cache = tokenCache
	store.accountsByID[53].setRelayGuardianSchedulingHint(true, 5, 0)
	for _, accountID := range []int64{51, 50, 53} {
		guardian.ensureLoaded(accountID)
	}

	requireRelayGuardianHint(t, store.accountsByID[51], true, 3, 0)
	requireRelayGuardianHint(t, store.accountsByID[50], false, 0, 50)
	requireRelayGuardianHint(t, store.accountsByID[53], false, 0, 0)

	// The last-resort record intentionally omits LastResortFailureID to model
	// an upgrade from the previous runtime schema. Its old failures must be
	// consumed on restore rather than replayed as a level-3 escalation.
	guardian.mu.Lock()
	guardian.capacitySamples = append(guardian.capacitySamples, relayGuardianCapacitySample{At: clock.Now(), Active: 1_000})
	guardian.mu.Unlock()
	guardian.reconcile(context.Background())
	guardian.mu.Lock()
	restored := guardian.stateLocked(51)
	if restored.LastResortLevel != 2 || restored.LastResortCap != 3 || restored.LastResortFailureID != "restored-2" {
		guardian.mu.Unlock()
		t.Fatalf("legacy restored incident replayed: %+v", restored)
	}
	guardian.mu.Unlock()
}

func TestRelayGuardianStateHintIsRespectedByAllSchedulerPaths(t *testing.T) {
	for _, schedulerMode := range []string{"slow", "fast", "lazy"} {
		t.Run(schedulerMode, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
			degraded := store.accountsByID[51]
			normal := store.accountsByID[50]
			guardian.mu.Lock()
			guardian.capacitySamples = append(guardian.capacitySamples, relayGuardianCapacitySample{At: clock.Now(), Active: 1_000})
			guardian.mu.Unlock()
			guardian.observe(guardianObservation(51, schedulerMode+"-1", 500, false, clock.Now()))
			guardian.observe(guardianObservation(51, schedulerMode+"-2", 500, false, clock.Now()))
			requireRelayGuardianHint(t, degraded, true, 5, 0)

			switch schedulerMode {
			case "fast":
				store.SetFastSchedulerEnabled(true)
			case "lazy":
				store.SetLazyMode(true)
			}

			first := store.Next()
			if first == nil || first.DBID != normal.DBID {
				t.Fatalf("first Next()=%+v, want normal account %d", first, normal.DBID)
			}
			store.Release(first)

			atomic.StoreInt64(&normal.ActiveRequests, 100)
			acquired := make([]*Account, 0, 5)
			for i := 0; i < 5; i++ {
				account := store.Next()
				if account == nil || account.DBID != degraded.DBID {
					t.Fatalf("last-resort slot %d=%+v, want account %d", i+1, account, degraded.DBID)
				}
				acquired = append(acquired, account)
			}
			if account := store.Next(); account != nil {
				store.Release(account)
				t.Fatalf("scheduler exceeded Guardian hard cap: active=%d", degraded.GetActiveRequests())
			}
			for _, account := range acquired {
				store.Release(account)
			}
			atomic.StoreInt64(&normal.ActiveRequests, 0)
		})
	}
}
