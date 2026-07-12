package auth

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/cache"
)

func waitForCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		runtime.Gosched()
	}
}

func waitForAccountAndWriter(t *testing.T, next <-chan *Account, writer <-chan struct{}) *Account {
	t.Helper()
	var account *Account
	for account == nil || writer != nil {
		select {
		case account = <-next:
		case <-writer:
			writer = nil
		case <-time.After(2 * time.Second):
			t.Fatal("scheduler/writer lock regression timed out")
		}
	}
	return account
}

func TestStoreSchedulersDoNotReenterStoreLockBehindQueuedWriter(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	for _, mode := range []string{"slow", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, _ := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			if mode == "lazy" {
				store.SetLazyMode(true)
			}
			account := store.accountsByID[51]
			account.mu.Lock()

			nextDone := make(chan *Account, 1)
			go func() { nextDone <- store.Next() }()
			waitForCondition(t, "scheduler Store read lock", func() bool {
				if store.mu.TryLock() {
					store.mu.Unlock()
					return false
				}
				return true
			})

			writerDone := make(chan struct{})
			go func() {
				store.mu.Lock()
				store.mu.Unlock()
				close(writerDone)
			}()
			waitForCondition(t, "queued Store writer", func() bool {
				if store.mu.TryRLock() {
					store.mu.RUnlock()
					return false
				}
				return true
			})

			account.mu.Unlock()
			selected := waitForAccountAndWriter(t, nextDone, writerDone)
			if selected == nil || selected.DBID != 51 {
				t.Fatalf("Next()=%+v, want account 51", selected)
			}
			store.Release(selected)
		})
	}
}

func TestFastSchedulerDoesNotInvertStoreAndSchedulerLocks(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	clock := newRelayCircuitTestClock()
	store, _ := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	store.SetFastSchedulerEnabled(true)
	scheduler := store.getFastScheduler()
	account := store.accountsByID[51]
	account.mu.Lock()

	nextDone := make(chan *Account, 1)
	go func() { nextDone <- store.Next() }()
	waitForCondition(t, "FastScheduler lock", func() bool {
		if scheduler.mu.TryLock() {
			scheduler.mu.Unlock()
			return false
		}
		return true
	})

	writerDone := make(chan struct{})
	go func() {
		store.mu.Lock()
		store.fastSchedulerUpdate(relayCircuitSchedulerAccount(99, 0))
		store.mu.Unlock()
		close(writerDone)
	}()
	waitForCondition(t, "writer holding Store lock", func() bool {
		if store.mu.TryRLock() {
			store.mu.RUnlock()
			return false
		}
		return true
	})

	account.mu.Unlock()
	selected := waitForAccountAndWriter(t, nextDone, writerDone)
	if selected == nil || selected.DBID != 51 {
		t.Fatalf("Next()=%+v, want account 51", selected)
	}
	store.Release(selected)
}

func installProbationHint(guardian *relayHealthGuardian, account *Account, percent int) {
	guardian.mu.Lock()
	guardian.loaded[account.DBID] = true
	state := guardian.stateLocked(account.DBID)
	state.Mode = RelayGuardianEnforce
	state.ScopeGroupID = 7
	state.State = RelayGuardianProbation
	state.Generation++
	state.ProbationPercent = percent
	state.ProbationStartedAt = guardian.nowTime()
	relayGuardianApplySchedulingHint(account, state)
	guardian.mu.Unlock()
}

func TestRelayGuardianReenableReplaysRetainedSchedulingHint(t *testing.T) {
	t.Run("dispatch_paused", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
		account := store.accountsByID[51]
		installProbationHint(guardian, account, 50)
		if !store.ApplyAccountEnabled(51, false) {
			t.Fatal("disable failed")
		}
		requireRelayGuardianHint(t, account, false, 0, 0)
		if !store.ApplyAccountEnabled(51, true) {
			t.Fatal("re-enable failed")
		}
		requireRelayGuardianHint(t, account, false, 0, 50)
	})

	for _, method := range []string{"clear_cooldown", "manual_test"} {
		t.Run(method, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			account := store.accountsByID[51]
			installProbationHint(guardian, account, 10)
			atomic.StoreInt32(&account.Disabled, 1)
			guardian.reconcile(context.Background())
			requireRelayGuardianHint(t, account, false, 0, 0)
			if method == "clear_cooldown" {
				store.ClearCooldown(account)
			} else {
				store.RecordManualTestSuccess(account, time.Millisecond)
			}
			requireRelayGuardianHint(t, account, false, 0, 10)
		})
	}
}

func TestRelayGuardianSameDBIDReplacementReceivesLiveHint(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	installProbationHint(guardian, store.accountsByID[51], 50)

	store.RemoveAccount(51)
	replacement := relayCircuitSchedulerAccount(51, 100)
	store.AddAccount(replacement)
	if store.FindByID(51) != replacement {
		t.Fatal("replacement account was not installed")
	}
	requireRelayGuardianHint(t, replacement, false, 0, 50)
}

func TestRelayGuardianLeaveRejoinStartsHealthyForBothGroupEntrypoints(t *testing.T) {
	for _, entrypoint := range []string{"single", "bulk"} {
		t.Run(entrypoint, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
			account := store.accountsByID[51]
			installProbationHint(guardian, account, 50)

			if entrypoint == "single" {
				store.ApplyAccountGroups(51, nil)
			} else {
				store.ApplyAccountGroupMemberships(map[int64][]int64{51: nil})
			}
			requireRelayGuardianHint(t, account, false, 0, 0)
			guardian.mu.Lock()
			_, stateRetained := guardian.states[51]
			loadedRetained := guardian.loaded[51]
			guardian.mu.Unlock()
			if stateRetained || loadedRetained {
				t.Fatalf("leave retained Guardian state: state=%v loaded=%v", stateRetained, loadedRetained)
			}

			if entrypoint == "single" {
				store.ApplyAccountGroups(51, []int64{7})
			} else {
				store.ApplyAccountGroupMemberships(map[int64][]int64{51: []int64{7}})
			}
			requireRelayGuardianHint(t, account, false, 0, 0)
			if !guardian.selectable(account) {
				t.Fatal("freshly rejoined account was not healthy/selectable")
			}
			guardian.mu.Lock()
			state := guardian.stateLocked(51)
			gotState := state.State
			guardian.mu.Unlock()
			if gotState != RelayGuardianHealthy {
				t.Fatalf("rejoined state=%q, want healthy", gotState)
			}
		})
	}
}

func TestRelayConfigSwitchPreloadsNewGroupBeforeFirstNext(t *testing.T) {
	for _, mode := range []string{"slow", "fast", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, _ := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50)
			for _, account := range store.Accounts() {
				account.mu.Lock()
				account.GroupIDs = []int64{7, 9}
				account.mu.Unlock()
			}
			if mode == "fast" {
				store.SetFastSchedulerEnabled(true)
			}
			if mode == "lazy" {
				store.SetLazyMode(true)
			}
			store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 9})
			selected := store.Next()
			if selected == nil {
				t.Fatal("first Next after group switch rejected every preloaded account")
			}
			store.Release(selected)
		})
	}
}

func TestFastSchedulerRejectsHintChangesDuringAndAfterAcquire(t *testing.T) {
	newScheduler := func() (*FastScheduler, *Account, *Account) {
		preferred := newFastSchedulerTestAccount(1, HealthTierHealthy, 500, 1)
		preferred.SetSchedulerPriority(100)
		normal := newFastSchedulerTestAccount(2, HealthTierHealthy, 1, 1)
		normal.SetSchedulerPriority(0)
		scheduler := NewFastScheduler(1, "round_robin")
		scheduler.Rebuild([]*Account{preferred, normal})
		return scheduler, preferred, normal
	}

	t.Run("group_check", func(t *testing.T) {
		scheduler, preferred, normal := newScheduler()
		var once sync.Once
		scheduler.SetGroupCheck(func(_ int64, account *Account) bool {
			if account == preferred {
				once.Do(func() { preferred.setRelayGuardianSchedulingHint(true, 1, 0) })
			}
			return true
		})
		if got := scheduler.Acquire(); got != normal {
			t.Fatalf("Acquire=%+v, want normal account after groupCheck changed hint", got)
		}
	})

	t.Run("post_cas", func(t *testing.T) {
		scheduler, preferred, normal := newScheduler()
		var once sync.Once
		scheduler.SetAcquireFunc(func(account *Account, limit int64) bool {
			if !tryAcquireAccount(account, limit) {
				return false
			}
			if account == preferred {
				once.Do(func() { preferred.setRelayGuardianSchedulingHint(true, 1, 0) })
			}
			return true
		})
		if got := scheduler.Acquire(); got != normal {
			t.Fatalf("Acquire=%+v, want normal account after post-CAS hint change", got)
		}
		if active := atomic.LoadInt64(&preferred.ActiveRequests); active != 0 {
			t.Fatalf("post-CAS rejection leaked ActiveRequests=%d", active)
		}
	})
}

func TestRelayRuntimeCacheIsNotReadFromSchedulerHotPath(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51)
	base := cache.NewMemory(4)
	defer base.Close()
	counting := &relayGuardianCountingCache{TokenCache: base}
	store.tokenCache = counting
	guardian.cache = counting
	store.relayCircuit = newRelayCircuitBreaker(counting)
	guardian.mu.Lock()
	guardian.loaded[51] = true
	guardian.mu.Unlock()

	if store.RelayCircuitSelectable(store.accountsByID[51]) {
		t.Fatal("unloaded circuit should fail closed")
	}
	if gets := counting.gets.Load(); gets != 0 {
		t.Fatalf("scheduler hot path performed %d cache reads", gets)
	}
	guardian.reconcile(context.Background())
	loadedGets := counting.gets.Load()
	if loadedGets == 0 {
		t.Fatal("reconcile did not preload runtime cache")
	}
	if !store.RelayCircuitSelectable(store.accountsByID[51]) {
		t.Fatal("preloaded healthy account remained fenced")
	}
	if gets := counting.gets.Load(); gets != loadedGets {
		t.Fatalf("scheduler hot path added cache reads: before=%d after=%d", loadedGets, gets)
	}
}

func TestRelayGuardianStrongGatewayPoolCorrelationOverridesVisibleTrigger(t *testing.T) {
	for _, mode := range []RelayGuardianMode{RelayGuardianMonitor, RelayGuardianEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			_, guardian := newGuardianTestStore(t, mode, clock, 50, 53, 54)
			guardian.observe(guardianObservation(50, "50-attempt-1", 524, true, clock.Now()))
			clock.Advance(2 * time.Minute)
			guardian.observe(guardianObservation(50, "50-attempt-2", 524, true, clock.Now()))
			guardian.observe(guardianObservation(53, "53-final-1", 524, false, clock.Now()))
			clock.Advance(2 * time.Minute)
			guardian.observe(guardianObservation(53, "53-final-2", 524, false, clock.Now()))

			guardian.mu.Lock()
			state53 := guardian.stateLocked(53)
			if mode == RelayGuardianMonitor {
				if state53.ShadowAction != "pool_alert" || state53.Reason != "pool_wide_failure_guard" {
					guardian.mu.Unlock()
					t.Fatalf("second final 524 did not become monitor pool alert: %+v", state53)
				}
			} else if !state53.LastResort || state53.Reason != "pool_wide_failure_guard" || state53.State == RelayGuardianQuarantined {
				guardian.mu.Unlock()
				t.Fatalf("second final 524 was not enforce pool-wide last-resort: %+v", state53)
			}
			for _, accountID := range []int64{50, 53, 54} {
				if state := guardian.states[accountID]; state != nil && state.State == RelayGuardianQuarantined {
					guardian.mu.Unlock()
					t.Fatalf("account %d was hard quarantined during shared 524 incident", accountID)
				}
			}
			guardian.mu.Unlock()

			clock.Advance(time.Minute)
			guardian.observe(guardianObservation(53, "53-final-3", 524, false, clock.Now()))
			guardian.mu.Lock()
			if guardian.stateLocked(53).State == RelayGuardianQuarantined {
				guardian.mu.Unlock()
				t.Fatal("third final 524 hard-quarantined an account after pool-wide detection")
			}
			guardian.mu.Unlock()
		})
	}
}

func TestRelayGuardianCapacityWarmupPreventsColdStartHardQuarantine(t *testing.T) {
	clock := newRelayCircuitTestClock()
	_, guardian := newGuardianTestStore(t, RelayGuardianEnforce, clock, 51, 50, 53)
	guardian.mu.Lock()
	guardian.capacitySamples = nil
	guardian.mu.Unlock()
	guardian.reconcile(context.Background()) // first post-restart sample

	guardian.observe(guardianObservation(51, "cold-1", 500, false, clock.Now()))
	guardian.observe(guardianObservation(51, "cold-2", 500, false, clock.Now()))
	guardian.mu.Lock()
	cold := guardian.stateLocked(51)
	if cold.State == RelayGuardianQuarantined || !cold.LastResort || cold.Reason != "capacity_warmup" {
		guardian.mu.Unlock()
		t.Fatalf("cold-start capacity made unsafe decision: %+v", cold)
	}
	cold.State = RelayGuardianHealthy
	cold.LastResort = false
	cold.LastResortCap = 0
	cold.Reason = ""
	cold.TriggerSource = ""
	cold.Failures = nil
	cold.SeenFinal = make(map[string]time.Time)
	cold.SeenStrong = make(map[string]time.Time)
	relayGuardianSchedulingHint(guardian.store.accountsByID[51], false, 0, 0)
	guardian.mu.Unlock()

	clock.Advance(RelayGuardianScanInterval)
	guardian.reconcile(context.Background())
	clock.Advance(RelayGuardianScanInterval)
	guardian.reconcile(context.Background())
	guardian.observe(guardianObservation(53, "warm-1", 501, false, clock.Now()))
	guardian.observe(guardianObservation(53, "warm-2", 501, false, clock.Now()))
	guardian.mu.Lock()
	warm := guardian.stateLocked(53)
	if warm.State != RelayGuardianQuarantined {
		guardian.mu.Unlock()
		t.Fatalf("mature capacity samples never enabled a safe quarantine: %+v", warm)
	}
	guardian.mu.Unlock()
}
