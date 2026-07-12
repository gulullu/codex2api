package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newGuardianSchedulingAccount(id int64, token string, priority int64) *Account {
	account := &Account{
		DBID:        id,
		AccessToken: token,
		Status:      StatusReady,
		PlanType:    "free",
	}
	account.SetSchedulerPriority(priority)
	return account
}

func newGuardianSchedulingStore(mode string) (*Store, *Account, *Account) {
	degraded := newGuardianSchedulingAccount(1, "degraded", maxSchedulerPriority)
	normal := newGuardianSchedulingAccount(2, "normal", minSchedulerPriority)
	degraded.setRelayGuardianSchedulingHint(true, 3, 0)
	store := &Store{
		accounts:       []*Account{degraded, normal},
		maxConcurrency: 8,
	}
	switch mode {
	case "fast":
		store.SetFastSchedulerEnabled(true)
	case "lazy":
		store.SetLazyMode(true)
	}
	return store, degraded, normal
}

func TestRelayGuardianLastResortOrderingAcrossStorePaths(t *testing.T) {
	for _, mode := range []string{"slow", "fast", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			store, degraded, normal := newGuardianSchedulingStore(mode)

			first := store.Next()
			if first == nil {
				t.Fatal("first Next() returned nil")
			}
			if first.DBID != normal.DBID {
				t.Fatalf("first Next() picked dbID=%d, want normal account %d", first.DBID, normal.DBID)
			}
			store.Release(first)

			// Saturating every normal account makes the degraded account an explicit
			// last resort instead of an outage.
			atomic.StoreInt64(&normal.ActiveRequests, 1_000_000)
			fallback := store.Next()
			if fallback == nil {
				t.Fatal("Next() returned nil with last-resort capacity available")
			}
			if fallback.DBID != degraded.DBID {
				t.Fatalf("fallback Next() picked dbID=%d, want degraded account %d", fallback.DBID, degraded.DBID)
			}
			store.Release(fallback)
			atomic.StoreInt64(&normal.ActiveRequests, 0)
		})
	}
}

func TestFastSchedulerLastResortIsBelowEveryNormalHealthTier(t *testing.T) {
	degradedHealthy := newFastSchedulerTestAccount(1, HealthTierHealthy, 500, 1)
	degradedHealthy.SetSchedulerPriority(maxSchedulerPriority)
	degradedHealthy.setRelayGuardianSchedulingHint(true, 1, 0)
	normalWarm := newFastSchedulerTestAccount(2, HealthTierWarm, 1, 1)
	normalWarm.SetSchedulerPriority(minSchedulerPriority)

	scheduler := NewFastScheduler(1, "round_robin")
	scheduler.Rebuild([]*Account{degradedHealthy, normalWarm})

	first := scheduler.Acquire()
	if first == nil || first.DBID != normalWarm.DBID {
		t.Fatalf("first Acquire() = %#v, want normal warm account %d", first, normalWarm.DBID)
	}
	second := scheduler.Acquire()
	if second == nil || second.DBID != degradedHealthy.DBID {
		t.Fatalf("second Acquire() = %#v, want last-resort account %d", second, degradedHealthy.DBID)
	}
	scheduler.Release(first)
	scheduler.Release(second)
}

func TestFastSchedulerSameClassPriorityPrecedesHealthTier(t *testing.T) {
	highPriorityRisky := newFastSchedulerTestAccount(1, HealthTierRisky, 1, 1)
	highPriorityRisky.SetSchedulerPriority(50)
	lowPriorityHealthy := newFastSchedulerTestAccount(2, HealthTierHealthy, 500, 1)
	lowPriorityHealthy.SetSchedulerPriority(0)

	scheduler := NewFastScheduler(1, "round_robin")
	scheduler.Rebuild([]*Account{lowPriorityHealthy, highPriorityRisky})

	got := scheduler.Acquire()
	if got == nil || got.DBID != highPriorityRisky.DBID {
		t.Fatalf("Acquire() = %#v, want higher-priority risky account %d", got, highPriorityRisky.DBID)
	}
	scheduler.Release(got)
}

func TestFastSchedulerLastResortSegmentHasIndependentRoundRobinCursor(t *testing.T) {
	first := newFastSchedulerTestAccount(1, HealthTierHealthy, 100, 4)
	second := newFastSchedulerTestAccount(2, HealthTierHealthy, 100, 4)
	first.setRelayGuardianSchedulingHint(true, 4, 0)
	second.setRelayGuardianSchedulingHint(true, 4, 0)

	scheduler := NewFastScheduler(4, "round_robin")
	scheduler.Rebuild([]*Account{first, second})

	want := []int64{first.DBID, second.DBID, first.DBID, second.DBID}
	for i, wantID := range want {
		got := scheduler.Acquire()
		if got == nil {
			t.Fatalf("Acquire() returned nil at iteration %d", i)
		}
		if got.DBID != wantID {
			t.Fatalf("round robin iteration %d picked dbID=%d, want %d", i, got.DBID, wantID)
		}
		scheduler.Release(got)
	}
}

func TestFastSchedulerRemainingQuotaPrioritySegmentsDoNotShareCursor(t *testing.T) {
	highPriorityFull := newFastSchedulerTestAccount(1, HealthTierHealthy, 100, 1)
	highPriorityFull.SetSchedulerPriority(10)
	atomic.StoreInt64(&highPriorityFull.ActiveRequests, 1)

	lowUsage := newFastSchedulerTestAccount(2, HealthTierHealthy, 100, 1)
	lowUsage.SetSchedulerPriority(0)
	lowUsage.UsagePercent7d = 10
	lowUsage.UsagePercent7dValid = true
	highUsage := newFastSchedulerTestAccount(3, HealthTierHealthy, 100, 1)
	highUsage.SetSchedulerPriority(0)
	highUsage.UsagePercent7d = 90
	highUsage.UsagePercent7dValid = true

	scheduler := NewFastScheduler(1, "remaining_quota")
	scheduler.Rebuild([]*Account{highPriorityFull, highUsage, lowUsage})

	got := scheduler.Acquire()
	if got == nil || got.DBID != lowUsage.DBID {
		t.Fatalf("Acquire() = %#v, want lowest-usage account %d in fallback priority segment", got, lowUsage.DBID)
	}
	scheduler.Release(got)
}

func TestFastSchedulerReadsLiveLastResortHintWithoutRebuild(t *testing.T) {
	preferred := newFastSchedulerTestAccount(1, HealthTierHealthy, 500, 1)
	preferred.SetSchedulerPriority(maxSchedulerPriority)
	normal := newFastSchedulerTestAccount(2, HealthTierHealthy, 1, 1)
	normal.SetSchedulerPriority(minSchedulerPriority)

	scheduler := NewFastScheduler(1, "round_robin")
	scheduler.Rebuild([]*Account{preferred, normal})

	first := scheduler.Acquire()
	if first == nil || first.DBID != preferred.DBID {
		t.Fatalf("initial Acquire() = %#v, want preferred account %d", first, preferred.DBID)
	}
	scheduler.Release(first)

	preferred.setRelayGuardianSchedulingHint(true, 1, 0)
	second := scheduler.Acquire()
	if second == nil || second.DBID != normal.DBID {
		t.Fatalf("Acquire() after live degrade = %#v, want normal account %d", second, normal.DBID)
	}
	scheduler.Release(second)

	preferred.clearRelayGuardianSchedulingHint()
	third := scheduler.Acquire()
	if third == nil || third.DBID != preferred.DBID {
		t.Fatalf("Acquire() after live recovery = %#v, want preferred account %d", third, preferred.DBID)
	}
	scheduler.Release(third)
}

func TestRelayGuardianOnlyAccountRemainsAvailableWithinHardCap(t *testing.T) {
	account := newGuardianSchedulingAccount(1, "only-relay", 0)
	account.setRelayGuardianSchedulingHint(true, 3, 0)
	store := &Store{accounts: []*Account{account}, maxConcurrency: 100}

	acquired := make([]*Account, 0, 3)
	for i := 0; i < 3; i++ {
		got := store.Next()
		if got == nil {
			t.Fatalf("Next() returned nil at hard-cap slot %d", i+1)
		}
		acquired = append(acquired, got)
	}
	if got := store.Next(); got != nil {
		store.Release(got)
		t.Fatalf("Next() exceeded hard cap: active=%d", account.GetActiveRequests())
	}
	for _, got := range acquired {
		store.Release(got)
	}
}

func TestRelayGuardianCapRejectsBeforeDispatchAccounting(t *testing.T) {
	account := newGuardianSchedulingAccount(1, "relay", 0)
	account.SetDispatchCountLimit(1)
	account.SetReset7dAt(time.Now().Add(time.Hour))
	account.setRelayGuardianSchedulingHint(true, 1, 0)
	store := &Store{accounts: []*Account{account}, maxConcurrency: 100}

	atomic.StoreInt64(&account.ActiveRequests, 1)
	if store.tryAcquireAccount(account, 100, false) {
		t.Fatal("tryAcquireAccount succeeded above Guardian cap")
	}
	if got := atomic.LoadInt64(&account.TotalRequests); got != 0 {
		t.Fatalf("TotalRequests=%d after Guardian rejection, want 0", got)
	}
	snapshot := account.GetDispatchCountSnapshot()
	if snapshot.Used != 0 || snapshot.Limited {
		t.Fatalf("dispatch count changed after Guardian rejection: %#v", snapshot)
	}

	atomic.StoreInt64(&account.ActiveRequests, 0)
	if !store.tryAcquireAccount(account, 100, false) {
		t.Fatal("tryAcquireAccount failed within Guardian cap")
	}
	if got := atomic.LoadInt64(&account.TotalRequests); got != 1 {
		t.Fatalf("TotalRequests=%d after accepted request, want 1", got)
	}
	snapshot = account.GetDispatchCountSnapshot()
	if snapshot.Used != 1 {
		t.Fatalf("dispatch count after accepted request = %#v, want used=1", snapshot)
	}
	store.Release(account)
}

func TestRelayGuardianRecoveryPercentConcurrencyBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		limit    int64
		hardCap  int64
		percent  int
		expected int
	}{
		{name: "ten_percent", limit: 100, percent: 10, expected: 10},
		{name: "fifty_percent", limit: 100, percent: 50, expected: 50},
		{name: "small_limit_rounds_up", limit: 7, percent: 10, expected: 1},
		{name: "hard_cap_and_percent_take_min", limit: 100, hardCap: 3, percent: 10, expected: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := newGuardianSchedulingAccount(1, "relay", 0)
			account.setRelayGuardianSchedulingHint(false, tt.hardCap, tt.percent)
			store := &Store{accounts: []*Account{account}, maxConcurrency: tt.limit}

			for i := 0; i < tt.expected; i++ {
				if !store.tryAcquireAccount(account, tt.limit, false) {
					t.Fatalf("acquire %d/%d was rejected", i+1, tt.expected)
				}
			}
			if store.tryAcquireAccount(account, tt.limit, false) {
				t.Fatalf("acquire beyond expected cap %d succeeded", tt.expected)
			}
			if got := account.GetActiveRequests(); got != int64(tt.expected) {
				t.Fatalf("active=%d, want %d", got, tt.expected)
			}
			if got := account.GetTotalRequests(); got != int64(tt.expected) {
				t.Fatalf("total=%d, want %d", got, tt.expected)
			}
			for i := 0; i < tt.expected; i++ {
				store.Release(account)
			}
		})
	}
}

func TestRelayGuardianRecoveryPercentAppliedOnceAcrossStorePaths(t *testing.T) {
	for _, mode := range []string{"slow", "fast", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			account := newGuardianSchedulingAccount(1, "relay", 0)
			account.setRelayGuardianSchedulingHint(false, 0, 10)
			store := &Store{accounts: []*Account{account}, maxConcurrency: 100}
			switch mode {
			case "fast":
				store.SetFastSchedulerEnabled(true)
			case "lazy":
				store.SetLazyMode(true)
			}

			acquired := make([]*Account, 0, 10)
			for i := 0; i < 10; i++ {
				got := store.Next()
				if got == nil {
					t.Fatalf("Next() rejected slot %d/10; percent cap may have been applied twice", i+1)
				}
				acquired = append(acquired, got)
			}
			if got := store.Next(); got != nil {
				store.Release(got)
				t.Fatal("Next() exceeded 10% of concurrency 100")
			}
			if got := account.GetTotalRequests(); got != 10 {
				t.Fatalf("TotalRequests=%d, want 10", got)
			}
			for _, got := range acquired {
				store.Release(got)
			}
		})
	}
}

func TestRelayGuardianFallbackHardCapBoundaries(t *testing.T) {
	for _, cap := range []int64{5, 3, 1} {
		t.Run(string(rune('0'+cap)), func(t *testing.T) {
			account := newGuardianSchedulingAccount(1, "relay", 0)
			account.setRelayGuardianSchedulingHint(true, cap, 0)
			store := &Store{accounts: []*Account{account}, maxConcurrency: 100}
			for i := int64(0); i < cap; i++ {
				if !store.tryAcquireAccount(account, 100, false) {
					t.Fatalf("acquire %d/%d was rejected", i+1, cap)
				}
			}
			if store.tryAcquireAccount(account, 100, false) {
				t.Fatalf("acquire exceeded hard cap %d", cap)
			}
			for i := int64(0); i < cap; i++ {
				store.Release(account)
			}
		})
	}
}

func TestRelayGuardianSchedulingHintSnapshotAndClear(t *testing.T) {
	account := &Account{}
	account.setRelayGuardianSchedulingHint(true, 5, 50)
	hint := account.relayGuardianSchedulingHintSnapshot()
	if !hint.lastResort || hint.hardCap != 5 || hint.percent != 50 {
		t.Fatalf("hint=%#v, want lastResort cap=5 percent=50", hint)
	}
	account.clearRelayGuardianSchedulingHint()
	if hint = account.relayGuardianSchedulingHintSnapshot(); hint != (relayGuardianSchedulingHintSnapshot{}) {
		t.Fatalf("hint after clear=%#v, want zero", hint)
	}
}

func TestRelayGuardianSchedulingHintConcurrentUpdateAndAcquire(t *testing.T) {
	account := newGuardianSchedulingAccount(1, "relay", 0)
	store := &Store{accounts: []*Account{account}, maxConcurrency: 100}
	start := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 5_000; i++ {
			switch i % 4 {
			case 0:
				account.setRelayGuardianSchedulingHint(true, 5, 0)
			case 1:
				account.setRelayGuardianSchedulingHint(true, 3, 10)
			case 2:
				account.setRelayGuardianSchedulingHint(false, 0, 50)
			default:
				account.clearRelayGuardianSchedulingHint()
			}
		}
	}()

	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 2_000; i++ {
				if store.tryAcquireAccount(account, 100, false) {
					store.Release(account)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := account.GetActiveRequests(); got != 0 {
		t.Fatalf("active=%d after concurrent acquire/release, want 0", got)
	}
}
