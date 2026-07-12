package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codex2api/cache"
)

type relayCircuitFlakyRuntimeCache struct {
	cache.TokenCache
	mu       sync.Mutex
	failures int
}

func (c *relayCircuitFlakyRuntimeCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	c.mu.Lock()
	if c.failures > 0 {
		c.failures--
		c.mu.Unlock()
		return nil, false, errors.New("temporary runtime cache failure")
	}
	c.mu.Unlock()
	return c.TokenCache.GetRuntime(ctx, namespace, key)
}

type relayCircuitTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newRelayCircuitTestClock() *relayCircuitTestClock {
	return &relayCircuitTestClock{now: time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)}
}

func (c *relayCircuitTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *relayCircuitTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newRelayCircuitTestBreaker(clock *relayCircuitTestClock) *relayCircuitBreaker {
	breaker := newRelayCircuitBreaker(nil)
	breaker.now = clock.Now
	return breaker
}

func TestRelayCircuitStrongFailureOpensImmediately(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit, ok := breaker.begin(51)
	if !ok {
		t.Fatal("initial request permit denied")
	}
	if !breaker.reportFailure(permit, 502) {
		t.Fatal("first 502 must open the circuit")
	}

	snapshot := breaker.snapshot(51)
	if snapshot.State != RelayCircuitOpen {
		t.Fatalf("state = %q, want open", snapshot.State)
	}
	if got, want := snapshot.OpenUntil.Sub(clock.Now()), 30*time.Second; got != want {
		t.Fatalf("open duration = %s, want %s", got, want)
	}
	if _, ok := breaker.begin(51); ok {
		t.Fatal("request was allowed while circuit is open")
	}
}

func TestRelayCircuitCloudflareGatewayFailuresAreStrong(t *testing.T) {
	for _, statusCode := range []int{520, 521, 522, 523, 524, 525, 526, 527, 530} {
		t.Run(strconv.Itoa(statusCode), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			breaker := newRelayCircuitTestBreaker(clock)
			permit, ok := breaker.begin(51)
			if !ok {
				t.Fatal("initial request permit denied")
			}
			if !breaker.reportFailure(permit, statusCode) {
				t.Fatalf("status %d did not immediately open circuit", statusCode)
			}
			if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen || snapshot.LastStatusCode != statusCode {
				t.Fatalf("status %d snapshot=%+v", statusCode, snapshot)
			}
		})
	}
}

func TestRelayCircuitWeakFailuresOpenAtThreeWithinWindow(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	for i := 1; i <= 3; i++ {
		permit, ok := breaker.begin(50)
		if !ok {
			t.Fatalf("request %d permit denied before threshold", i)
		}
		opened := breaker.reportFailure(permit, 503)
		if opened != (i == 3) {
			t.Fatalf("failure %d opened=%v, want %v", i, opened, i == 3)
		}
		clock.Advance(5 * time.Second)
	}
	if got := breaker.snapshot(50).State; got != RelayCircuitOpen {
		t.Fatalf("state = %q, want open", got)
	}

	clock = newRelayCircuitTestClock()
	breaker = newRelayCircuitTestBreaker(clock)
	for i := 0; i < 2; i++ {
		permit, _ := breaker.begin(50)
		breaker.reportFailure(permit, 500)
		clock.Advance(31 * time.Second)
	}
	if got := breaker.snapshot(50).State; got != RelayCircuitClosed {
		t.Fatalf("failures outside window state = %q, want closed", got)
	}
}

func TestRelayCircuitWeakFailuresUseRollingWindow(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit, _ := breaker.begin(50)
	breaker.reportFailure(permit, 503) // t=0; should age out later
	clock.Advance(20 * time.Second)
	permit, _ = breaker.begin(50)
	breaker.reportFailure(permit, 503) // t=20
	clock.Advance(11 * time.Second)
	permit, _ = breaker.begin(50)
	if breaker.reportFailure(permit, 503) { // t=31: t=0 is out, t=20 remains
		t.Fatal("rolling window opened with only two current failures")
	}
	clock.Advance(9 * time.Second)
	permit, _ = breaker.begin(50)
	if !breaker.reportFailure(permit, 503) { // t=40: t=20,31,40 are all current
		t.Fatal("rolling window did not open on three failures in the latest 30 seconds")
	}
}

func TestRelayCircuitHalfOpenAllowsOnlyOneGlobalProbe(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit, _ := breaker.begin(51)
	breaker.reportFailure(permit, 504)
	clock.Advance(relayCircuitInitialOpen)

	const workers = 256
	var allowed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if permit, ok := breaker.begin(51); ok {
				if !permit.Probe {
					t.Errorf("half-open permit is not marked as probe: %+v", permit)
				}
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 1 {
		t.Fatalf("half-open allowed %d probes, want 1", got)
	}
	if !breaker.snapshot(51).ProbeInFlight {
		t.Fatal("snapshot does not expose the in-flight recovery probe")
	}
}

func TestRelayCircuitRequiresThreeSequentialProbeSuccesses(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	initial, _ := breaker.begin(51)
	breaker.reportFailure(initial, 502)
	clock.Advance(relayCircuitInitialOpen)

	for success := 1; success <= relayCircuitRecoverySuccesses; success++ {
		probe, ok := breaker.begin(51)
		if !ok || !probe.Probe {
			t.Fatalf("probe %d denied: permit=%+v ok=%v", success, probe, ok)
		}
		closed := breaker.reportSuccess(probe)
		if closed != (success == relayCircuitRecoverySuccesses) {
			t.Fatalf("probe %d closed=%v, want %v", success, closed, success == relayCircuitRecoverySuccesses)
		}
	}
	if got := breaker.snapshot(51).State; got != RelayCircuitClosed {
		t.Fatalf("state = %q, want closed", got)
	}
}

func TestRelayCircuitAbandonReleasesHalfOpenLeaseWithoutSuccess(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	initial, _ := breaker.begin(51)
	breaker.reportFailure(initial, 502)
	clock.Advance(relayCircuitInitialOpen)

	firstProbe, ok := breaker.begin(51)
	if !ok || !firstProbe.Probe {
		t.Fatal("first half-open probe denied")
	}
	if !breaker.abandon(firstProbe) {
		t.Fatal("abandon did not release half-open lease")
	}
	if got := breaker.snapshot(51).ProbeSuccesses; got != 0 {
		t.Fatalf("abandon counted as success: %d", got)
	}
	secondProbe, ok := breaker.begin(51)
	if !ok || !secondProbe.Probe {
		t.Fatal("replacement half-open probe denied")
	}
	if secondProbe.LeaseID == firstProbe.LeaseID {
		t.Fatal("replacement probe reused stale lease id")
	}
	if breaker.reportSuccess(firstProbe) {
		t.Fatal("abandoned probe later closed the circuit")
	}
	if got := breaker.snapshot(51); !got.ProbeInFlight || got.ProbeSuccesses != 0 {
		t.Fatalf("stale abandoned result changed replacement probe: %+v", got)
	}
}

func TestRelayCircuitHalfOpenFailureUsesCappedBackoff(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	initial, _ := breaker.begin(51)
	breaker.reportFailure(initial, 502)

	wants := []time.Duration{60 * time.Second, 120 * time.Second, 300 * time.Second, 300 * time.Second}
	clock.Advance(relayCircuitInitialOpen)
	for i, want := range wants {
		probe, ok := breaker.begin(51)
		if !ok || !probe.Probe {
			t.Fatalf("recovery probe %d denied", i+1)
		}
		if !breaker.reportFailure(probe, 502) {
			t.Fatalf("recovery failure %d did not reopen", i+1)
		}
		snapshot := breaker.snapshot(51)
		if got := snapshot.OpenUntil.Sub(clock.Now()); got != want {
			t.Fatalf("recovery failure %d backoff = %s, want %s", i+1, got, want)
		}
		clock.Advance(want)
	}
}

func TestRelayCircuitIgnoresSuccessFromOlderGeneration(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	failing, _ := breaker.begin(51)
	oldSuccess, _ := breaker.begin(51)
	breaker.reportFailure(failing, 502)
	clock.Advance(relayCircuitInitialOpen)
	probe, ok := breaker.begin(51)
	if !ok {
		t.Fatal("half-open probe denied")
	}

	if breaker.reportSuccess(oldSuccess) {
		t.Fatal("old in-flight success closed a newer circuit")
	}
	snapshot := breaker.snapshot(51)
	if snapshot.State != RelayCircuitHalfOpen || !snapshot.ProbeInFlight || snapshot.ProbeSuccesses != 0 {
		t.Fatalf("old success changed half-open state: %+v", snapshot)
	}
	breaker.reportSuccess(probe)
	if got := breaker.snapshot(51).ProbeSuccesses; got != 1 {
		t.Fatalf("valid probe successes = %d, want 1", got)
	}
}

func relayCircuitSchedulerAccount(id int64, priority int64) *Account {
	return &Account{
		DBID:                     id,
		UpstreamType:             UpstreamOpenAIResponses,
		BaseURL:                  "https://relay.example/v1",
		APIKey:                   "test-key",
		Status:                   StatusReady,
		HealthTier:               HealthTierHealthy,
		SchedulerScore:           100,
		DispatchScore:            100,
		BaseConcurrencyEffective: 100,
		DynamicConcurrencyLimit:  100,
		SchedulerPriority:        priority,
		SkipWarmTier:             true,
		GroupIDs:                 []int64{7},
	}
}

func newRelayCircuitSchedulerStore(fast bool, clock *relayCircuitTestClock) (*Store, *Account, *Account) {
	primary := relayCircuitSchedulerAccount(51, 100)
	fallback := relayCircuitSchedulerAccount(50, -100)
	breaker := newRelayCircuitTestBreaker(clock)
	store := &Store{
		accounts:     []*Account{primary, fallback},
		accountsByID: map[int64]*Account{primary.DBID: primary, fallback.DBID: fallback},
		relayCircuit: breaker,
	}
	atomic.StoreInt64(&store.maxConcurrency, 100)
	store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 7})
	if fast {
		store.fastSchedulerEnabled.Store(true)
		store.rebuildFastScheduler()
	}
	return store, primary, fallback
}

func TestRelayCircuitFenceOutranksPriorityScoreAndSkipWarm(t *testing.T) {
	for _, fast := range []bool{false, true} {
		name := "slow_scheduler"
		if fast {
			name = "fast_scheduler"
		}
		t.Run(name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(fast, clock)
			permit, ok := store.BeginRelayCircuitRequest(primary)
			if !ok || !store.ReportRelayCircuitFailure(permit, 502) {
				t.Fatal("failed to open primary circuit")
			}
			if store.RelayCircuitSelectable(primary) {
				t.Fatal("open primary remained scheduler-selectable")
			}
			got := store.NextExcludingWithFilter(0, nil, nil)
			if got == nil {
				t.Fatal("scheduler returned nil instead of fallback")
			}
			defer store.Release(got)
			if got.DBID != fallback.DBID {
				t.Fatalf("scheduler selected account %d, want fallback %d", got.DBID, fallback.DBID)
			}
			if primary.SkipWarmTier != true || primary.SchedulerPriority <= fallback.SchedulerPriority {
				t.Fatal("test setup did not exercise skip-warm and strict priority")
			}
		})
	}
}

func TestRelayCircuitDoesNotOverwriteAccountCooldownSlot(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
	primary.SetCooldownWithReason(time.Hour, "rate_limited")
	reasonBefore, untilBefore := primary.GetCooldownSnapshot()
	permit, ok := store.BeginRelayCircuitRequest(primary)
	if !ok {
		t.Fatal("breaker permit denied")
	}
	store.ReportRelayCircuitFailure(permit, 502)
	reasonAfter, untilAfter := primary.GetCooldownSnapshot()
	if reasonAfter != reasonBefore || !untilAfter.Equal(untilBefore) {
		t.Fatalf("account cooldown changed from (%q,%s) to (%q,%s)", reasonBefore, untilBefore, reasonAfter, untilAfter)
	}
}

func TestRelayCircuitPermitIsConsumedExactlyOnce(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit, ok := breaker.begin(51)
	if !ok {
		t.Fatal("breaker permit denied")
	}
	if breaker.reportFailure(permit, 503) {
		t.Fatal("first weak failure unexpectedly opened circuit")
	}
	if breaker.reportFailure(permit, 503) {
		t.Fatal("duplicate permit unexpectedly opened circuit")
	}
	if got := breaker.snapshot(51).WeakFailures; got != 1 {
		t.Fatalf("duplicate permit counted %d weak failures, want 1", got)
	}
	for i := 0; i < 2; i++ {
		unique, uniqueOK := breaker.begin(51)
		if !uniqueOK {
			t.Fatalf("unique permit %d denied", i+1)
		}
		opened := breaker.reportFailure(unique, 503)
		if opened != (i == 1) {
			t.Fatalf("unique weak failure %d opened=%v", i+1, opened)
		}
	}
}

func TestRelayCircuitRestoresOpenFenceFromRuntimeCache(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()

	first := newRelayCircuitBreaker(tokenCache)
	first.now = clock.Now
	permit, _ := first.begin(51)
	first.reportFailure(permit, 502)

	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	if _, ok := restarted.begin(51); ok {
		t.Fatal("restart lost the cached open fence")
	}
	clock.Advance(relayCircuitInitialOpen)
	probe, ok := restarted.begin(51)
	if !ok || !probe.Probe {
		t.Fatalf("expired restored fence did not enter half-open: permit=%+v ok=%v", probe, ok)
	}
}

func TestRelayCircuitRestoreRetriesAndFailsClosedAfterCacheError(t *testing.T) {
	base := cache.NewMemory(1)
	defer base.Close()
	clock := newRelayCircuitTestClock()

	first := newRelayCircuitBreaker(base)
	first.now = clock.Now
	permit, _ := first.begin(51)
	first.reportFailure(permit, 502)

	flaky := &relayCircuitFlakyRuntimeCache{TokenCache: base, failures: 1}
	restarted := newRelayCircuitBreaker(flaky)
	restarted.now = clock.Now
	if restarted.selectable(51) {
		t.Fatal("account was selectable while runtime fence restore was unresolved")
	}
	if _, ok := restarted.begin(51); ok {
		t.Fatal("request permit was issued while runtime fence restore was unresolved")
	}
	clock.Advance(time.Second)
	if restarted.selectable(51) {
		t.Fatal("restored open circuit became selectable before its deadline")
	}
	if got := restarted.snapshot(51).State; got != RelayCircuitOpen {
		t.Fatalf("restored state = %q, want open", got)
	}
}
