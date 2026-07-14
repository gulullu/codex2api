package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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

type relayCircuitDeleteFailRuntimeCache struct {
	cache.TokenCache
	mu             sync.Mutex
	deleteFailures int
}

type relayCircuitBlockingGetRuntimeCache struct {
	cache.TokenCache
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *relayCircuitBlockingGetRuntimeCache) GetRuntime(ctx context.Context, namespace, key string) (json.RawMessage, bool, error) {
	payload, ok, err := c.TokenCache.GetRuntime(ctx, namespace, key)
	c.once.Do(func() { close(c.started) })
	select {
	case <-c.release:
		return payload, ok, err
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

type relayCircuitBlockingDeleteFailRuntimeCache struct {
	cache.TokenCache
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type relayCircuitTargetBlockingDeleteRuntimeCache struct {
	cache.TokenCache
	targetKey string
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (c *relayCircuitBlockingDeleteFailRuntimeCache) DeleteRuntime(ctx context.Context, _, _ string) error {
	c.once.Do(func() { close(c.started) })
	select {
	case <-c.release:
		return errors.New("blocked runtime cache delete failure")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *relayCircuitTargetBlockingDeleteRuntimeCache) DeleteRuntime(ctx context.Context, namespace, key string) error {
	if namespace != relayCircuitRuntimeCacheNamespace || key != c.targetKey {
		return c.TokenCache.DeleteRuntime(ctx, namespace, key)
	}
	c.once.Do(func() { close(c.started) })
	select {
	case <-c.release:
		return c.TokenCache.DeleteRuntime(ctx, namespace, key)
	case <-ctx.Done():
		return ctx.Err()
	}
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

func (c *relayCircuitDeleteFailRuntimeCache) DeleteRuntime(ctx context.Context, namespace, key string) error {
	c.mu.Lock()
	if c.deleteFailures > 0 {
		c.deleteFailures--
		c.mu.Unlock()
		return errors.New("temporary runtime cache delete failure")
	}
	c.mu.Unlock()
	return c.TokenCache.DeleteRuntime(ctx, namespace, key)
}

func TestRelayCircuitStaleRuntimeLoadCannotReviveAfterReset(t *testing.T) {
	for _, sameIdentity := range []bool{false, true} {
		name := "identity_changed"
		if sameIdentity {
			name = "same_identity_rejoined"
		}
		t.Run(name, func(t *testing.T) {
			base := cache.NewMemory(1)
			defer base.Close()
			clock := newRelayCircuitTestClock()
			oldIdentity := "old-fingerprint"
			newIdentity := "new-fingerprint"
			if sameIdentity {
				newIdentity = oldIdentity
			}
			record := relayCircuitRuntimeRecord{
				State: RelayCircuitHalfOpen, Generation: 7, LastStatusCode: 502,
				OpenUntil: clock.Now().Add(time.Minute), UpdatedAt: clock.Now(),
				LastResort: true, AdmissionLimit: relayCircuitLastResortAdmissionLimit,
				IdentityFingerprint: oldIdentity,
			}
			payload, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := base.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(51), payload, time.Hour); err != nil {
				t.Fatal(err)
			}
			blocking := &relayCircuitBlockingGetRuntimeCache{
				TokenCache: base,
				started:    make(chan struct{}),
				release:    make(chan struct{}),
			}
			breaker := newRelayCircuitBreaker(blocking)
			breaker.now = clock.Now
			done := make(chan struct{})
			go func() {
				breaker.ensureLoadedWithIdentity(51, oldIdentity)
				close(done)
			}()
			<-blocking.started
			breaker.forgetAccountRuntime(51, newIdentity)
			close(blocking.release)
			<-done

			breaker.mu.Lock()
			state := breaker.stateLocked(51)
			gotState, gotIdentity, gotLastResort := state.state, state.identityFingerprint, state.lastResort
			breaker.mu.Unlock()
			if gotState != RelayCircuitClosed || gotIdentity != newIdentity || gotLastResort {
				t.Fatalf("stale restore survived reset: state=%q identity=%q last_resort=%t", gotState, gotIdentity, gotLastResort)
			}
			if !breaker.selectable(51) {
				t.Fatal("freshly reset account remained blocked by stale restore")
			}
		})
	}
}

func TestRelayCircuitDeleteFailureUsesImmutableClosedTombstone(t *testing.T) {
	base := cache.NewMemory(1)
	defer base.Close()
	blocking := &relayCircuitBlockingDeleteFailRuntimeCache{
		TokenCache: base,
		started:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	breaker := newRelayCircuitBreaker(blocking)
	breaker.ensureLoadedWithIdentity(51, "old-fingerprint")
	done := make(chan struct{})
	go func() {
		breaker.forgetAccountRuntime(51, "new-fingerprint")
		close(done)
	}()
	<-blocking.started

	// Model a newly admitted request mutating the fresh generation while the
	// old cache record is still being deleted. The fallback record must remain
	// the closed reset snapshot, not this live state.
	breaker.mu.Lock()
	state := breaker.stateLocked(51)
	state.state = RelayCircuitSuspect
	state.reason = "new-generation-live-evidence"
	state.lastStatusCode = 502
	state.lastResort = true
	breaker.mu.Unlock()
	close(blocking.release)
	<-done

	record := relayCircuitReadRuntimeRecord(t, base, 51)
	if record.State != RelayCircuitClosed || record.IdentityFingerprint != "new-fingerprint" || record.LastResort {
		t.Fatalf("delete fallback persisted mutable live state instead of reset tombstone: %+v", record)
	}
}

func relayCircuitReadRuntimeRecord(t *testing.T, tokenCache cache.TokenCache, accountID int64) relayCircuitRuntimeRecord {
	t.Helper()
	payload, ok, err := tokenCache.GetRuntime(
		context.Background(),
		relayCircuitRuntimeCacheNamespace,
		relayCircuitRuntimeKey(accountID),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("runtime record for account %d is missing", accountID)
	}
	var record relayCircuitRuntimeRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	return record
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

func TestRelayCircuitPermitRemainsComparable(t *testing.T) {
	permits := map[RelayCircuitPermit]struct{}{{AccountID: 51, Generation: 1, LeaseID: 1}: {}}
	if len(permits) != 1 {
		t.Fatal("RelayCircuitPermit unexpectedly lost value semantics")
	}
}

func relayCircuitBeginEvidence(t *testing.T, breaker *relayCircuitBreaker, accountID int64, logicalID string) RelayCircuitPermit {
	t.Helper()
	permit, ok := breaker.beginWithEvidence(accountID, logicalID, 100)
	if !ok {
		t.Fatalf("permit denied for %s", logicalID)
	}
	return permit
}

func relayCircuitConfirmStrongOpen(t *testing.T, breaker *relayCircuitBreaker, accountID int64) {
	t.Helper()
	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, accountID, "strong-"+strconv.Itoa(i))
		opened := breaker.reportFailure(permit, 502)
		if opened != (i == relayCircuitStrongFailureLimit) {
			t.Fatalf("strong failure %d opened=%v", i, opened)
		}
	}
}

func relayCircuitRecoverStrongOpen(t *testing.T, breaker *relayCircuitBreaker, clock *relayCircuitTestClock, accountID int64) {
	t.Helper()
	open := breaker.snapshot(accountID)
	if !open.OpenUntil.After(clock.Now()) {
		t.Fatalf("open deadline missing before recovery: %+v", open)
	}
	clock.Advance(open.OpenUntil.Sub(clock.Now()))
	for success := 1; success <= relayCircuitRecoverySuccesses; success++ {
		probe, ok := breaker.beginWithEvidence(accountID, "cycle-recovery-"+strconv.Itoa(success), 100)
		if !ok || !probe.Probe {
			t.Fatalf("recovery probe %d denied: permit=%+v ok=%v", success, probe, ok)
		}
		closed := breaker.reportSuccess(probe)
		if closed != (success == relayCircuitRecoverySuccesses) {
			t.Fatalf("recovery probe %d closed=%v", success, closed)
		}
	}
}

func TestRelayCircuitConfirmedStrongCycleTokenTracksOnlyConfirmedStrongCycles(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	if token := breaker.snapshot(51).confirmedStrongCycleToken; token != 0 {
		t.Fatalf("new breaker cycle token=%d, want 0", token)
	}
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	if token := breaker.snapshot(51).confirmedStrongCycleToken; token != 1 {
		t.Fatalf("first confirmed strong cycle token=%d, want 1", token)
	}

	// A single strong recovery probe can reopen the transport fence, but it is
	// not a second independently confirmed strong quorum.
	clock.Advance(breaker.snapshot(51).OpenUntil.Sub(clock.Now()))
	probe, ok := breaker.beginWithEvidence(51, "single-strong-recovery-failure", 100)
	if !ok || !probe.Probe {
		t.Fatalf("strong recovery probe denied: permit=%+v ok=%v", probe, ok)
	}
	if !breaker.reportFailure(probe, http.StatusBadGateway) {
		t.Fatal("single strong recovery failure did not reopen circuit")
	}
	if token := breaker.snapshot(51).confirmedStrongCycleToken; token != 1 {
		t.Fatalf("single strong recovery failure advanced confirmed cycle token to %d", token)
	}

	relayCircuitRecoverStrongOpen(t, breaker, clock, 51)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	if token := breaker.snapshot(51).confirmedStrongCycleToken; token != 2 {
		t.Fatalf("second confirmed strong cycle token=%d, want 2", token)
	}
}

func TestRelayCircuitConfirmedStrongCycleTokenSurvivesBreakerOnlyIdentityReset(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)

	breaker.forgetAccountRuntime(51, "replacement-identity")
	afterReset := breaker.snapshot(51)
	if afterReset.State != RelayCircuitClosed || afterReset.confirmedStrongCycleToken != 1 {
		t.Fatalf("breaker-only identity reset reused cycle namespace: %+v token=%d", afterReset, afterReset.confirmedStrongCycleToken)
	}
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	if token := breaker.snapshot(51).confirmedStrongCycleToken; token != 2 {
		t.Fatalf("post-reset confirmed cycle token=%d, want 2", token)
	}
}

func TestRelayCircuitSingleStrongFailureEntersSuspectAndNewSuccessClears(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit := relayCircuitBeginEvidence(t, breaker, 51, "first")
	if breaker.reportFailure(permit, 502) {
		t.Fatal("first 502 opened the circuit")
	}

	snapshot := breaker.snapshot(51)
	if snapshot.State != RelayCircuitSuspect || snapshot.StrongFailures != 1 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("snapshot after first 502 = %+v", snapshot)
	}
	if snapshot.AdmissionLimit != 8 {
		t.Fatalf("suspect admission limit=%d want 8", snapshot.AdmissionLimit)
	}
	success := relayCircuitBeginEvidence(t, breaker, 51, "success")
	if !breaker.reportSuccess(success) {
		t.Fatal("newly admitted success did not clear suspect")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
		t.Fatalf("snapshot after success = %+v", snapshot)
	}
}

func TestRelayCircuitLateSuspectFailuresStartFreshEvidenceCycle(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	first := relayCircuitBeginEvidence(t, breaker, 51, "initial-failure")
	if breaker.reportFailure(first, 502) {
		t.Fatal("first failure opened circuit")
	}
	fastSuccess := relayCircuitBeginEvidence(t, breaker, 51, "fast-success")
	lateFailureA := relayCircuitBeginEvidence(t, breaker, 51, "late-failure-a")
	lateFailureB := relayCircuitBeginEvidence(t, breaker, 51, "late-failure-b")
	if !breaker.reportSuccess(fastSuccess) {
		t.Fatal("new suspect-cohort success did not close suspect")
	}
	if breaker.reportFailure(lateFailureA, 502) || breaker.reportFailure(lateFailureB, 502) {
		t.Fatal("late old-cohort failures opened circuit without new-cohort quorum")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitSuspect ||
		snapshot.StrongFailures != 2 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("late failures were lost or misclassified: %+v", snapshot)
	}

	currentA := relayCircuitBeginEvidence(t, breaker, 51, "current-failure-a")
	currentB := relayCircuitBeginEvidence(t, breaker, 51, "current-failure-b")
	if breaker.reportFailure(currentA, 502) {
		t.Fatal("one current-cohort failure opened circuit")
	}
	if !breaker.reportFailure(currentB, 502) {
		t.Fatal("two current-cohort failures plus retained late evidence did not open circuit")
	}
}

func TestRelayCircuitLateSuspectWeakFailuresPreserveRollingThreshold(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	first := relayCircuitBeginEvidence(t, breaker, 51, "initial-strong")
	if breaker.reportFailure(first, 502) {
		t.Fatal("first strong failure opened circuit")
	}
	fastSuccess := relayCircuitBeginEvidence(t, breaker, 51, "fast-success")
	lateFailures := make([]RelayCircuitPermit, 0, relayCircuitWeakFailureLimit)
	for i := 0; i < relayCircuitWeakFailureLimit; i++ {
		lateFailures = append(lateFailures, relayCircuitBeginEvidence(t, breaker, 51, "late-weak-"+strconv.Itoa(i)))
	}
	if !breaker.reportSuccess(fastSuccess) {
		t.Fatal("suspect-cohort success did not close suspect")
	}
	for i, permit := range lateFailures {
		opened := breaker.reportFailure(permit, 503)
		if opened != (i == relayCircuitWeakFailureLimit-1) {
			t.Fatalf("late weak failure %d opened=%v", i+1, opened)
		}
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen {
		t.Fatalf("late weak majority did not open circuit: %+v", snapshot)
	}
}

func TestRelayCircuitLateSuspectSuccessesPreserveWeakRateDenominator(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	for i := 0; i < 4; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, 51, "prior-success-"+strconv.Itoa(i))
		breaker.reportSuccess(permit)
	}
	first := relayCircuitBeginEvidence(t, breaker, 51, "initial-strong")
	breaker.reportFailure(first, 502)
	fastSuccess := relayCircuitBeginEvidence(t, breaker, 51, "fast-success")
	lateSuccess := relayCircuitBeginEvidence(t, breaker, 51, "late-success")
	lateFailures := make([]RelayCircuitPermit, 0, relayCircuitWeakFailureLimit)
	for i := 0; i < relayCircuitWeakFailureLimit; i++ {
		lateFailures = append(lateFailures, relayCircuitBeginEvidence(t, breaker, 51, "late-weak-"+strconv.Itoa(i)))
	}
	if !breaker.reportSuccess(fastSuccess) {
		t.Fatal("suspect-cohort success did not close suspect")
	}
	if breaker.reportSuccess(lateSuccess) {
		t.Fatal("late prior-generation success changed circuit state")
	}
	for i, permit := range lateFailures {
		if breaker.reportFailure(permit, 503) {
			t.Fatalf("late weak failure %d opened below 50%% actual failure rate", i+1)
		}
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed ||
		snapshot.WeakFailures != relayCircuitWeakFailureLimit || snapshot.WeakSamples != 11 {
		t.Fatalf("late success denominator was lost: %+v", snapshot)
	}
}

func TestRelayCircuitLateWeakEvidenceRejectsDuplicateUnlimitedAndOlderGeneration(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	unlimited := relayCircuitBeginEvidence(t, breaker, 51, "unlimited")
	first := relayCircuitBeginEvidence(t, breaker, 51, "initial-strong")
	breaker.reportFailure(first, 502)
	fastSuccess := relayCircuitBeginEvidence(t, breaker, 51, "fast-success")
	duplicateA := relayCircuitBeginEvidence(t, breaker, 51, "same-late-request")
	duplicateB := relayCircuitBeginEvidence(t, breaker, 51, "same-late-request")
	olderGeneration := relayCircuitBeginEvidence(t, breaker, 51, "two-generations-old")
	breaker.reportSuccess(fastSuccess)

	if breaker.reportFailure(unlimited, 503) {
		t.Fatal("unlimited closed-cohort failure changed circuit state")
	}
	if breaker.reportFailure(duplicateA, 503) || breaker.reportFailure(duplicateA, 503) || breaker.reportFailure(duplicateB, 503) {
		t.Fatal("deduplicated late weak failure changed circuit state")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed || snapshot.WeakFailures != 1 || snapshot.WeakSamples != 2 {
		t.Fatalf("late weak guards or deduplication failed: %+v", snapshot)
	}

	secondStrong := relayCircuitBeginEvidence(t, breaker, 51, "second-strong")
	breaker.reportFailure(secondStrong, 502)
	secondSuccess := relayCircuitBeginEvidence(t, breaker, 51, "second-success")
	breaker.reportSuccess(secondSuccess)
	before := breaker.snapshot(51)
	if breaker.reportFailure(olderGeneration, 503) {
		t.Fatal("two-generation-old weak failure changed circuit state")
	}
	after := breaker.snapshot(51)
	if after.WeakFailures != before.WeakFailures || after.WeakSamples != before.WeakSamples || after.State != RelayCircuitClosed {
		t.Fatalf("two-generation-old weak evidence leaked into current window: before=%+v after=%+v", before, after)
	}
}

func TestRelayCircuitLateWeakDoesNotContributeStrongSuspectQuorum(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	first := relayCircuitBeginEvidence(t, breaker, 51, "initial-strong")
	breaker.reportFailure(first, 502)
	fastSuccess := relayCircuitBeginEvidence(t, breaker, 51, "fast-success")
	lateWeak := relayCircuitBeginEvidence(t, breaker, 51, "late-weak")
	breaker.reportSuccess(fastSuccess)
	currentStrong := relayCircuitBeginEvidence(t, breaker, 51, "current-strong")
	breaker.reportFailure(currentStrong, 502)
	if breaker.reportFailure(lateWeak, 503) {
		t.Fatal("single late weak failure opened current suspect cycle")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitSuspect || snapshot.StrongFailures != 1 ||
		snapshot.PostSuspectFailures != 0 || snapshot.WeakFailures != 1 {
		t.Fatalf("late weak failure contaminated strong quorum: %+v", snapshot)
	}
}

func TestRelayCircuitStrongEvidenceDeduplicatesLogicalRequest(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	first := relayCircuitBeginEvidence(t, breaker, 51, "same-request")
	if breaker.reportFailure(first, 502) {
		t.Fatal("first logical failure opened circuit")
	}
	duplicate := relayCircuitBeginEvidence(t, breaker, 51, "same-request")
	if breaker.reportFailure(duplicate, 502) {
		t.Fatal("duplicate logical failure opened circuit")
	}
	if snapshot := breaker.snapshot(51); snapshot.StrongFailures != 1 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("duplicate logical request was counted twice: %+v", snapshot)
	}

	second := relayCircuitBeginEvidence(t, breaker, 51, "second-request")
	if breaker.reportFailure(second, 502) {
		t.Fatal("second distinct logical failure opened circuit too early")
	}
	third := relayCircuitBeginEvidence(t, breaker, 51, "third-request")
	if !breaker.reportFailure(third, 502) {
		t.Fatal("third distinct logical failure did not confirm open")
	}
}

func TestRelayCircuitClosedCohortDoesNotBlockSuspectAdmissionOrCountPostSuspect(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	closedCohort := make([]RelayCircuitPermit, 0, 20)
	for i := 0; i < 20; i++ {
		closedCohort = append(closedCohort, relayCircuitBeginEvidence(t, breaker, 51, "closed-cohort-"+strconv.Itoa(i)))
	}
	if breaker.reportFailure(closedCohort[0], 502) {
		t.Fatal("single closed-cohort failure opened circuit")
	}

	suspectPermits := make([]RelayCircuitPermit, 0, relayCircuitSuspectAdmissionMax)
	for i := 0; i < relayCircuitSuspectAdmissionMax; i++ {
		permit, ok := breaker.beginWithEvidence(51, "suspect-current-"+strconv.Itoa(i), 100)
		if !ok {
			t.Fatalf("suspect permit %d denied by old closed cohort", i)
		}
		suspectPermits = append(suspectPermits, permit)
	}
	if _, ok := breaker.beginWithEvidence(51, "suspect-over-cap", 100); ok {
		t.Fatal("suspect admitted above current-epoch cap")
	}
	breaker.reportFailure(closedCohort[1], 502)
	breaker.reportFailure(closedCohort[2], 502)
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitSuspect || snapshot.StrongFailures != 3 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("old cohort was counted as post-suspect evidence: %+v", snapshot)
	}
	if breaker.reportFailure(suspectPermits[0], 502) {
		t.Fatal("first post-suspect failure opened circuit")
	}
	if !breaker.reportFailure(suspectPermits[1], 502) {
		t.Fatal("second post-suspect failure did not confirm circuit")
	}
	for _, permit := range closedCohort[3:] {
		breaker.abandon(permit)
	}
	for _, permit := range suspectPermits[2:] {
		breaker.abandon(permit)
	}
}

func TestRelayCircuitOldCohortFailureDoesNotExtendSuspectWindow(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	first := relayCircuitBeginEvidence(t, breaker, 51, "first")
	oldPending := relayCircuitBeginEvidence(t, breaker, 51, "old-pending")
	breaker.reportFailure(first, 502)
	clock.Advance(4 * time.Second)
	breaker.reportFailure(oldPending, 502)
	clock.Advance(2 * time.Second)
	permit, ok := breaker.beginWithEvidence(51, "after-fixed-window", 100)
	if !ok {
		t.Fatal("suspect remained blocked after its fixed evidence window")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed {
		t.Fatalf("old cohort failure extended suspect window: %+v", snapshot)
	}
	breaker.abandon(permit)
}

func TestRelayCircuitUsesCanonicalIssuedPermitEvidence(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit := relayCircuitBeginEvidence(t, breaker, 51, "canonical-logical-request")
	permit.LogicalRequestID = "forged-logical-request"
	permit.EvidenceEpoch = 999
	permit.AdmissionLimit = 2
	breaker.reportFailure(permit, 502)
	if snapshot := breaker.snapshot(51); snapshot.AdmissionLimit != relayCircuitSuspectAdmissionMax || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("caller-mutated permit evidence was trusted: %+v", snapshot)
	}
}

func TestRelayCircuitCloudflareGatewayFailuresAreStrong(t *testing.T) {
	for _, statusCode := range []int{520, 521, 522, 523, 524, 525, 526, 527, 530} {
		t.Run(strconv.Itoa(statusCode), func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			breaker := newRelayCircuitTestBreaker(clock)
			permit := relayCircuitBeginEvidence(t, breaker, 51, "gateway")
			if breaker.reportFailure(permit, statusCode) {
				t.Fatalf("status %d immediately opened circuit", statusCode)
			}
			if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitSuspect || snapshot.LastStatusCode != statusCode {
				t.Fatalf("status %d snapshot=%+v", statusCode, snapshot)
			}
		})
	}
}

func TestRelayCircuitTransportFailuresUseDistinctLogicalQuorum(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)

	first := relayCircuitBeginEvidence(t, breaker, 51, "transport-1")
	if breaker.reportFailure(first, RelayCircuitTransportFailureStatus) {
		t.Fatal("first transport failure opened circuit")
	}
	duplicate := relayCircuitBeginEvidence(t, breaker, 51, "transport-1")
	if breaker.reportFailure(duplicate, RelayCircuitTransportFailureStatus) {
		t.Fatal("duplicate logical transport failure opened circuit")
	}
	if snapshot := breaker.snapshot(51); snapshot.StrongFailures != 1 || snapshot.PostSuspectFailures != 0 {
		t.Fatalf("duplicate logical transport failure was counted: %+v", snapshot)
	}

	second := relayCircuitBeginEvidence(t, breaker, 51, "transport-2")
	if breaker.reportFailure(second, RelayCircuitTransportFailureStatus) {
		t.Fatal("second distinct transport failure opened circuit")
	}
	third := relayCircuitBeginEvidence(t, breaker, 51, "transport-3")
	if !breaker.reportFailure(third, RelayCircuitTransportFailureStatus) {
		t.Fatal("third distinct transport failure did not open circuit")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen ||
		snapshot.LastStatusCode != RelayCircuitTransportFailureStatus || snapshot.Reason != "upstream_transport_failure" {
		t.Fatalf("transport quorum snapshot=%+v", snapshot)
	}
}

func TestRelayCircuitTransportAndGatewayFailuresShareStrongQuorum(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	statuses := []int{RelayCircuitTransportFailureStatus, 502, 504}
	for index, statusCode := range statuses {
		permit := relayCircuitBeginEvidence(t, breaker, 51, "mixed-strong-"+strconv.Itoa(index))
		opened := breaker.reportFailure(permit, statusCode)
		if opened != (index == len(statuses)-1) {
			t.Fatalf("mixed strong evidence %d status=%d opened=%t", index+1, statusCode, opened)
		}
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen || snapshot.LastStatusCode != 504 {
		t.Fatalf("mixed transport/gateway evidence did not share quorum: %+v", snapshot)
	}
}

func TestRelayCircuitWeakFailuresRequireFiveAndFailureRate(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	for i := 1; i <= relayCircuitWeakFailureLimit; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, 50, "weak-"+strconv.Itoa(i))
		opened := breaker.reportFailure(permit, 503)
		if opened != (i == relayCircuitWeakFailureLimit) {
			t.Fatalf("failure %d opened=%v", i, opened)
		}
	}
	if got := breaker.snapshot(50).State; got != RelayCircuitOpen {
		t.Fatalf("state = %q, want open", got)
	}

	clock = newRelayCircuitTestClock()
	breaker = newRelayCircuitTestBreaker(clock)
	for i := 0; i < 6; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, 50, "ok-"+strconv.Itoa(i))
		breaker.reportSuccess(permit)
	}
	for i := 0; i < 5; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, 50, "bad-"+strconv.Itoa(i))
		if breaker.reportFailure(permit, 500) {
			t.Fatal("weak failures below 50% opened circuit")
		}
	}
	if snapshot := breaker.snapshot(50); snapshot.State != RelayCircuitClosed || snapshot.WeakFailures != 5 || snapshot.WeakSamples != 11 {
		t.Fatalf("rate-aware weak snapshot=%+v", snapshot)
	}
}

func TestRelayCircuitWeakFailuresUseRollingWindow(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	permit := relayCircuitBeginEvidence(t, breaker, 50, "old")
	breaker.reportFailure(permit, 503)
	clock.Advance(20 * time.Second)
	for i := 0; i < 2; i++ {
		permit = relayCircuitBeginEvidence(t, breaker, 50, "mid-"+strconv.Itoa(i))
		breaker.reportFailure(permit, 503)
	}
	clock.Advance(11 * time.Second)
	for i := 0; i < 2; i++ {
		permit = relayCircuitBeginEvidence(t, breaker, 50, "new-"+strconv.Itoa(i))
		if breaker.reportFailure(permit, 503) {
			t.Fatal("rolling window opened before five current failures")
		}
	}
	permit = relayCircuitBeginEvidence(t, breaker, 50, "new-2")
	if !breaker.reportFailure(permit, 503) {
		t.Fatal("rolling window did not open on five current failures")
	}
}

func TestRelayCircuitProbationAllowsAtMostThreeConcurrentRequests(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)

	const workers = 256
	var allowed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(worker int) {
			defer wg.Done()
			if permit, ok := breaker.beginWithEvidence(51, "probation-"+strconv.Itoa(worker), 100); ok {
				if !permit.Probe {
					t.Errorf("probation permit is not marked as probe: %+v", permit)
				}
				allowed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := allowed.Load(); got != relayCircuitProbationMaxInFlight {
		t.Fatalf("probation allowed %d requests, want %d", got, relayCircuitProbationMaxInFlight)
	}
	if snapshot := breaker.snapshot(51); !snapshot.ProbeInFlight || snapshot.InFlight != relayCircuitProbationMaxInFlight || snapshot.State != RelayCircuitProbation {
		t.Fatalf("probation snapshot=%+v", snapshot)
	}
}

func TestRelayCircuitRequiresTwoProbationSuccesses(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
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

func TestRelayCircuitConcurrentProbationFailureWinsRegardlessOfCompletionOrder(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)

	probes := make([]RelayCircuitPermit, 0, relayCircuitProbationMaxInFlight)
	for i := 0; i < relayCircuitProbationMaxInFlight; i++ {
		probe, ok := breaker.beginWithEvidence(51, "probation-cohort-"+strconv.Itoa(i), 100)
		if !ok || !probe.Probe {
			t.Fatalf("probation permit %d denied: %+v", i, probe)
		}
		probes = append(probes, probe)
	}
	if breaker.reportSuccess(probes[0]) {
		t.Fatal("first probation success closed circuit")
	}
	if !breaker.reportSuccess(probes[1]) {
		t.Fatal("second probation success did not close promptly")
	}
	if !breaker.reportFailure(probes[2], 502) {
		t.Fatal("late concurrently issued probation failure was hidden by two earlier successes")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen || snapshot.BackoffLevel != 1 {
		t.Fatalf("probation failure snapshot=%+v", snapshot)
	}
}

func TestRelayCircuitLateProbationWeakFailureReopens(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)

	probes := make([]RelayCircuitPermit, 0, relayCircuitProbationMaxInFlight)
	for i := 0; i < relayCircuitProbationMaxInFlight; i++ {
		probe, ok := breaker.beginWithEvidence(51, "weak-probation-cohort-"+strconv.Itoa(i), 100)
		if !ok || !probe.Probe {
			t.Fatalf("probation permit %d denied: %+v", i, probe)
		}
		probes = append(probes, probe)
	}
	if breaker.reportSuccess(probes[0]) {
		t.Fatal("first probation success closed circuit")
	}
	if !breaker.reportSuccess(probes[1]) {
		t.Fatal("second probation success did not close promptly")
	}
	if !breaker.reportFailure(probes[2], 503) {
		t.Fatal("late probation 503 was treated as an ordinary weak observation")
	}
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitOpen || snapshot.BackoffLevel != 1 || snapshot.LastStatusCode != 503 {
		t.Fatalf("late probation 503 snapshot=%+v", snapshot)
	}
}

func TestRelayCircuitOldGenerationInFlightDoesNotBlockProbationAdmission(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	pending := relayCircuitBeginEvidence(t, breaker, 51, "pre-open-pending")
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)

	probes := make([]RelayCircuitPermit, 0, relayCircuitProbationMaxInFlight)
	for i := 0; i < relayCircuitProbationMaxInFlight; i++ {
		probe, ok := breaker.beginWithEvidence(51, "probation-current-"+strconv.Itoa(i), 100)
		if !ok || !probe.Probe {
			t.Fatalf("probation permit %d denied by an old-generation request", i)
		}
		probes = append(probes, probe)
	}
	if _, ok := breaker.beginWithEvidence(51, "probation-over-current-cap", 100); ok {
		t.Fatal("probation admitted above its current-generation cap")
	}
	if snapshot := breaker.snapshot(51); snapshot.InFlight != relayCircuitProbationMaxInFlight {
		t.Fatalf("probation admission in-flight=%d want %d", snapshot.InFlight, relayCircuitProbationMaxInFlight)
	}
	for _, probe := range probes {
		breaker.abandon(probe)
	}
	breaker.abandon(pending)
}

func TestRelayCircuitAbandonReleasesProbationSlotWithoutSuccess(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)

	firstProbe, ok := breaker.begin(51)
	if !ok || !firstProbe.Probe {
		t.Fatal("first probation request denied")
	}
	if !breaker.abandon(firstProbe) {
		t.Fatal("abandon did not release half-open lease")
	}
	if got := breaker.snapshot(51).ProbeSuccesses; got != 0 {
		t.Fatalf("abandon counted as success: %d", got)
	}
	secondProbe, ok := breaker.begin(51)
	if !ok || !secondProbe.Probe {
		t.Fatal("replacement probation request denied")
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

func TestRelayCircuitProbationFailureUsesCappedBackoff(t *testing.T) {
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitTestBreaker(clock)
	relayCircuitConfirmStrongOpen(t, breaker, 51)

	wants := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 300 * time.Second, 300 * time.Second}
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
	failing := relayCircuitBeginEvidence(t, breaker, 51, "first-failure")
	oldSuccess := relayCircuitBeginEvidence(t, breaker, 51, "old-success")
	breaker.reportFailure(failing, 502)
	for i := 0; i < relayCircuitStrongPostSuspectLimit; i++ {
		permit := relayCircuitBeginEvidence(t, breaker, 51, "confirm-"+strconv.Itoa(i))
		breaker.reportFailure(permit, 502)
	}
	clock.Advance(relayCircuitInitialOpen)
	probe, ok := breaker.begin(51)
	if !ok {
		t.Fatal("half-open probe denied")
	}

	if breaker.reportSuccess(oldSuccess) {
		t.Fatal("old in-flight success closed a newer circuit")
	}
	snapshot := breaker.snapshot(51)
	if snapshot.State != RelayCircuitProbation || !snapshot.ProbeInFlight || snapshot.ProbeSuccesses != 0 {
		t.Fatalf("old success changed probation state: %+v", snapshot)
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

func newRelayCircuitConfigEpochStore(clock *relayCircuitTestClock, tokenCache cache.TokenCache, withGuardian bool) (*Store, *Account, *Account) {
	shared := relayCircuitSchedulerAccount(51, 100)
	shared.GroupIDs = []int64{7, 8}
	oldOnly := relayCircuitSchedulerAccount(50, -100)
	oldOnly.GroupIDs = []int64{7}
	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	store := &Store{
		accounts:     []*Account{shared, oldOnly},
		accountsByID: map[int64]*Account{shared.DBID: shared, oldOnly.DBID: oldOnly},
		tokenCache:   tokenCache,
		relayCircuit: breaker,
	}
	atomic.StoreInt64(&store.maxConcurrency, 100)
	store.cybRelayConfig.Store(NormalizeCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 7}))
	breaker.ensureLoadedForAccount(shared)
	breaker.ensureLoadedForAccount(oldOnly)
	if withGuardian {
		store.relayGuardianMode.Store(string(RelayGuardianEnforce))
		store.relayGuardian = newRelayHealthGuardian(store)
		store.preloadRelayRuntimeAccount(shared)
		store.preloadRelayRuntimeAccount(oldOnly)
	}
	return store, shared, oldOnly
}

func relayCircuitConfirmStoreStrongOpen(t *testing.T, store *Store, account *Account) {
	t.Helper()
	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "store-strong-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("store permit %d denied", i)
		}
		opened := store.ReportRelayCircuitFailure(permit, 502)
		if opened != (i == relayCircuitStrongFailureLimit) {
			t.Fatalf("store failure %d opened=%v", i, opened)
		}
	}
}

func relayCircuitConfirmStoreLastResort(t *testing.T, store *Store, account *Account, prefix string) {
	t.Helper()
	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, prefix+"-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("last-resort permit %d denied", i)
		}
		if store.ReportRelayCircuitFailure(permit, 502) {
			t.Fatalf("last usable front fully opened on failure %d", i)
		}
	}
	snapshot := store.RelayCircuitSnapshot(account.ID())
	if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort ||
		snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("last-resort snapshot=%+v", snapshot)
	}
}

func relayCircuitSetStoreOpenWithLastResort(t *testing.T, store *Store, clock *relayCircuitTestClock, lastResort *Account, accounts ...*Account) {
	t.Helper()
	breaker := store.relayCircuitManager()
	for _, account := range accounts {
		breaker.ensureLoadedForAccount(account)
	}
	breaker.mu.Lock()
	for _, account := range accounts {
		state := breaker.stateLocked(account.ID())
		breaker.openLocked(account.ID(), state, clock.Now(), 502, false)
		account.setRelayCircuitLastResort(false)
	}
	state := breaker.stateLocked(lastResort.ID())
	breaker.activateLastResortLocked(lastResort.ID(), state, clock.Now(), 502)
	lastResort.setRelayCircuitLastResort(true)
	breaker.mu.Unlock()
}

func TestRelayCircuitConfigPublishesBeforeFinalBreakerReset(t *testing.T) {
	for _, withGuardian := range []bool{false, true} {
		name := "nil_guardian"
		if withGuardian {
			name = "guardian_enforce"
		}
		t.Run(name, func(t *testing.T) {
			base := cache.NewMemory(1)
			defer base.Close()
			clock := newRelayCircuitTestClock()
			blocking := &relayCircuitTargetBlockingDeleteRuntimeCache{
				TokenCache: base,
				targetKey:  relayCircuitRuntimeKey(51),
				started:    make(chan struct{}),
				release:    make(chan struct{}),
			}
			store, shared, _ := newRelayCircuitConfigEpochStore(clock, blocking, withGuardian)

			setDone := make(chan struct{})
			go func() {
				defer close(setDone)
				store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
			}()
			select {
			case <-blocking.started:
			case <-time.After(2 * time.Second):
				t.Fatal("config transition did not reach target breaker reset")
			}

			published := store.GetCybRelayConfig()
			var postPublishPermit RelayCircuitPermit
			var beginOK bool
			if withGuardian {
				postPublishPermit, beginOK = store.BeginRelayCircuitRequestForLogicalRequest(shared, "post-publish-during-reset")
			}
			close(blocking.release)
			select {
			case <-setDone:
			case <-time.After(2 * time.Second):
				t.Fatal("config transition did not finish after breaker reset release")
			}

			if !published.Enabled || published.GroupID != 8 {
				var polluted RelayCircuitSnapshot
				if withGuardian && beginOK {
					store.ReportRelayCircuitFailure(postPublishPermit, 502)
					polluted = store.RelayCircuitSnapshot(shared.ID())
				}
				t.Fatalf("breaker reset was visible before config publication: config=%+v begin_ok=%v final=%+v", published, beginOK, polluted)
			}
			if withGuardian {
				if !beginOK {
					t.Fatal("new-scope request was fail-closed for the duration of breaker cache reset")
				}
				store.ReportRelayCircuitFailure(postPublishPermit, 502)
				if snapshot := store.RelayCircuitSnapshot(shared.ID()); snapshot.State != RelayCircuitSuspect || snapshot.StrongFailures != 1 {
					t.Fatalf("post-publish permit was not retained in the new scope: %+v", snapshot)
				}
			} else if snapshot := store.RelayCircuitSnapshot(shared.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 {
				t.Fatalf("nil-Guardian transition did not finish with a clean breaker: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitConfigTransitionRevokesOldEpochOutcomes(t *testing.T) {
	for _, withGuardian := range []bool{false, true} {
		guardianName := "nil_guardian"
		if withGuardian {
			guardianName = "guardian_enforce"
		}
		for _, outcome := range []string{"failure", "success"} {
			t.Run(guardianName+"/"+outcome, func(t *testing.T) {
				base := cache.NewMemory(1)
				defer base.Close()
				clock := newRelayCircuitTestClock()
				store, shared, _ := newRelayCircuitConfigEpochStore(clock, base, withGuardian)

				var permit RelayCircuitPermit
				var ok bool
				if withGuardian {
					permit, ok = store.BeginRelayCircuitRequestForLogicalRequest(shared, "old-config-outcome")
				} else {
					permit, ok = store.relayCircuitManager().beginWithEvidence(shared.ID(), "old-config-outcome", 100)
				}
				if !ok {
					t.Fatal("old-scope permit denied")
				}

				store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
				switch outcome {
				case "failure":
					store.ReportRelayCircuitFailure(permit, 502)
				case "success":
					if store.ReportRelayCircuitSuccess(permit) {
						t.Fatal("old-scope success was accepted after config transition")
					}
				}
				if snapshot := store.RelayCircuitSnapshot(shared.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 || snapshot.WeakSamples != 0 || snapshot.InFlight != 0 {
					t.Fatalf("old-scope %s crossed config epoch: %+v", outcome, snapshot)
				}
			})
		}
	}
}

func TestRelayCircuitConfigTransitionClearsOldScopeEnsurePromotion(t *testing.T) {
	for _, withGuardian := range []bool{false, true} {
		name := "nil_guardian"
		if withGuardian {
			name = "guardian_enforce"
		}
		t.Run(name, func(t *testing.T) {
			base := cache.NewMemory(1)
			defer base.Close()
			clock := newRelayCircuitTestClock()
			store, shared, oldOnly := newRelayCircuitConfigEpochStore(clock, base, withGuardian)
			breaker := store.relayCircuitManager()
			breaker.mu.Lock()
			state := breaker.stateLocked(shared.ID())
			breaker.openLocked(shared.ID(), state, clock.Now(), 502, false)
			shared.setRelayCircuitLastResort(false)
			breaker.mu.Unlock()
			if !store.EnsureRelayCircuitRequestPoolInvariant(func(account *Account) bool {
				return account != nil && account.ID() == shared.ID()
			}, map[int64]bool{oldOnly.ID(): true}) {
				t.Fatal("old-scope Ensure did not create its test last-resort")
			}
			if snapshot := store.RelayCircuitSnapshot(shared.ID()); !snapshot.LastResort {
				t.Fatalf("old-scope Ensure setup failed: %+v", snapshot)
			}

			store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
			if snapshot := store.RelayCircuitSnapshot(shared.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort || snapshot.StrongFailures != 0 {
				t.Fatalf("old-scope Ensure state survived config epoch: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitConfigDisableThenEnableStartsFreshEpoch(t *testing.T) {
	for _, withGuardian := range []bool{false, true} {
		name := "nil_guardian"
		if withGuardian {
			name = "guardian_enforce"
		}
		t.Run(name, func(t *testing.T) {
			base := cache.NewMemory(1)
			defer base.Close()
			clock := newRelayCircuitTestClock()
			store, shared, _ := newRelayCircuitConfigEpochStore(clock, base, withGuardian)
			var oldPermit RelayCircuitPermit
			var ok bool
			if withGuardian {
				oldPermit, ok = store.BeginRelayCircuitRequestForLogicalRequest(shared, "before-disable")
			} else {
				oldPermit, ok = store.relayCircuitManager().beginWithEvidence(shared.ID(), "before-disable", 100)
			}
			if !ok {
				t.Fatal("pre-disable permit denied")
			}

			store.SetCybRelayConfig(CybRelayConfig{Enabled: false})
			if cfg := store.GetCybRelayConfig(); cfg.Enabled || cfg.GroupID != 0 {
				t.Fatalf("disable was not published: %+v", cfg)
			}
			if permit, beginOK := store.BeginRelayCircuitRequestForLogicalRequest(shared, "while-disabled"); beginOK || permit.Active {
				t.Fatalf("disabled Relay scope admitted request: permit=%+v ok=%v", permit, beginOK)
			}
			if store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
				t.Fatal("disabled Relay scope exposed last-resort capacity")
			}
			store.ReportRelayCircuitFailure(oldPermit, 502)
			if snapshot := store.RelayCircuitSnapshot(shared.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 {
				t.Fatalf("pre-disable outcome survived disabled epoch: %+v", snapshot)
			}

			store.SetCybRelayConfig(CybRelayConfig{Enabled: true, GroupID: 8})
			if cfg := store.GetCybRelayConfig(); !cfg.Enabled || cfg.GroupID != 8 {
				t.Fatalf("re-enable was not published: %+v", cfg)
			}
			newPermit, beginOK := store.BeginRelayCircuitRequestForLogicalRequest(shared, "after-reenable")
			if !beginOK || !newPermit.Active {
				t.Fatalf("fresh enabled epoch did not admit request: permit=%+v ok=%v", newPermit, beginOK)
			}
			store.AbandonRelayCircuitRequest(newPermit)
		})
	}
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
			relayCircuitConfirmStoreStrongOpen(t, store, primary)
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

func TestRelayCircuitLastHealthyFrontBecomesCappedLastResort(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	atomic.StoreInt32(&fallback.Disabled, 1)

	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("permit %d denied", i)
		}
		if store.ReportRelayCircuitFailure(permit, 502) {
			t.Fatalf("last healthy front fully opened on failure %d", i)
		}
	}
	snapshot := store.RelayCircuitSnapshot(primary.ID())
	if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("last-resort snapshot=%+v", snapshot)
	}
	permits := make([]RelayCircuitPermit, 0, relayCircuitLastResortAdmissionLimit)
	for i := 0; i < relayCircuitLastResortAdmissionLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-live-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("last-resort permit %d denied", i)
		}
		permits = append(permits, permit)
	}
	if _, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-over-cap"); ok {
		t.Fatal("last-resort admitted above cap")
	}
	for _, permit := range permits {
		store.AbandonRelayCircuitRequest(permit)
	}
}

func TestRelayCircuitMembershipLeaveAndRejoinStartsFreshEpoch(t *testing.T) {
	tests := []struct {
		name       string
		lastResort bool
	}{
		{name: "confirmed_open"},
		{name: "last_resort", lastResort: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
			latePermit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "old-membership-late")
			if !ok {
				t.Fatal("old-membership permit denied")
			}
			if tt.lastResort {
				atomic.StoreInt32(&fallback.Disabled, 1)
				relayCircuitConfirmStoreLastResort(t, store, primary, "membership-last-resort")
			} else {
				relayCircuitConfirmStoreStrongOpen(t, store, primary)
			}

			if !store.ApplyAccountGroups(primary.ID(), nil) {
				t.Fatal("leave Relay membership failed")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
				t.Fatalf("leave retained old breaker state: %+v", snapshot)
			}
			if !store.ApplyAccountGroups(primary.ID(), []int64{7}) {
				t.Fatal("rejoin Relay membership failed")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
				t.Fatalf("rejoin inherited old breaker state: %+v", snapshot)
			}
			if primary.relayAvailabilityLastResort() {
				t.Fatal("rejoined account retained a last-resort scheduler hint")
			}
			if store.ReportRelayCircuitFailure(latePermit, 502) {
				t.Fatal("old membership permit reopened the new epoch")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed ||
				snapshot.StrongFailures != 0 || snapshot.LastResort {
				t.Fatalf("old membership completion mutated new epoch: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitBulkMembershipLeaveAndRejoinInvalidatesOldPermit(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	latePermit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "old-bulk-membership-late")
	if !ok {
		t.Fatal("old bulk-membership permit denied")
	}
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	store.ApplyAccountGroupMemberships(map[int64][]int64{
		primary.ID():  nil,
		fallback.ID(): []int64{7},
	})
	store.ApplyAccountGroupMemberships(map[int64][]int64{
		primary.ID():  []int64{7},
		fallback.ID(): []int64{7},
	})
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
		t.Fatalf("bulk rejoin inherited old breaker state: %+v", snapshot)
	}
	if store.ReportRelayCircuitFailure(latePermit, 502) {
		t.Fatal("old bulk-membership permit reopened the new epoch")
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 {
		t.Fatalf("old bulk-membership completion mutated new epoch: %+v", snapshot)
	}
}

func TestRelayCircuitRemoveAndReaddSameAccountIDStartsFreshEpoch(t *testing.T) {
	tests := []struct {
		name       string
		lastResort bool
	}{
		{name: "confirmed_open"},
		{name: "last_resort", lastResort: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
			latePermit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "removed-object-late")
			if !ok {
				t.Fatal("removed-object permit denied")
			}
			if tt.lastResort {
				atomic.StoreInt32(&fallback.Disabled, 1)
				relayCircuitConfirmStoreLastResort(t, store, primary, "remove-last-resort")
			} else {
				relayCircuitConfirmStoreStrongOpen(t, store, primary)
			}
			if token := store.RelayCircuitSnapshot(primary.ID()).confirmedStrongCycleToken; token != 1 {
				t.Fatalf("pre-removal confirmed cycle token=%d, want 1", token)
			}

			store.RemoveAccount(primary.ID())
			replacement := relayCircuitSchedulerAccount(primary.ID(), primary.schedulerPriority())
			store.AddAccount(replacement)
			if snapshot := store.RelayCircuitSnapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort || snapshot.confirmedStrongCycleToken != 1 {
				t.Fatalf("replacement account inherited removed membership state: %+v", snapshot)
			}
			if !store.RelayCircuitSelectable(replacement) {
				t.Fatal("replacement account remained fenced by removed membership")
			}
			if store.ReportRelayCircuitFailure(latePermit, 502) {
				t.Fatal("removed object's permit reopened replacement account")
			}
			if snapshot := store.RelayCircuitSnapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 {
				t.Fatalf("removed object's completion mutated replacement account: %+v", snapshot)
			}
			if tt.lastResort {
				relayCircuitConfirmStoreLastResort(t, store, replacement, "replacement-last-resort")
			} else {
				relayCircuitConfirmStoreStrongOpen(t, store, replacement)
			}
			if token := store.RelayCircuitSnapshot(replacement.ID()).confirmedStrongCycleToken; token != 2 {
				t.Fatalf("replacement confirmed cycle token=%d, want monotonic token 2", token)
			}
		})
	}
}

func TestRelayCircuitBulkRemoveAndReaddSameAccountIDStartsFreshEpoch(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	store.RemoveAccounts([]int64{primary.ID()})
	replacement := relayCircuitSchedulerAccount(primary.ID(), primary.schedulerPriority())
	store.AddAccount(replacement)
	if snapshot := store.RelayCircuitSnapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
		t.Fatalf("bulk replacement inherited removed membership state: %+v", snapshot)
	}
	if !store.RelayCircuitSelectable(replacement) {
		t.Fatal("bulk replacement remained fenced by removed membership")
	}
}

func TestRelayCircuitSelectedOldObjectCannotBeginAfterSameIDReplacement(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
	selected := store.NextExcludingWithFilter(0, nil, func(account *Account) bool {
		return account != nil && account.ID() == primary.ID()
	})
	if selected != primary {
		t.Fatalf("selected account=%v want old primary", selected)
	}

	store.RemoveAccount(primary.ID())
	replacement := relayCircuitSchedulerAccount(primary.ID(), primary.schedulerPriority())
	store.AddAccount(replacement)
	if permit, ok := store.BeginRelayCircuitRequestForLogicalRequestWithFilter(primary, "selected-before-replace", nil); ok || permit.Active {
		t.Fatalf("removed Account object acquired replacement generation permit: permit=%+v ok=%v", permit, ok)
	}
	store.Release(primary)
	if snapshot := store.RelayCircuitSnapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort || snapshot.StrongFailures != 0 {
		t.Fatalf("replacement state changed after rejected old-object Begin: %+v", snapshot)
	}
}

func TestRelayCircuitConcurrentRemoveAndBeginLinearizesMembership(t *testing.T) {
	for iteration := 0; iteration < 32; iteration++ {
		clock := newRelayCircuitTestClock()
		store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
		selected := store.NextExcludingWithFilter(0, nil, func(account *Account) bool {
			return account != nil && account.ID() == primary.ID()
		})
		if selected != primary {
			t.Fatalf("iteration %d selected account=%v want old primary", iteration, selected)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var permit RelayCircuitPermit
		var beginOK bool
		var replacement *Account
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			permit, beginOK = store.BeginRelayCircuitRequestForLogicalRequestWithFilter(primary, "concurrent-remove-begin", nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			store.RemoveAccount(primary.ID())
			replacement = relayCircuitSchedulerAccount(primary.ID(), primary.schedulerPriority())
			store.AddAccount(replacement)
		}()
		close(start)
		wg.Wait()
		store.Release(primary)

		if beginOK {
			// Begin linearized first, so Remove must have revoked this permit.
			store.ReportRelayCircuitFailure(permit, 502)
		}
		if replacement == nil {
			t.Fatalf("iteration %d replacement was not installed", iteration)
		}
		if snapshot := store.RelayCircuitSnapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort || snapshot.StrongFailures != 0 {
			t.Fatalf("iteration %d old object crossed membership boundary: %+v", iteration, snapshot)
		}
	}
}

func TestRelayCircuitBeginAndRemoveWriterLockOrderTerminates(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Store)
		lock    func(*Store)
		unlock  func(*Store)
	}{
		{
			name: "breaker",
			lock: func(store *Store) {
				store.relayCircuitManager().mu.Lock()
			},
			unlock: func(store *Store) {
				store.relayCircuitManager().mu.Unlock()
			},
		},
		{
			name: "guardian",
			prepare: func(store *Store) {
				store.SetRelayGuardianMode(string(RelayGuardianEnforce))
			},
			lock: func(store *Store) {
				store.relayGuardianManager().mu.Lock()
			},
			unlock: func(store *Store) {
				store.relayGuardianManager().mu.Unlock()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
			if tt.prepare != nil {
				tt.prepare(store)
			}

			tt.lock(store)
			gateLocked := true
			defer func() {
				if gateLocked {
					tt.unlock(store)
				}
			}()

			beginDone := make(chan struct{})
			go func() {
				defer close(beginDone)
				store.BeginRelayCircuitRequestForLogicalRequest(primary, "writer-lock-order")
			}()

			// The blocked Begin must already own the Store read lock before the
			// writer starts. This specifically catches a nested Store read under
			// breaker/Guardian mutex after a writer is queued, which would deadlock
			// sync.RWMutex even though the same goroutine already has an RLock.
			deadline := time.Now().Add(time.Second)
			for store.mu.TryLock() {
				store.mu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("Begin did not reach the gated lock while holding Store membership")
				}
				time.Sleep(time.Millisecond)
			}

			removeDone := make(chan struct{})
			go func() {
				defer close(removeDone)
				store.RemoveAccount(primary.ID())
			}()

			tt.unlock(store)
			gateLocked = false
			for name, done := range map[string]<-chan struct{}{"Begin": beginDone, "RemoveAccount": removeDone} {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatalf("%s did not terminate after releasing %s gate", name, tt.name)
				}
			}
		})
	}
}

func TestRelayCircuitTransportIdentityChangesResetButRenameDoesNot(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*Store, *Account) bool
	}{
		{
			name: "endpoint",
			mutate: func(store *Store, account *Account) bool {
				return store.ApplyOpenAIResponsesConfig(account.ID(), "https://replacement-relay.example/v1", account.APIKey,
					[]string{"gpt-5.4"}, "", account.CodexClientMetadataMode, account.ProxyURL)
			},
		},
		{
			name: "api_key",
			mutate: func(store *Store, account *Account) bool {
				return store.ApplyOpenAIResponsesConfig(account.ID(), account.BaseURL, "replacement-key",
					[]string{"gpt-5.4"}, "", account.CodexClientMetadataMode, account.ProxyURL)
			},
		},
		{
			name: "proxy",
			mutate: func(store *Store, account *Account) bool {
				return store.ApplyAccountProxyURL(account.ID(), "http://127.0.0.1:18080")
			},
		},
		{
			name: "custom_headers",
			mutate: func(store *Store, account *Account) bool {
				return store.ApplyAccountCustomHeaders(account.ID(), map[string]string{"X-Relay-Tenant": "replacement"})
			},
		},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
			latePermit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "old-identity-late")
			if !ok {
				t.Fatal("old-identity permit denied")
			}
			relayCircuitConfirmStoreStrongOpen(t, store, primary)
			if !tt.mutate(store, primary) {
				t.Fatal("identity mutation failed")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
				t.Fatalf("replacement identity inherited old breaker state: %+v", snapshot)
			}
			if store.ReportRelayCircuitFailure(latePermit, 502) {
				t.Fatal("old identity permit reopened replacement front")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitClosed || snapshot.StrongFailures != 0 {
				t.Fatalf("old identity completion mutated replacement front: %+v", snapshot)
			}
		})
	}

	t.Run("display_name", func(t *testing.T) {
		clock := newRelayCircuitTestClock()
		store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
		relayCircuitConfirmStoreStrongOpen(t, store, primary)
		before := store.RelayCircuitSnapshot(primary.ID())
		if !store.ApplyAccountName(primary.ID(), "renamed relay front") {
			t.Fatal("rename failed")
		}
		after := store.RelayCircuitSnapshot(primary.ID())
		if after.State != RelayCircuitOpen || after.Generation != before.Generation || after.LastResort != before.LastResort {
			t.Fatalf("display rename erased breaker evidence: before=%+v after=%+v", before, after)
		}
	})
}

func TestRelayCircuitLastResortAlwaysSchedulesBehindNormalPeer(t *testing.T) {
	for _, fast := range []bool{false, true} {
		name := "slow_scheduler"
		if fast {
			name = "fast_scheduler"
		}
		t.Run(name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(fast, clock)
			if !store.ApplyAccountEnabled(fallback.ID(), false) {
				t.Fatal("disable fallback failed")
			}
			relayCircuitConfirmStoreLastResort(t, store, primary, "scheduler-last-resort")

			if !store.ApplyAccountEnabled(fallback.ID(), true) {
				t.Fatal("restore normal peer failed")
			}
			selected := store.NextExcludingWithFilter(0, nil, nil)
			if selected == nil {
				t.Fatal("scheduler returned no account after normal peer recovered")
			}
			if selected.ID() != fallback.ID() {
				store.Release(selected)
				t.Fatalf("scheduler selected last-resort %d ahead of normal peer %d", selected.ID(), fallback.ID())
			}
			store.Release(selected)

			if !store.ApplyAccountEnabled(fallback.ID(), false) {
				t.Fatal("disable normal peer for cap check failed")
			}
			selectedAccounts := make([]*Account, 0, relayCircuitLastResortAdmissionLimit)
			permits := make([]RelayCircuitPermit, 0, relayCircuitLastResortAdmissionLimit)
			for i := 0; i < relayCircuitLastResortAdmissionLimit; i++ {
				account := store.NextExcludingWithFilter(0, nil, nil)
				if account == nil || account.ID() != primary.ID() {
					t.Fatalf("last-resort selection %d = %v, want primary", i, account)
				}
				permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(account, "last-resort-cap-"+strconv.Itoa(i))
				if !ok {
					store.Release(account)
					t.Fatalf("last-resort permit %d denied", i)
				}
				selectedAccounts = append(selectedAccounts, account)
				permits = append(permits, permit)
			}
			if account := store.NextExcludingWithFilter(0, nil, nil); account != nil {
				store.Release(account)
				t.Fatalf("scheduler exceeded last-resort cap with account %d", account.ID())
			}
			for i, permit := range permits {
				store.AbandonRelayCircuitRequest(permit)
				store.Release(selectedAccounts[i])
			}
		})
	}
}

func TestRelayCircuitRequestPoolInvariantPromotesOpenAfterHealthyPeerPaused(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	confirmedToken := store.RelayCircuitSnapshot(primary.ID()).confirmedStrongCycleToken
	if confirmedToken != 1 {
		t.Fatalf("confirmed open token=%d, want 1", confirmedToken)
	}
	if !store.ApplyAccountEnabled(fallback.ID(), false) {
		t.Fatal("pause healthy peer failed")
	}

	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("request pool invariant did not expose a re-selection path")
	}
	snapshot := store.RelayCircuitSnapshot(primary.ID())
	if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("open account was not promoted to capped last-resort: %+v", snapshot)
	}
	if snapshot.confirmedStrongCycleToken != confirmedToken {
		t.Fatalf("pool-invariant promotion advanced confirmed cycle token: before=%d after=%d", confirmedToken, snapshot.confirmedStrongCycleToken)
	}
	if atomic.LoadInt32(&fallback.DispatchPaused) == 0 {
		t.Fatal("pool invariant re-enabled the manually paused peer")
	}
	if fallbackSnapshot := store.RelayCircuitSnapshot(fallback.ID()); fallbackSnapshot.LastResort {
		t.Fatalf("paused peer was promoted instead of remaining untouched: %+v", fallbackSnapshot)
	}
}

func TestRelayCircuitLastResortNewStrongQuorumAdvancesConfirmedCycleToken(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	if !store.ApplyAccountEnabled(fallback.ID(), false) {
		t.Fatal("pause healthy peer failed")
	}
	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("request pool invariant did not promote open front")
	}
	if token := store.RelayCircuitSnapshot(primary.ID()).confirmedStrongCycleToken; token != 1 {
		t.Fatalf("promoted last-resort token=%d, want 1", token)
	}

	for index := 1; index <= relayCircuitStrongFailureLimit; index++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-new-quorum-"+strconv.Itoa(index))
		if !ok {
			t.Fatalf("last-resort permit %d denied", index)
		}
		if store.ReportRelayCircuitFailure(permit, http.StatusBadGateway) {
			t.Fatalf("last-resort failure %d unexpectedly removed the sole front", index)
		}
	}
	snapshot := store.RelayCircuitSnapshot(primary.ID())
	if !snapshot.LastResort || snapshot.confirmedStrongCycleToken != 2 {
		t.Fatalf("new confirmed last-resort quorum did not advance cycle token: %+v token=%d", snapshot, snapshot.confirmedStrongCycleToken)
	}
}

func TestRelayCircuitRequestPoolInvariantDoesNotPromoteWhileNormalCandidateExists(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, _ := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	if store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("pool invariant requested re-selection while a normal closed peer existed")
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitOpen || snapshot.LastResort {
		t.Fatalf("open account was relaxed despite normal capacity: %+v", snapshot)
	}
}

func TestRelayCircuitRequestPoolInvariantExcludedLastResortBlocksSecondPromotionInSameClass(t *testing.T) {
	// Hard transport exclusions and soft first-token exclusions are merged by
	// retry selection before reaching auth. Exercise both origins explicitly so
	// neither call path may turn a request-scoped exclusion into cap-2*N.
	for _, exclusionOrigin := range []string{"hard", "soft"} {
		t.Run(exclusionOrigin, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
			relayCircuitSetStoreOpenWithLastResort(t, store, clock, primary, primary, fallback)

			if store.EnsureRelayCircuitRequestPoolInvariant(nil, map[int64]bool{primary.ID(): true}) {
				t.Fatal("excluded same-class last-resort advertised a re-selection path")
			}
			if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
				t.Fatalf("existing last-resort changed unexpectedly: %+v", snapshot)
			}
			if snapshot := store.RelayCircuitSnapshot(fallback.ID()); snapshot.State != RelayCircuitOpen || snapshot.LastResort {
				t.Fatalf("same-class peer was promoted behind an excluded last-resort: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitRequestPoolInvariantDisjointQualificationClassMayPromote(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitSetStoreOpenWithLastResort(t, store, clock, primary, primary, fallback)

	// Model/API-key eligibility is represented by the request pool filter. The
	// existing last-resort is outside this request's qualification class, so it
	// must not strand an otherwise eligible open front.
	poolFilter := func(account *Account) bool {
		return account != nil && account.ID() == fallback.ID()
	}
	if !store.EnsureRelayCircuitRequestPoolInvariant(poolFilter, map[int64]bool{primary.ID(): true}) {
		t.Fatal("disjoint request qualification class did not create last-resort capacity")
	}
	if snapshot := store.RelayCircuitSnapshot(fallback.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("eligible disjoint peer was not promoted: %+v", snapshot)
	}
}

func TestRelayCircuitRequestPoolInvariantManuallyPausedLastResortDoesNotBlockEligiblePeer(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitSetStoreOpenWithLastResort(t, store, clock, primary, primary, fallback)
	if !store.ApplyAccountEnabled(primary.ID(), false) {
		t.Fatal("manual pause failed")
	}

	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("manually paused last-resort stranded the eligible open peer")
	}
	if atomic.LoadInt32(&primary.DispatchPaused) == 0 {
		t.Fatal("pool invariant re-enabled the manually paused last-resort")
	}
	if snapshot := store.RelayCircuitSnapshot(fallback.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
		t.Fatalf("eligible peer was not promoted after manual pause: %+v", snapshot)
	}
}

func TestRelayCircuitRequestPoolInvariantRemovedLastResortDoesNotBlockEligiblePeer(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitSetStoreOpenWithLastResort(t, store, clock, primary, primary, fallback)
	store.RemoveAccount(primary.ID())

	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("removed last-resort stranded the eligible open peer")
	}
	if snapshot := store.RelayCircuitSnapshot(fallback.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
		t.Fatalf("eligible peer was not promoted after membership removal: %+v", snapshot)
	}
}

func TestRelayCircuitRequestPoolInvariantNeverRestoresDisabledOrIneligibleAccount(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	if !store.ApplyAccountEnabled(primary.ID(), false) || !store.ApplyAccountEnabled(fallback.ID(), false) {
		t.Fatal("pause test accounts failed")
	}
	if store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("disabled account was presented as request capacity")
	}
	if atomic.LoadInt32(&primary.DispatchPaused) == 0 || atomic.LoadInt32(&fallback.DispatchPaused) == 0 {
		t.Fatal("pool invariant changed a manual scheduling flag")
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitOpen || snapshot.LastResort {
		t.Fatalf("disabled open account was promoted: %+v", snapshot)
	}

	if !store.ApplyAccountEnabled(primary.ID(), true) {
		t.Fatal("re-enable primary failed")
	}
	if store.EnsureRelayCircuitRequestPoolInvariant(func(account *Account) bool {
		return account != nil && account.ID() != primary.ID()
	}, nil) {
		t.Fatal("request-filter-ineligible open account was promoted")
	}
	if store.EnsureRelayCircuitRequestPoolInvariant(nil, map[int64]bool{primary.ID(): true}) {
		t.Fatal("request-excluded open account was promoted")
	}
}

func TestRelayCircuitRequestPoolInvariantConcurrentPromotionCreatesOnlyOneLastResort(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	for _, account := range []*Account{primary, fallback} {
		state := breaker.stateLocked(account.ID())
		breaker.openLocked(account.ID(), state, clock.Now(), 502, false)
		account.setRelayCircuitLastResort(false)
	}
	breaker.mu.Unlock()

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			<-start
			store.EnsureRelayCircuitRequestPoolInvariant(nil, nil)
		}()
	}
	close(start)
	wg.Wait()

	lastResorts := 0
	open := 0
	for _, account := range []*Account{primary, fallback} {
		snapshot := store.RelayCircuitSnapshot(account.ID())
		if snapshot.LastResort {
			lastResorts++
			if snapshot.State != RelayCircuitSuspect || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
				t.Fatalf("promoted state is not capped suspect: %+v", snapshot)
			}
		} else if snapshot.State == RelayCircuitOpen {
			open++
		}
	}
	if lastResorts != 1 || open != 1 {
		t.Fatalf("concurrent invariant produced last_resort=%d open=%d, want 1/1", lastResorts, open)
	}
}

func TestRelayCircuitRequestPoolInvariantConcurrentOppositeExclusionsCreateOneLastResortPerClass(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := store.relayCircuitManager()
	breaker.mu.Lock()
	for _, account := range []*Account{primary, fallback} {
		state := breaker.stateLocked(account.ID())
		breaker.openLocked(account.ID(), state, clock.Now(), 502, false)
		account.setRelayCircuitLastResort(false)
	}
	breaker.mu.Unlock()

	const callers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		excludedID := primary.ID()
		if i%2 != 0 {
			excludedID = fallback.ID()
		}
		go func() {
			defer wg.Done()
			<-start
			store.EnsureRelayCircuitRequestPoolInvariant(nil, map[int64]bool{excludedID: true})
		}()
	}
	close(start)
	wg.Wait()

	lastResorts := 0
	for _, account := range []*Account{primary, fallback} {
		if snapshot := store.RelayCircuitSnapshot(account.ID()); snapshot.LastResort {
			lastResorts++
			if snapshot.State != RelayCircuitSuspect || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
				t.Fatalf("promoted state is not capped last-resort: %+v", snapshot)
			}
		} else if snapshot.State != RelayCircuitOpen {
			t.Fatalf("non-promoted peer left open state: %+v", snapshot)
		}
	}
	if lastResorts != 1 {
		t.Fatalf("opposite selection exclusions produced %d same-class last-resorts, want 1", lastResorts)
	}
}

func TestRelayCircuitRequestPoolInvariantPersistsRollbackSafeLastResort(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	store.relayCircuit = breaker
	breaker.ensureLoadedForAccount(primary)
	breaker.ensureLoadedForAccount(fallback)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)
	if !store.ApplyAccountEnabled(fallback.ID(), false) {
		t.Fatal("pause healthy peer failed")
	}
	if !store.EnsureRelayCircuitRequestPoolInvariant(nil, nil) {
		t.Fatal("request pool invariant did not promote persisted last-resort")
	}

	record := relayCircuitReadRuntimeRecord(t, tokenCache, primary.ID())
	if record.State != RelayCircuitHalfOpen || !record.LastResort || record.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("last-resort wire record is not rollback safe: %+v", record)
	}
	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoadedForAccount(primary)
	if snapshot := restarted.snapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("restart lost promoted last-resort cap: %+v", snapshot)
	}
}

func TestRelayCircuitLateWeakThresholdPersistsAndRestoresLastResort(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	store.relayCircuit = breaker
	breaker.ensureLoaded(primary.ID())
	breaker.ensureLoaded(fallback.ID())
	atomic.StoreInt32(&fallback.Disabled, 1)

	first, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-initial-strong")
	if !ok || store.ReportRelayCircuitFailure(first, 502) {
		t.Fatalf("initial strong attempt: permit=%+v ok=%v", first, ok)
	}
	fastSuccess, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-fast-success")
	if !ok {
		t.Fatal("fast-success permit denied")
	}
	lateFailures := make([]RelayCircuitPermit, 0, relayCircuitWeakFailureLimit)
	for i := 0; i < relayCircuitWeakFailureLimit; i++ {
		permit, permitOK := store.BeginRelayCircuitRequestForLogicalRequest(primary, "last-resort-late-weak-"+strconv.Itoa(i))
		if !permitOK {
			t.Fatalf("late weak permit %d denied", i)
		}
		lateFailures = append(lateFailures, permit)
	}
	if !store.ReportRelayCircuitSuccess(fastSuccess) {
		t.Fatal("fast success did not close suspect generation")
	}
	for i, permit := range lateFailures {
		if store.ReportRelayCircuitFailure(permit, 503) {
			t.Fatalf("last usable front fully opened on late weak failure %d", i+1)
		}
	}
	snapshot := store.RelayCircuitSnapshot(primary.ID())
	if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("late weak threshold did not enter last-resort: %+v", snapshot)
	}

	key := relayCircuitRuntimeKey(primary.ID())
	deadline := time.Now().Add(time.Second)
	for {
		payload, found, err := tokenCache.GetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			var persisted relayCircuitRuntimeRecord
			if err := json.Unmarshal(payload, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.LastResort && persisted.State == RelayCircuitHalfOpen {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("late weak last-resort runtime record was not persisted")
		}
		time.Sleep(time.Millisecond)
	}

	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoaded(primary.ID())
	restored := restarted.snapshot(primary.ID())
	if restored.State != RelayCircuitSuspect || !restored.LastResort || restored.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("late weak last-resort cap was not restored: %+v", restored)
	}
}

func TestRelayCircuitSaturatedPeerDoesNotPreventLastResort(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	atomic.StoreInt64(&fallback.ActiveRequests, 100)

	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "saturated-peer-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("permit %d denied", i)
		}
		if store.ReportRelayCircuitFailure(permit, 502) {
			t.Fatalf("primary fully opened while only peer had no available concurrency on failure %d", i)
		}
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
		t.Fatalf("saturated peer incorrectly counted as healthy capacity: %+v", snapshot)
	}
}

func TestRelayCircuitSuspectPeerAtAdmissionCapDoesNotPreventLastResort(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	firstFailure, ok := store.BeginRelayCircuitRequestForLogicalRequest(fallback, "fallback-suspect")
	if !ok {
		t.Fatal("fallback suspect permit denied")
	}
	if store.ReportRelayCircuitFailure(firstFailure, 502) {
		t.Fatal("single fallback failure opened circuit")
	}
	fallbackSnapshot := store.RelayCircuitSnapshot(fallback.ID())
	for i := 0; i < fallbackSnapshot.AdmissionLimit; i++ {
		if _, ok := store.BeginRelayCircuitRequestForLogicalRequest(fallback, "fallback-capped-"+strconv.Itoa(i)); !ok {
			t.Fatalf("fallback permit %d denied before cap", i)
		}
	}
	if _, ok := store.BeginRelayCircuitRequestForLogicalRequest(fallback, "fallback-over-cap"); ok {
		t.Fatal("fallback admitted above suspect cap")
	}

	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "capped-peer-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("primary permit %d denied", i)
		}
		if store.ReportRelayCircuitFailure(permit, 502) {
			t.Fatalf("primary fully opened while suspect peer was at admission cap on failure %d", i)
		}
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
		t.Fatalf("capped suspect peer incorrectly counted as healthy capacity: %+v", snapshot)
	}
}

func TestRelayCircuitGuardianRecoveryPeerDoesNotPreventLastResort(t *testing.T) {
	tests := []struct {
		name       string
		state      RelayGuardianState
		lastResort bool
		wantOpen   bool
	}{
		{name: "half_open", state: RelayGuardianHalfOpen},
		{name: "probation", state: RelayGuardianProbation},
		{name: "temporary_bypass", state: RelayGuardianTemporaryBypass},
		{name: "guardian_last_resort", state: RelayGuardianHealthy, lastResort: true},
		{name: "healthy_peer", state: RelayGuardianHealthy, wantOpen: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
			store.SetRelayGuardianMode(string(RelayGuardianEnforce))
			guardian := store.relayGuardianManager()
			guardian.now = clock.Now
			guardian.mu.Lock()
			guardian.loaded[fallback.DBID] = true
			state := guardian.stateLocked(fallback.DBID)
			state.State = tt.state
			state.LastResort = tt.lastResort
			state.LastResortCap = 1
			state.QuarantineUntil = clock.Now().Add(time.Hour)
			state.TemporaryBypassUntil = clock.Now().Add(time.Hour)
			state.ProbationPercent = 10
			relayGuardianApplySchedulingHint(fallback, state)
			guardian.mu.Unlock()

			for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
				permit, ok := store.BeginRelayCircuitRequestForLogicalRequest(primary, "guardian-peer-"+strconv.Itoa(i))
				if !ok {
					t.Fatalf("permit %d denied", i)
				}
				opened := store.ReportRelayCircuitFailure(permit, 502)
				if opened != (tt.wantOpen && i == relayCircuitStrongFailureLimit) {
					t.Fatalf("failure %d opened=%t wantOpen=%t", i, opened, tt.wantOpen)
				}
			}
			snapshot := store.RelayCircuitSnapshot(primary.ID())
			if tt.wantOpen {
				if snapshot.State != RelayCircuitOpen || snapshot.LastResort {
					t.Fatalf("healthy peer did not permit open: %+v", snapshot)
				}
			} else if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
				t.Fatalf("Guardian recovery-only peer counted as stable capacity: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitRequestFilterExcludesModelCooledPeer(t *testing.T) {
	tests := []struct {
		name           string
		cooledModel    string
		requestModel   string
		wantLastResort bool
	}{
		{name: "same_model", cooledModel: "gpt-5.4", requestModel: "gpt-5.4", wantLastResort: true},
		{name: "different_model", cooledModel: "gpt-5.5", requestModel: "gpt-5.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newRelayCircuitTestClock()
			store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
			fallback.SetModelCooldownUntil(tt.cooledModel, "model_capacity", time.Now().Add(time.Hour))
			poolFilter := store.WithModelCooldownFilter(tt.requestModel, nil)
			for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
				permit, ok := store.BeginRelayCircuitRequestForLogicalRequestWithFilter(primary, "model-peer-"+strconv.Itoa(i), poolFilter)
				if !ok {
					t.Fatalf("permit %d denied", i)
				}
				store.ReportRelayCircuitFailure(permit, 502)
			}
			snapshot := store.RelayCircuitSnapshot(primary.ID())
			if tt.wantLastResort {
				if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
					t.Fatalf("same-model cooled peer counted as healthy capacity: %+v", snapshot)
				}
			} else if snapshot.State != RelayCircuitOpen || snapshot.LastResort {
				t.Fatalf("different-model cooldown incorrectly removed peer capacity: %+v", snapshot)
			}
		})
	}
}

func TestRelayCircuitRequestFilterExcludesUnsupportedPeer(t *testing.T) {
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	poolFilter := func(account *Account) bool {
		return account != nil && account.DBID != fallback.DBID
	}
	for i := 1; i <= relayCircuitStrongFailureLimit; i++ {
		permit, ok := store.BeginRelayCircuitRequestForLogicalRequestWithFilter(primary, "unsupported-peer-"+strconv.Itoa(i), poolFilter)
		if !ok {
			t.Fatalf("permit %d denied", i)
		}
		if store.ReportRelayCircuitFailure(permit, 502) {
			t.Fatalf("unsupported peer allowed primary to open on failure %d", i)
		}
	}
	if snapshot := store.RelayCircuitSnapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort {
		t.Fatalf("unsupported peer counted as healthy request capacity: %+v", snapshot)
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
	for i := 0; i < relayCircuitWeakFailureLimit-1; i++ {
		unique := relayCircuitBeginEvidence(t, breaker, 51, "unique-"+strconv.Itoa(i))
		uniqueOK := unique.Active
		if !uniqueOK {
			t.Fatalf("unique permit %d denied", i+1)
		}
		opened := breaker.reportFailure(unique, 503)
		if opened != (i == relayCircuitWeakFailureLimit-2) {
			t.Fatalf("unique weak failure %d opened=%v", i+1, opened)
		}
	}
}

func TestRelayCircuitDeleteFailureWritesClosedTombstone(t *testing.T) {
	base := cache.NewMemory(1)
	defer base.Close()
	flaky := &relayCircuitDeleteFailRuntimeCache{TokenCache: base, deleteFailures: 1}
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := newRelayCircuitBreaker(flaky)
	breaker.now = clock.Now
	store.relayCircuit = breaker
	breaker.ensureLoadedForAccount(primary)
	breaker.ensureLoadedForAccount(fallback)
	relayCircuitConfirmStoreStrongOpen(t, store, primary)

	if !store.ApplyAccountGroups(primary.ID(), nil) {
		t.Fatal("leave Relay membership failed")
	}
	record := relayCircuitReadRuntimeRecord(t, base, primary.ID())
	if record.State != RelayCircuitClosed {
		t.Fatalf("failed delete left stale runtime state %q instead of a closed tombstone", record.State)
	}
	if record.IdentityFingerprint != relayCircuitAccountIdentityFingerprint(primary) {
		t.Fatalf("closed tombstone identity=%q want current identity", record.IdentityFingerprint)
	}

	replacement := relayCircuitSchedulerAccount(primary.ID(), primary.schedulerPriority())
	restarted := newRelayCircuitBreaker(base)
	restarted.now = clock.Now
	restarted.ensureLoadedForAccount(replacement)
	if snapshot := restarted.snapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
		t.Fatalf("restart restored stale open after closed tombstone: %+v", snapshot)
	}
}

func TestRelayCircuitPersistedIdentityMismatchDiscardsOldOpen(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	oldAccount := relayCircuitSchedulerAccount(51, 100)
	first := newRelayCircuitBreaker(tokenCache)
	first.now = clock.Now
	first.ensureLoadedForAccount(oldAccount)
	relayCircuitConfirmStrongOpen(t, first, oldAccount.ID())
	persisted := relayCircuitReadRuntimeRecord(t, tokenCache, oldAccount.ID())
	if persisted.State != RelayCircuitOpen || persisted.IdentityFingerprint == "" {
		t.Fatalf("persisted open is not identity-fenced: %+v", persisted)
	}

	replacement := relayCircuitSchedulerAccount(oldAccount.ID(), 100)
	replacement.APIKey = "replacement-key"
	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoadedForAccount(replacement)
	if snapshot := restarted.snapshot(replacement.ID()); snapshot.State != RelayCircuitClosed || snapshot.LastResort {
		t.Fatalf("replacement identity inherited persisted open: %+v", snapshot)
	}
	permit, ok := restarted.beginWithEvidence(replacement.ID(), "replacement-first-request", 100)
	if !ok || permit.Probe {
		t.Fatalf("replacement identity did not start closed: permit=%+v ok=%v", permit, ok)
	}
	restarted.abandon(permit)

	deadline := time.Now().Add(time.Second)
	for {
		_, found, err := tokenCache.GetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, relayCircuitRuntimeKey(replacement.ID()))
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("identity-mismatched open record was not deleted")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRelayCircuitProbationUsesRollbackCompatibleWireState(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	breaker.ensureLoaded(51)
	relayCircuitConfirmStrongOpen(t, breaker, 51)
	clock.Advance(relayCircuitInitialOpen)
	probe, ok := breaker.beginWithEvidence(51, "first-probation-success", 100)
	if !ok || !probe.Probe {
		t.Fatalf("probation permit=%+v ok=%v", probe, ok)
	}
	if breaker.reportSuccess(probe) {
		t.Fatal("one probation success closed circuit")
	}

	record := relayCircuitReadRuntimeRecord(t, tokenCache, 51)
	if record.State != RelayCircuitHalfOpen || record.LastResort || record.ProbeSuccesses != 1 {
		t.Fatalf("probation wire record is not rollback-compatible: %+v", record)
	}
	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoaded(51)
	if token := restarted.snapshot(51).confirmedStrongCycleToken; token != 0 {
		t.Fatalf("process restart restored process-local confirmed cycle token=%d", token)
	}
	if snapshot := restarted.snapshot(51); snapshot.State != RelayCircuitProbation || snapshot.LastResort ||
		snapshot.ProbeSuccesses != 1 || snapshot.AdmissionLimit != relayCircuitProbationMaxInFlight {
		t.Fatalf("rb12 did not restore probation semantics from half_open wire state: %+v", snapshot)
	}
}

func TestRelayCircuitLastResortUsesRollbackCompatibleWireState(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	store, primary, fallback := newRelayCircuitSchedulerStore(false, clock)
	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	store.relayCircuit = breaker
	breaker.ensureLoadedForAccount(primary)
	breaker.ensureLoadedForAccount(fallback)
	atomic.StoreInt32(&fallback.Disabled, 1)
	relayCircuitConfirmStoreLastResort(t, store, primary, "wire-last-resort")

	record := relayCircuitReadRuntimeRecord(t, tokenCache, primary.ID())
	if record.State != RelayCircuitHalfOpen || !record.LastResort ||
		record.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("last-resort wire record is not rollback-compatible: %+v", record)
	}
	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoadedForAccount(primary)
	if snapshot := restarted.snapshot(primary.ID()); snapshot.State != RelayCircuitSuspect || !snapshot.LastResort ||
		snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("rb12 did not restore last-resort semantics from half_open wire state: %+v", snapshot)
	}
}

func TestRelayCircuitRestoresOpenFenceFromRuntimeCache(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()

	first := newRelayCircuitBreaker(tokenCache)
	first.now = clock.Now
	first.ensureLoaded(51)
	relayCircuitConfirmStrongOpen(t, first, 51)

	restarted := newRelayCircuitBreaker(tokenCache)
	restarted.now = clock.Now
	restarted.ensureLoaded(51)
	if _, ok := restarted.begin(51); ok {
		t.Fatal("restart lost the cached open fence")
	}
	clock.Advance(relayCircuitInitialOpen)
	probe, ok := restarted.begin(51)
	if !ok || !probe.Probe {
		t.Fatalf("expired restored fence did not enter half-open: permit=%+v ok=%v", probe, ok)
	}
}

func TestRelayCircuitRestoreClosesSatisfiedRecoveryRecord(t *testing.T) {
	for _, state := range []RelayCircuitState{RelayCircuitProbation, RelayCircuitHalfOpen} {
		t.Run(string(state), func(t *testing.T) {
			tokenCache := cache.NewMemory(1)
			defer tokenCache.Close()
			clock := newRelayCircuitTestClock()
			key := relayCircuitRuntimeKey(51)
			record := relayCircuitRuntimeRecord{
				State: state, Generation: 3, LastStatusCode: 502,
				OpenedAt: clock.Now().Add(-time.Minute), OpenUntil: clock.Now().Add(-time.Second),
				UpdatedAt: clock.Now(), ProbeSuccesses: relayCircuitRecoverySuccesses,
				AdmissionLimit: relayCircuitProbationMaxInFlight,
			}
			payload, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key, payload, time.Hour); err != nil {
				t.Fatal(err)
			}

			breaker := newRelayCircuitBreaker(tokenCache)
			breaker.now = clock.Now
			breaker.ensureLoaded(51)
			if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed {
				t.Fatalf("satisfied recovery record restored as blocked state: %+v", snapshot)
			}
			permit, ok := breaker.beginWithEvidence(51, "after-restart", 100)
			if !ok || permit.Probe {
				t.Fatalf("satisfied recovery record blocked normal request: permit=%+v ok=%v", permit, ok)
			}
			breaker.abandon(permit)
		})
	}
}

func TestRelayCircuitDiscardedSuspectRuntimeRecordIsDeleted(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	key := relayCircuitRuntimeKey(51)
	record := relayCircuitRuntimeRecord{
		State: RelayCircuitSuspect, Generation: 3, LastStatusCode: 502,
		LastFailureAt: clock.Now(), UpdatedAt: clock.Now(), EvidenceEpoch: 2,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key, payload, time.Hour); err != nil {
		t.Fatal(err)
	}

	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	breaker.ensureLoaded(51)
	if snapshot := breaker.snapshot(51); snapshot.State != RelayCircuitClosed {
		t.Fatalf("suspect runtime record restored as restriction: %+v", snapshot)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, ok, err := tokenCache.GetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("discarded suspect runtime record was not deleted")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRelayCircuitRestoresLastResortCapFromRuntimeCache(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	key := relayCircuitRuntimeKey(51)
	record := relayCircuitRuntimeRecord{
		State: RelayCircuitHalfOpen, Generation: 3, LastStatusCode: 502,
		LastFailureAt: clock.Now(), UpdatedAt: clock.Now(), EvidenceEpoch: 2,
		LastResort: true, AdmissionLimit: relayCircuitLastResortAdmissionLimit,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key, payload, time.Hour); err != nil {
		t.Fatal(err)
	}

	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	breaker.ensureLoaded(51)
	snapshot := breaker.snapshot(51)
	if snapshot.State != RelayCircuitSuspect || !snapshot.LastResort || snapshot.AdmissionLimit != relayCircuitLastResortAdmissionLimit {
		t.Fatalf("last-resort cap was lost on restart: %+v", snapshot)
	}
	for i := 0; i < relayCircuitLastResortAdmissionLimit; i++ {
		if _, ok := breaker.beginWithEvidence(51, "restored-last-resort-"+strconv.Itoa(i), 100); !ok {
			t.Fatalf("restored last-resort permit %d denied", i)
		}
	}
	if _, ok := breaker.beginWithEvidence(51, "restored-last-resort-over-cap", 100); ok {
		t.Fatal("restored last-resort admitted above cap")
	}
}

func TestRelayCircuitRestoreRetriesAndFailsClosedAfterCacheError(t *testing.T) {
	base := cache.NewMemory(1)
	defer base.Close()
	clock := newRelayCircuitTestClock()

	first := newRelayCircuitBreaker(base)
	first.now = clock.Now
	first.ensureLoaded(51)
	relayCircuitConfirmStrongOpen(t, first, 51)

	flaky := &relayCircuitFlakyRuntimeCache{TokenCache: base, failures: 1}
	restarted := newRelayCircuitBreaker(flaky)
	restarted.now = clock.Now
	restarted.ensureLoaded(51)
	if restarted.selectable(51) {
		t.Fatal("account was selectable while runtime fence restore was unresolved")
	}
	if _, ok := restarted.begin(51); ok {
		t.Fatal("request permit was issued while runtime fence restore was unresolved")
	}
	clock.Advance(time.Second)
	restarted.ensureLoaded(51)
	if restarted.selectable(51) {
		t.Fatal("restored open circuit became selectable before its deadline")
	}
	if got := restarted.snapshot(51).State; got != RelayCircuitOpen {
		t.Fatalf("restored state = %q, want open", got)
	}
}

func TestRelayCircuitCorruptRuntimeCacheFailsClosedUntilValidRetry(t *testing.T) {
	tokenCache := cache.NewMemory(1)
	defer tokenCache.Close()
	clock := newRelayCircuitTestClock()
	key := relayCircuitRuntimeKey(51)
	if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key, json.RawMessage(`{"state":`), time.Hour); err != nil {
		t.Fatal(err)
	}

	breaker := newRelayCircuitBreaker(tokenCache)
	breaker.now = clock.Now
	breaker.ensureLoaded(51)
	if breaker.selectable(51) {
		t.Fatal("corrupt runtime fence failed open")
	}
	if _, ok := breaker.begin(51); ok {
		t.Fatal("corrupt runtime fence issued a request permit")
	}

	record := relayCircuitRuntimeRecord{State: RelayCircuitOpen, Generation: 3, OpenUntil: clock.Now().Add(time.Minute), UpdatedAt: clock.Now()}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokenCache.SetRuntime(context.Background(), relayCircuitRuntimeCacheNamespace, key, payload, time.Hour); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	breaker.ensureLoaded(51)
	if breaker.selectable(51) {
		t.Fatal("valid retried open fence became selectable")
	}
	if got := breaker.snapshot(51).State; got != RelayCircuitOpen {
		t.Fatalf("retried state=%q want open", got)
	}
}
