package wsrelay

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixedOwnerAdmissionManager(fill byte) *Manager {
	m := NewManager()
	for i := range m.ownerAdmissionSalt {
		m.ownerAdmissionSalt[i] = fill
	}
	m.ownerAdmissionSaltValid = true
	return m
}

func admitOwnerDecision(m *Manager, accountID int64, owner string, config safePoolOwnerAdmissionConfig) safePoolOwnerAdmissionDecision {
	decision, _ := m.admitSafePoolOwner(accountID, owner, config)
	return decision
}

func TestSafePoolOwnerAdmissionEnvFailsClosed(t *testing.T) {
	t.Setenv(safePoolOwnerSampleBPSEnv, "")
	t.Setenv(safePoolOwnerBudgetPerAccountEnv, "")
	config := currentSafePoolOwnerAdmissionConfig()
	if !config.valid || config.sampleBPS != 0 || config.budget != 0 {
		t.Fatalf("missing config = %+v, want valid fail-closed zeros", config)
	}

	for _, tc := range []struct {
		name   string
		sample string
		budget string
		valid  bool
	}{
		{name: "minimum", sample: "0", budget: "0", valid: true},
		{name: "maximum", sample: "10000", budget: "10000", valid: true},
		{name: "negative sample", sample: "-1", budget: "1", valid: false},
		{name: "oversized sample", sample: "10001", budget: "1", valid: false},
		{name: "invalid sample", sample: "all", budget: "1", valid: false},
		{name: "negative budget", sample: "1", budget: "-1", valid: false},
		{name: "oversized budget", sample: "1", budget: "10001", valid: false},
		{name: "invalid budget", sample: "1", budget: "one", valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(safePoolOwnerSampleBPSEnv, tc.sample)
			t.Setenv(safePoolOwnerBudgetPerAccountEnv, tc.budget)
			if got := currentSafePoolOwnerAdmissionConfig().valid; got != tc.valid {
				t.Fatalf("valid = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestSafePoolOwnerSamplingIsStableOnlyWithinManager(t *testing.T) {
	first := fixedOwnerAdmissionManager(0x11)
	t.Cleanup(first.Stop)
	second := fixedOwnerAdmissionManager(0x22)
	t.Cleanup(second.Stop)

	const accountID = int64(7001)
	for i := 0; i < 1000; i++ {
		owner := fmt.Sprintf("owner-%d", i)
		got := first.safePoolOwnerSampled(accountID, owner, 5000)
		if repeat := first.safePoolOwnerSampled(accountID, owner, 5000); repeat != got {
			t.Fatalf("sampling changed within one manager for %q", owner)
		}
		if second.safePoolOwnerSampled(accountID, owner, 5000) != got {
			return
		}
	}
	t.Fatal("different process salts produced the same 50% sample for 1000 owners")
}

func TestSafePoolOwnerAdmissionConcurrentSameOwnerIsIdempotent(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x33)
	t.Cleanup(manager.Stop)
	config := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}

	var admittedNew atomic.Int32
	var admittedExisting atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch admitOwnerDecision(manager, 7101, "same-owner", config) {
			case safePoolOwnerAdmittedNew:
				admittedNew.Add(1)
			case safePoolOwnerAdmittedExisting:
				admittedExisting.Add(1)
			}
		}()
	}
	wg.Wait()
	if admittedNew.Load() != 1 || admittedExisting.Load() != 99 {
		t.Fatalf("new=%d existing=%d, want 1/99", admittedNew.Load(), admittedExisting.Load())
	}
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 1 || accounts != 1 || over != 0 {
		t.Fatalf("snapshot owners=%d accounts=%d over=%d, want 1/1/0", owners, accounts, over)
	}
}

func TestSafePoolOwnerAdmissionBudgetIsAtomicAndPerAccount(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x44)
	t.Cleanup(manager.Stop)
	config := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}

	var admitted atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		owner := fmt.Sprintf("owner-%03d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if admitOwnerDecision(manager, 7201, owner, config).admitted() {
				admitted.Add(1)
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 || rejected.Load() != 99 {
		t.Fatalf("admitted=%d rejected=%d, want 1/99", admitted.Load(), rejected.Load())
	}
	if decision := admitOwnerDecision(manager, 7202, "other-account-owner", config); decision != safePoolOwnerAdmittedNew {
		t.Fatalf("second account decision=%v, want admitted-new", decision)
	}
	metrics := manager.SafePoolMetricsSnapshot()
	if metrics.OwnerAdmittedNew != 2 || metrics.OwnerBudgetRejected != 99 || metrics.OwnerOneShotFallbacks != 99 {
		t.Fatalf("metrics=%+v, want new=2 budget-rejected=99 one-shot=99", metrics)
	}
}

func TestSafePoolOwnerAdmissionRetireInvalidatesGenerationAndOwners(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x55)
	t.Cleanup(manager.Stop)
	wide := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 2, valid: true}
	firstDecision, firstGeneration := manager.admitSafePoolOwner(7301, "owner-A", wide)
	secondDecision, secondGeneration := manager.admitSafePoolOwner(7301, "owner-B", wide)
	if firstDecision != safePoolOwnerAdmittedNew || secondDecision != safePoolOwnerAdmittedNew || firstGeneration == 0 || secondGeneration != firstGeneration {
		t.Fatal("failed to admit initial owners")
	}
	if _, exists := manager.safePoolAccounts.Load(int64(7301)); !exists {
		t.Fatal("admitted owner was not published as an account lifecycle hint")
	}
	manager.RetireSafePoolAccount(7301)
	if _, exists := manager.safePoolAccounts.Load(int64(7301)); exists {
		t.Fatal("owner-only admission survived generation retirement without a socket")
	}

	tight := safePoolOwnerAdmissionConfig{sampleBPS: 0, budget: 1, valid: true}
	if got := admitOwnerDecision(manager, 7301, "owner-A", tight); got != safePoolOwnerRejectedBySample {
		t.Fatalf("old owner after retire/tighten = %v, want sample rejection in a new generation", got)
	}
	if got := admitOwnerDecision(manager, 7301, "owner-C", tight); got != safePoolOwnerRejectedBySample {
		t.Fatalf("new owner after tighten = %v, want sample rejection", got)
	}
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("snapshot owners=%d accounts=%d over=%d, want cleared generation", owners, accounts, over)
	}
	if metrics := manager.SafePoolMetricsSnapshot(); metrics.GenerationInvalidations != 1 || metrics.RetiredOwners != 2 {
		t.Fatalf("retire metrics=%+v, want one generation invalidation and two retired owners", metrics)
	}

	manager.Stop()
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("stopped snapshot owners=%d accounts=%d over=%d, want cleared", owners, accounts, over)
	}
}

func TestSafePoolOwnerAdmissionReaddStartsNewGeneration(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x56)
	t.Cleanup(manager.Stop)
	config := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}
	firstDecision, firstGeneration := manager.admitSafePoolOwner(7302, "same-owner", config)
	if firstDecision != safePoolOwnerAdmittedNew || firstGeneration == 0 {
		t.Fatalf("first admission=(%v,%d), want admitted nonzero generation", firstDecision, firstGeneration)
	}
	manager.RetireSafePoolAccount(7302)
	secondDecision, secondGeneration := manager.admitSafePoolOwner(7302, "same-owner", config)
	if secondDecision != safePoolOwnerAdmittedNew || secondGeneration <= firstGeneration {
		t.Fatalf("re-add admission=(%v,%d), want admitted generation after %d", secondDecision, secondGeneration, firstGeneration)
	}
	oldIdentity := safeConnectionIdentity{ownerKey: "same-owner", handshakeFingerprint: "headers", generation: firstGeneration}
	newIdentity := safeConnectionIdentity{ownerKey: "same-owner", handshakeFingerprint: "headers", generation: secondGeneration}
	if manager.safePoolIdentityGenerationCurrent(7302, oldIdentity) {
		t.Fatal("old generation remained current after re-add")
	}
	if !manager.safePoolIdentityGenerationCurrent(7302, newIdentity) {
		t.Fatal("new generation was not current after re-add")
	}
}

func TestHandleAccountTagsUpdatedRetiresOnlyEffectiveSafeToUnsafeTransition(t *testing.T) {
	tests := []struct {
		name       string
		scope      string
		globalKill string
		fused      bool
		previous   []string
		current    []string
		wantRetire bool
	}{
		{name: "tagged removes safe", scope: "tagged", previous: []string{safePoolAccountTag}, wantRetire: true},
		{name: "tagged adds oneshot", scope: "tagged", previous: []string{safePoolAccountTag}, current: []string{safePoolAccountTag, oneShotAccountTag}, wantRetire: true},
		{name: "all adds oneshot", scope: "all", current: []string{oneShotAccountTag}, wantRetire: true},
		{name: "all ignores safe tag removal", scope: "all", previous: []string{safePoolAccountTag}, wantRetire: false},
		{name: "global kill already unsafe", scope: "tagged", globalKill: "1", previous: []string{safePoolAccountTag}, wantRetire: false},
		{name: "fused already unsafe", scope: "tagged", fused: true, previous: []string{safePoolAccountTag}, wantRetire: false},
		{name: "disabled never safe", scope: "disabled", previous: []string{safePoolAccountTag}, wantRetire: false},
		{name: "legacy never safe", scope: "legacy", previous: []string{safePoolAccountTag}, wantRetire: false},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(safePoolScopeEnv, tc.scope)
			t.Setenv("CODEX_WS_STATELESS_ONESHOT", tc.globalKill)
			manager := NewManager()
			t.Cleanup(manager.Stop)
			accountID := int64(7600 + index)
			if tc.fused {
				manager.safePoolFuses.Store(accountID, safePoolFuseState{trippedAt: time.Now(), reason: "test"})
			}
			before := manager.SafePoolMetricsSnapshot().GenerationInvalidations
			manager.HandleAccountTagsUpdated(accountID, tc.previous, tc.current)
			delta := manager.SafePoolMetricsSnapshot().GenerationInvalidations - before
			if tc.wantRetire && delta != 1 {
				t.Fatalf("generation invalidation delta=%d, want 1", delta)
			}
			if !tc.wantRetire && delta != 0 {
				t.Fatalf("generation invalidation delta=%d, want 0", delta)
			}
		})
	}
}

func TestSafePoolOwnerAdmissionRejectsInvalidSaltAndConfig(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.ownerAdmissionSaltValid = false
	valid := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}
	if got := admitOwnerDecision(manager, 7401, "owner", valid); got != safePoolOwnerRejectedBySample {
		t.Fatalf("invalid salt decision=%v, want sample rejection", got)
	}
	invalid := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: false}
	if got := admitOwnerDecision(manager, 7402, "owner", invalid); got != safePoolOwnerRejectedBySample {
		t.Fatalf("invalid config decision=%v, want sample rejection", got)
	}
	metrics := manager.SafePoolMetricsSnapshot()
	if metrics.OwnerConfigErrors != 2 || metrics.OwnerSampleRejected != 2 || metrics.OwnerOneShotFallbacks != 2 {
		t.Fatalf("metrics=%+v, want two fail-closed config/sample/one-shot events", metrics)
	}
}

func TestSafePoolOwnerAdmissionCannotRepopulateAfterStop(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x66)
	config := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}
	commitEntered := make(chan struct{})
	releaseCommit := make(chan struct{})
	var enteredOnce sync.Once
	manager.beforeOwnerAdmissionCommit = func() {
		enteredOnce.Do(func() { close(commitEntered) })
		<-releaseCommit
	}

	decisionCh := make(chan safePoolOwnerAdmissionDecision, 1)
	go func() {
		decisionCh <- admitOwnerDecision(manager, 7501, "owner-before-stop", config)
	}()
	<-commitEntered

	stopDone := make(chan struct{})
	go func() {
		manager.Stop()
		close(stopDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		manager.lifecycleMu.Lock()
		stopped := manager.stopped
		manager.lifecycleMu.Unlock()
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Stop did not close the operation gate before waiting")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-stopDone:
		t.Fatal("Stop returned before an admitted owner commit finished")
	default:
	}
	close(releaseCommit)
	if decision := <-decisionCh; decision != safePoolOwnerAdmittedNew {
		t.Fatalf("in-flight decision=%v, want admitted-new before terminal clear", decision)
	}
	<-stopDone

	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("post-stop snapshot owners=%d accounts=%d over=%d, want terminal empty registry", owners, accounts, over)
	}
	if decision := admitOwnerDecision(manager, 7501, "owner-after-stop", config); decision != safePoolOwnerRejectedByLifecycle {
		t.Fatalf("post-stop decision=%v, want lifecycle rejection", decision)
	}
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("post-stop re-admission populated registry: owners=%d accounts=%d over=%d", owners, accounts, over)
	}
}
