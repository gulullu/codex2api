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
			switch manager.admitSafePoolOwner(7101, "same-owner", config) {
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
			if manager.admitSafePoolOwner(7201, owner, config).admitted() {
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
	if decision := manager.admitSafePoolOwner(7202, "other-account-owner", config); decision != safePoolOwnerAdmittedNew {
		t.Fatalf("second account decision=%v, want admitted-new", decision)
	}
	metrics := manager.SafePoolMetricsSnapshot()
	if metrics.OwnerAdmittedNew != 2 || metrics.OwnerBudgetRejected != 99 || metrics.OwnerOneShotFallbacks != 99 {
		t.Fatalf("metrics=%+v, want new=2 budget-rejected=99 one-shot=99", metrics)
	}
}

func TestSafePoolOwnerAdmissionPersistsAcrossRetireAndTightening(t *testing.T) {
	manager := fixedOwnerAdmissionManager(0x55)
	t.Cleanup(manager.Stop)
	wide := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 2, valid: true}
	if manager.admitSafePoolOwner(7301, "owner-A", wide) != safePoolOwnerAdmittedNew ||
		manager.admitSafePoolOwner(7301, "owner-B", wide) != safePoolOwnerAdmittedNew {
		t.Fatal("failed to admit initial owners")
	}
	manager.RetireSafePoolAccount(7301)

	tight := safePoolOwnerAdmissionConfig{sampleBPS: 0, budget: 1, valid: true}
	if got := manager.admitSafePoolOwner(7301, "owner-A", tight); got != safePoolOwnerAdmittedExisting {
		t.Fatalf("existing owner after retire/tighten = %v, want admitted-existing", got)
	}
	if got := manager.admitSafePoolOwner(7301, "owner-C", tight); got != safePoolOwnerRejectedBySample {
		t.Fatalf("new owner after tighten = %v, want sample rejection", got)
	}
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 2 || accounts != 1 || over != 1 {
		t.Fatalf("snapshot owners=%d accounts=%d over=%d, want 2/1/1", owners, accounts, over)
	}

	manager.Stop()
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("stopped snapshot owners=%d accounts=%d over=%d, want cleared", owners, accounts, over)
	}
}

func TestSafePoolOwnerAdmissionRejectsInvalidSaltAndConfig(t *testing.T) {
	manager := NewManager()
	t.Cleanup(manager.Stop)
	manager.ownerAdmissionSaltValid = false
	valid := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: true}
	if got := manager.admitSafePoolOwner(7401, "owner", valid); got != safePoolOwnerRejectedBySample {
		t.Fatalf("invalid salt decision=%v, want sample rejection", got)
	}
	invalid := safePoolOwnerAdmissionConfig{sampleBPS: 10000, budget: 1, valid: false}
	if got := manager.admitSafePoolOwner(7402, "owner", invalid); got != safePoolOwnerRejectedBySample {
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
		decisionCh <- manager.admitSafePoolOwner(7501, "owner-before-stop", config)
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
	if decision := manager.admitSafePoolOwner(7501, "owner-after-stop", config); decision != safePoolOwnerRejectedByLifecycle {
		t.Fatalf("post-stop decision=%v, want lifecycle rejection", decision)
	}
	if owners, accounts, over := manager.safePoolOwnerAdmissionSnapshot(1); owners != 0 || accounts != 0 || over != 0 {
		t.Fatalf("post-stop re-admission populated registry: owners=%d accounts=%d over=%d", owners, accounts, over)
	}
}
