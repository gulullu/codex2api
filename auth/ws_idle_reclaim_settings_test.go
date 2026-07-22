package auth

import (
	"testing"

	"github.com/codex2api/database"
)

func TestStoreWSIdleReclaimDefaultsAndHotUpdate(t *testing.T) {
	var nilStore *Store
	if nilStore.CodexWSIdleReclaimEnabled() || nilStore.CodexWSIdleReclaimPercent() != 0 || nilStore.CodexWSIdleReclaimIdleSec() != 600 {
		t.Fatal("nil store idle reclaim defaults must be false/0/600")
	}

	store := NewStore(nil, nil, nil)
	t.Cleanup(store.Stop)
	if store.CodexWSIdleReclaimEnabled() || store.CodexWSIdleReclaimPercent() != 0 || store.CodexWSIdleReclaimIdleSec() != 600 {
		t.Fatalf("default idle reclaim = enabled:%v percent:%d idle:%d, want false/0/600", store.CodexWSIdleReclaimEnabled(), store.CodexWSIdleReclaimPercent(), store.CodexWSIdleReclaimIdleSec())
	}

	store.SetCodexWSIdleReclaimEnabled(true)
	store.SetCodexWSIdleReclaimPercent(20)
	store.SetCodexWSIdleReclaimIdleSec(900)
	if !store.CodexWSIdleReclaimEnabled() || store.CodexWSIdleReclaimPercent() != 20 || store.CodexWSIdleReclaimIdleSec() != 900 {
		t.Fatalf("hot idle reclaim = enabled:%v percent:%d idle:%d, want true/20/900", store.CodexWSIdleReclaimEnabled(), store.CodexWSIdleReclaimPercent(), store.CodexWSIdleReclaimIdleSec())
	}

	store.SetCodexWSIdleReclaimPercent(17)
	store.SetCodexWSIdleReclaimIdleSec(60)
	if store.CodexWSIdleReclaimPercent() != 0 || store.CodexWSIdleReclaimIdleSec() != 600 {
		t.Fatalf("invalid hot idle reclaim = percent:%d idle:%d, want 0/600", store.CodexWSIdleReclaimPercent(), store.CodexWSIdleReclaimIdleSec())
	}
}

func TestStoreWSIdleReclaimInitialSettingsNormalization(t *testing.T) {
	store := NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:            2,
		TestConcurrency:           1,
		TestModel:                 "gpt-5.4",
		CodexWSIdleReclaimEnabled: true,
		CodexWSIdleReclaimPercent: 50,
		CodexWSIdleReclaimIdleSec: 86400,
	})
	t.Cleanup(store.Stop)
	if !store.CodexWSIdleReclaimEnabled() || store.CodexWSIdleReclaimPercent() != 50 || store.CodexWSIdleReclaimIdleSec() != 86400 {
		t.Fatalf("initial idle reclaim = enabled:%v percent:%d idle:%d, want true/50/86400", store.CodexWSIdleReclaimEnabled(), store.CodexWSIdleReclaimPercent(), store.CodexWSIdleReclaimIdleSec())
	}

	invalid := NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:            2,
		TestConcurrency:           1,
		TestModel:                 "gpt-5.4",
		CodexWSIdleReclaimEnabled: true,
		CodexWSIdleReclaimPercent: 6,
		CodexWSIdleReclaimIdleSec: 90000,
	})
	t.Cleanup(invalid.Stop)
	if !invalid.CodexWSIdleReclaimEnabled() || invalid.CodexWSIdleReclaimPercent() != 0 || invalid.CodexWSIdleReclaimIdleSec() != 86400 {
		t.Fatalf("normalized initial idle reclaim = enabled:%v percent:%d idle:%d, want true/0/86400", invalid.CodexWSIdleReclaimEnabled(), invalid.CodexWSIdleReclaimPercent(), invalid.CodexWSIdleReclaimIdleSec())
	}
}
