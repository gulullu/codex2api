package auth

import (
	"testing"

	"github.com/codex2api/database"
)

func TestNormalizeCybRelayConfigBoundsTTL(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "default", in: 0, want: DefaultCybRelaySessionPinTTLSeconds},
		{name: "minimum", in: 1, want: MinCybRelaySessionPinTTLSeconds},
		{name: "maximum", in: MaxCybRelaySessionPinTTLSeconds + 1, want: MaxCybRelaySessionPinTTLSeconds},
		{name: "unchanged", in: 3600, want: 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCybRelayConfig(CybRelayConfig{GroupID: -1, SessionPinTTLSeconds: tt.in})
			if got.GroupID != 0 || got.SessionPinTTLSeconds != tt.want {
				t.Fatalf("NormalizeCybRelayConfig() = %+v, want group 0 ttl %d", got, tt.want)
			}
		})
	}
}

func TestNewStoreDefaultsCybSessionPinOn(t *testing.T) {
	store := NewStore(nil, nil, nil)
	cfg := store.GetCybRelayConfig()
	if cfg.Enabled || cfg.GroupID != 0 || !cfg.SessionPinEnabled || cfg.SessionPinTTLSeconds != DefaultCybRelaySessionPinTTLSeconds || !cfg.UserTextRescanEnabled() {
		t.Fatalf("default CYB relay config = %+v", cfg)
	}
}

func TestNewStoreDefaultsUserTextRescanOnForLegacySettingsLiteral(t *testing.T) {
	legacy := NewStore(nil, nil, &database.SystemSettings{})
	if !legacy.GetCybRelayConfig().UserTextRescanEnabled() {
		t.Fatal("legacy SystemSettings zero value disabled user-text safety rescan")
	}

	explicit := NewStore(nil, nil, &database.SystemSettings{
		PromptFilterUserTextRescanConfigured: true,
		PromptFilterUserTextRescanEnabled:    false,
	})
	if explicit.GetCybRelayConfig().UserTextRescanEnabled() {
		t.Fatal("explicit persisted false did not disable user-text rescan")
	}
}

func TestAccountHasGroupID(t *testing.T) {
	account := &Account{GroupIDs: []int64{2, 7}}
	if !account.HasGroupID(7) {
		t.Fatal("HasGroupID(7) = false, want true")
	}
	if account.HasGroupID(0) || account.HasGroupID(9) {
		t.Fatal("HasGroupID accepted missing or invalid group")
	}
}
