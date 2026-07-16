package auth

import (
	"testing"

	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
)

func TestRuntimePromptFilterConfigAlwaysDisablesOutputBlocking(t *testing.T) {
	fromSettings := promptFilterConfigFromSettings(&database.SystemSettings{
		PromptFilterEnabled:        true,
		PromptFilterAdvancedConfig: `{"output":{"enabled":true,"buffer_bytes":512,"overlap_bytes":64,"strict_only":true}}`,
	})
	if fromSettings.Advanced.Output.Enabled {
		t.Fatal("database output.enabled=true reached runtime config")
	}

	store := &Store{}
	cfg := promptfilter.DefaultConfig()
	cfg.Advanced.Output.Enabled = true
	store.SetPromptFilterConfig(cfg)
	if got := store.GetPromptFilterConfig(); got.Advanced.Output.Enabled {
		t.Fatal("Set/Get restored output blocking")
	}
}
