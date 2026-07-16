package admin

import (
	"testing"

	"github.com/codex2api/security/promptfilter"
)

func TestShouldReviewPromptFilterVerdictSkipsEveryTerminalVerdict(t *testing.T) {
	cfg := promptfilter.DefaultConfig()
	cfg.StrictTerminalEnabled = false
	cfg.Review.Enabled = true
	cfg.Review.APIKey = "test-review-key"

	terminal := promptfilter.Verdict{Action: promptfilter.ActionBlock, TerminalStrictHit: true}
	if shouldReviewPromptFilterVerdict(terminal, cfg) {
		t.Fatal("terminal verdict was sent to secondary review while strict terminal enforcement was disabled")
	}

	nonTerminal := promptfilter.Verdict{Action: promptfilter.ActionWarn}
	if !shouldReviewPromptFilterVerdict(nonTerminal, cfg) {
		t.Fatal("eligible non-terminal verdict did not enter secondary review")
	}
}

func TestRelayBasesPromptFilterAdminConfigNeverAdvertisesLocalModeration(t *testing.T) {
	cfg := promptfilter.DefaultConfig()
	cfg.Mode = promptfilter.ModeBlock
	cfg.Review.Enabled = true
	cfg.Review.All = true
	cfg.Advanced.Output.Enabled = true
	cfg.Advanced.Intelligence.Enabled = true
	cfg.Advanced.Normalization.Enabled = true

	got := relayBasesPromptFilterAdminConfig(cfg)
	if got.Mode != promptfilter.ModeMonitor {
		t.Fatalf("mode = %q, want monitor", got.Mode)
	}
	if got.Review.Enabled || got.Review.All {
		t.Fatalf("semantic review remained enabled: %+v", got.Review)
	}
	if got.Advanced.Output.Enabled {
		t.Fatal("local output interruption remained enabled")
	}
	if !got.Advanced.Intelligence.Enabled || !got.Advanced.Normalization.Enabled {
		t.Fatalf("unrelated official configuration was changed: %+v", got.Advanced)
	}
	if relayBasesSemanticReviewEnabled(true) {
		t.Fatal("legacy standalone semantic review could be re-enabled")
	}
}
