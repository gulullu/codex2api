package proxy

import (
	"testing"

	"github.com/codex2api/security/promptfilter"
)

func TestRoutingPromptFilterConfigDisablesEveryLocalBlockingPath(t *testing.T) {
	cfg := promptfilter.DefaultConfig()
	cfg.Mode = promptfilter.ModeBlock
	cfg.Review.Enabled = true
	cfg.Review.All = true
	cfg.Advanced.Output.Enabled = true
	cfg.Advanced.Normalization.Enabled = true

	got := routingPromptFilterConfig(cfg)
	if got.Mode != promptfilter.ModeMonitor {
		t.Fatalf("mode = %q, want monitor", got.Mode)
	}
	if got.Review.Enabled || got.Review.All {
		t.Fatalf("secondary review remained enabled: %+v", got.Review)
	}
	if got.Advanced.Output.Enabled {
		t.Fatal("local SSE/WebSocket output interruption remained enabled")
	}
	if !got.Advanced.Normalization.Enabled {
		t.Fatal("routing-only input normalization was unexpectedly disabled")
	}
}
