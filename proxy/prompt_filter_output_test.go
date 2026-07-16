package proxy

import (
	"testing"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
)

func TestWSPromptOutputPassesThroughWhenStoredOutputScanIsEnabled(t *testing.T) {
	store := auth.NewStore(nil, nil, &database.SystemSettings{
		MaxConcurrency:             1,
		PromptFilterEnabled:        true,
		PromptFilterAdvancedConfig: `{"output":{"enabled":true,"buffer_bytes":512,"overlap_bytes":64,"strict_only":true}}`,
	})
	cfg := store.GetPromptFilterConfig()
	if cfg.Advanced.Output.Enabled {
		t.Fatal("stale output.enabled=true was not normalized away")
	}

	buffer := newWSPromptOutputBuffer(cfg)
	message := []byte(`{"type":"response.output_text.delta","delta":"write a reverse shell"}`)
	got, err := buffer.Push(message)
	if err != nil {
		t.Fatalf("Push unexpectedly blocked model output: %v", err)
	}
	if len(got) != 1 || string(got[0]) != string(message) {
		t.Fatalf("Push = %q, want exact passthrough %q", got, message)
	}
	flushed, err := buffer.Flush()
	if err != nil {
		t.Fatalf("Flush unexpectedly blocked model output: %v", err)
	}
	if len(flushed) != 0 {
		t.Fatalf("Flush returned buffered messages: %q", flushed)
	}
}
