package cybroute

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeSignatureProductionCorpus(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{text: "hi", want: "hello"},
		{text: "hello", want: "hello"},
		{text: "ping", want: "ping"},
		{text: "pong", want: "ping"},
		{text: "test", want: "test"},
		{text: "ok", want: "ok"},
		{text: "hello world", want: "hello_world"},
		{text: "count to seven", want: "count_to_seven"},
		{text: "count to 7", want: "count_to_seven"},
		{text: "what's the opposite of dark?", want: "opposite_dark"},
		{text: "what is the opposite of dark", want: "opposite_dark"},
		{text: "2 乘 2 等于几", want: "two_times_two"},
		{text: "2乘2等于几", want: "two_times_two"},
		{text: "2*2等于几", want: "two_times_two"},
		{text: "2×2等于几", want: "two_times_two"},
		{text: "2 x 2 equals what", want: "two_times_two"},
		{text: "what is 2+2", want: "two_plus_two"},
		{text: "what is two plus two", want: "two_plus_two"},
		{
			text: "call the probe_ping function with ok=true to acknowledge readiness you must use the tool",
			want: "probe_ping",
		},
		{text: "please call probe_ping now with ok=true", want: "probe_ping"},
		{text: "probe this endpoint to acknowledge readiness", want: "probe_readiness"},
		{text: "hello, please explain this response"},
		{text: "please acknowledge service readiness"},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			if got := ProbeSignature(tc.text); got != tc.want {
				t.Fatalf("signature = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetectProbeUsesLatestUserTextOnly(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "gpt-5.5",
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
			map[string]any{"role": "assistant", "content": "Hello!"},
			map[string]any{"role": "user", "content": "Explain this API response."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if signature, matched := DetectProbe(body, "/v1/chat/completions"); matched || signature != "" {
		t.Fatalf("historical probe leaked into latest turn: signature=%q matched=%v", signature, matched)
	}

	body, err = json.Marshal(map[string]any{
		"model": "gpt-5.5",
		"messages": []any{
			map[string]any{"role": "user", "content": "Explain this API response."},
			map[string]any{"role": "assistant", "content": "Ready."},
			map[string]any{"role": "user", "content": "ping"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if signature, matched := DetectProbe(body, "/v1/chat/completions"); !matched || signature != "ping" {
		t.Fatalf("latest probe missed: signature=%q matched=%v", signature, matched)
	}
}

func TestDetectProbeKeepsSmallCurrentUserWithOversizedNonUserContext(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"instructions": strings.Repeat("system context ", 2*1024*1024),
		"input":        "ping",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signature, matched := DetectProbe(body, "/v1/responses"); !matched || signature != "ping" {
		t.Fatalf("oversized non-user context hid current probe: signature=%q matched=%v", signature, matched)
	}
}

func TestDetectProbeRejectsOversizedCurrentUserEvenWhenTailLooksLikeProbe(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"input": strings.Repeat("ordinary user context ", 2*1024*1024) + " ping",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signature, matched := DetectProbe(body, "/v1/responses"); matched || signature != "" {
		t.Fatalf("oversized current user became a probe: signature=%q matched=%v", signature, matched)
	}
}
