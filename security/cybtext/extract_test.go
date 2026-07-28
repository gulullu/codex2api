package cybtext

import (
	"strings"
	"testing"
)

func TestExtractUserSegmentsExcludesNonUserProvenance(t *testing.T) {
	body := []byte(`{
		"messages":[
			{"role":"system","content":"SYSTEM_EXCLUDED"},
			{"role":"user","content":"OLDER_USER"},
			{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
			{"role":"user","content":[
				{"type":"tool_result","content":"TOOL_EXCLUDED"},
				{"type":"future_unknown","text":"UNKNOWN_EXCLUDED"},
				{"type":"text","text":"LATEST_USER"}
			]}
		]
	}`)
	current, history := ExtractUserSegments(body, "/v1/messages")
	if got := strings.Join(current, "\n"); got != "LATEST_USER" {
		t.Fatalf("current = %q, want LATEST_USER", got)
	}
	if got := strings.Join(history, "\n"); got != "OLDER_USER" {
		t.Fatalf("history = %q, want OLDER_USER", got)
	}
}

func TestExtractUserSegmentsToolOnlyContinuationHasNoCurrentUser(t *testing.T) {
	body := []byte(`{
		"input":[
			{"role":"user","content":"PREVIOUS_USER"},
			{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
			{"type":"function_call_output","call_id":"call_1","output":"TOOL_EXCLUDED"}
		]
	}`)
	current, history := ExtractUserSegments(body, "/v1/responses")
	if len(current) != 0 {
		t.Fatalf("tool-only current = %q, want empty", current)
	}
	if got := strings.Join(history, "\n"); got != "PREVIOUS_USER" {
		t.Fatalf("history = %q, want PREVIOUS_USER", got)
	}
}

func TestExtractUserSegmentsPrefersCanonicalUserContent(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "explicit user message",
			body: `{"input":[
				{"role":"user","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
			]}`,
		},
		{
			name: "typed input text",
			body: `{"input":[
				{"type":"input_text","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
			]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current, history := ExtractUserSegments([]byte(test.body), "/v1/responses")
			if got := strings.Join(current, "\n"); got != "ACTUAL_USER_CONTENT" {
				t.Fatalf("current = %q, want canonical content", got)
			}
			if len(history) != 0 {
				t.Fatalf("history = %q, want empty", history)
			}
		})
	}
}
