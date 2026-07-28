package cybtext

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWalkUserTextChunksScansCompleteOversizedMiddle(t *testing.T) {
	const signal = "COMPLETE_MIDDLE_RISK_WITNESS"
	body, err := json.Marshal(map[string]any{
		"input": strings.Repeat("ordinary-prefix-", 16*1024) +
			signal +
			strings.Repeat("-ordinary-suffix", 16*1024),
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		64*1024,
		4*1024,
		func(origin TextOrigin, text string) {
			if origin != TextOriginCurrentUser {
				t.Fatalf("origin = %v, want current user", origin)
			}
			if len(text) > 64*1024 {
				t.Fatalf("chunk length = %d, want <= 64 KiB", len(text))
			}
			if strings.Contains(text, signal) {
				found = true
			}
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("WalkUserTextChunks = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if !found {
		t.Fatal("complete middle witness was not visited")
	}
}

func TestWalkUserTextChunksPreservesBoundaryWitnessAndUTF8(t *testing.T) {
	const signal = "BOUNDARY_WITNESS"
	value := strings.Repeat("x", 57) + signal + "你好"
	body, err := json.Marshal(map[string]any{"input": value})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	_, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		64,
		32,
		func(_ TextOrigin, text string) {
			if !utf8.ValidString(text) {
				t.Fatalf("invalid UTF-8 chunk: %q", text)
			}
			if strings.Contains(text, signal) {
				found = true
			}
		},
	)
	if !ok {
		t.Fatal("WalkUserTextChunks rejected valid request")
	}
	if !found {
		t.Fatal("overlap did not preserve witness crossing a chunk boundary")
	}
}

func TestWalkUserTextChunksCurrentBeforeHistoryAndExcludesNonUser(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"system","content":"SYSTEM_EXCLUDED"},
		{"role":"user","content":"PREVIOUS_USER"},
		{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
		{"role":"user","content":"CURRENT_USER"}
	]}`)
	var origins []TextOrigin
	var all strings.Builder
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/chat/completions",
		1024,
		64,
		func(origin TextOrigin, text string) {
			origins = append(origins, origin)
			all.WriteString(text)
			all.WriteByte('\n')
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("WalkUserTextChunks = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if len(origins) != 2 ||
		origins[0] != TextOriginCurrentUser ||
		origins[1] != TextOriginHistory {
		t.Fatalf("origins = %v, want current then history", origins)
	}
	got := all.String()
	if !strings.Contains(got, "CURRENT_USER") || !strings.Contains(got, "PREVIOUS_USER") {
		t.Fatalf("user text missing: %q", got)
	}
	if strings.Contains(got, "SYSTEM_EXCLUDED") || strings.Contains(got, "ASSISTANT_EXCLUDED") {
		t.Fatalf("non-user text leaked: %q", got)
	}
}

func TestWalkUserTextChunksWhitespaceFieldDoesNotHideLaterInput(t *testing.T) {
	body := []byte(`{"input":[
		{"type":"input_text","text":"CURRENT_PREFIX"},
		{"type":"input_text","text":"   ","input":"CURRENT_TAIL"}
	]}`)
	var got strings.Builder
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		1024,
		64,
		func(origin TextOrigin, text string) {
			if origin == TextOriginCurrentUser {
				got.WriteString(text)
			}
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("user walker = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if !strings.Contains(got.String(), "CURRENT_PREFIX") ||
		!strings.Contains(got.String(), "CURRENT_TAIL") {
		t.Fatalf("whitespace field hid later current-user input: %q", got.String())
	}
}

func TestWalkRoutingTextChunksScansToolOnlyMiddleButLearningDoesNot(t *testing.T) {
	const signal = "TOOL_MIDDLE_RISK_WITNESS"
	toolOutput := strings.Repeat("tool-prefix-", 16*1024) +
		signal +
		strings.Repeat("-tool-suffix", 16*1024)
	body, err := json.Marshal(map[string]any{
		"input": []any{
			map[string]any{"role": "user", "content": "PREVIOUS_USER"},
			map[string]any{
				"type":    "function_call_output",
				"call_id": "call_1",
				"output":  toolOutput,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	userSawTool := false
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		64*1024,
		4*1024,
		func(_ TextOrigin, text string) {
			userSawTool = userSawTool || strings.Contains(text, signal)
		},
	)
	if !ok || hasCurrent {
		t.Fatalf("user walker = hasCurrent %v, ok %v; want tool-only continuation", hasCurrent, ok)
	}
	if userSawTool {
		t.Fatal("routing-only tool output leaked into user learning walker")
	}

	toolFound := false
	_, ok = WalkRoutingTextChunks(
		body,
		"/v1/responses",
		64*1024,
		4*1024,
		func(origin TextOrigin, text string) {
			if strings.Contains(text, signal) {
				if origin != TextOriginToolOutput {
					t.Fatalf("tool witness origin = %v", origin)
				}
				toolFound = true
			}
		},
	)
	if !ok || !toolFound {
		t.Fatalf("routing walker lost complete tool middle witness: ok=%v found=%v", ok, toolFound)
	}
}

func TestWalkRoutingTextChunksIgnoresToolWhenCurrentUserExists(t *testing.T) {
	body := []byte(`{"input":[
		{"type":"function_call_output","call_id":"call_1","output":"TOOL_EXCLUDED"},
		{"type":"input_text","text":"CURRENT_USER"}
	]}`)
	var got strings.Builder
	hasCurrent, ok := WalkRoutingTextChunks(
		body,
		"/v1/responses",
		1,
		0,
		func(_ TextOrigin, text string) {
			got.WriteString(text)
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("routing walker = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if strings.Contains(got.String(), "TOOL_EXCLUDED") {
		t.Fatalf("tool output overrode a current user turn: %q", got.String())
	}
	if !strings.Contains(got.String(), "CURRENT_USER") {
		t.Fatalf("current user missing: %q", got.String())
	}
}

func TestWalkRoutingTextChunksRoleToolPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","content":"PREVIOUS_USER"},
		{"role":"tool","content":"CANONICAL_TOOL_CONTENT","output":"BENIGN_FALLBACK"}
	]}`)
	var got strings.Builder
	_, ok := WalkRoutingTextChunks(
		body,
		"/v1/chat/completions",
		32,
		8,
		func(origin TextOrigin, text string) {
			if origin == TextOriginToolOutput {
				got.WriteString(text)
			}
		},
	)
	if !ok {
		t.Fatal("routing walker rejected valid role=tool request")
	}
	if !strings.Contains(got.String(), "CANONICAL_TOOL_CONTENT") {
		t.Fatalf("canonical tool content missing: %q", got.String())
	}
	if strings.Contains(got.String(), "BENIGN_FALLBACK") {
		t.Fatalf("non-canonical output fallback overrode content: %q", got.String())
	}
}

func TestWalkUserTextChunksRoleUserPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
	]}`)
	var got strings.Builder
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/chat/completions",
		32,
		8,
		func(origin TextOrigin, text string) {
			if origin == TextOriginCurrentUser {
				got.WriteString(text)
			}
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("user walker = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if !strings.Contains(got.String(), "ACTUAL_USER_CONTENT") {
		t.Fatalf("canonical user content missing: %q", got.String())
	}
	if strings.Contains(got.String(), "FIXED_TRANSPORT_PREFIX") {
		t.Fatalf("non-canonical fixed text entered user scan: %q", got.String())
	}
}

func TestWalkUserTextChunksTypedInputPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"input":[
		{"type":"input_text","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
	]}`)
	var got strings.Builder
	hasCurrent, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		32,
		8,
		func(origin TextOrigin, text string) {
			if origin == TextOriginCurrentUser {
				got.WriteString(text)
			}
		},
	)
	if !ok || !hasCurrent {
		t.Fatalf("user walker = hasCurrent %v, ok %v", hasCurrent, ok)
	}
	if !strings.Contains(got.String(), "ACTUAL_USER_CONTENT") {
		t.Fatalf("canonical typed content missing: %q", got.String())
	}
	if strings.Contains(got.String(), "FIXED_TRANSPORT_PREFIX") {
		t.Fatalf("non-canonical typed text entered user scan: %q", got.String())
	}
}

func TestWalkUserTextChunksSmallUTF8ChunkMakesProgress(t *testing.T) {
	body, err := json.Marshal(map[string]any{"input": "A😀"})
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	_, ok := WalkUserTextChunks(
		body,
		"/v1/responses",
		4,
		1,
		func(_ TextOrigin, text string) {
			got.WriteString(text)
		},
	)
	if !ok {
		t.Fatal("walker rejected valid UTF-8 request")
	}
	if got.String() != "A😀" {
		t.Fatalf("walked text = %q, want A😀", got.String())
	}
}
