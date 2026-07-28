package cybtext

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var (
	benchmarkUserWindowsCurrent []string
	benchmarkUserWindowsHistory []string
)

func TestExtractUserWindowsPreservesEndpointSemanticsAndEscapes(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "responses",
			endpoint: "/v1/responses",
			body:     `{"input":[{"role":"user","content":[{"type":"input_text","text":"old"}]},{"type":"input_text","text":"latest\\nuser \u4f60\u597d"}]}`,
		},
		{
			name:     "responses compact",
			endpoint: "/v1/responses/compact",
			body:     `{"input":[{"role":"user","content":"old"},{"role":"user","content":"latest\\nuser \u4f60\u597d"}]}`,
		},
		{
			name:     "chat",
			endpoint: "/v1/chat/completions",
			body:     `{"messages":[{"role":"user","content":"old"},{"role":"user","content":"latest\\nuser \u4f60\u597d"}]}`,
		},
		{
			name:     "messages",
			endpoint: "/v1/messages",
			body:     `{"messages":[{"role":"user","content":"old"},{"role":"user","content":"latest\\nuser \u4f60\u597d"}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current, history := ExtractUserWindows([]byte(test.body), test.endpoint, 1024)
			if got := strings.Join(current, "|"); got != "latest\\nuser 你好" {
				t.Fatalf("current = %q, want decoded latest user", got)
			}
			if got := strings.Join(history, "|"); got != "old" {
				t.Fatalf("history = %q, want old", got)
			}
		})
	}
}

func TestExtractUserWindowsExcludesUnknownToolAndNonUserContent(t *testing.T) {
	body := []byte(`{
		"messages":[
			{"role":"system","content":"SYSTEM_EXCLUDED"},
			{"role":"developer","content":"DEVELOPER_EXCLUDED"},
			{"role":"user","content":"OLDER_USER"},
			{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
			{"role":"user","content":[
				{"type":"tool_result","content":"TOOL_EXCLUDED"},
				{"type":"input_image","image_url":"ATTACHMENT_EXCLUDED"},
				{"type":"future_unknown","text":"UNKNOWN_EXCLUDED"},
				{"type":"text","text":"LATEST_USER"}
			]}
		]
	}`)
	current, history := ExtractUserWindows(body, "/v1/messages", 1024)
	if got := strings.Join(current, "\n"); got != "LATEST_USER" {
		t.Fatalf("current = %q, want LATEST_USER", got)
	}
	if got := strings.Join(history, "\n"); got != "OLDER_USER" {
		t.Fatalf("history = %q, want OLDER_USER", got)
	}
}

func TestExtractUserWindowsRejectsInvalidOrDuplicateRoleAndType(t *testing.T) {
	overlongRole := "assistant" + strings.Repeat(" ", 1024)
	overlongType := "tool_result" + strings.Repeat(" ", 1024)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "overlong role",
			body: `{"messages":[{"role":"` + overlongRole + `","content":"NON_USER"}]}`,
		},
		{
			name: "non-string role",
			body: `{"messages":[{"role":123,"content":"NON_USER"}]}`,
		},
		{
			name: "duplicate role",
			body: `{"messages":[{"role":"user","role":"assistant","content":"NON_USER"}]}`,
		},
		{
			name: "overlong type",
			body: `{"messages":[{"type":"` + overlongType + `","content":"NON_USER"}]}`,
		},
		{
			name: "non-string type",
			body: `{"messages":[{"type":true,"content":"NON_USER"}]}`,
		},
		{
			name: "duplicate type",
			body: `{"messages":[{"type":"text","type":"tool_result","text":"NON_USER"}]}`,
		},
		{
			name: "nested assistant role",
			body: `{"messages":[{"role":"user","content":[{"role":"assistant","content":"NON_USER"}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current, history := ExtractUserWindows([]byte(test.body), "/v1/messages", 1024)
			if len(current) != 0 || len(history) != 0 {
				t.Fatalf("invalid metadata leaked into user windows: current=%q history=%q", current, history)
			}
		})
	}

	body := []byte(`{"input":[
		{"role":"user","content":"PREVIOUS_USER"},
		{"role":"assistant","role":"user","content":"NON_USER"}
	]}`)
	current, history := ExtractUserWindows(body, "/v1/responses", 1024)
	if len(current) != 0 {
		t.Fatalf("invalid trailing item resurrected current user: %q", current)
	}
	if got := strings.Join(history, "\n"); got != "PREVIOUS_USER" {
		t.Fatalf("history = %q, want PREVIOUS_USER", got)
	}
}

func TestExtractUserWindowsReplacesInvalidUTF8AndPreservesTail(t *testing.T) {
	body := append([]byte(`{"input":"HEAD_`+strings.Repeat("x", 1024)), 0xff)
	body = append(body, []byte(`_ACTUAL_USER_TAIL"}`)...)
	current, history := ExtractUserWindows(body, "/v1/responses", 128)
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
	if len(current) != 2 {
		t.Fatalf("current windows = %d, want head and tail: %q", len(current), current)
	}
	if !utf8.ValidString(current[1]) {
		t.Fatalf("tail is not valid UTF-8: %q", current[1])
	}
	if !strings.Contains(current[1], "\uFFFD_ACTUAL_USER_TAIL") {
		t.Fatalf("invalid UTF-8 replacement or actual tail missing: %q", current[1])
	}

	surrogate := []byte(`{"input":"BEFORE_\ud800_AFTER"}`)
	current, _ = ExtractUserWindows(surrogate, "/v1/responses", 1024)
	if got := strings.Join(current, "\n"); got != "BEFORE_\uFFFD_AFTER" {
		t.Fatalf("unpaired surrogate = %q, want replacement rune", got)
	}
}

func TestExtractUserWindowsPreservesUnicodeWhitespaceTrimming(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"\u2003\t alpha\u2003beta \u3000\n"}]}`)
	current, history := ExtractUserWindows(body, "/v1/chat/completions", 1024)
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
	if got := strings.Join(current, "\n"); got != "alpha\u2003beta" {
		t.Fatalf("current = %q, want trimmed Unicode whitespace with internal space preserved", got)
	}

	whitespaceOnly := []byte(`{"messages":[{"role":"user","content":"\u2003\t \u3000\n"}]}`)
	current, history = ExtractUserWindows(whitespaceOnly, "/v1/chat/completions", 1024)
	if len(current) != 0 || len(history) != 0 {
		t.Fatalf("whitespace-only windows = current %q history %q, want empty", current, history)
	}
}

func TestExtractUserWindowsHugeScalarKeepsActualTailWithinBudget(t *testing.T) {
	const maxBytes = 128
	body := []byte(`{"input":"HEAD_MARKER_` +
		strings.Repeat("a", 3*1024*1024) +
		`_ACTUAL_USER_TAIL"}`)
	current, history := ExtractUserWindows(body, "/v1/responses", maxBytes)
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
	if len(current) != 2 {
		t.Fatalf("current windows = %d, want separate head and tail: %q", len(current), current)
	}
	if !strings.Contains(current[0], "HEAD_MARKER") {
		t.Fatalf("head window lost marker: %q", current[0])
	}
	if !strings.Contains(current[1], "ACTUAL_USER_TAIL") {
		t.Fatalf("tail window lost actual user text: %q", current[1])
	}
	total := 0
	for _, window := range current {
		total += len(window)
	}
	if total > maxBytes {
		t.Fatalf("bounded windows total = %d, want <= %d", total, maxBytes)
	}
}

func TestExtractUserWindowsNeverMatchesAcrossTruncatedHole(t *testing.T) {
	body := []byte(`{"input":"LEFT_BOUNDARY_` +
		strings.Repeat("x", 1024) +
		`_RIGHT_BOUNDARY"}`)
	current, _ := ExtractUserWindows(body, "/v1/responses", 64)
	if len(current) != 2 {
		t.Fatalf("current windows = %d, want 2: %q", len(current), current)
	}
	crossHole := regexp.MustCompile(`LEFT_BOUNDARY(?s:.*)RIGHT_BOUNDARY`)
	for index, window := range current {
		if crossHole.MatchString(window) {
			t.Fatalf("window %d bridged omitted middle: %q", index, window)
		}
	}
	if !strings.Contains(current[0], "LEFT_BOUNDARY") ||
		!strings.Contains(current[1], "RIGHT_BOUNDARY") {
		t.Fatalf("expected boundary evidence in independent windows: %q", current)
	}
}

func TestExtractUserWindowsToolOnlyContinuationHasNoCurrentUser(t *testing.T) {
	body := []byte(`{
		"input":[
			{"role":"user","content":"PREVIOUS_USER"},
			{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
			{"type":"function_call_output","call_id":"call_1","output":"TOOL_EXCLUDED"}
		]
	}`)
	current, history := ExtractUserWindows(body, "/v1/responses", 1024)
	if len(current) != 0 {
		t.Fatalf("tool-only current = %q, want empty", current)
	}
	if got := strings.Join(history, "\n"); got != "PREVIOUS_USER" {
		t.Fatalf("history = %q, want PREVIOUS_USER", got)
	}
}

func TestExtractRoutingWindowsOversizedToolOnlyContinuations(t *testing.T) {
	const maxBytes = 128
	toolOutput := "HEAD_TOOL_" + strings.Repeat("z", 1024*1024) + "_ACTUAL_TOOL_TAIL"
	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "responses function call output",
			endpoint: "/v1/responses",
			body: `{"input":[
				{"role":"user","content":"PREVIOUS_USER"},
				{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
				{"type":"function_call_output","call_id":"call_1","output":"` + toolOutput + `"}
			]}`,
		},
		{
			name:     "chat tool role",
			endpoint: "/v1/chat/completions",
			body: `{"messages":[
				{"role":"user","content":"PREVIOUS_USER"},
				{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
				{"role":"tool","tool_call_id":"call_1","content":"` + toolOutput + `"}
			]}`,
		},
		{
			name:     "messages user tool result",
			endpoint: "/v1/messages",
			body: `{"messages":[
				{"role":"user","content":"PREVIOUS_USER"},
				{"role":"assistant","content":"ASSISTANT_EXCLUDED"},
				{"role":"user","content":[
					{"type":"tool_result","tool_use_id":"call_1","content":"` + toolOutput + `"}
				]}
			]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			learningCurrent, learningHistory := ExtractUserWindows(
				[]byte(test.body),
				test.endpoint,
				maxBytes,
			)
			if len(learningCurrent) != 0 {
				t.Fatalf("learning current = %q, want empty", learningCurrent)
			}
			if got := strings.Join(learningHistory, "\n"); got != "PREVIOUS_USER" {
				t.Fatalf("learning history = %q, want only PREVIOUS_USER", got)
			}

			current, history, tool := ExtractRoutingWindows(
				[]byte(test.body),
				test.endpoint,
				maxBytes,
			)
			if len(current) != 0 {
				t.Fatalf("routing current = %q, want empty", current)
			}
			if got := strings.Join(history, "\n"); got != "PREVIOUS_USER" {
				t.Fatalf("routing history = %q, want PREVIOUS_USER", got)
			}
			if len(tool) != 2 {
				t.Fatalf("tool windows = %d, want separate head and tail: %q", len(tool), tool)
			}
			if !strings.Contains(tool[0], "HEAD_TOOL") ||
				!strings.Contains(tool[1], "ACTUAL_TOOL_TAIL") {
				t.Fatalf("bounded tool windows lost head or tail: %q", tool)
			}
			total := 0
			for _, window := range tool {
				total += len(window)
			}
			if total > maxBytes {
				t.Fatalf("tool windows total = %d, want <= %d", total, maxBytes)
			}
		})
	}
}

func TestExtractRoutingWindowsToolOutputRequiresNoCurrentUser(t *testing.T) {
	body := []byte(`{"input":[
		{"type":"function_call_output","call_id":"call_1","output":"TOOL_EXCLUDED"},
		{"type":"input_text","text":"ACTUAL_CURRENT_USER"}
	]}`)
	current, history, tool := ExtractRoutingWindows(body, "/v1/responses", 1024)
	if got := strings.Join(current, "\n"); got != "ACTUAL_CURRENT_USER" {
		t.Fatalf("current = %q, want ACTUAL_CURRENT_USER", got)
	}
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
	if len(tool) != 0 {
		t.Fatalf("tool = %q, want empty when current user exists", tool)
	}
}

func TestExtractRoutingWindowsRoleToolPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","content":"PREVIOUS_USER"},
		{"role":"tool","content":"CANONICAL_TOOL_CONTENT","output":"BENIGN_FALLBACK"}
	]}`)
	current, history, tool := ExtractRoutingWindows(body, "/v1/chat/completions", 1024)
	if len(current) != 0 {
		t.Fatalf("current = %q, want empty", current)
	}
	if got := strings.Join(history, "\n"); got != "PREVIOUS_USER" {
		t.Fatalf("history = %q, want PREVIOUS_USER", got)
	}
	if got := strings.Join(tool, "\n"); got != "CANONICAL_TOOL_CONTENT" {
		t.Fatalf("tool = %q, want canonical content before output fallback", got)
	}
}

func TestExtractUserWindowsRoleUserPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"messages":[
		{"role":"user","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
	]}`)
	current, history := ExtractUserWindows(body, "/v1/chat/completions", 1024)
	if got := strings.Join(current, "\n"); got != "ACTUAL_USER_CONTENT" {
		t.Fatalf("current = %q, want canonical content", got)
	}
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
}

func TestExtractUserWindowsTypedInputPrefersCanonicalContent(t *testing.T) {
	body := []byte(`{"input":[
		{"type":"input_text","text":"FIXED_TRANSPORT_PREFIX","content":"ACTUAL_USER_CONTENT"}
	]}`)
	current, history := ExtractUserWindows(body, "/v1/responses", 1024)
	if got := strings.Join(current, "\n"); got != "ACTUAL_USER_CONTENT" {
		t.Fatalf("current = %q, want canonical typed content", got)
	}
	if len(history) != 0 {
		t.Fatalf("history = %q, want empty", history)
	}
}

func TestExtractRoutingWindowsRejectsInvalidToolMetadata(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "responses duplicate type",
			endpoint: "/v1/responses",
			body:     `{"input":[{"type":"function_call_output","type":"message","output":"NON_USER"}]}`,
		},
		{
			name:     "chat duplicate role",
			endpoint: "/v1/chat/completions",
			body:     `{"messages":[{"role":"tool","role":"user","content":"NON_USER"}]}`,
		},
		{
			name:     "messages non-string tool type",
			endpoint: "/v1/messages",
			body:     `{"messages":[{"role":"user","content":[{"type":123,"content":"NON_USER"}]}]}`,
		},
		{
			name:     "unknown outer role",
			endpoint: "/v1/chat/completions",
			body:     `{"messages":[{"role":"future_role","content":[{"type":"tool_result","content":"NON_USER"}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current, history, tool := ExtractRoutingWindows(
				[]byte(test.body),
				test.endpoint,
				1024,
			)
			if len(current) != 0 || len(history) != 0 || len(tool) != 0 {
				t.Fatalf(
					"invalid tool metadata leaked: current=%q history=%q tool=%q",
					current,
					history,
					tool,
				)
			}
		})
	}
}

func TestExtractWindowsMatchesOfficialRoleAndFirstKeyPrecedence(t *testing.T) {
	current, history := ExtractUserWindows(
		[]byte(`{"messages":[
			{"role":"user","content":"FIRST_USER_CONTENT","content":"SECOND_IGNORED"},
			{"role":"user","type":"future_message","content":"CURRENT_USER_CONTENT"}
		]}`),
		"/v1/chat/completions",
		1024,
	)
	if got := strings.Join(current, "\n"); got != "CURRENT_USER_CONTENT" {
		t.Fatalf("current = %q, want role-first current content", got)
	}
	if got := strings.Join(history, "\n"); got != "FIRST_USER_CONTENT" {
		t.Fatalf("history = %q, want first duplicate-key value", got)
	}

	current, history, tool := ExtractRoutingWindows(
		[]byte(`{"messages":[
			{"role":"user","content":"PREVIOUS_USER"},
			{"role":"user","type":"future_message","content":[
				{"type":"tool_result","content":"TOOL_FROM_ROLE_MESSAGE"}
			]}
		]}`),
		"/v1/messages",
		1024,
	)
	if len(current) != 0 || strings.Join(history, "\n") != "PREVIOUS_USER" {
		t.Fatalf("role precedence user windows = current %q history %q", current, history)
	}
	if got := strings.Join(tool, "\n"); got != "TOOL_FROM_ROLE_MESSAGE" {
		t.Fatalf("tool = %q, want nested tool result despite outer advisory type", got)
	}
}

func BenchmarkExtractUserWindowsHugeScalar(b *testing.B) {
	for _, test := range []struct {
		name string
		size int
	}{
		{name: "3MiB", size: 3 * 1024 * 1024},
		{name: "35MiB", size: 35 * 1024 * 1024},
	} {
		b.Run(test.name, func(b *testing.B) {
			body := []byte(`{"input":"HEAD_` +
				strings.Repeat("x", test.size) +
				`_ACTUAL_USER_TAIL"}`)
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for range b.N {
				benchmarkUserWindowsCurrent, benchmarkUserWindowsHistory =
					ExtractUserWindows(body, "/v1/responses", 128*1024)
			}
			b.StopTimer()
			if len(benchmarkUserWindowsCurrent) != 2 ||
				!strings.Contains(benchmarkUserWindowsCurrent[1], "ACTUAL_USER_TAIL") {
				b.Fatalf("tail window missing after benchmark: %q", benchmarkUserWindowsCurrent)
			}
		})
	}
}
