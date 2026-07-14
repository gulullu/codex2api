package promptfilter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func partitionText(t *testing.T, scan RoutingPayloadPartitions, name string) string {
	t.Helper()
	for _, partition := range scan.Partitions {
		if partition.Name == name {
			return partition.Text
		}
	}
	t.Fatalf("partition %q not found: %+v", name, scan.Partitions)
	return ""
}

func TestExtractRoutingPartitionsEndpointCoverage(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		body     string
	}{
		{
			name:     "responses",
			endpoint: "/v1/responses",
			body:     `{"instructions":"SYSTEM_MARKER","input":[{"role":"user","content":[{"type":"input_text","text":"USER_MARKER"}]},{"role":"assistant","content":[{"type":"output_text","text":"OTHER_MARKER"}]}],"tools":[{"name":"TOOL_MARKER"}],"skills":[{"instructions":"SKILL_MARKER"}]}`,
		},
		{
			name:     "responses_compact",
			endpoint: "/v1/responses/compact",
			body:     `{"instructions":"SYSTEM_MARKER","input":"USER_MARKER","tools":[{"description":"TOOL_MARKER"}],"messages":[{"role":"assistant","content":"OTHER_MARKER"}]}`,
		},
		{
			name:     "chat",
			endpoint: "/v1/chat/completions",
			body:     `{"messages":[{"role":"system","content":"SYSTEM_MARKER"},{"role":"assistant","content":"OTHER_MARKER"},{"role":"user","content":"USER_MARKER"}],"functions":[{"description":"TOOL_MARKER"}]}`,
		},
		{
			name:     "anthropic",
			endpoint: "/v1/messages",
			body:     `{"system":"SYSTEM_MARKER","messages":[{"role":"assistant","content":"OTHER_MARKER"},{"role":"user","content":[{"type":"text","text":"USER_MARKER"}]}],"tools":[{"description":"TOOL_MARKER"}]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scan := ExtractRoutingPartitions([]byte(tc.body), tc.endpoint)
			if scan.Version != RoutingPartitionScanVersion || scan.PayloadBytes != len(tc.body) || !scan.ValidJSON || !scan.Supported {
				t.Fatalf("metadata = %+v", scan)
			}
			for partition, marker := range map[string]string{
				RoutingPartitionUser:   "USER_MARKER",
				RoutingPartitionSystem: "SYSTEM_MARKER",
				RoutingPartitionTools:  "TOOL_MARKER",
				RoutingPartitionOther:  "OTHER_MARKER",
			} {
				got := partitionText(t, scan, partition)
				if !strings.Contains(got, marker) {
					t.Fatalf("%s = %q, want %s", partition, got, marker)
				}
			}
			if strings.Contains(partitionText(t, scan, RoutingPartitionUser), "SYSTEM_MARKER") {
				t.Fatal("system text leaked into user partition")
			}
		})
	}
}

func TestExtractRoutingPartitionsInvalidAndUnsupportedPayloadMetadata(t *testing.T) {
	invalid := ExtractRoutingPartitions([]byte(`{"input":"unterminated"`), "/v1/responses")
	if invalid.ValidJSON || invalid.Supported || invalid.ScannedBytes != 0 {
		t.Fatalf("invalid JSON metadata = %+v", invalid)
	}
	unsupported := ExtractRoutingPartitions([]byte(`{"unknown":"readable but unsupported"}`), "/v1/responses")
	if !unsupported.ValidJSON || unsupported.Supported || unsupported.ScannedBytes != 0 {
		t.Fatalf("unsupported payload metadata = %+v", unsupported)
	}
}

func TestExtractRoutingPartitionsEnforcesFixedBudgetsAndFairTools(t *testing.T) {
	tools := make([]map[string]any, 4)
	for index := range tools {
		tools[index] = map[string]any{
			"name":        fmt.Sprintf("TOOL_%d_BEGIN", index),
			"description": strings.Repeat(fmt.Sprintf("tool-%d-doc ", index), 5000) + fmt.Sprintf("TOOL_%d_END", index),
		}
	}
	body, err := json.Marshal(map[string]any{
		"instructions": "SYSTEM_BEGIN " + strings.Repeat("system-doc ", 8000) + " SYSTEM_END",
		"input": []any{
			map[string]any{"role": "user", "content": "OLDER_USER " + strings.Repeat("older ", 12000)},
			map[string]any{"role": "assistant", "content": "OTHER_BEGIN " + strings.Repeat("history ", 8000) + " OTHER_END"},
			map[string]any{"role": "user", "content": "LATEST_USER_BEGIN " + strings.Repeat("current ", 12000) + " LATEST_USER_END"},
		},
		"tools": tools,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	scan := ExtractRoutingPartitions(body, "/v1/responses")
	if scan.ScannedBytes > RoutingTotalScanBudget {
		t.Fatalf("scanned_bytes = %d, budget = %d", scan.ScannedBytes, RoutingTotalScanBudget)
	}
	if !scan.ScanTruncated {
		t.Fatal("large payload did not report truncation")
	}
	for _, partition := range scan.Partitions {
		if partition.ScannedBytes > partition.BudgetBytes || len(partition.Text) != partition.ScannedBytes {
			t.Fatalf("partition exceeded budget: %+v", partition)
		}
		if !utf8.ValidString(partition.Text) {
			t.Fatalf("partition %s contains invalid UTF-8", partition.Name)
		}
	}
	userText := partitionText(t, scan, RoutingPartitionUser)
	for _, marker := range []string{"LATEST_USER_BEGIN", "LATEST_USER_END"} {
		if !strings.Contains(userText, marker) {
			t.Fatalf("latest user text lost %s", marker)
		}
	}
	toolText := partitionText(t, scan, RoutingPartitionTools)
	for index := range tools {
		for _, marker := range []string{fmt.Sprintf("TOOL_%d_BEGIN", index), fmt.Sprintf("TOOL_%d_END", index)} {
			if !strings.Contains(toolText, marker) {
				t.Fatalf("fair tool scan lost %s", marker)
			}
		}
	}
}

func TestExtractRoutingPartitionsCountsButNeverScansOpaqueValuesOrMutatesBody(t *testing.T) {
	ciphertext := strings.Repeat("ENCRYPTED_SENTINEL_", 5000)
	binary := strings.Repeat("BASE64_SENTINEL_", 5000)
	body, err := json.Marshal(map[string]any{
		"instructions": "SYSTEM_VISIBLE",
		"input": []any{
			map[string]any{"type": "reasoning", "encrypted_content": ciphertext, "summary": []any{map[string]any{"type": "summary_text", "text": "READABLE_SUMMARY"}}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "input_text", "text": "USER_VISIBLE"},
				map[string]any{"type": "input_image", "source": map[string]any{"type": "base64", "data": binary}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	before := sha256.Sum256(body)
	scan := ExtractRoutingPartitions(body, "/v1/responses")
	after := sha256.Sum256(body)
	if before != after {
		t.Fatal("extractor mutated original request bytes")
	}
	if scan.OpaqueBytes < len(ciphertext)+len(binary) {
		t.Fatalf("opaque_bytes = %d, want at least %d", scan.OpaqueBytes, len(ciphertext)+len(binary))
	}
	for _, partition := range scan.Partitions {
		for _, sentinel := range []string{"ENCRYPTED_SENTINEL", "BASE64_SENTINEL"} {
			if strings.Contains(partition.Text, sentinel) {
				t.Fatalf("partition %s leaked %s", partition.Name, sentinel)
			}
		}
	}
	if !strings.Contains(partitionText(t, scan, RoutingPartitionOther), "READABLE_SUMMARY") {
		t.Fatal("readable reasoning summary was not retained in other partition")
	}
}

func TestExtractRoutingPartitionsScansOrdinaryDataSourceAndURLToolFields(t *testing.T) {
	body := []byte(`{"tools":[{"name":"field_test","data":"DATA_FIELD_MARKER","source":"SOURCE_FIELD_MARKER","url":"URL_FIELD_MARKER","parameters":{"properties":{"payload":{"description":"SCHEMA_MARKER"}}}}]}`)
	scan := ExtractRoutingPartitions(body, "/v1/responses")
	toolText := partitionText(t, scan, RoutingPartitionTools)
	for _, marker := range []string{"DATA_FIELD_MARKER", "SOURCE_FIELD_MARKER", "URL_FIELD_MARKER", "SCHEMA_MARKER"} {
		if !strings.Contains(toolText, marker) {
			t.Fatalf("ordinary tool field %s was treated as opaque: %q", marker, toolText)
		}
	}
	if scan.OpaqueBytes != 0 {
		t.Fatalf("ordinary tool fields counted as opaque: %d", scan.OpaqueBytes)
	}
}

func TestBuildFairPartitionSamplesBothEndsWhenToolCountExceedsBudget(t *testing.T) {
	segments := make([]string, RoutingToolsScanBudget+1000)
	for index := range segments {
		segments[index] = fmt.Sprintf("tool_%05d", index)
	}
	segments[0] = "HEAD_TOOL_MARKER"
	segments[len(segments)-1] = "TAIL_TOOL_MARKER"
	partition := buildFairPartition(RoutingPartitionTools, RoutingToolsScanBudget, segments)
	for _, marker := range []string{"HEAD_TOOL_MARKER", "TAIL_TOOL_MARKER"} {
		if !strings.Contains(partition.Text, marker) {
			t.Fatalf("extreme tool sampling lost %s", marker)
		}
	}
	if partition.ScannedBytes > RoutingToolsScanBudget || !partition.Truncated {
		t.Fatalf("extreme tool partition metadata = %+v", partition)
	}
}

func TestPartitionSourceBytesCountPreDedupReadableText(t *testing.T) {
	partition := buildOrderedPartition(RoutingPartitionSystem, 1024, []string{"duplicate", "duplicate"})
	if partition.SourceBytes != len("duplicate\nduplicate") {
		t.Fatalf("source bytes = %d", partition.SourceBytes)
	}
	if partition.ScannedBytes != len("duplicate") || !partition.Truncated {
		t.Fatalf("dedup scan metadata = %+v", partition)
	}
}

func BenchmarkExtractRoutingPartitionsLargeResponses(b *testing.B) {
	body, err := json.Marshal(map[string]any{
		"instructions": strings.Repeat("system documentation ", 15000),
		"input": []any{
			map[string]any{"type": "reasoning", "encrypted_content": strings.Repeat("ciphertext", 80000)},
			map[string]any{"role": "user", "content": strings.Repeat("current request ", 10000)},
			map[string]any{"type": "function_call_output", "output": strings.Repeat("tool output ", 20000)},
		},
		"tools": []any{map[string]any{"description": strings.Repeat("tool schema ", 30000)}},
	})
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		scan := ExtractRoutingPartitions(body, "/v1/responses")
		if scan.ScannedBytes > RoutingTotalScanBudget {
			b.Fatalf("scan exceeded budget: %d", scan.ScannedBytes)
		}
	}
}
