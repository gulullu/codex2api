package promptfilter

import (
	"strings"
	"unicode/utf8"

	"github.com/tidwall/gjson"
)

// RoutingPartitionScanVersion is persisted with prompt-filter audit metadata so
// readers can remain compatible when the partition layout evolves.
const RoutingPartitionScanVersion = 1

const (
	RoutingPartitionUser   = "user"
	RoutingPartitionSystem = "system"
	RoutingPartitionTools  = "tools_skills"
	RoutingPartitionOther  = "other"

	RoutingUserScanBudget   = 64 * 1024
	RoutingSystemScanBudget = 32 * 1024
	RoutingToolsScanBudget  = 32 * 1024
	RoutingOtherScanBudget  = 32 * 1024
	RoutingTotalScanBudget  = RoutingUserScanBudget + RoutingSystemScanBudget + RoutingToolsScanBudget + RoutingOtherScanBudget
)

// RoutingTextPartition contains the bounded text sent to the local rule
// engine. SourceBytes describes readable text before the per-partition cap;
// opaque values are never copied into Text.
type RoutingTextPartition struct {
	Name         string `json:"name"`
	BudgetBytes  int    `json:"budget_bytes"`
	SourceBytes  int    `json:"source_bytes"`
	ScannedBytes int    `json:"scanned_bytes"`
	Truncated    bool   `json:"truncated"`
	Text         string `json:"-"`
}

// RoutingPayloadPartitions is a read-only extraction result. PayloadBytes and
// OpaqueBytes are byte counts only; the original request body is never changed.
type RoutingPayloadPartitions struct {
	Version       int                    `json:"version"`
	PayloadBytes  int                    `json:"payload_bytes"`
	ValidJSON     bool                   `json:"valid_json"`
	Supported     bool                   `json:"supported_payload"`
	ScannedBytes  int                    `json:"scanned_bytes"`
	ScanTruncated bool                   `json:"scan_truncated"`
	OpaqueBytes   int                    `json:"opaque_bytes"`
	Partitions    []RoutingTextPartition `json:"partitions"`
}

// ExtractRoutingPartitions assigns every supported readable prompt field to a
// fixed-budget compartment. It intentionally does not concatenate compartments
// for scoring: callers must inspect each Text independently.
func ExtractRoutingPartitions(body []byte, endpoint string) RoutingPayloadPartitions {
	result := RoutingPayloadPartitions{
		Version:      RoutingPartitionScanVersion,
		PayloadBytes: len(body),
		Partitions: []RoutingTextPartition{
			{Name: RoutingPartitionUser, BudgetBytes: RoutingUserScanBudget},
			{Name: RoutingPartitionSystem, BudgetBytes: RoutingSystemScanBudget},
			{Name: RoutingPartitionTools, BudgetBytes: RoutingToolsScanBudget},
			{Name: RoutingPartitionOther, BudgetBytes: RoutingOtherScanBudget},
		},
	}
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return result
	}
	result.ValidJSON = true

	root := gjson.ParseBytes(body)
	result.Supported = hasSupportedRoutingField(root)
	result.OpaqueBytes = countOpaqueJSONBytes(root)

	var userSegments []string
	var systemSegments []string
	var toolSegments []string
	var otherSegments []string

	for _, field := range []string{"instructions", "system"} {
		appendSafeResultSegment(root.Get(field), &systemSegments)
	}
	for _, field := range []string{"tools", "functions", "skills", "tool_choice"} {
		appendFairSegments(root.Get(field), &toolSegments)
	}
	collectConversationPartitions(root.Get("messages"), false, &userSegments, &systemSegments, &otherSegments)
	collectConversationPartitions(root.Get("input"), true, &userSegments, &systemSegments, &otherSegments)
	appendSafeResultSegment(root.Get("prompt"), &userSegments)

	result.Partitions[0] = buildLatestFirstPartition(RoutingPartitionUser, RoutingUserScanBudget, userSegments)
	result.Partitions[1] = buildOrderedPartition(RoutingPartitionSystem, RoutingSystemScanBudget, systemSegments)
	result.Partitions[2] = buildFairPartition(RoutingPartitionTools, RoutingToolsScanBudget, toolSegments)
	result.Partitions[3] = buildLatestFirstPartition(RoutingPartitionOther, RoutingOtherScanBudget, otherSegments)
	for _, partition := range result.Partitions {
		result.ScannedBytes += partition.ScannedBytes
		result.ScanTruncated = result.ScanTruncated || partition.Truncated
	}
	return result
}

func hasSupportedRoutingField(root gjson.Result) bool {
	for _, field := range []string{
		"instructions", "system", "tools", "functions", "skills",
		"tool_choice", "messages", "input", "prompt",
	} {
		if root.Get(field).Exists() {
			return true
		}
	}
	return false
}

func collectConversationPartitions(result gjson.Result, directStringIsUser bool, user, system, other *[]string) {
	if !result.Exists() || result.Type == gjson.Null {
		return
	}
	if result.IsArray() {
		for _, item := range result.Array() {
			collectConversationPartitions(item, directStringIsUser, user, system, other)
		}
		return
	}
	if result.Type == gjson.String {
		if directStringIsUser {
			appendTextSegment(result.String(), user)
		} else {
			appendTextSegment(result.String(), other)
		}
		return
	}
	if !result.IsObject() || isOpaqueObject(result) {
		return
	}

	role := strings.ToLower(strings.TrimSpace(result.Get("role").String()))
	switch role {
	case "user":
		appendTextSegment(routingVisibleMessageText(result), user)
		return
	case "system", "developer":
		appendSafeMessageText(result, system)
		return
	case "assistant", "tool", "function":
		appendSafeMessageText(result, other)
		return
	}

	typeName := strings.ToLower(strings.TrimSpace(result.Get("type").String()))
	switch typeName {
	case "input_text", "text":
		appendSafeMessageText(result, user)
	default:
		appendSafeResultSegment(result, other)
	}
}

func appendSafeMessageText(message gjson.Result, segments *[]string) {
	var parts []string
	for _, field := range []string{"content", "text", "input_text", "output_text", "output", "summary"} {
		collectSafeGJSONText(message.Get(field), &parts)
	}
	appendTextSegment(strings.Join(parts, "\n"), segments)
}

func appendFairSegments(result gjson.Result, segments *[]string) {
	if !result.Exists() || result.Type == gjson.Null {
		return
	}
	if result.IsArray() {
		for _, item := range result.Array() {
			appendSafeResultSegment(item, segments)
		}
		return
	}
	appendSafeResultSegment(result, segments)
}

func appendSafeResultSegment(result gjson.Result, segments *[]string) {
	var parts []string
	collectSafeGJSONText(result, &parts)
	appendTextSegment(strings.Join(parts, "\n"), segments)
}

func appendTextSegment(text string, segments *[]string) {
	text = strings.TrimSpace(text)
	if text != "" {
		*segments = append(*segments, text)
	}
}

func collectSafeGJSONText(result gjson.Result, parts *[]string) {
	if !result.Exists() || result.Type == gjson.Null || isOpaqueObject(result) {
		return
	}
	switch {
	case result.IsArray():
		for _, item := range result.Array() {
			collectSafeGJSONText(item, parts)
		}
	case result.IsObject():
		result.ForEach(func(key, value gjson.Result) bool {
			name := strings.ToLower(strings.TrimSpace(key.String()))
			if name == "type" || name == "role" || isAlwaysOpaqueField(name) {
				return true
			}
			collectSafeGJSONText(value, parts)
			return true
		})
	case result.Type == gjson.String:
		appendTextSegment(result.String(), parts)
	}
}

func countOpaqueJSONBytes(result gjson.Result) int {
	if !result.Exists() || result.Type == gjson.Null {
		return 0
	}
	if isOpaqueObject(result) {
		return rawResultBytes(result)
	}
	if result.IsArray() {
		total := 0
		for _, item := range result.Array() {
			total += countOpaqueJSONBytes(item)
		}
		return total
	}
	if !result.IsObject() {
		return 0
	}
	total := 0
	result.ForEach(func(key, value gjson.Result) bool {
		if isAlwaysOpaqueField(strings.ToLower(strings.TrimSpace(key.String()))) {
			total += rawResultBytes(value)
			return true
		}
		total += countOpaqueJSONBytes(value)
		return true
	})
	return total
}

func isOpaqueObject(result gjson.Result) bool {
	if !result.IsObject() {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(result.Get("type").String())) {
	case "image", "image_url", "input_image", "output_image", "audio", "input_audio", "output_audio", "file", "input_file", "computer_screenshot", "screenshot":
		return true
	default:
		return false
	}
}

func isAlwaysOpaqueField(name string) bool {
	switch name {
	case "encrypted_content", "b64_json", "file_data", "bytes", "binary", "blob":
		return true
	default:
		return false
	}
}

func rawResultBytes(result gjson.Result) int {
	if result.Raw != "" {
		return len(result.Raw)
	}
	return len(result.String())
}

func buildLatestFirstPartition(name string, budget int, segments []string) RoutingTextPartition {
	sourceSegments := normalizedTextSegments(segments)
	sourceBytes := joinedSourceBytes(sourceSegments)
	segments = uniqueTextSegments(sourceSegments)
	remaining := budget
	selected := make([]string, 0, len(segments))
	for index := len(segments) - 1; index >= 0 && remaining > 0; index-- {
		separator := 0
		if len(selected) > 0 {
			separator = 1
		}
		if remaining <= separator {
			break
		}
		text := segments[index]
		pieceBudget := remaining - separator
		piece := text
		if len(piece) > pieceBudget {
			piece = boundedHeadTail(piece, pieceBudget)
		}
		if piece == "" {
			continue
		}
		selected = append(selected, piece)
		remaining -= separator + len(piece)
		if len(piece) < len(text) {
			break
		}
	}
	text := strings.Join(selected, "\n")
	return RoutingTextPartition{Name: name, BudgetBytes: budget, SourceBytes: sourceBytes, ScannedBytes: len(text), Truncated: len(text) < sourceBytes, Text: text}
}

func buildOrderedPartition(name string, budget int, segments []string) RoutingTextPartition {
	sourceSegments := normalizedTextSegments(segments)
	sourceBytes := joinedSourceBytes(sourceSegments)
	segments = uniqueTextSegments(sourceSegments)
	source := strings.Join(segments, "\n")
	text := boundedHeadTail(source, budget)
	return RoutingTextPartition{Name: name, BudgetBytes: budget, SourceBytes: sourceBytes, ScannedBytes: len(text), Truncated: len(text) < sourceBytes, Text: text}
}

func buildFairPartition(name string, budget int, segments []string) RoutingTextPartition {
	sourceSegments := normalizedTextSegments(segments)
	sourceBytes := joinedSourceBytes(sourceSegments)
	segments = uniqueTextSegments(sourceSegments)
	if len(segments) == 0 || budget <= 0 {
		return RoutingTextPartition{Name: name, BudgetBytes: budget, SourceBytes: sourceBytes, Truncated: sourceBytes > 0}
	}

	separatorBytes := len(segments) - 1
	if separatorBytes >= budget {
		segments = sampleHeadTailSegments(segments, fairSegmentLimit(budget))
		separatorBytes = len(segments) - 1
	}
	available := budget - separatorBytes
	allocations := fairByteAllocations(segments, available)
	selected := make([]string, 0, len(segments))
	for index, segment := range segments {
		if allocations[index] <= 0 {
			continue
		}
		selected = append(selected, boundedHeadTail(segment, allocations[index]))
	}
	text := strings.Join(selected, "\n")
	return RoutingTextPartition{Name: name, BudgetBytes: budget, SourceBytes: sourceBytes, ScannedBytes: len(text), Truncated: len(text) < sourceBytes, Text: text}
}

const minimumFairSegmentBytes = 32

func fairSegmentLimit(budget int) int {
	if budget <= 0 {
		return 0
	}
	limit := (budget + 1) / (minimumFairSegmentBytes + 1)
	if limit < 1 {
		return 1
	}
	return limit
}

// sampleHeadTailSegments deterministically alternates from the beginning and
// end, then restores source order. This prevents very large tool arrays from
// making every later tool permanently invisible.
func sampleHeadTailSegments(segments []string, limit int) []string {
	if limit <= 0 || len(segments) == 0 {
		return nil
	}
	if len(segments) <= limit {
		return segments
	}
	selected := make([]bool, len(segments))
	left, right := 0, len(segments)-1
	count := 0
	for count < limit && left <= right {
		selected[left] = true
		left++
		count++
		if count < limit && left <= right {
			selected[right] = true
			right--
			count++
		}
	}
	result := make([]string, 0, count)
	for index, segment := range segments {
		if selected[index] {
			result = append(result, segment)
		}
	}
	return result
}

func fairByteAllocations(segments []string, budget int) []int {
	allocations := make([]int, len(segments))
	active := make([]int, 0, len(segments))
	for index, segment := range segments {
		if segment != "" {
			active = append(active, index)
		}
	}
	remaining := budget
	for remaining > 0 && len(active) > 0 {
		share := remaining / len(active)
		if share <= 0 {
			share = 1
		}
		next := active[:0]
		for _, index := range active {
			need := len(segments[index]) - allocations[index]
			give := share
			if give > need {
				give = need
			}
			if give > remaining {
				give = remaining
			}
			allocations[index] += give
			remaining -= give
			if allocations[index] < len(segments[index]) {
				next = append(next, index)
			}
			if remaining == 0 {
				break
			}
		}
		active = next
	}
	return allocations
}

func uniqueTextSegments(segments []string) []string {
	seen := make(map[string]struct{}, len(segments))
	result := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if _, ok := seen[segment]; ok {
			continue
		}
		seen[segment] = struct{}{}
		result = append(result, segment)
	}
	return result
}

func normalizedTextSegments(segments []string) []string {
	result := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			result = append(result, segment)
		}
	}
	return result
}

func joinedSourceBytes(segments []string) int {
	if len(segments) == 0 {
		return 0
	}
	total := len(segments) - 1
	for _, segment := range segments {
		total += len(segment)
	}
	return total
}

func boundedHeadTail(text string, budget int) string {
	if budget <= 0 || text == "" {
		return ""
	}
	if len(text) <= budget {
		return text
	}
	if budget == 1 {
		return safeUTF8Prefix(text, budget)
	}
	headBudget := (budget - 1) * 4 / 5
	tailBudget := budget - 1 - headBudget
	head := safeUTF8Prefix(text, headBudget)
	tail := safeUTF8Suffix(text, tailBudget)
	for len(head)+1+len(tail) > budget {
		if len(tail) > 0 {
			tail = safeUTF8Suffix(tail, len(tail)-1)
		} else if len(head) > 0 {
			head = safeUTF8Prefix(head, len(head)-1)
		} else {
			break
		}
	}
	if !utf8.ValidString(head) || !utf8.ValidString(tail) {
		return safeUTF8Prefix(text, budget)
	}
	return head + "\n" + tail
}
