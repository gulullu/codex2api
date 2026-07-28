package cybtext

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// ExtractUserWindows returns independently bounded scan windows for the
// current user turn and prior user-authored history. Text that exceeds
// maxBytes is represented by separate head and tail windows; callers must scan
// each returned string independently so a match cannot bridge the omitted
// middle.
//
// The extractor walks the original JSON bytes and incrementally decodes only
// bounded windows. It never materializes a complete oversized JSON string.
func ExtractUserWindows(rawBody []byte, endpoint string, maxBytes int) (current, history []string) {
	current, history, _ = extractBoundedWindows(rawBody, endpoint, maxBytes, false)
	return current, history
}

// ExtractRoutingWindows returns the same user-authored windows as
// ExtractUserWindows plus bounded tool-output windows for a tool-only
// continuation. Tool output is returned only when the request has no current
// user text; callers must never use tool windows as learning samples.
func ExtractRoutingWindows(
	rawBody []byte,
	endpoint string,
	maxBytes int,
) (current, history, tool []string) {
	return extractBoundedWindows(rawBody, endpoint, maxBytes, true)
}

func extractBoundedWindows(
	rawBody []byte,
	endpoint string,
	maxBytes int,
	includeTool bool,
) (current, history, tool []string) {
	if len(rawBody) == 0 || maxBytes <= 0 || !json.Valid(rawBody) {
		return nil, nil, nil
	}
	root, ok := rootObjectFields(rawBody)
	if !ok {
		return nil, nil, nil
	}

	currentText := newBoundedText(maxBytes)
	historyText := newBoundedText(maxBytes)
	protocol := strings.ToLower(strings.TrimSpace(endpoint))
	switch protocol {
	case "/v1/responses", "/v1/responses/compact":
		appendConversationWindows(rawBody, root.input, currentText, historyText)
		appendUserValue(rawBody, root.prompt, nil, currentText, 0)
		if !currentText.hasText {
			appendConversationWindows(rawBody, root.messages, currentText, historyText)
		}
	case "/v1/chat/completions", "/v1/messages":
		appendConversationWindows(rawBody, root.messages, currentText, historyText)
	default:
		return nil, nil, nil
	}
	if includeTool && !currentText.hasText {
		toolText := newBoundedText(maxBytes)
		switch protocol {
		case "/v1/responses", "/v1/responses/compact":
			appendToolWindows(rawBody, root.input, toolText, 0)
			appendToolWindows(rawBody, root.messages, toolText, 0)
		case "/v1/chat/completions", "/v1/messages":
			appendToolWindows(rawBody, root.messages, toolText, 0)
		}
		tool = toolText.windows()
	}
	return currentText.windows(), historyText.windows(), tool
}

type rawSpan struct {
	start int
	end   int
	kind  byte
}

func (s rawSpan) exists() bool {
	return s.end > s.start
}

type rawObjectFields struct {
	role       rawSpan
	typ        rawSpan
	text       rawSpan
	content    rawSpan
	output     rawSpan
	input      rawSpan
	prompt     rawSpan
	messages   rawSpan
	roleFields int
	typeFields int
}

func rootObjectFields(body []byte) (rawObjectFields, bool) {
	start := skipJSONSpace(body, 0)
	if start >= len(body) || body[start] != '{' {
		return rawObjectFields{}, false
	}
	end := len(body)
	for end > start {
		switch body[end-1] {
		case ' ', '\t', '\n', '\r':
			end--
		default:
			if body[end-1] != '}' {
				return rawObjectFields{}, false
			}
			return readObjectFields(body, rawSpan{start: start, end: end, kind: '{'})
		}
	}
	if end <= start {
		return rawObjectFields{}, false
	}
	return readObjectFields(body, rawSpan{start: start, end: end, kind: '{'})
}

func readObjectFields(body []byte, object rawSpan) (rawObjectFields, bool) {
	var fields rawObjectFields
	if !object.exists() || object.kind != '{' {
		return fields, false
	}
	index := skipJSONSpace(body, object.start+1)
	for index < object.end-1 && body[index] != '}' {
		keyStart := index
		keyEnd := skipJSONString(body, keyStart)
		if keyEnd <= keyStart {
			return rawObjectFields{}, false
		}
		key := shortJSONString(body, rawSpan{start: keyStart, end: keyEnd, kind: '"'}, 32)
		index = skipJSONSpace(body, keyEnd)
		if index >= object.end || body[index] != ':' {
			return rawObjectFields{}, false
		}
		index = skipJSONSpace(body, index+1)
		valueEnd := skipJSONValue(body, index)
		if valueEnd <= index {
			return rawObjectFields{}, false
		}
		value := rawSpan{start: index, end: valueEnd, kind: body[index]}
		switch key {
		case "role":
			fields.roleFields++
			if fields.roleFields == 1 {
				fields.role = value
			}
		case "type":
			fields.typeFields++
			if fields.typeFields == 1 {
				fields.typ = value
			}
		case "text":
			if !fields.text.exists() {
				fields.text = value
			}
		case "content":
			if !fields.content.exists() {
				fields.content = value
			}
		case "output":
			if !fields.output.exists() {
				fields.output = value
			}
		case "input":
			if !fields.input.exists() {
				fields.input = value
			}
		case "prompt":
			if !fields.prompt.exists() {
				fields.prompt = value
			}
		case "messages":
			if !fields.messages.exists() {
				fields.messages = value
			}
		}
		index = skipJSONSpace(body, valueEnd)
		if index < object.end && body[index] == ',' {
			index = skipJSONSpace(body, index+1)
			continue
		}
		break
	}
	return fields, true
}

func skipJSONSpace(body []byte, index int) int {
	for index < len(body) {
		switch body[index] {
		case ' ', '\t', '\n', '\r':
			index++
		default:
			return index
		}
	}
	return index
}

func skipJSONString(body []byte, index int) int {
	if index >= len(body) || body[index] != '"' {
		return -1
	}
	for index++; index < len(body); index++ {
		switch body[index] {
		case '"':
			return index + 1
		case '\\':
			index++
			if index >= len(body) {
				return -1
			}
			if body[index] == 'u' {
				index += 4
				if index >= len(body) {
					return -1
				}
			}
		}
	}
	return -1
}

func skipJSONValue(body []byte, index int) int {
	index = skipJSONSpace(body, index)
	if index >= len(body) {
		return -1
	}
	switch body[index] {
	case '"':
		return skipJSONString(body, index)
	case '{', '[':
		depth := 0
		for cursor := index; cursor < len(body); cursor++ {
			switch body[cursor] {
			case '"':
				next := skipJSONString(body, cursor)
				if next < 0 {
					return -1
				}
				cursor = next - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return cursor + 1
				}
			}
		}
		return -1
	default:
		cursor := index
		for cursor < len(body) {
			switch body[cursor] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return cursor
			default:
				cursor++
			}
		}
		return cursor
	}
}

func walkJSONArray(body []byte, array rawSpan, visit func(index int, value rawSpan) bool) bool {
	if !array.exists() || array.kind != '[' {
		return false
	}
	index := skipJSONSpace(body, array.start+1)
	itemIndex := 0
	for index < array.end-1 && body[index] != ']' {
		valueEnd := skipJSONValue(body, index)
		if valueEnd <= index {
			return false
		}
		if !visit(itemIndex, rawSpan{start: index, end: valueEnd, kind: body[index]}) {
			return true
		}
		itemIndex++
		index = skipJSONSpace(body, valueEnd)
		if index < array.end && body[index] == ',' {
			index = skipJSONSpace(body, index+1)
			continue
		}
		break
	}
	return true
}

type windowInputKind uint8

const (
	windowInputNone windowInputKind = iota
	windowInputExplicitMessage
	windowInputTextBlock
	windowInputImplicitMessage
	windowInputScalar
)

type windowItemInfo struct {
	kind       windowInputKind
	fields     rawObjectFields
	closes     bool
	attachment bool
}

func classifyWindowItem(body []byte, value rawSpan) windowItemInfo {
	if value.kind == '"' {
		return windowItemInfo{kind: windowInputScalar}
	}
	if value.kind != '{' {
		return windowItemInfo{}
	}
	fields, ok := readObjectFields(body, value)
	if !ok {
		return windowItemInfo{}
	}
	role, roleState := normalizedMetadataField(body, fields.role, fields.roleFields)
	if roleState == metadataInvalid {
		return windowItemInfo{fields: fields, closes: true}
	}
	if roleState == metadataValid && role != "" {
		if role == "user" {
			return windowItemInfo{kind: windowInputExplicitMessage, fields: fields}
		}
		return windowItemInfo{
			fields: fields,
			closes: role == "assistant" || role == "tool" || role == "function",
		}
	}
	itemType, typeState := normalizedMetadataField(body, fields.typ, fields.typeFields)
	if typeState == metadataInvalid {
		return windowItemInfo{fields: fields, closes: true}
	}
	switch itemType {
	case "input_text":
		return windowItemInfo{kind: windowInputTextBlock, fields: fields}
	case "", "message":
		return windowItemInfo{kind: windowInputImplicitMessage, fields: fields}
	case "input_file", "input_image", "image_url", "file", "image", "attachment", "computer_screenshot":
		return windowItemInfo{fields: fields, attachment: true}
	default:
		return windowItemInfo{fields: fields, closes: windowTypeClosesPrompt(itemType)}
	}
}

func windowTypeClosesPrompt(itemType string) bool {
	switch itemType {
	case "output_text", "refusal",
		"function_call_output", "tool_call_output", "local_shell_call_output", "shell_call_output",
		"apply_patch_call_output", "tool_search_output", "tool_search_call_output", "custom_tool_call_output",
		"mcp_tool_call_output", "computer_call_output", "mcp_call_output", "tool_result",
		"function_call", "tool_call", "local_shell_call", "shell_call", "apply_patch_call",
		"tool_search_call", "custom_tool_call", "mcp_tool_call", "mcp_call", "mcp_list_tools",
		"mcp_approval_request", "mcp_approval_response", "additional_tools", "code_interpreter_call",
		"computer_call", "file_search_call", "image_generation_call", "web_search_call", "tool_use":
		return true
	default:
		return false
	}
}

func windowTypeIsToolOutput(itemType string) bool {
	switch itemType {
	case "function_call_output", "tool_call_output", "local_shell_call_output", "shell_call_output",
		"apply_patch_call_output", "tool_search_output", "tool_search_call_output", "custom_tool_call_output",
		"mcp_tool_call_output", "computer_call_output", "mcp_call_output", "tool_result":
		return true
	default:
		return false
	}
}

func appendConversationWindows(body []byte, value rawSpan, current, history *boundedText) {
	if !value.exists() || value.kind == 'n' {
		return
	}
	if value.kind != '[' {
		info := classifyWindowItem(body, value)
		if info.kind != windowInputNone {
			appendUserValue(body, value, &info.fields, current, 0)
		}
		return
	}
	selection := analyzeUserConversation(body, value)
	if !selection.valid {
		return
	}
	walkJSONArray(body, value, func(index int, item rawSpan) bool {
		info := classifyWindowItem(body, item)
		if info.kind == windowInputNone {
			return true
		}
		selected := false
		if !selection.closedAfterLast {
			if selection.lastKind == windowInputTextBlock {
				selected = info.kind == windowInputTextBlock &&
					index >= selection.lastTextBlockStart &&
					index <= selection.lastCandidate
			} else {
				selected = index == selection.lastCandidate
			}
		}
		target := history
		if selected {
			target = current
		}
		appendUserValue(body, item, &info.fields, target, 0)
		return true
	})
}

func appendUserValue(
	body []byte,
	value rawSpan,
	knownFields *rawObjectFields,
	target *boundedText,
	depth int,
) bool {
	if !value.exists() || depth > 64 {
		return false
	}
	switch value.kind {
	case '"':
		return target.appendJSONString(body[value.start:value.end])
	case '[':
		added := false
		walkJSONArray(body, value, func(_ int, item rawSpan) bool {
			if appendUserValue(body, item, nil, target, depth+1) {
				added = true
			}
			return true
		})
		return added
	case '{':
		fields := rawObjectFields{}
		if knownFields != nil {
			fields = *knownFields
		} else {
			var ok bool
			fields, ok = readObjectFields(body, value)
			if !ok {
				return false
			}
		}
		role, roleState := normalizedMetadataField(body, fields.role, fields.roleFields)
		if roleState == metadataInvalid ||
			(roleState == metadataValid && role != "" && role != "user") {
			return false
		}
		if roleState == metadataValid && role == "user" {
			// Keep explicit messages aligned with the official envelope
			// adapter: content is canonical and text is only a fallback.
			// Scanning both can let a transport-side fixed text field crowd
			// the real latest user content out of a bounded learning sample.
			value := firstNonNullSpan(fields.content, fields.text)
			return appendUserValue(body, value, nil, target, depth+1)
		}
		itemType, typeState := normalizedMetadataField(body, fields.typ, fields.typeFields)
		if typeState == metadataInvalid {
			return false
		}
		switch itemType {
		case "", "message", "input_text", "text":
		default:
			return false
		}
		if itemType == "message" || itemType == "input_text" {
			value := firstNonNullSpan(fields.content, fields.text)
			if appendUserValue(body, value, nil, target, depth+1) {
				return true
			}
			if itemType == "input_text" && fields.input.kind == '"' {
				return appendUserValue(body, fields.input, nil, target, depth+1)
			}
			return false
		}
		added := false
		if fields.text.kind == '"' && appendUserValue(body, fields.text, nil, target, depth+1) {
			added = true
		}
		if fields.content.exists() && appendUserValue(body, fields.content, nil, target, depth+1) {
			added = true
		}
		return added
	default:
		return false
	}
}

func appendToolWindows(body []byte, value rawSpan, target *boundedText, depth int) {
	if !value.exists() || target == nil || depth > 64 {
		return
	}
	switch value.kind {
	case '[':
		walkJSONArray(body, value, func(_ int, item rawSpan) bool {
			appendToolWindows(body, item, target, depth+1)
			return true
		})
	case '{':
		fields, ok := readObjectFields(body, value)
		if !ok {
			return
		}
		role, roleState := normalizedMetadataField(body, fields.role, fields.roleFields)
		if roleState == metadataInvalid {
			return
		}
		if roleState == metadataValid && role != "" && !windowRoleIsKnown(role) {
			return
		}
		if roleState == metadataValid && role != "" {
			if role == "tool" || role == "function" {
				appendRoleToolObjectPayload(body, fields, target, depth+1)
				return
			}
			appendToolWindows(body, fields.content, target, depth+1)
			return
		}
		itemType, typeState := normalizedMetadataField(body, fields.typ, fields.typeFields)
		if typeState == metadataInvalid {
			return
		}
		if windowTypeIsToolOutput(itemType) {
			appendToolObjectPayload(body, fields, target, depth+1)
			return
		}
		switch itemType {
		case "", "message":
			appendToolWindows(body, fields.content, target, depth+1)
		}
	}
}

func appendRoleToolObjectPayload(
	body []byte,
	fields rawObjectFields,
	target *boundedText,
	depth int,
) bool {
	// Chat/legacy role=tool messages define content as the canonical payload.
	// Keep this order aligned with the official envelope adapter; typed
	// function_call_output items below remain output-first.
	value := firstNonNullSpan(fields.content, fields.output, fields.text)
	return appendToolPayloadValue(body, value, target, depth+1)
}

func appendToolObjectPayload(
	body []byte,
	fields rawObjectFields,
	target *boundedText,
	depth int,
) bool {
	value := firstNonNullSpan(fields.output, fields.content, fields.text)
	return appendToolPayloadValue(body, value, target, depth+1)
}

func firstNonNullSpan(values ...rawSpan) rawSpan {
	for _, value := range values {
		if value.exists() && value.kind != 'n' {
			return value
		}
	}
	return rawSpan{}
}

func appendToolPayloadValue(
	body []byte,
	value rawSpan,
	target *boundedText,
	depth int,
) bool {
	if !value.exists() || target == nil || depth > 64 {
		return false
	}
	switch value.kind {
	case '"':
		return target.appendJSONString(body[value.start:value.end])
	case '[':
		added := false
		walkJSONArray(body, value, func(_ int, item rawSpan) bool {
			if appendToolPayloadValue(body, item, target, depth+1) {
				added = true
			}
			return true
		})
		return added
	case '{':
		fields, ok := readObjectFields(body, value)
		if !ok {
			return false
		}
		role, roleState := normalizedMetadataField(body, fields.role, fields.roleFields)
		if roleState == metadataInvalid ||
			(roleState == metadataValid && role != "" && !windowRoleIsKnown(role)) {
			return false
		}
		itemType, typeState := normalizedMetadataField(body, fields.typ, fields.typeFields)
		if typeState == metadataInvalid {
			return false
		}
		if windowTypeIsToolOutput(itemType) {
			return appendToolObjectPayload(body, fields, target, depth+1)
		}
		switch itemType {
		case "", "message", "input_text", "text", "output_text", "refusal":
		default:
			return false
		}
		added := false
		if fields.text.kind == '"' &&
			appendToolPayloadValue(body, fields.text, target, depth+1) {
			added = true
		}
		if fields.content.exists() &&
			appendToolPayloadValue(body, fields.content, target, depth+1) {
			added = true
		}
		if !added && itemType == "input_text" && fields.input.kind == '"' &&
			appendToolPayloadValue(body, fields.input, target, depth+1) {
			added = true
		}
		return added
	default:
		return false
	}
}

func windowRoleIsKnown(role string) bool {
	switch role {
	case "user", "assistant", "system", "developer", "tool", "function":
		return true
	default:
		return false
	}
}

type metadataState uint8

const (
	metadataAbsent metadataState = iota
	metadataValid
	metadataInvalid
)

func normalizedMetadataField(body []byte, value rawSpan, count int) (string, metadataState) {
	if count == 0 {
		return "", metadataAbsent
	}
	if count != 1 || value.kind != '"' {
		return "", metadataInvalid
	}
	decoded, ok := decodeShortJSONString(body, value, 96)
	if !ok {
		return "", metadataInvalid
	}
	return strings.ToLower(strings.TrimSpace(decoded)), metadataValid
}

func shortJSONString(body []byte, value rawSpan, maxBytes int) string {
	decoded, _ := decodeShortJSONString(body, value, maxBytes)
	return decoded
}

func decodeShortJSONString(body []byte, value rawSpan, maxBytes int) (string, bool) {
	if value.kind != '"' || value.end-value.start > maxBytes*6+2 {
		return "", false
	}
	out := make([]byte, 0, maxBytes)
	ok := walkDecodedJSONString(body[value.start:value.end], func(decoded []byte) bool {
		if !utf8.Valid(decoded) || len(out)+len(decoded) > maxBytes {
			return false
		}
		out = append(out, decoded...)
		return true
	})
	if !ok {
		return "", false
	}
	return string(out), true
}

// utf8.EncodeRune takes a []byte in newer Go releases; keep a small adapter so
// the code remains clear at call sites.
func encodeWindowRune(dst []byte, r rune) int {
	return utf8.EncodeRune(dst, r)
}

func walkDecodedJSONString(raw []byte, emit func([]byte) bool) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	end := len(raw) - 1
	for index := 1; index < end; {
		nextEscape := bytes.IndexByte(raw[index:end], '\\')
		if nextEscape < 0 {
			return emit(raw[index:end])
		}
		nextEscape += index
		if nextEscape > index && !emit(raw[index:nextEscape]) {
			return false
		}
		index = nextEscape + 1
		if index >= end {
			return false
		}
		var decoded [utf8.UTFMax]byte
		var size int
		switch raw[index] {
		case '"', '\\', '/':
			decoded[0] = raw[index]
			size = 1
			index++
		case 'b':
			decoded[0] = '\b'
			size = 1
			index++
		case 'f':
			decoded[0] = '\f'
			size = 1
			index++
		case 'n':
			decoded[0] = '\n'
			size = 1
			index++
		case 'r':
			decoded[0] = '\r'
			size = 1
			index++
		case 't':
			decoded[0] = '\t'
			size = 1
			index++
		case 'u':
			first, ok := decodeWindowHex(raw, index+1)
			if !ok {
				return false
			}
			index += 5
			r := rune(first)
			if utf16.IsSurrogate(r) && index+6 <= end &&
				raw[index] == '\\' && raw[index+1] == 'u' {
				second, secondOK := decodeWindowHex(raw, index+2)
				if secondOK {
					if decoded := utf16.DecodeRune(r, rune(second)); decoded != unicode.ReplacementChar {
						r = decoded
						index += 6
					}
				}
			}
			if utf16.IsSurrogate(r) {
				r = unicode.ReplacementChar
			}
			size = encodeWindowRune(decoded[:], r)
		default:
			return false
		}
		if !emit(decoded[:size]) {
			return false
		}
	}
	return true
}

func decodeWindowHex(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, char := range raw[start : start+4] {
		value <<= 4
		switch {
		case char >= '0' && char <= '9':
			value |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			value |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

type boundedAccumulator struct {
	maxBytes   int
	tailCap    int
	total      int64
	prefix     []byte
	suffix     []byte
	suffixHead int
}

func newBoundedAccumulator(maxBytes int) boundedAccumulator {
	tailCap := maxBytes - maxBytes/4
	if tailCap < 0 {
		tailCap = 0
	}
	return boundedAccumulator{
		maxBytes: maxBytes,
		tailCap:  tailCap,
	}
}

func (a *boundedAccumulator) reset() {
	a.total = 0
	a.prefix = a.prefix[:0]
	a.suffix = a.suffix[:0]
	a.suffixHead = 0
}

func (a *boundedAccumulator) write(bytes []byte) {
	if len(bytes) == 0 {
		return
	}
	if remaining := a.maxBytes - len(a.prefix); remaining > 0 {
		if remaining > len(bytes) {
			remaining = len(bytes)
		}
		a.prefix = append(a.prefix, bytes[:remaining]...)
	}
	a.appendSuffix(bytes)
	a.total += int64(len(bytes))
}

func (a *boundedAccumulator) appendSuffix(bytes []byte) {
	if a.tailCap == 0 || len(bytes) == 0 {
		return
	}
	if len(bytes) >= a.tailCap {
		a.suffix = append(a.suffix[:0], bytes[len(bytes)-a.tailCap:]...)
		a.suffixHead = 0
		return
	}
	if len(a.suffix) < a.tailCap {
		available := a.tailCap - len(a.suffix)
		if available > len(bytes) {
			available = len(bytes)
		}
		a.suffix = append(a.suffix, bytes[:available]...)
		bytes = bytes[available:]
		if len(bytes) == 0 {
			return
		}
	}
	first := len(bytes)
	if remaining := a.tailCap - a.suffixHead; first > remaining {
		first = remaining
	}
	copy(a.suffix[a.suffixHead:], bytes[:first])
	a.suffixHead = (a.suffixHead + first) % a.tailCap
	bytes = bytes[first:]
	if len(bytes) > 0 {
		copy(a.suffix[a.suffixHead:], bytes)
		a.suffixHead = (a.suffixHead + len(bytes)) % a.tailCap
	}
}

func (a *boundedAccumulator) appendAccumulator(other *boundedAccumulator) {
	if other == nil || other.total == 0 {
		return
	}
	if remaining := a.maxBytes - len(a.prefix); remaining > 0 {
		first := other.prefix
		if len(first) > remaining {
			first = first[:remaining]
		}
		a.prefix = append(a.prefix, first...)
	}
	if other.total >= int64(a.tailCap) {
		a.suffix = a.suffix[:0]
		a.suffixHead = 0
		first, second := other.suffixParts()
		a.appendSuffix(first)
		a.appendSuffix(second)
	} else {
		a.appendSuffix(other.prefix[:int(other.total)])
	}
	a.total += other.total
}

func (a *boundedAccumulator) suffixParts() (first, second []byte) {
	if len(a.suffix) == 0 {
		return nil, nil
	}
	if len(a.suffix) < a.tailCap || a.suffixHead == 0 {
		return a.suffix, nil
	}
	return a.suffix[a.suffixHead:], a.suffix[:a.suffixHead]
}

func (a *boundedAccumulator) orderedSuffix() []byte {
	first, second := a.suffixParts()
	if len(second) == 0 {
		return first
	}
	ordered := make([]byte, 0, len(a.suffix))
	ordered = append(ordered, first...)
	ordered = append(ordered, second...)
	return ordered
}

type boundedText struct {
	acc     boundedAccumulator
	pending boundedAccumulator
	hasText bool
}

func newBoundedText(maxBytes int) *boundedText {
	return &boundedText{
		acc:     newBoundedAccumulator(maxBytes),
		pending: newBoundedAccumulator(maxBytes),
	}
}

func (b *boundedText) appendJSONString(raw []byte) bool {
	if b == nil {
		return false
	}
	started := false
	b.pending.reset()
	ok := walkDecodedJSONString(raw, func(decoded []byte) bool {
		appendDecodedWindowChunk(b, decoded, &started)
		return true
	})
	b.pending.reset()
	return ok && started
}

func appendDecodedWindowChunk(target *boundedText, decoded []byte, started *bool) {
	for len(decoded) > 0 {
		nonSpaceEnd := 0
		for nonSpaceEnd < len(decoded) {
			char := decoded[nonSpaceEnd]
			if char < utf8.RuneSelf {
				if isASCIIWindowSpace(char) {
					break
				}
				nonSpaceEnd++
				continue
			}
			r, size := utf8.DecodeRune(decoded[nonSpaceEnd:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			if unicode.IsSpace(r) {
				break
			}
			nonSpaceEnd += size
		}
		if nonSpaceEnd > 0 {
			if !*started {
				if target.hasText {
					target.acc.write([]byte{'\n'})
				}
				target.hasText = true
				*started = true
			} else {
				target.acc.appendAccumulator(&target.pending)
				target.pending.reset()
			}
			target.acc.write(decoded[:nonSpaceEnd])
			decoded = decoded[nonSpaceEnd:]
			continue
		}

		spaceEnd := 0
		for spaceEnd < len(decoded) {
			char := decoded[spaceEnd]
			if char < utf8.RuneSelf {
				if !isASCIIWindowSpace(char) {
					break
				}
				spaceEnd++
				continue
			}
			r, size := utf8.DecodeRune(decoded[spaceEnd:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			if !unicode.IsSpace(r) {
				break
			}
			spaceEnd += size
		}
		if spaceEnd == 0 {
			// encoding/json accepts invalid UTF-8 in a syntactically valid JSON
			// string and replaces each invalid byte sequence with U+FFFD.
			// Normalize it here without materializing the complete string, so
			// later valid user text remains available to the tail window.
			_, size := utf8.DecodeRune(decoded)
			if !*started {
				if target.hasText {
					target.acc.write([]byte{'\n'})
				}
				target.hasText = true
				*started = true
			} else {
				target.acc.appendAccumulator(&target.pending)
				target.pending.reset()
			}
			var replacement [utf8.UTFMax]byte
			replacementSize := encodeWindowRune(replacement[:], unicode.ReplacementChar)
			target.acc.write(replacement[:replacementSize])
			decoded = decoded[size:]
			continue
		}
		if *started {
			target.pending.write(decoded[:spaceEnd])
		}
		decoded = decoded[spaceEnd:]
	}
}

func isASCIIWindowSpace(char byte) bool {
	return char == ' ' || (char >= '\t' && char <= '\r')
}

func (b *boundedText) windows() []string {
	if b == nil || !b.hasText || b.acc.total == 0 {
		return nil
	}
	if b.acc.total <= int64(b.acc.maxBytes) {
		window := trimWindowUTF8(b.acc.prefix)
		if window == "" {
			return nil
		}
		return []string{window}
	}
	headBytes := b.acc.maxBytes / 4
	if headBytes == 0 && b.acc.maxBytes > 0 {
		headBytes = 1
	}
	head := trimWindowUTF8(b.acc.prefix[:headBytes])
	tail := trimWindowUTF8Prefix(b.acc.orderedSuffix())
	out := make([]string, 0, 2)
	if head != "" {
		out = append(out, head)
	}
	if tail != "" {
		out = append(out, tail)
	}
	return out
}

func trimWindowUTF8(bytes []byte) string {
	for len(bytes) > 0 && !utf8.Valid(bytes) {
		bytes = bytes[:len(bytes)-1]
	}
	return strings.TrimSpace(string(bytes))
}

func trimWindowUTF8Prefix(bytes []byte) string {
	for len(bytes) > 0 && !utf8.RuneStart(bytes[0]) {
		bytes = bytes[1:]
	}
	for len(bytes) > 0 && !utf8.Valid(bytes) {
		bytes = bytes[1:]
	}
	return strings.TrimSpace(string(bytes))
}
