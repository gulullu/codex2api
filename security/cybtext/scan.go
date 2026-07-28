package cybtext

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TextOrigin identifies the provenance class exposed by the chunk walkers.
// Tool output is available only from WalkRoutingTextChunks and never enters
// the user-only learning extractor.
type TextOrigin uint8

const (
	TextOriginCurrentUser TextOrigin = iota + 1
	TextOriginHistory
	TextOriginToolOutput
)

// WalkUserTextChunks scans every user-authored byte of a supported request
// without materializing an oversized JSON string. Each callback receives a
// contiguous UTF-8-safe window; adjacent windows overlap by overlapBytes so
// rules near a chunk boundary remain visible. Current-user chunks are emitted
// before history chunks to preserve routing provenance precedence.
//
// hasCurrent reports whether a non-whitespace current-user turn exists. ok is
// false for invalid JSON, unsupported endpoints, or a malformed root object;
// individual items with ambiguous metadata are skipped fail-closed.
func WalkUserTextChunks(
	rawBody []byte,
	endpoint string,
	chunkBytes int,
	overlapBytes int,
	visit func(origin TextOrigin, text string),
) (hasCurrent bool, ok bool) {
	return walkTextChunks(rawBody, endpoint, chunkBytes, overlapBytes, false, visit)
}

// WalkRoutingTextChunks scans the same current-user and user-history text as
// WalkUserTextChunks. When there is no current-user text, it additionally
// scans every supported tool-output payload as routing-only continuation
// evidence. Tool chunks are never returned by ExtractUserWindows and therefore
// cannot become CYB learning samples.
func WalkRoutingTextChunks(
	rawBody []byte,
	endpoint string,
	chunkBytes int,
	overlapBytes int,
	visit func(origin TextOrigin, text string),
) (hasCurrent bool, ok bool) {
	return walkTextChunks(rawBody, endpoint, chunkBytes, overlapBytes, true, visit)
}

func walkTextChunks(
	rawBody []byte,
	endpoint string,
	chunkBytes int,
	overlapBytes int,
	includeTool bool,
	visit func(origin TextOrigin, text string),
) (hasCurrent bool, ok bool) {
	if len(rawBody) == 0 || chunkBytes <= 0 || !json.Valid(rawBody) {
		return false, false
	}
	if chunkBytes < utf8.UTFMax {
		chunkBytes = utf8.UTFMax
	}
	if overlapBytes < 0 {
		overlapBytes = 0
	}
	if overlapBytes >= chunkBytes {
		overlapBytes = chunkBytes / 4
	}
	root, rootOK := rootObjectFields(rawBody)
	if !rootOK {
		return false, false
	}

	current := newChunkTextSink(TextOriginCurrentUser, chunkBytes, overlapBytes, visit)
	history := newChunkTextSink(TextOriginHistory, chunkBytes, overlapBytes, visit)
	protocol := strings.ToLower(strings.TrimSpace(endpoint))
	switch protocol {
	case "/v1/responses", "/v1/responses/compact":
		inputSelection := analyzeUserConversation(rawBody, root.input)
		walkSelectedUserValues(rawBody, root.input, inputSelection, true, current)
		walkUserValueStrings(rawBody, root.prompt, nil, current, 0)

		var fallbackSelection userConversationSelection
		useFallback := !current.hasText
		if useFallback {
			current.reset()
			fallbackSelection = analyzeUserConversation(rawBody, root.messages)
			walkSelectedUserValues(rawBody, root.messages, fallbackSelection, true, current)
		}
		current.finish()

		walkSelectedUserValues(rawBody, root.input, inputSelection, false, history)
		if useFallback {
			walkSelectedUserValues(rawBody, root.messages, fallbackSelection, false, history)
		}
		history.finish()
	case "/v1/chat/completions", "/v1/messages":
		selection := analyzeUserConversation(rawBody, root.messages)
		walkSelectedUserValues(rawBody, root.messages, selection, true, current)
		current.finish()
		walkSelectedUserValues(rawBody, root.messages, selection, false, history)
		history.finish()
	default:
		return false, false
	}
	if includeTool && !current.hasText {
		tool := newChunkTextSink(TextOriginToolOutput, chunkBytes, overlapBytes, visit)
		switch protocol {
		case "/v1/responses", "/v1/responses/compact":
			walkToolValues(rawBody, root.input, tool, 0)
			walkToolValues(rawBody, root.messages, tool, 0)
		case "/v1/chat/completions", "/v1/messages":
			walkToolValues(rawBody, root.messages, tool, 0)
		}
		tool.finish()
	}
	return current.hasText, true
}

type userConversationSelection struct {
	valid              bool
	scalarCurrent      bool
	lastCandidate      int
	lastKind           windowInputKind
	lastTextBlockStart int
	closedAfterLast    bool
}

func analyzeUserConversation(body []byte, value rawSpan) userConversationSelection {
	selection := userConversationSelection{
		valid:              true,
		lastCandidate:      -1,
		lastTextBlockStart: -1,
	}
	if !value.exists() || value.kind == 'n' {
		return selection
	}
	if value.kind != '[' {
		info := classifyWindowItem(body, value)
		selection.scalarCurrent = info.kind != windowInputNone
		return selection
	}

	textBlockStart := -1
	textBlockExtendable := false
	if !walkJSONArray(body, value, func(index int, item rawSpan) bool {
		info := classifyWindowItem(body, item)
		if info.kind != windowInputNone {
			if info.kind == windowInputTextBlock {
				if !textBlockExtendable {
					textBlockStart = index
				}
				selection.lastTextBlockStart = textBlockStart
				textBlockExtendable = true
			} else {
				textBlockExtendable = false
			}
			selection.lastCandidate = index
			selection.lastKind = info.kind
			selection.closedAfterLast = false
			return true
		}
		if info.closes && selection.lastCandidate >= 0 {
			selection.closedAfterLast = true
		}
		if !info.attachment {
			textBlockExtendable = false
		}
		return true
	}) {
		selection.valid = false
	}
	return selection
}

func walkSelectedUserValues(
	body []byte,
	value rawSpan,
	selection userConversationSelection,
	wantCurrent bool,
	target *chunkTextSink,
) {
	if target == nil || !selection.valid || !value.exists() || value.kind == 'n' {
		return
	}
	if value.kind != '[' {
		if wantCurrent && selection.scalarCurrent {
			info := classifyWindowItem(body, value)
			walkUserValueStrings(body, value, &info.fields, target, 0)
		}
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
		if selected == wantCurrent {
			walkUserValueStrings(body, item, &info.fields, target, 0)
		}
		return true
	})
}

func walkUserValueStrings(
	body []byte,
	value rawSpan,
	knownFields *rawObjectFields,
	target *chunkTextSink,
	depth int,
) bool {
	if target == nil || !value.exists() || depth > 64 {
		return false
	}
	switch value.kind {
	case '"':
		return target.appendJSONString(body[value.start:value.end])
	case '[':
		added := false
		walkJSONArray(body, value, func(_ int, item rawSpan) bool {
			if walkUserValueStrings(body, item, nil, target, depth+1) {
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
			var fieldsOK bool
			fields, fieldsOK = readObjectFields(body, value)
			if !fieldsOK {
				return false
			}
		}
		role, roleState := normalizedMetadataField(body, fields.role, fields.roleFields)
		if roleState == metadataInvalid ||
			(roleState == metadataValid && role != "" && role != "user") {
			return false
		}
		if roleState == metadataValid && role == "user" {
			value := firstNonNullSpan(fields.content, fields.text)
			return walkUserValueStrings(body, value, nil, target, depth+1)
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
			if walkUserValueStrings(body, value, nil, target, depth+1) {
				return true
			}
			if itemType == "input_text" && fields.input.kind == '"' {
				return walkUserValueStrings(body, fields.input, nil, target, depth+1)
			}
			return false
		}
		added := false
		if fields.text.kind == '"' &&
			walkUserValueStrings(body, fields.text, nil, target, depth+1) {
			added = true
		}
		if fields.content.exists() &&
			walkUserValueStrings(body, fields.content, nil, target, depth+1) {
			added = true
		}
		return added
	default:
		return false
	}
}

func walkToolValues(body []byte, value rawSpan, target *chunkTextSink, depth int) {
	if !value.exists() || target == nil || depth > 64 {
		return
	}
	switch value.kind {
	case '[':
		walkJSONArray(body, value, func(_ int, item rawSpan) bool {
			walkToolValues(body, item, target, depth+1)
			return true
		})
	case '{':
		fields, fieldsOK := readObjectFields(body, value)
		if !fieldsOK {
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
				walkRoleToolObjectPayload(body, fields, target, depth+1)
				return
			}
			walkToolValues(body, fields.content, target, depth+1)
			return
		}
		itemType, typeState := normalizedMetadataField(body, fields.typ, fields.typeFields)
		if typeState == metadataInvalid {
			return
		}
		if windowTypeIsToolOutput(itemType) {
			walkToolObjectPayload(body, fields, target, depth+1)
			return
		}
		switch itemType {
		case "", "message":
			walkToolValues(body, fields.content, target, depth+1)
		}
	}
}

func walkRoleToolObjectPayload(
	body []byte,
	fields rawObjectFields,
	target *chunkTextSink,
	depth int,
) bool {
	value := firstNonNullSpan(fields.content, fields.output, fields.text)
	return walkToolPayloadStrings(body, value, target, depth+1)
}

func walkToolObjectPayload(
	body []byte,
	fields rawObjectFields,
	target *chunkTextSink,
	depth int,
) bool {
	value := firstNonNullSpan(fields.output, fields.content, fields.text)
	return walkToolPayloadStrings(body, value, target, depth+1)
}

func walkToolPayloadStrings(
	body []byte,
	value rawSpan,
	target *chunkTextSink,
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
			if walkToolPayloadStrings(body, item, target, depth+1) {
				added = true
			}
			return true
		})
		return added
	case '{':
		fields, fieldsOK := readObjectFields(body, value)
		if !fieldsOK {
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
			return walkToolObjectPayload(body, fields, target, depth+1)
		}
		switch itemType {
		case "", "message", "input_text", "text", "output_text", "refusal":
		default:
			return false
		}
		added := false
		if fields.text.kind == '"' &&
			walkToolPayloadStrings(body, fields.text, target, depth+1) {
			added = true
		}
		if fields.content.exists() &&
			walkToolPayloadStrings(body, fields.content, target, depth+1) {
			added = true
		}
		if !added && itemType == "input_text" && fields.input.kind == '"' &&
			walkToolPayloadStrings(body, fields.input, target, depth+1) {
			added = true
		}
		return added
	default:
		return false
	}
}

type chunkTextSink struct {
	origin       TextOrigin
	chunkBytes   int
	overlapBytes int
	visit        func(origin TextOrigin, text string)
	buffer       []byte
	hasText      bool
	wroteValue   bool
}

func newChunkTextSink(
	origin TextOrigin,
	chunkBytes int,
	overlapBytes int,
	visit func(origin TextOrigin, text string),
) *chunkTextSink {
	return &chunkTextSink{
		origin:       origin,
		chunkBytes:   chunkBytes,
		overlapBytes: overlapBytes,
		visit:        visit,
		buffer:       make([]byte, 0, chunkBytes),
	}
}

func (s *chunkTextSink) reset() {
	if s == nil {
		return
	}
	s.buffer = s.buffer[:0]
	s.hasText = false
	s.wroteValue = false
}

func (s *chunkTextSink) appendJSONString(raw []byte) bool {
	if s == nil {
		return false
	}
	valueHasText := false
	ok := walkDecodedJSONString(raw, func(decoded []byte) bool {
		if !valueHasText {
			decoded = trimLeadingChunkSpace(decoded)
			if len(decoded) == 0 {
				return true
			}
			if s.wroteValue {
				s.writeValid([]byte{'\n'})
			}
			s.wroteValue = true
			valueHasText = true
		}
		s.writeDecoded(decoded)
		return true
	})
	return ok && valueHasText
}

func trimLeadingChunkSpace(value []byte) []byte {
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			return value
		}
		if !unicode.IsSpace(r) {
			return value
		}
		value = value[size:]
	}
	return nil
}

func (s *chunkTextSink) writeDecoded(decoded []byte) {
	if len(decoded) == 0 {
		return
	}
	if utf8.Valid(decoded) {
		s.noteNonSpace(decoded)
		s.writeValid(decoded)
		return
	}
	for len(decoded) > 0 {
		r, size := utf8.DecodeRune(decoded)
		if r == utf8.RuneError && size == 1 {
			var replacement [utf8.UTFMax]byte
			replacementSize := encodeWindowRune(replacement[:], unicode.ReplacementChar)
			s.hasText = true
			s.writeValid(replacement[:replacementSize])
			decoded = decoded[1:]
			continue
		}
		s.noteNonSpace(decoded[:size])
		s.writeValid(decoded[:size])
		decoded = decoded[size:]
	}
}

func (s *chunkTextSink) noteNonSpace(value []byte) {
	if s == nil || s.hasText {
		return
	}
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			s.hasText = true
			return
		}
		if !unicode.IsSpace(r) {
			s.hasText = true
			return
		}
		value = value[size:]
	}
}

func (s *chunkTextSink) writeValid(value []byte) {
	if s == nil || len(value) == 0 {
		return
	}
	for len(value) > 0 {
		remaining := s.chunkBytes - len(s.buffer)
		if remaining <= 0 {
			s.emitFull()
			remaining = s.chunkBytes - len(s.buffer)
		}
		take := min(remaining, len(value))
		s.buffer = append(s.buffer, value[:take]...)
		value = value[take:]
		if len(s.buffer) >= s.chunkBytes {
			s.emitFull()
		}
	}
}

func (s *chunkTextSink) emitFull() {
	if s == nil || len(s.buffer) == 0 {
		return
	}
	end := min(s.chunkBytes, len(s.buffer))
	for end > 0 && !utf8.Valid(s.buffer[:end]) {
		end--
	}
	if end <= 0 {
		return
	}
	s.emit(s.buffer[:end])
	start := end - min(s.overlapBytes, end)
	for start < end && !utf8.RuneStart(s.buffer[start]) {
		start++
	}
	if start == 0 && len(s.buffer) >= s.chunkBytes {
		// A very small chunk can contain one complete byte followed by an
		// incomplete multi-byte rune. Retaining the requested overlap would
		// leave the buffer full and make the writer spin forever; prefer
		// forward progress while preserving the incomplete trailing rune.
		start = end
	}
	copy(s.buffer, s.buffer[start:])
	s.buffer = s.buffer[:len(s.buffer)-start]
}

func (s *chunkTextSink) finish() {
	if s == nil || len(s.buffer) == 0 {
		return
	}
	for len(s.buffer) > 0 && !utf8.Valid(s.buffer) {
		s.buffer = s.buffer[:len(s.buffer)-1]
	}
	s.emit(s.buffer)
	s.buffer = s.buffer[:0]
}

func (s *chunkTextSink) emit(value []byte) {
	if s == nil || s.visit == nil {
		return
	}
	text := strings.TrimSpace(string(value))
	if text != "" {
		s.visit(s.origin, text)
	}
}
