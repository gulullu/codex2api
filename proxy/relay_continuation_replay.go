package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/cache"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// ErrRelayContinuationReplayUnavailable means a request containing
// previous_response_id cannot safely move to a Relay account because its
// complete, account-independent history is unavailable.
var ErrRelayContinuationReplayUnavailable = errors.New("complete relay continuation replay unavailable")

type RelayContinuationReplayFailureReason string

const (
	RelayReplayCacheMiss  RelayContinuationReplayFailureReason = "cache_miss"
	RelayReplayIncomplete RelayContinuationReplayFailureReason = "incomplete"
	RelayReplayInvalid    RelayContinuationReplayFailureReason = "invalid"
)

type RelayContinuationReplayError struct {
	Reason RelayContinuationReplayFailureReason
	err    error
}

func (e *RelayContinuationReplayError) Error() string {
	if e == nil {
		return ErrRelayContinuationReplayUnavailable.Error()
	}
	if e.err != nil {
		return fmt.Sprintf("%s: %s: %v", ErrRelayContinuationReplayUnavailable, e.Reason, e.err)
	}
	return fmt.Sprintf("%s: %s", ErrRelayContinuationReplayUnavailable, e.Reason)
}

func (e *RelayContinuationReplayError) Unwrap() error {
	if e == nil || e.err == nil {
		return ErrRelayContinuationReplayUnavailable
	}
	return errors.Join(ErrRelayContinuationReplayUnavailable, e.err)
}

type RelayContinuationReplayCompleteness string

const RelayContinuationReplayComplete RelayContinuationReplayCompleteness = "complete"

type RelayContinuationReplayQuery struct {
	Owner              string
	PreviousResponseID string
	CurrentRequestBody []byte
}

type RelayContinuationReplaySnapshot struct {
	StandaloneRequestBody []byte
	Completeness          RelayContinuationReplayCompleteness
	Source                string
	RelayGroupID          int64
}

type RelayContinuationReplayProvider interface {
	ResolveRelayContinuation(context.Context, RelayContinuationReplayQuery) (RelayContinuationReplaySnapshot, error)
}

const (
	relayReplayRuntimeNamespace  = "relay-continuation-replay-v1"
	relayReplayRecordVersion     = 1
	relayReplayTTL               = 24 * time.Hour
	relayReplayMaxEntries        = 2000
	relayReplayMaxItems          = 400
	relayReplayMaxItemBytes      = 256 << 10
	relayReplayMaxEntryBytes     = 2 << 20
	relayReplayMaxTotalBytes     = 64 << 20
	relayReplayCacheReadTimeout  = 250 * time.Millisecond
	relayReplayCacheWriteTimeout = 500 * time.Millisecond
)

type relayReplayLimits struct {
	ttl           time.Duration
	maxEntries    int
	maxItems      int
	maxItemBytes  int
	maxEntryBytes int
	maxTotalBytes int64
}

var defaultRelayReplayLimits = relayReplayLimits{
	ttl:           relayReplayTTL,
	maxEntries:    relayReplayMaxEntries,
	maxItems:      relayReplayMaxItems,
	maxItemBytes:  relayReplayMaxItemBytes,
	maxEntryBytes: relayReplayMaxEntryBytes,
	maxTotalBytes: relayReplayMaxTotalBytes,
}

type relayReplayRecord struct {
	Version int               `json:"version"`
	Model   string            `json:"model,omitempty"`
	GroupID int64             `json:"relay_group_id,omitempty"`
	Items   []json.RawMessage `json:"items"`
}

type relayReplayEntry struct {
	payload   json.RawMessage
	expiresAt time.Time
	sequence  uint64
}

type relayContinuationReplayStore struct {
	mu           sync.Mutex
	entries      map[string]relayReplayEntry
	totalBytes   int64
	sequence     uint64
	runtimeCache cache.TokenCache
	limits       relayReplayLimits
	now          func() time.Time
}

func newRelayContinuationReplayStore(limits relayReplayLimits) *relayContinuationReplayStore {
	if limits.ttl <= 0 {
		limits.ttl = relayReplayTTL
	}
	if limits.maxEntries <= 0 {
		limits.maxEntries = relayReplayMaxEntries
	}
	if limits.maxItems <= 0 {
		limits.maxItems = relayReplayMaxItems
	}
	if limits.maxItemBytes <= 0 {
		limits.maxItemBytes = relayReplayMaxItemBytes
	}
	if limits.maxEntryBytes <= 0 {
		limits.maxEntryBytes = relayReplayMaxEntryBytes
	}
	if limits.maxTotalBytes <= 0 {
		limits.maxTotalBytes = relayReplayMaxTotalBytes
	}
	return &relayContinuationReplayStore{
		entries: make(map[string]relayReplayEntry),
		limits:  limits,
		now:     time.Now,
	}
}

var relayReplayStore = newRelayContinuationReplayStore(defaultRelayReplayLimits)

var relayContinuationReplayProviderState struct {
	mu       sync.RWMutex
	provider RelayContinuationReplayProvider
}

// SetRelayContinuationReplayCache enables cross-instance replay recovery
// through the application's existing runtime cache. In-memory replay remains
// available when the cache is nil or temporarily unavailable.
func SetRelayContinuationReplayCache(tc cache.TokenCache) {
	relayReplayStore.mu.Lock()
	relayReplayStore.runtimeCache = tc
	relayReplayStore.mu.Unlock()
}

// SetRelayContinuationReplayProvider is a test/extension seam. Passing nil
// restores the built-in bounded replay store.
func SetRelayContinuationReplayProvider(provider RelayContinuationReplayProvider) {
	relayContinuationReplayProviderState.mu.Lock()
	relayContinuationReplayProviderState.provider = provider
	relayContinuationReplayProviderState.mu.Unlock()
}

func relayContinuationReplayProvider() RelayContinuationReplayProvider {
	relayContinuationReplayProviderState.mu.RLock()
	provider := relayContinuationReplayProviderState.provider
	relayContinuationReplayProviderState.mu.RUnlock()
	if provider != nil {
		return provider
	}
	return relayReplayStore
}

func (s *relayContinuationReplayStore) ResolveRelayContinuation(
	ctx context.Context,
	query RelayContinuationReplayQuery,
) (RelayContinuationReplaySnapshot, error) {
	record, source, ok := s.get(ctx, query.Owner, query.PreviousResponseID)
	if !ok {
		return RelayContinuationReplaySnapshot{}, &RelayContinuationReplayError{
			Reason: RelayReplayCacheMiss,
		}
	}
	currentRoot, currentItems, err := relayReplayRequest(query.CurrentRequestBody)
	if err != nil {
		return RelayContinuationReplaySnapshot{}, err
	}
	currentModel := strings.TrimSpace(firstNonEmptyAnyString(currentRoot["model"]))
	if currentModel == "" && record.Model != "" {
		currentRoot["model"] = record.Model
	}

	merged := make([]json.RawMessage, 0, len(record.Items)+len(currentItems))
	merged = append(merged, cloneRawMessages(record.Items)...)
	merged = append(merged, currentItems...)
	if err := s.validateItems(merged); err != nil {
		return RelayContinuationReplaySnapshot{}, err
	}
	decoded, err := decodeReplayItems(merged)
	if err != nil {
		return RelayContinuationReplaySnapshot{}, &RelayContinuationReplayError{
			Reason: RelayReplayInvalid,
			err:    err,
		}
	}
	currentRoot["input"] = decoded
	delete(currentRoot, "previous_response_id")
	normalizeRelayReplayRequest(currentRoot)
	standalone, err := json.Marshal(currentRoot)
	if err != nil {
		return RelayContinuationReplaySnapshot{}, &RelayContinuationReplayError{
			Reason: RelayReplayInvalid,
			err:    err,
		}
	}
	return RelayContinuationReplaySnapshot{
		StandaloneRequestBody: standalone,
		Completeness:          RelayContinuationReplayComplete,
		Source:                source,
		RelayGroupID:          record.GroupID,
	}, nil
}

// PrepareRelayContinuationHTTPFallback reconstructs a standalone request for
// Relay HTTP. It never returns a body containing previous_response_id.
func PrepareRelayContinuationHTTPFallback(
	ctx context.Context,
	owner string,
	requestBody []byte,
) (body []byte, replayed bool, source string, relayGroupID int64, err error) {
	previousResponseID := strings.TrimSpace(gjson.GetBytes(requestBody, "previous_response_id").String())
	if previousResponseID == "" {
		return bytes.Clone(requestBody), false, "", 0, nil
	}
	snapshot, resolveErr := relayContinuationReplayProvider().ResolveRelayContinuation(ctx, RelayContinuationReplayQuery{
		Owner:              strings.TrimSpace(owner),
		PreviousResponseID: previousResponseID,
		CurrentRequestBody: bytes.Clone(requestBody),
	})
	if resolveErr != nil {
		var replayErr *RelayContinuationReplayError
		if errors.As(resolveErr, &replayErr) {
			return nil, false, "", 0, replayErr
		}
		return nil, false, "", 0, &RelayContinuationReplayError{
			Reason: RelayReplayIncomplete,
			err:    resolveErr,
		}
	}
	if snapshot.Completeness != RelayContinuationReplayComplete {
		return nil, false, "", 0, &RelayContinuationReplayError{Reason: RelayReplayIncomplete}
	}
	standalone := bytes.TrimSpace(snapshot.StandaloneRequestBody)
	if len(standalone) == 0 ||
		standalone[0] != '{' ||
		!gjson.ValidBytes(standalone) ||
		!gjson.GetBytes(standalone, "input").Exists() ||
		gjson.GetBytes(standalone, "previous_response_id").Exists() {
		return nil, false, "", 0, &RelayContinuationReplayError{Reason: RelayReplayInvalid}
	}
	return standalone, true, strings.TrimSpace(snapshot.Source), snapshot.RelayGroupID, nil
}

// cacheRelayContinuationReplay stores a complete request+response transcript.
// requestComplete must be false when a previous_response_id cache lookup
// missed; a partial child must never be promoted to a complete replay root.
func cacheRelayContinuationReplay(
	owner string,
	completeRequestBody []byte,
	requestComplete bool,
	relayGroupID int64,
	completedData []byte,
	outputItems []json.RawMessage,
) {
	if !requestComplete {
		return
	}
	responseID := relayReplayResponseID(completedData)
	if responseID == "" {
		return
	}
	root, requestItems, err := relayReplayRequest(completeRequestBody)
	if err != nil {
		return
	}
	items := append([]json.RawMessage(nil), requestItems...)
	items = append(items, relayReplayResponseItems(completedData, outputItems)...)
	if len(items) == 0 {
		return
	}
	record := relayReplayRecord{
		Version: relayReplayRecordVersion,
		Model:   strings.TrimSpace(firstNonEmptyAnyString(root["model"])),
		GroupID: relayGroupID,
		Items:   items,
	}
	if err := relayReplayStore.put(owner, responseID, record); err != nil {
		log.Printf("Relay continuation replay 未缓存: reason=%v", err)
	}
}

func relayReplayResponseID(data []byte) string {
	for _, path := range []string{"response.id", "id"} {
		if id := strings.TrimSpace(gjson.GetBytes(data, path).String()); id != "" {
			return id
		}
	}
	return ""
}

func relayReplayResponseItems(data []byte, streamed []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(streamed)+2)
	seen := make(map[string]struct{})
	appendItem := func(raw json.RawMessage) {
		key := responseOutputItemDoneKey(gjson.ParseBytes(raw))
		if key == "" {
			key = string(raw)
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		if item, ok := sanitizeRelayReplayItem(raw, true); ok {
			out = append(out, item)
		}
	}
	for _, path := range []string{"response.output", "output"} {
		output := gjson.GetBytes(data, path)
		if !output.IsArray() {
			continue
		}
		output.ForEach(func(_, item gjson.Result) bool {
			appendItem(json.RawMessage(item.Raw))
			return true
		})
	}
	for _, raw := range streamed {
		appendItem(raw)
	}
	return out
}

func relayReplayRequest(body []byte) (map[string]any, []json.RawMessage, error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return nil, nil, &RelayContinuationReplayError{
			Reason: RelayReplayInvalid,
			err:    err,
		}
	}
	input, exists := root["input"]
	if !exists {
		return nil, nil, &RelayContinuationReplayError{Reason: RelayReplayInvalid}
	}
	var values []any
	switch typed := input.(type) {
	case []any:
		values = typed
	case string:
		values = []any{map[string]any{
			"type": "message",
			"role": "user",
			"content": []any{map[string]any{
				"type": "input_text",
				"text": typed,
			}},
		}}
	default:
		values = []any{typed}
	}
	items := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, nil, &RelayContinuationReplayError{
				Reason: RelayReplayInvalid,
				err:    err,
			}
		}
		if item, ok := sanitizeRelayReplayItem(raw, false); ok {
			items = append(items, item)
		}
	}
	return root, items, nil
}

func sanitizeRelayReplayItem(raw json.RawMessage, output bool) (json.RawMessage, bool) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	item, ok := value.(map[string]any)
	if !ok || item == nil {
		if output {
			return nil, false
		}
		clean, err := json.Marshal(value)
		return clean, err == nil
	}
	typ := strings.TrimSpace(firstNonEmptyAnyString(item["type"]))
	if typ == "reasoning" {
		return nil, false
	}
	if output && !relayReplayableOutputType(typ, item) {
		return nil, false
	}
	cleaned, keep := sanitizeRelayReplayValue(item)
	if !keep {
		return nil, false
	}
	clean, err := json.Marshal(cleaned)
	if err != nil {
		return nil, false
	}
	return clean, true
}

func relayReplayableOutputType(typ string, item map[string]any) bool {
	if isResponsesMessageInputItem(item) {
		return true
	}
	if isCodexToolCallContextType(typ) || isCodexToolCallOutputType(typ) {
		return true
	}
	if strings.HasSuffix(typ, "_call_output") {
		return true
	}
	if strings.HasSuffix(typ, "_call") {
		switch typ {
		case "web_search_call", "image_generation_call", "code_interpreter_call":
			return false
		default:
			return true
		}
	}
	return false
}

func sanitizeRelayReplayValue(value any) (any, bool) {
	switch typed := value.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, child := range typed {
			cleaned, keep := sanitizeRelayReplayValue(child)
			if keep {
				out = append(out, cleaned)
			}
		}
		return out, true
	case map[string]any:
		if strings.TrimSpace(firstNonEmptyAnyString(typed["type"])) == "reasoning" {
			return nil, false
		}
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			switch key {
			case "id", "status", "encrypted_content":
				continue
			}
			cleaned, keep := sanitizeRelayReplayValue(child)
			if keep {
				out[key] = cleaned
			}
		}
		return out, true
	default:
		return value, true
	}
}

func normalizeRelayReplayRequest(root map[string]any) {
	normalizeResponsesCompactionItems(root)
	normalizeResponsesSystemRoleMessages(root)
	normalizeResponsesContentPartTypes(root)
	normalizeResponsesInputMessageContent(root)
	normalizeResponsesToolCallArgumentTypes(root)
	normalizeResponsesInputItemIDs(root)
	dropBareReasoningInputItems(root)
}

func decodeReplayItems(items []json.RawMessage) ([]any, error) {
	decoded := make([]any, 0, len(items))
	for _, raw := range items {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		decoded = append(decoded, value)
	}
	return decoded, nil
}

func cloneRawMessages(items []json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, len(items))
	for i, item := range items {
		out[i] = append(json.RawMessage(nil), item...)
	}
	return out
}

func relayReplayStoreKey(owner, responseID string) string {
	composed := responseCacheStoreKey(strings.TrimSpace(owner), strings.TrimSpace(responseID))
	digest := sha256.Sum256([]byte(composed))
	return fmt.Sprintf("%x", digest[:])
}

func relayContinuationReplayOwner(apiKeyOwner, stableScope string) string {
	apiKeyOwner = strings.TrimSpace(apiKeyOwner)
	stableScope = strings.TrimSpace(stableScope)
	if stableScope == "" {
		return apiKeyOwner
	}
	digest := sha256.Sum256([]byte("relay-continuation-scope:" + stableScope))
	return fmt.Sprintf("%s|scope:%x", apiKeyOwner, digest[:16])
}

func relayContinuationStableScope(headers http.Header, body []byte) string {
	if scope := resolveDownstreamAffinityID(headers); scope != "" {
		return scope
	}
	if headers != nil {
		for _, key := range []string{"Session-Id", "Session_id", "Conversation-Id", "Conversation_id"} {
			if value := strings.TrimSpace(headers.Get(key)); value != "" {
				return value
			}
		}
	}
	return strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String())
}

func (s *relayContinuationReplayStore) validateItems(items []json.RawMessage) error {
	if len(items) == 0 || len(items) > s.limits.maxItems {
		return &RelayContinuationReplayError{Reason: RelayReplayIncomplete}
	}
	total := 0
	for _, item := range items {
		if len(item) == 0 || len(item) > s.limits.maxItemBytes {
			return &RelayContinuationReplayError{Reason: RelayReplayIncomplete}
		}
		total += len(item)
		if total > s.limits.maxEntryBytes {
			return &RelayContinuationReplayError{Reason: RelayReplayIncomplete}
		}
	}
	return nil
}

func (s *relayContinuationReplayStore) put(owner, responseID string, record relayReplayRecord) error {
	owner = strings.TrimSpace(owner)
	responseID = strings.TrimSpace(responseID)
	if owner == "" || responseID == "" || record.Version != relayReplayRecordVersion || record.GroupID < 0 {
		return &RelayContinuationReplayError{Reason: RelayReplayInvalid}
	}
	if err := s.validateItems(record.Items); err != nil {
		return err
	}
	record.Items = cloneRawMessages(record.Items)
	payload, err := json.Marshal(record)
	if err != nil || len(payload) > s.limits.maxEntryBytes || int64(len(payload)) > s.limits.maxTotalBytes {
		return &RelayContinuationReplayError{Reason: RelayReplayIncomplete, err: err}
	}
	storeKey := relayReplayStoreKey(owner, responseID)
	now := s.now()
	s.mu.Lock()
	s.purgeExpiredLocked(now)
	s.removeLocked(storeKey)
	for len(s.entries) >= s.limits.maxEntries ||
		s.totalBytes+int64(len(payload)) > s.limits.maxTotalBytes {
		if !s.evictOldestLocked() {
			break
		}
	}
	if len(s.entries) >= s.limits.maxEntries ||
		s.totalBytes+int64(len(payload)) > s.limits.maxTotalBytes {
		s.mu.Unlock()
		return &RelayContinuationReplayError{Reason: RelayReplayIncomplete}
	}
	s.sequence++
	s.entries[storeKey] = relayReplayEntry{
		payload:   append(json.RawMessage(nil), payload...),
		expiresAt: now.Add(s.limits.ttl),
		sequence:  s.sequence,
	}
	s.totalBytes += int64(len(payload))
	runtimeCache := s.runtimeCache
	s.mu.Unlock()
	s.persistRuntime(runtimeCache, storeKey, payload)
	return nil
}

func (s *relayContinuationReplayStore) get(
	ctx context.Context,
	owner string,
	responseID string,
) (relayReplayRecord, string, bool) {
	storeKey := relayReplayStoreKey(owner, responseID)
	now := s.now()
	s.mu.Lock()
	s.purgeExpiredLocked(now)
	entry, ok := s.entries[storeKey]
	if ok {
		s.sequence++
		entry.sequence = s.sequence
		s.entries[storeKey] = entry
	}
	runtimeCache := s.runtimeCache
	s.mu.Unlock()
	if ok {
		record, valid := s.decodeRecord(entry.payload)
		return record, "memory", valid
	}
	if runtimeCache == nil {
		return relayReplayRecord{}, "", false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cacheCtx, cancel := context.WithTimeout(ctx, relayReplayCacheReadTimeout)
	defer cancel()
	payload, found, err := runtimeCache.GetRuntime(cacheCtx, relayReplayRuntimeNamespace, storeKey)
	if err != nil || !found {
		if err != nil {
			log.Printf("读取 Relay continuation replay 缓存失败: %v", err)
		}
		return relayReplayRecord{}, "", false
	}
	record, valid := s.decodeRecord(payload)
	if !valid {
		return relayReplayRecord{}, "", false
	}
	s.putLocal(storeKey, payload, now)
	return record, "runtime-cache", true
}

func (s *relayContinuationReplayStore) decodeRecord(payload json.RawMessage) (relayReplayRecord, bool) {
	if len(payload) == 0 || len(payload) > s.limits.maxEntryBytes {
		return relayReplayRecord{}, false
	}
	var record relayReplayRecord
	if err := json.Unmarshal(payload, &record); err != nil ||
		record.Version != relayReplayRecordVersion ||
		record.GroupID < 0 ||
		s.validateItems(record.Items) != nil {
		return relayReplayRecord{}, false
	}
	record.Items = cloneRawMessages(record.Items)
	return record, true
}

func (s *relayContinuationReplayStore) putLocal(storeKey string, payload json.RawMessage, now time.Time) {
	if len(payload) == 0 || len(payload) > s.limits.maxEntryBytes ||
		int64(len(payload)) > s.limits.maxTotalBytes {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	s.removeLocked(storeKey)
	for len(s.entries) >= s.limits.maxEntries ||
		s.totalBytes+int64(len(payload)) > s.limits.maxTotalBytes {
		if !s.evictOldestLocked() {
			return
		}
	}
	s.sequence++
	s.entries[storeKey] = relayReplayEntry{
		payload:   append(json.RawMessage(nil), payload...),
		expiresAt: now.Add(s.limits.ttl),
		sequence:  s.sequence,
	}
	s.totalBytes += int64(len(payload))
}

func (s *relayContinuationReplayStore) persistRuntime(
	runtimeCache cache.TokenCache,
	storeKey string,
	payload json.RawMessage,
) {
	if runtimeCache == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayReplayCacheWriteTimeout)
	defer cancel()
	if err := runtimeCache.SetRuntime(ctx, relayReplayRuntimeNamespace, storeKey, payload, s.limits.ttl); err != nil {
		log.Printf("写入 Relay continuation replay 缓存失败: %v", err)
	}
}

func (s *relayContinuationReplayStore) purgeExpiredLocked(now time.Time) {
	for key, entry := range s.entries {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			s.totalBytes -= int64(len(entry.payload))
			delete(s.entries, key)
		}
	}
}

func (s *relayContinuationReplayStore) removeLocked(key string) {
	if entry, exists := s.entries[key]; exists {
		s.totalBytes -= int64(len(entry.payload))
		delete(s.entries, key)
	}
}

func (s *relayContinuationReplayStore) evictOldestLocked() bool {
	var oldestKey string
	var oldestSequence uint64
	for key, entry := range s.entries {
		if oldestKey == "" || entry.sequence < oldestSequence {
			oldestKey = key
			oldestSequence = entry.sequence
		}
	}
	if oldestKey == "" {
		return false
	}
	s.removeLocked(oldestKey)
	return true
}

func replyRelayContinuationReplayUnavailable(c *gin.Context, err error) {
	if c == nil {
		return
	}
	reason := RelayReplayCacheMiss
	var replayErr *RelayContinuationReplayError
	if errors.As(err, &replayErr) && replayErr.Reason != "" {
		reason = replayErr.Reason
	}
	c.JSON(http.StatusConflict, gin.H{
		"error": gin.H{
			"type":    "relay_continuation_replay_unavailable",
			"code":    "relay_continuation_replay_unavailable",
			"reason":  reason,
			"message": "Complete local conversation history is unavailable. No Relay HTTP request was sent, and the raw previous_response_id was not forwarded to another account.",
		},
	})
}
