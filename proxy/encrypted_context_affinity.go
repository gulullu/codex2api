package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	encryptedContextOwnerNamespace  = "encrypted-context-owner-v1"
	encryptedContextLeaseNamespace  = "encrypted-context-owner-claim-v1"
	encryptedContextDefaultTTL      = 24 * time.Hour
	encryptedContextMaxTTL          = 7 * 24 * time.Hour
	encryptedContextCacheTimeout    = 500 * time.Millisecond
	encryptedContextMaxFingerprints = 64
	contextEncryptedAffinityState   = "encryptedContextAffinityState"

	encryptedOwnerHitSignal         = "encrypted_owner_hit"
	encryptedOwnerMissSignal        = "encrypted_owner_miss"
	encryptedOwnerPartialMissSignal = "encrypted_owner_partial_miss"
	encryptedOwnerConflictSignal    = "encrypted_owner_conflict"
	encryptedOwnerUnavailableSignal = "encrypted_owner_unavailable"
	encryptedContextDowngradeSignal = "encrypted_context_downgraded"
	encryptedContextPinKind         = "encrypted_content"
)

var errEncryptedContextNoReplayableInput = errors.New("encrypted context owner is unavailable and no replayable input remains")

type encryptedContextAffinityState struct {
	Keys           []string
	Owner          responseRouteOwner
	HasOwner       bool
	NeedsDowngrade bool
	Signals        []string
}

type encryptedContextCapture struct {
	apiKeyID int64
	keys     map[string]struct{}
}

func encryptedContextAffinityEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_ENABLED"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func encryptedContextAffinityTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CODEX_ENCRYPTED_CONTEXT_AFFINITY_TTL"))
	if raw == "" {
		return encryptedContextDefaultTTL
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 {
		return encryptedContextDefaultTTL
	}
	if ttl > encryptedContextMaxTTL {
		return encryptedContextMaxTTL
	}
	return ttl
}

func encryptedContextOwnerKey(apiKeyID int64, encryptedContent string) string {
	if apiKeyID <= 0 || encryptedContent == "" {
		return ""
	}
	return cybRelayPinCacheKey(
		encryptedContextPinKind,
		responseCacheOwner(apiKeyID),
		encryptedContent,
	)
}

func encryptedContextOwnerKeys(apiKeyID int64, payload []byte) []string {
	if apiKeyID <= 0 || len(payload) == 0 || !bytes.Contains(payload, []byte(`"encrypted_content"`)) {
		return nil
	}
	var root any
	if json.Unmarshal(payload, &root) != nil {
		return nil
	}
	return encryptedContextOwnerKeysFromValue(apiKeyID, root)
}

func encryptedContextInputOwnerKeys(apiKeyID int64, payload []byte) []string {
	if apiKeyID <= 0 || len(payload) == 0 || !bytes.Contains(payload, []byte(`"encrypted_content"`)) {
		return nil
	}
	var root map[string]any
	if json.Unmarshal(payload, &root) != nil || root == nil {
		return nil
	}
	input, ok := root["input"]
	if !ok {
		return nil
	}
	return encryptedContextOwnerKeysFromValue(apiKeyID, input)
}

func encryptedContextOwnerKeysFromValue(apiKeyID int64, root any) []string {
	seen := make(map[string]struct{})
	keys := make([]string, 0, 2)
	var walk func(any)
	walk = func(value any) {
		if len(keys) >= encryptedContextMaxFingerprints {
			return
		}
		switch item := value.(type) {
		case []any:
			for _, child := range item {
				walk(child)
				if len(keys) >= encryptedContextMaxFingerprints {
					return
				}
			}
		case map[string]any:
			itemType := firstNonEmptyAnyString(item["type"])
			isEncryptedReasoningDone := strings.EqualFold(strings.TrimSpace(itemType), "response.reasoning.encrypted_content.done")
			if isOpaqueEncryptedHistoryItemType(itemType) || isEncryptedReasoningDone {
				if encrypted, ok := item["encrypted_content"].(string); ok && encrypted != "" {
					key := encryptedContextOwnerKey(apiKeyID, encrypted)
					if key != "" {
						if _, exists := seen[key]; !exists {
							seen[key] = struct{}{}
							keys = append(keys, key)
						}
					}
				}
			}
			for field, child := range item {
				if field == "encrypted_content" {
					continue
				}
				walk(child)
				if len(keys) >= encryptedContextMaxFingerprints {
					return
				}
			}
		}
	}
	walk(root)
	return keys
}

func encryptedContextStateFromContext(c *gin.Context) (encryptedContextAffinityState, bool) {
	if c == nil {
		return encryptedContextAffinityState{}, false
	}
	value, ok := c.Get(contextEncryptedAffinityState)
	if !ok {
		return encryptedContextAffinityState{}, false
	}
	state, ok := value.(encryptedContextAffinityState)
	return state, ok && len(state.Keys) > 0
}

func setEncryptedContextState(c *gin.Context, state encryptedContextAffinityState) {
	if c != nil {
		c.Set(contextEncryptedAffinityState, state)
	}
}

func addEncryptedContextSignal(state *encryptedContextAffinityState, signal string) {
	if state == nil || strings.TrimSpace(signal) == "" {
		return
	}
	state.Signals = appendUniqueRouteSignal(state.Signals, signal)
}

func markEncryptedContextDowngrade(c *gin.Context, reason string) {
	state, ok := encryptedContextStateFromContext(c)
	if !ok {
		return
	}
	state.NeedsDowngrade = true
	addEncryptedContextSignal(&state, reason)
	addEncryptedContextSignal(&state, encryptedContextDowngradeSignal)
	setEncryptedContextState(c, state)
}

func encryptedContextOwnerFromContext(c *gin.Context) (responseRouteOwner, bool) {
	state, ok := encryptedContextStateFromContext(c)
	if !ok || !state.HasOwner || state.NeedsDowngrade || state.Owner.AccountID <= 0 {
		return responseRouteOwner{}, false
	}
	return state.Owner, true
}

func encryptedContextSignalsFromContext(c *gin.Context) []string {
	state, ok := encryptedContextStateFromContext(c)
	if !ok {
		return nil
	}
	return append([]string(nil), state.Signals...)
}

func encryptedContextNeedsDowngrade(c *gin.Context) bool {
	state, ok := encryptedContextStateFromContext(c)
	return ok && state.NeedsDowngrade
}

func completeEncryptedContextDowngrade(c *gin.Context) {
	state, ok := encryptedContextStateFromContext(c)
	if !ok {
		return
	}
	state.Owner = responseRouteOwner{}
	state.HasOwner = false
	state.NeedsDowngrade = false
	setEncryptedContextState(c, state)
}

func (h *Handler) loadEncryptedContextAffinity(c *gin.Context, rawBody []byte) {
	if c == nil {
		return
	}
	setEncryptedContextState(c, encryptedContextAffinityState{})
	if h == nil || h.cache == nil || !encryptedContextAffinityEnabled() {
		return
	}
	apiKeyID := requestAPIKeyID(c)
	keys := encryptedContextInputOwnerKeys(apiKeyID, rawBody)
	if len(keys) == 0 {
		return
	}

	state := encryptedContextAffinityState{Keys: keys}
	requestCtx := context.Background()
	if c.Request != nil {
		requestCtx = c.Request.Context()
	}
	cacheCtx, cancel := context.WithTimeout(requestCtx, encryptedContextCacheTimeout)
	defer cancel()
	owners := make(map[int64]responseRouteOwner)
	misses := 0
	for _, key := range keys {
		payload, ok, err := h.cache.GetRuntime(cacheCtx, encryptedContextOwnerNamespace, key)
		if err != nil || !ok {
			misses++
			continue
		}
		var owner responseRouteOwner
		if json.Unmarshal(payload, &owner) != nil || owner.AccountID <= 0 {
			misses++
			continue
		}
		// A live request proves this opaque state is still in use. Refresh only
		// the already-known owner record; never create ownership on lookup.
		_ = h.cache.SetRuntime(cacheCtx, encryptedContextOwnerNamespace, key, payload, encryptedContextAffinityTTL())
		owners[owner.AccountID] = owner
	}

	switch len(owners) {
	case 0:
		addEncryptedContextSignal(&state, encryptedOwnerMissSignal)
	case 1:
		for _, owner := range owners {
			state.Owner = owner
			state.HasOwner = true
		}
		addEncryptedContextSignal(&state, encryptedOwnerHitSignal)
		if misses > 0 {
			addEncryptedContextSignal(&state, encryptedOwnerPartialMissSignal)
		}
	default:
		addEncryptedContextSignal(&state, encryptedOwnerConflictSignal)
		addEncryptedContextSignal(&state, encryptedContextDowngradeSignal)
		state.NeedsDowngrade = true
	}
	setEncryptedContextState(c, state)

	if responseOwner, ok := responseRouteOwnerFromContext(c); ok && state.HasOwner && responseOwner.AccountID != state.Owner.AccountID {
		markEncryptedContextDowngrade(c, encryptedOwnerConflictSignal)
	}
}

func (h *Handler) repairEncryptedContextForAccountSwitch(c *gin.Context, rawBody []byte) ([]byte, encryptedContentRepair, error) {
	if !encryptedContextNeedsDowngrade(c) {
		return rawBody, encryptedContentRepair{}, nil
	}
	repaired, repair := repairInvalidEncryptedContentFromResponsesBody(rawBody)
	if !repair.Changed || repair.InputEmpty {
		return rawBody, repair, errEncryptedContextNoReplayableInput
	}
	completeEncryptedContextDowngrade(c)
	return repaired, repair, nil
}

func (h *Handler) invalidateEncryptedContextBindings(c *gin.Context) {
	state, ok := encryptedContextStateFromContext(c)
	if !ok {
		return
	}
	if h != nil && h.cache != nil {
		cacheCtx, cancel := context.WithTimeout(context.Background(), encryptedContextCacheTimeout)
		for _, key := range state.Keys {
			_ = h.cache.DeleteRuntime(cacheCtx, encryptedContextOwnerNamespace, key)
		}
		cancel()
	}
	state.Owner = responseRouteOwner{}
	state.HasOwner = false
	state.NeedsDowngrade = false
	addEncryptedContextSignal(&state, encryptedContextDowngradeSignal)
	setEncryptedContextState(c, state)
}

func newEncryptedContextCapture(apiKeyID int64) *encryptedContextCapture {
	if apiKeyID <= 0 || !encryptedContextAffinityEnabled() {
		return nil
	}
	return &encryptedContextCapture{
		apiKeyID: apiKeyID,
		keys:     make(map[string]struct{}),
	}
}

func (capture *encryptedContextCapture) Observe(payload []byte) {
	if capture == nil || len(capture.keys) >= encryptedContextMaxFingerprints {
		return
	}
	for _, key := range encryptedContextOwnerKeys(capture.apiKeyID, payload) {
		capture.keys[key] = struct{}{}
		if len(capture.keys) >= encryptedContextMaxFingerprints {
			return
		}
	}
}

func encryptedContextOwnerForAccount(account *auth.Account) responseRouteOwner {
	if account == nil {
		return responseRouteOwner{}
	}
	owner := responseRouteOwner{AccountID: account.ID(), AccountType: "oauth"}
	if account.IsOpenAIResponsesAPI() {
		owner.AccountType = auth.UpstreamOpenAIResponses
		owner.RouteClass = cybRelayRouteClass
	}
	return owner
}

func sameResponseRouteOwner(left, right responseRouteOwner) bool {
	return left.AccountID > 0 && left.AccountID == right.AccountID && left.AccountType == right.AccountType
}

func (h *Handler) commitEncryptedContextCapture(account *auth.Account, capture *encryptedContextCapture) {
	if h == nil || h.cache == nil || capture == nil || len(capture.keys) == 0 || !encryptedContextAffinityEnabled() {
		return
	}
	owner := encryptedContextOwnerForAccount(account)
	if owner.AccountID <= 0 {
		return
	}
	payload, err := json.Marshal(owner)
	if err != nil {
		return
	}
	cacheCtx, cancel := context.WithTimeout(context.Background(), encryptedContextCacheTimeout)
	defer cancel()
	for key := range capture.keys {
		leaseOwner := uuid.NewString()
		acquired, err := h.cache.AcquireLease(cacheCtx, encryptedContextLeaseNamespace, key, leaseOwner, time.Second)
		if err != nil || !acquired {
			continue
		}
		existingPayload, ok, getErr := h.cache.GetRuntime(cacheCtx, encryptedContextOwnerNamespace, key)
		if getErr == nil {
			if !ok {
				_ = h.cache.SetRuntime(cacheCtx, encryptedContextOwnerNamespace, key, payload, encryptedContextAffinityTTL())
			} else {
				var existing responseRouteOwner
				decodeErr := json.Unmarshal(existingPayload, &existing)
				if decodeErr != nil || existing.AccountID <= 0 {
					_ = h.cache.SetRuntime(cacheCtx, encryptedContextOwnerNamespace, key, payload, encryptedContextAffinityTTL())
				} else if sameResponseRouteOwner(existing, owner) {
					_ = h.cache.SetRuntime(cacheCtx, encryptedContextOwnerNamespace, key, payload, encryptedContextAffinityTTL())
				} else if existing.AccountID > 0 && existing.AccountID != owner.AccountID {
					logSafeEncryptedOwnerConflict(existing.AccountID, owner.AccountID)
				}
			}
		}
		_ = h.cache.ReleaseLease(cacheCtx, encryptedContextLeaseNamespace, key, leaseOwner)
	}
}

func logSafeEncryptedOwnerConflict(existingAccountID, observedAccountID int64) {
	// Account ids are operational metadata; ciphertext and fingerprints are
	// intentionally excluded from logs.
	log.Printf("encrypted context owner conflict: existing_account=%d observed_account=%d", existingAccountID, observedAccountID)
}

func encryptedContextPromptRiskDecision(owner responseRouteOwner) promptRiskDecision {
	decision := defaultPromptRiskDecision()
	decision.RouteSource = cybRelayRouteSourcePin
	decision.PinKind = encryptedContextPinKind
	decision.RoutePinned = true
	decision.Signals = []string{encryptedOwnerHitSignal}
	decision.Reason = "continued on the account that owns encrypted context"
	if owner.AccountType == auth.UpstreamOpenAIResponses || owner.RouteClass == cybRelayRouteClass {
		decision.Disposition = promptRiskDispositionRelay
	}
	return decision
}
