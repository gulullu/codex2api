package proxy

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codex2api/database"
	"github.com/gin-gonic/gin"
)

const (
	upstreamCybFeedbackSignal         = "upstream_cyb_feedback_hash"
	contextUpstreamCybFeedbackDigest  = "upstreamCybFeedbackDigest"
	upstreamCybFeedbackHashDomain     = "codex2api-upstream-cyb-feedback-v1"
	upstreamCybFeedbackDefaultTTL     = 24 * time.Hour
	upstreamCybFeedbackMaximumTTL     = 24 * time.Hour
	upstreamCybFeedbackDefaultEntries = 1024
	upstreamCybFeedbackMaximumEntries = 16384
)

type upstreamCybFeedbackConfig struct {
	Enabled    bool
	TTL        time.Duration
	MaxEntries int
}

type upstreamCybFeedbackDigest [sha256.Size]byte

type upstreamCybFeedbackEntry struct {
	Digest    upstreamCybFeedbackDigest
	ExpiresAt time.Time
}

// upstreamCybFeedbackCache remembers only a keyed digest of an exact request.
// It deliberately stores neither prompt text nor a reusable session identity.
// The process-random key also makes persisted/offline dictionary attacks
// impossible because the whole cache disappears when the process exits.
type upstreamCybFeedbackCache struct {
	mu         sync.Mutex
	enabled    bool
	ttl        time.Duration
	maxEntries int
	key        [sha256.Size]byte
	now        func() time.Time
	lru        *list.List
	entries    map[upstreamCybFeedbackDigest]*list.Element
}

func upstreamCybFeedbackConfigFromEnv() upstreamCybFeedbackConfig {
	cfg := upstreamCybFeedbackConfig{
		Enabled:    true,
		TTL:        upstreamCybFeedbackDefaultTTL,
		MaxEntries: upstreamCybFeedbackDefaultEntries,
	}
	if raw := strings.TrimSpace(os.Getenv("CODEX_UPSTREAM_CYB_FEEDBACK_ENABLED")); raw != "" {
		if enabled, err := strconv.ParseBool(raw); err == nil {
			cfg.Enabled = enabled
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CODEX_UPSTREAM_CYB_FEEDBACK_TTL")); raw != "" {
		if ttl, err := time.ParseDuration(raw); err == nil && ttl > 0 {
			cfg.TTL = ttl
		}
	}
	if cfg.TTL > upstreamCybFeedbackMaximumTTL {
		cfg.TTL = upstreamCybFeedbackMaximumTTL
	}
	if raw := strings.TrimSpace(os.Getenv("CODEX_UPSTREAM_CYB_FEEDBACK_MAX_ENTRIES")); raw != "" {
		if maxEntries, err := strconv.Atoi(raw); err == nil && maxEntries > 0 {
			cfg.MaxEntries = maxEntries
		}
	}
	if cfg.MaxEntries > upstreamCybFeedbackMaximumEntries {
		cfg.MaxEntries = upstreamCybFeedbackMaximumEntries
	}
	return cfg
}

func newUpstreamCybFeedbackCache(cfg upstreamCybFeedbackConfig) *upstreamCybFeedbackCache {
	cache := &upstreamCybFeedbackCache{
		enabled:    cfg.Enabled,
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		now:        time.Now,
		lru:        list.New(),
		entries:    make(map[upstreamCybFeedbackDigest]*list.Element),
	}
	if !cache.enabled {
		return cache
	}
	if cache.ttl <= 0 {
		cache.ttl = upstreamCybFeedbackDefaultTTL
	}
	if cache.maxEntries <= 0 {
		cache.maxEntries = upstreamCybFeedbackDefaultEntries
	}
	if _, err := io.ReadFull(rand.Reader, cache.key[:]); err != nil {
		// A deterministic or empty HMAC key would turn hashes of low-entropy
		// prompts into an avoidable disclosure risk. Fail closed for the cache;
		// normal routing remains available.
		cache.enabled = false
		log.Printf("upstream CYB feedback cache disabled: random key unavailable: %v", err)
	}
	return cache
}

func newUpstreamCybFeedbackCacheForTest(cfg upstreamCybFeedbackConfig, key [sha256.Size]byte, now func() time.Time) *upstreamCybFeedbackCache {
	cache := &upstreamCybFeedbackCache{
		enabled:    cfg.Enabled,
		ttl:        cfg.TTL,
		maxEntries: cfg.MaxEntries,
		key:        key,
		now:        now,
		lru:        list.New(),
		entries:    make(map[upstreamCybFeedbackDigest]*list.Element),
	}
	if cache.now == nil {
		cache.now = time.Now
	}
	if cache.ttl <= 0 {
		cache.ttl = upstreamCybFeedbackDefaultTTL
	}
	if cache.maxEntries <= 0 {
		cache.maxEntries = upstreamCybFeedbackDefaultEntries
	}
	return cache
}

func (c *upstreamCybFeedbackCache) digest(endpoint string, rawBody []byte) (upstreamCybFeedbackDigest, bool) {
	var digest upstreamCybFeedbackDigest
	if c == nil || !c.enabled || len(rawBody) == 0 || !cybRelayTextEndpoint(endpoint) {
		return digest, false
	}
	mac := hmac.New(sha256.New, c.key[:])
	writeUpstreamCybFeedbackFrame(mac, []byte(upstreamCybFeedbackHashDomain))
	writeUpstreamCybFeedbackFrame(mac, []byte(strings.ToLower(strings.TrimSpace(endpoint))))
	writeUpstreamCybFeedbackFrame(mac, rawBody)
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

type upstreamCybFeedbackHashWriter interface {
	Write([]byte) (int, error)
}

func writeUpstreamCybFeedbackFrame(writer upstreamCybFeedbackHashWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func (c *upstreamCybFeedbackCache) lookupDigest(digest upstreamCybFeedbackDigest) bool {
	if c == nil || !c.enabled {
		return false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(now)
	element, ok := c.entries[digest]
	if !ok {
		return false
	}
	c.lru.MoveToFront(element)
	return true
}

func (c *upstreamCybFeedbackCache) learnDigest(digest upstreamCybFeedbackDigest) {
	if c == nil || !c.enabled {
		return
	}
	now := c.now()
	expiresAt := now.Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpiredLocked(now)
	if element, ok := c.entries[digest]; ok {
		entry := element.Value.(*upstreamCybFeedbackEntry)
		entry.ExpiresAt = expiresAt
		c.lru.MoveToFront(element)
		return
	}
	entry := &upstreamCybFeedbackEntry{Digest: digest, ExpiresAt: expiresAt}
	c.entries[digest] = c.lru.PushFront(entry)
	for c.lru.Len() > c.maxEntries {
		c.removeElementLocked(c.lru.Back())
	}
}

func (c *upstreamCybFeedbackCache) pruneExpiredLocked(now time.Time) {
	for element := c.lru.Back(); element != nil; {
		previous := element.Prev()
		entry, _ := element.Value.(*upstreamCybFeedbackEntry)
		if entry == nil || !now.Before(entry.ExpiresAt) {
			c.removeElementLocked(element)
		}
		element = previous
	}
}

func (c *upstreamCybFeedbackCache) removeElementLocked(element *list.Element) {
	if element == nil {
		return
	}
	entry, _ := element.Value.(*upstreamCybFeedbackEntry)
	if entry != nil {
		delete(c.entries, entry.Digest)
	}
	c.lru.Remove(element)
}

// captureUpstreamCybFeedbackRequest records a digest of the original inbound
// bytes. HTTP handlers use overwrite=false so an internal /responses ->
// /responses/compact hand-off keeps the real public endpoint and body. A
// Responses WebSocket connection uses overwrite=true once per turn because a
// gin.Context is shared across turns.
func (h *Handler) captureUpstreamCybFeedbackRequest(c *gin.Context, endpoint string, rawBody []byte, overwrite bool) {
	if c == nil {
		return
	}
	if !overwrite {
		if _, ok := upstreamCybFeedbackDigestFromContext(c); ok {
			return
		}
	}
	c.Set(contextUpstreamCybFeedbackDigest, nil)
	if h == nil || h.upstreamCybFeedback == nil {
		return
	}
	if digest, ok := h.upstreamCybFeedback.digest(endpoint, rawBody); ok {
		c.Set(contextUpstreamCybFeedbackDigest, digest)
	}
}

// applyUpstreamCybFeedbackRoute upgrades an otherwise-default decision. When
// local/probe evidence already routes the request, it only appends the feedback
// signal and keeps the stronger source/reason/pin semantics.
func (h *Handler) applyUpstreamCybFeedbackRoute(c *gin.Context, rawBody []byte, endpoint string, decision promptRiskDecision) promptRiskDecision {
	h.captureUpstreamCybFeedbackRequest(c, endpoint, rawBody, false)
	if h == nil || h.upstreamCybFeedback == nil {
		return decision
	}
	digest, ok := upstreamCybFeedbackDigestFromContext(c)
	if !ok {
		return decision
	}
	relayCfg := h.cybRelayConfig()
	if !relayCfg.Enabled || relayCfg.GroupID <= 0 || !h.upstreamCybFeedback.lookupDigest(digest) {
		return decision
	}
	if decision.blocks() {
		return decision
	}
	if decision.routesToCybRelay() {
		decision.Signals = appendUniqueRouteSignal(decision.Signals, upstreamCybFeedbackSignal)
		return decision
	}
	return promptRiskDecision{
		Disposition:        promptRiskDispositionRelay,
		Reason:             "Exact request previously received OAuth cyber_policy",
		Signals:            []string{upstreamCybFeedbackSignal},
		RouteSource:        cybRelayRouteSourceDirect,
		SkipPinPersistence: true,
	}
}

func upstreamCybFeedbackDigestFromContext(c *gin.Context) (upstreamCybFeedbackDigest, bool) {
	var zero upstreamCybFeedbackDigest
	if c == nil {
		return zero, false
	}
	value, ok := c.Get(contextUpstreamCybFeedbackDigest)
	if !ok || value == nil {
		return zero, false
	}
	digest, ok := value.(upstreamCybFeedbackDigest)
	return digest, ok
}

// maybeLearnUpstreamCybFeedback is intentionally called only after canonical
// usage metadata has been finalized. Hidden retries, Guardian probes, Relay
// failures, pinned/overflow routes, and non-cyber errors must never train it.
func (h *Handler) maybeLearnUpstreamCybFeedback(c *gin.Context, input *database.UsageLogInput) {
	if h == nil || h.upstreamCybFeedback == nil || input == nil || input.GuardianAttemptOnly || input.AccountID <= 0 {
		return
	}
	relayCfg := h.cybRelayConfig()
	if !relayCfg.Enabled || relayCfg.GroupID <= 0 || strings.TrimSpace(input.LogicalRequestID) == "" {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(input.UpstreamErrorKind), "cyber_policy") ||
		!strings.EqualFold(strings.TrimSpace(input.UpstreamAccountType), "oauth") ||
		strings.TrimSpace(input.RouteClass) != promptRiskDispositionDefault ||
		strings.TrimSpace(input.RouteSource) != cybRelayRouteSourceDefault ||
		input.RoutePinned || strings.TrimSpace(input.PinKind) != "" {
		return
	}
	digest, ok := upstreamCybFeedbackDigestFromContext(c)
	if !ok {
		return
	}
	h.upstreamCybFeedback.learnDigest(digest)
}
