package proxy

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/codex2api/auth"
	"github.com/codex2api/database"
	"github.com/codex2api/security/cybroute"
	"github.com/gin-gonic/gin"
	"golang.org/x/text/unicode/norm"
)

const (
	relayCybFeedbackTTL        = 24 * time.Hour
	relayCybFeedbackMaxEntries = 1024
	relayCybFeedbackMinRunes   = 16
	// Large requests use bounded raw head/tail digest material. This keeps
	// one-shot OAuth feedback tail-sensitive without reparsing, normalizing,
	// or hashing a multi-megabyte user string on the first-token path.
	relayCybFeedbackNormalizedBodyMaxBytes = 256 * 1024
	relayCybFeedbackRawHeadBytes           = 32 * 1024
	relayCybFeedbackRawTailBytes           = 96 * 1024
)

type relayCybFeedbackDigest [sha256.Size]byte

type relayCybFeedbackEntry struct {
	digest    relayCybFeedbackDigest
	expiresAt time.Time
}

type relayCybFeedbackCache struct {
	mu      sync.Mutex
	key     [sha256.Size]byte
	enabled bool
	items   map[relayCybFeedbackDigest]*list.Element
	order   *list.List
}

var globalRelayCybFeedback = newRelayCybFeedbackCache()

func newRelayCybFeedbackCache() *relayCybFeedbackCache {
	cache := &relayCybFeedbackCache{
		enabled: true,
		items:   make(map[relayCybFeedbackDigest]*list.Element, relayCybFeedbackMaxEntries),
		order:   list.New(),
	}
	if _, err := rand.Read(cache.key[:]); err != nil {
		cache.enabled = false
	}
	return cache
}

func (c *relayCybFeedbackCache) digest(endpoint string, rawBody []byte) (relayCybFeedbackDigest, bool) {
	var digest relayCybFeedbackDigest
	if c == nil || !c.enabled || len(rawBody) == 0 || !relayCybFeedbackTextEndpoint(endpoint) {
		return digest, false
	}
	mode := "raw_body"
	material := rawBody
	if len(rawBody) <= relayCybFeedbackNormalizedBodyMaxBytes {
		if text := normalizeRelayCybFeedbackText(relayCybFeedbackLatestUserText(rawBody, endpoint)); utf8.RuneCountInString(text) >= relayCybFeedbackMinRunes {
			mode = "current_user"
			material = []byte(text)
		}
	}
	mac := hmac.New(sha256.New, c.key[:])
	writeRelayCybFeedbackFrame(mac, []byte("codex2api-relay-cyb-feedback-v1"))
	writeRelayCybFeedbackFrame(mac, []byte(strings.ToLower(strings.TrimSpace(endpoint))))
	writeRelayCybFeedbackFrame(mac, []byte(mode))
	if mode == "raw_body" && len(material) > relayCybFeedbackNormalizedBodyMaxBytes {
		writeRelayCybFeedbackFrame(mac, material[:relayCybFeedbackRawHeadBytes])
		writeRelayCybFeedbackFrame(mac, material[len(material)-relayCybFeedbackRawTailBytes:])
	} else {
		writeRelayCybFeedbackFrame(mac, material)
	}
	copy(digest[:], mac.Sum(nil))
	return digest, true
}

func relayCybFeedbackTextEndpoint(endpoint string) bool {
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "/v1/responses", "/v1/responses/compact", "/v1/chat/completions", "/v1/messages":
		return true
	default:
		return false
	}
}

func relayCybFeedbackLatestUserText(rawBody []byte, endpoint string) string {
	current, _ := relayCYBExtractUserSegments(rawBody, endpoint)
	return strings.Join(current, "\n")
}

func normalizeRelayCybFeedbackText(text string) string {
	text = norm.NFKC.String(text)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.TrimSpace(text)
}

type relayCybFeedbackWriter interface {
	Write([]byte) (int, error)
}

func writeRelayCybFeedbackFrame(writer relayCybFeedbackWriter, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func (c *relayCybFeedbackCache) contains(digest relayCybFeedbackDigest) bool {
	if c == nil || !c.enabled {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	element, ok := c.items[digest]
	if ok {
		c.order.MoveToFront(element)
	}
	return ok
}

func (c *relayCybFeedbackCache) learn(digest relayCybFeedbackDigest) {
	if c == nil || !c.enabled {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if element, ok := c.items[digest]; ok {
		element.Value.(*relayCybFeedbackEntry).expiresAt = now.Add(relayCybFeedbackTTL)
		c.order.MoveToFront(element)
		return
	}
	element := c.order.PushFront(&relayCybFeedbackEntry{digest: digest, expiresAt: now.Add(relayCybFeedbackTTL)})
	c.items[digest] = element
	for c.order.Len() > relayCybFeedbackMaxEntries {
		c.removeLocked(c.order.Back())
	}
}

func (c *relayCybFeedbackCache) pruneLocked(now time.Time) {
	for element := c.order.Back(); element != nil; {
		previous := element.Prev()
		entry, _ := element.Value.(*relayCybFeedbackEntry)
		if entry == nil || !now.Before(entry.expiresAt) {
			c.removeLocked(element)
		}
		element = previous
	}
}

func (c *relayCybFeedbackCache) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	if entry, ok := element.Value.(*relayCybFeedbackEntry); ok && entry != nil {
		delete(c.items, entry.digest)
	}
	c.order.Remove(element)
}

func (h *Handler) observeRelayRouteUsage(c *gin.Context, input *database.UsageLogInput) {
	if h == nil || h.store == nil || input == nil || input.AccountID <= 0 ||
		input.UpstreamErrorKind != "cyber_policy" ||
		(c != nil && c.GetBool(skipCYBLearningPipelineContextKey)) {
		return
	}
	plan, ok := relayRoutePlanFromContext(c)
	if !ok || !plan.Config.Enabled {
		return
	}
	account := h.store.FindByID(input.AccountID)
	if account == nil {
		return
	}
	if plan.Required() {
		h.logRelayCyberPolicyMetric(c, plan, false)
		if h.relayCYBLocalRuleMissEligible(plan, account) {
			h.enqueueRelayCYBMissSample(plan, account, database.RelayCYBMissSourceRelay)
		}
		return
	}
	if plan.Source != relayRouteSourceDefault ||
		account.IsRelayStyle() || account.IsCodexAgentIdentity() {
		return
	}
	h.logRelayCyberPolicyMetric(c, plan, true)
	h.enqueueRelayCYBMissSample(plan, account, database.RelayCYBMissSourceOAuth)
	if relayCybFeedbackLearnEligible(plan, account) {
		globalRelayCybFeedback.learn(plan.FeedbackDigest)
	}
}

// recordRelayCYBStreamAttempt preserves a real cyber_policy terminal event
// before a transparent stream retry can skip the normal final usage path. It
// writes only the independent route audit/learning state; billing usage remains
// one logical final row.
func (h *Handler) recordRelayCYBStreamAttempt(
	c *gin.Context,
	account *auth.Account,
	outcome streamOutcome,
	attemptIndex int,
	upstreamEndpoint string,
	viaWebsocket bool,
	isRetryAttempt bool,
) {
	if h == nil || account == nil || outcome.failureKind != "cyber_policy" {
		return
	}
	input := &database.UsageLogInput{
		AccountID:         account.ID(),
		Endpoint:          strings.TrimSpace(upstreamEndpoint),
		UpstreamEndpoint:  strings.TrimSpace(upstreamEndpoint),
		StatusCode:        outcome.logStatusCode,
		ViaWebsocket:      viaWebsocket,
		IsRetryAttempt:    isRetryAttempt,
		AttemptIndex:      attemptIndex,
		UpstreamErrorKind: outcome.failureKind,
		ErrorMessage:      outcome.failureMessage,
	}
	h.observeRelayRouteUsage(c, input)
	h.logRelayAuditUsage(c, input)
}

func (h *Handler) relayCYBLocalRuleMissEligible(plan *relayRoutePlan, account *auth.Account) bool {
	inspectionBody := plan.cybInspectionBody()
	if h == nil || h.store == nil || plan == nil || account == nil ||
		!plan.Required() || !plan.accountInTargetGroup(account) ||
		len(plan.AuditRawBody) == 0 || len(inspectionBody) == 0 ||
		!plan.relayCYBHasCurrentUserText() {
		return false
	}
	switch plan.Source {
	case relayRouteSourceNoAffinity, relayRouteSourceOverflow:
	case relayRouteSourceContinuation:
		// A continuation pin can carry a brand-new user turn. The common
		// current-user gate above excludes tool-only requests for every Relay
		// source, so stale history never becomes a learned rule.
	default:
		return false
	}
	if !plan.LocalRuleInspected {
		result := cybroute.Inspect(
			inspectionBody,
			plan.Endpoint,
			plan.Model,
			h.store.GetPromptFilterConfig(),
		)
		plan.LocalRuleInspected = true
		plan.LocalRuleMatched = result.Route
		plan.AuditScanTruncated = result.Truncated
		plan.AuditScannedBytes = result.ScannedBytes
		plan.AuditFullScan = result.FullScan
		plan.AuditScanDetails = relayRouteScanDetailsJSON(result)
		h.enrichRelayAuditScan(plan)
	}
	return !plan.LocalRuleMatched
}

func relayCybFeedbackLearnEligible(plan *relayRoutePlan, account *auth.Account) bool {
	return plan != nil &&
		plan.Config.Enabled &&
		!plan.Required() &&
		plan.Source == relayRouteSourceDefault &&
		plan.FeedbackDigestValid &&
		plan.relayCYBHasCurrentUserText() &&
		account != nil &&
		!account.IsRelayStyle() &&
		!account.IsCodexAgentIdentity()
}
