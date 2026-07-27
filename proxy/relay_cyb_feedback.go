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
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
	"golang.org/x/text/unicode/norm"
)

const (
	relayCybFeedbackTTL        = 24 * time.Hour
	relayCybFeedbackMaxEntries = 1024
	relayCybFeedbackMinRunes   = 16
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
	if text := normalizeRelayCybFeedbackText(relayCybFeedbackLatestUserText(rawBody, endpoint)); utf8.RuneCountInString(text) >= relayCybFeedbackMinRunes {
		mode = "current_user"
		material = []byte(text)
	}
	mac := hmac.New(sha256.New, c.key[:])
	writeRelayCybFeedbackFrame(mac, []byte("codex2api-relay-cyb-feedback-v1"))
	writeRelayCybFeedbackFrame(mac, []byte(strings.ToLower(strings.TrimSpace(endpoint))))
	writeRelayCybFeedbackFrame(mac, []byte(mode))
	writeRelayCybFeedbackFrame(mac, material)
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
	envelope := promptfilter.BuildEnvelope(
		rawBody,
		endpoint,
		"",
		promptfilter.TransportHTTP,
		max(len(rawBody), promptfilter.DefaultMaxTextLength),
	)
	parts := make([]string, 0, 2)
	for _, segment := range envelope.Segments {
		if segment.Origin != promptfilter.OriginCurrentUser {
			continue
		}
		if text := strings.TrimSpace(segment.Text); text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
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
		return
	}
	if account.IsRelayStyle() || account.IsCodexAgentIdentity() {
		return
	}
	h.logRelayCyberPolicyMetric(c, plan, true)
	h.enqueueRelayCYBMissSample(plan, account)
	if !relayCybFeedbackLearnEligible(plan, account) {
		return
	}
	globalRelayCybFeedback.learn(plan.FeedbackDigest)
}

func relayCybFeedbackLearnEligible(plan *relayRoutePlan, account *auth.Account) bool {
	return plan != nil &&
		plan.Config.Enabled &&
		!plan.Required() &&
		plan.Source == relayRouteSourceDefault &&
		plan.FeedbackDigestValid &&
		account != nil &&
		!account.IsRelayStyle() &&
		!account.IsCodexAgentIdentity()
}
