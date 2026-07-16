package wsrelay

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/codex2api/auth"
	"github.com/tidwall/gjson"
)

const (
	safePoolScopeEnv       = "CODEX_WS_SAFE_POOL_SCOPE"
	safePoolMaxSlotsEnv    = "CODEX_WS_SAFE_POOL_MAX_SLOTS"
	safePoolWaitMillisEnv  = "CODEX_WS_SAFE_POOL_WAIT_MS"
	safePoolFenceMillisEnv = "CODEX_WS_SAFE_POOL_REUSE_FENCE_MS"

	safePoolAccountTag = "sys:ws-safe-pool"
	oneShotAccountTag  = "sys:ws-oneshot"
	safePoolSlotsTag   = "sys:ws-safe-pool-slots="

	// Default to the configured hard ceiling and clamp to each dynamic account's
	// real concurrency limit. A fixed 32-owner default would turn healthy
	// 50/100-concurrency accounts into local 502s during a safe-pool rollout.
	defaultSafePoolMaxSlots        = maximumSafePoolConfiguredSlots
	defaultSafePoolWait            = 250 * time.Millisecond
	defaultSafePoolReuseFence      = 100 * time.Millisecond
	minimumSafePoolWait            = 10 * time.Millisecond
	maximumSafePoolWait            = 5 * time.Second
	minimumSafePoolReuseFence      = 10 * time.Millisecond
	maximumSafePoolReuseFence      = time.Second
	maximumSafePoolConfiguredSlots = 256
)

type statelessPoolMode uint8

const (
	// statelessPoolDefault preserves the pre-candidate explicit-session path.
	// It is intentionally distinct from the operator's hard one-shot switch so
	// a tagged canary cannot change transport semantics for unenrolled accounts.
	statelessPoolDefault statelessPoolMode = iota
	statelessPoolOneShot
	statelessPoolLegacy
	statelessPoolSafe
	statelessPoolHTTPFallback
)

type statelessPoolPolicy struct {
	mode       statelessPoolMode
	slots      int
	wait       time.Duration
	reuseFence time.Duration
}

// resolveStatelessPoolPolicy preserves the pre-candidate baseline unless an
// operator explicitly selects legacy/safe/one-shot behavior. Missing, disabled
// or invalid scope keeps that baseline. The tagged rollout is stricter: accounts
// without the opt-in tag stay on one-shot sockets so enabling one canary cannot
// silently restore explicit-session or continuation reuse for every other
// account. CODEX_WS_STATELESS_ONESHOT always wins, including over account tags.
func resolveStatelessPoolPolicy(account *auth.Account, manager *Manager) statelessPoolPolicy {
	policy := statelessPoolPolicy{
		mode:       statelessPoolDefault,
		slots:      defaultSafePoolMaxSlots,
		wait:       durationFromMillisEnv(safePoolWaitMillisEnv, defaultSafePoolWait, minimumSafePoolWait, maximumSafePoolWait),
		reuseFence: durationFromMillisEnv(safePoolFenceMillisEnv, defaultSafePoolReuseFence, minimumSafePoolReuseFence, maximumSafePoolReuseFence),
	}
	if statelessOneShotEnabled() {
		policy.mode = statelessPoolOneShot
		return policy
	}

	tags := accountTagSnapshot(account)
	if hasExactTag(tags, oneShotAccountTag) {
		policy.mode = statelessPoolOneShot
		return policy
	}
	// A process-local compatibility/isolation fuse persists even if rollout
	// scope or tags change. Otherwise a hot tag removal could silently re-enter
	// the older WS path that the same process just proved unsafe.
	if manager != nil && account != nil && manager.IsSafePoolFused(account.ID()) {
		policy.mode = statelessPoolHTTPFallback
		return policy
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(safePoolScopeEnv))) {
	case "legacy":
		policy.mode = statelessPoolLegacy
		policy.slots = StatelessConnectionSlots
		return policy
	case "tagged":
		if !hasExactTag(tags, safePoolAccountTag) {
			policy.mode = statelessPoolOneShot
			return policy
		}
	case "all":
		// Dynamic account discovery is intentional. No account ID or name is
		// embedded in the rollout policy.
	case "", "disabled", "off", "none":
		return policy
	default:
		return policy
	}
	policy.mode = statelessPoolSafe
	policy.slots = configuredSafePoolSlots(tags)
	return policy
}

func accountTagSnapshot(account *auth.Account) []string {
	if account == nil {
		return nil
	}
	account.Mu().RLock()
	tags := append([]string(nil), account.Tags...)
	account.Mu().RUnlock()
	return tags
}

func hasExactTag(tags []string, expected string) bool {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(tag), expected) {
			return true
		}
	}
	return false
}

func configuredSafePoolSlots(tags []string) int {
	slots := integerFromEnv(safePoolMaxSlotsEnv, defaultSafePoolMaxSlots, 1, maximumSafePoolConfiguredSlots)
	for _, rawTag := range tags {
		tag := strings.ToLower(strings.TrimSpace(rawTag))
		if !strings.HasPrefix(tag, safePoolSlotsTag) {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(tag, safePoolSlotsTag)))
		if err == nil && value >= 1 && value <= maximumSafePoolConfiguredSlots {
			slots = value
		}
	}
	return slots
}

func integerFromEnv(name string, fallback, minimum, maximum int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func durationFromMillisEnv(name string, fallback, minimum, maximum time.Duration) time.Duration {
	minimumMillis := int(minimum / time.Millisecond)
	maximumMillis := int(maximum / time.Millisecond)
	fallbackMillis := int(fallback / time.Millisecond)
	return time.Duration(integerFromEnv(name, fallbackMillis, minimumMillis, maximumMillis)) * time.Millisecond
}

// safePoolHandshakeHeaders returns the connection-scoped portion of an upgrade
// request. The official Codex client sends turn state and turn metadata in each
// response.create client_metadata object because HTTP upgrade headers are
// frozen for the lifetime of a reused socket. The caller copies those values
// into the frame before using this header set.
func safePoolHandshakeHeaders(headers http.Header) http.Header {
	stable := headers.Clone()
	stable.Del("X-Codex-Turn-State")
	stable.Del("X-Codex-Turn-Metadata")
	stable.Del("Traceparent")
	stable.Del("Tracestate")
	return stable
}

// safePoolOwnerHandshakeHeaders mirrors the stable identity emitted by the
// official Codex WebSocket client. The session/thread pair also exists in each
// response.create client_metadata object, so a gateway can reconstruct the
// frozen upgrade headers without borrowing identity from another request.
// Conflicting caller-provided values reject safe reuse. The executor then uses
// a pre-write same-account HTTP fallback, or fails a continuation closed.
func safePoolOwnerHandshakeHeaders(headers http.Header, requestBody []byte) (http.Header, bool) {
	sessionID := strings.TrimSpace(gjson.GetBytes(requestBody, "client_metadata.session_id").String())
	threadID := strings.TrimSpace(gjson.GetBytes(requestBody, "client_metadata.thread_id").String())
	if sessionID == "" || threadID == "" {
		return nil, false
	}
	stable := safePoolHandshakeHeaders(headers)
	// Stateless legacy routing may have derived underscore-style session
	// headers from prompt_cache_key. They are a different identity namespace
	// from the official Codex session/thread pair and must never coexist on a
	// persistent safe socket.
	stable.Del("Session_id")
	stable.Del("Conversation_id")
	for name, expected := range map[string]string{
		"Session-Id":          sessionID,
		"Thread-Id":           threadID,
		"X-Client-Request-Id": threadID,
	} {
		if existing := strings.TrimSpace(stable.Get(name)); existing != "" && existing != expected {
			return nil, false
		}
		stable.Set(name, expected)
	}
	if windowID := strings.TrimSpace(gjson.GetBytes(requestBody, "client_metadata.x-codex-window-id").String()); windowID != "" {
		if existing := strings.TrimSpace(stable.Get("X-Codex-Window-Id")); existing != "" && existing != windowID {
			return nil, false
		}
		stable.Set("X-Codex-Window-Id", windowID)
	}
	return stable, true
}

// safePoolHeaderFingerprint binds a physical socket to the exact stable
// HTTP-upgrade identity. Authorization, account identity, device attestation,
// client/thread identity and custom headers remain connection-scoped. The
// compatibility-only window header is deliberately excluded: the official
// client keeps the same physical socket across auto-compaction window changes
// and carries the current window in each response.create client_metadata.
// Only the digest is retained in the local pool key.
func safePoolHeaderFingerprint(headers http.Header) string {
	identityHeaders := headers.Clone()
	identityHeaders.Del("X-Codex-Window-Id")

	keys := make([]string, 0, len(identityHeaders))
	for key := range identityHeaders {
		keys = append(keys, http.CanonicalHeaderKey(key))
	}
	sort.Strings(keys)

	hash := sha256.New()
	for _, key := range keys {
		hash.Write([]byte(strconv.Itoa(len(key))))
		hash.Write([]byte{':'})
		hash.Write([]byte(key))
		values := identityHeaders.Values(key)
		for _, value := range values {
			hash.Write([]byte{'\n'})
			hash.Write([]byte(strconv.Itoa(len(value))))
			hash.Write([]byte{':'})
			hash.Write([]byte(value))
		}
		hash.Write([]byte{'\n', '\n'})
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func safePoolRouteKey(baseKey string, headers http.Header) string {
	return strings.TrimSpace(baseKey) + "#ws-safe:" + safePoolHeaderFingerprint(headers)
}

// safePoolOwnerKey accepts only the stable session+thread pair emitted by the
// official Codex Responses WebSocket client in every response.create frame.
// API key, prompt content, installation/window IDs and generated cache keys are
// deliberately insufficient: in a gateway they can represent many unrelated
// users or conversations. turn_id is intentionally excluded because it changes
// every turn; it is an audit identity, not the owner of a persistent socket.
func safePoolOwnerKey(requestBody []byte, apiKey string) (string, bool) {
	sessionID := strings.TrimSpace(gjson.GetBytes(requestBody, "client_metadata.session_id").String())
	threadID := strings.TrimSpace(gjson.GetBytes(requestBody, "client_metadata.thread_id").String())
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" || sessionID == "" || threadID == "" {
		return "", false
	}

	hash := sha256.New()
	for _, value := range []string{apiKey, sessionID, threadID} {
		hash.Write([]byte(strconv.Itoa(len(value))))
		hash.Write([]byte{':'})
		hash.Write([]byte(value))
		hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil)[:16]), true
}

// safePoolRequestEligible rejects response modes whose server events do not
// carry enough stable response/item ownership to validate a reused socket.
// Text requests remain eligible; audio-capable requests use the pre-write
// same-account HTTP fallback until the protocol exposes equivalent framing.
func safePoolRequestEligible(requestBody []byte) bool {
	for _, path := range []string{"modalities", "output_modalities"} {
		value := gjson.GetBytes(requestBody, path)
		if !value.Exists() {
			continue
		}
		if value.IsArray() {
			for _, modality := range value.Array() {
				if strings.EqualFold(strings.TrimSpace(modality.String()), "audio") {
					return false
				}
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(value.String()), "audio") {
			return false
		}
	}
	for _, path := range []string{"audio", "output_audio"} {
		value := gjson.GetBytes(requestBody, path)
		if value.Exists() && value.Type != gjson.Null {
			return false
		}
	}
	return true
}

func safePoolOwnedRouteKey(baseKey, ownerKey string, headers http.Header) string {
	return safePoolRouteKey(strings.TrimSpace(baseKey)+"#owner:"+ownerKey, headers)
}
