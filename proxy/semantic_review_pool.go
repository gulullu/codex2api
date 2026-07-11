package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SemanticReviewStrategyRoundRobin = "round_robin"
	SemanticReviewStrategyRandom     = "random"

	semanticReviewProviderCooldownDefault = 5 * time.Second
	semanticReviewProviderCooldownAuth    = 30 * time.Second
	semanticReviewProviderCooldownMax     = 60 * time.Second
	semanticReviewPoolTimeoutMin          = 1 * time.Second
	semanticReviewPoolTimeoutMax          = 30 * time.Second
)

// SemanticReviewProvider describes one independent OpenAI-compatible semantic
// reviewer. MaxConcurrency is enforced independently for each provider.
type SemanticReviewProvider struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	BaseURL          string `json:"base_url"`
	Model            string `json:"model"`
	APIKey           string `json:"api_key,omitempty"`
	APIKeyConfigured bool   `json:"api_key_configured"`
	TimeoutMS        int    `json:"timeout_ms"`
	MaxConcurrency   int    `json:"max_concurrency"`
}

// SemanticReviewProviderPool is persisted as one JSON value so provider
// credentials and the selection strategy change atomically.
type SemanticReviewProviderPool struct {
	Strategy  string                   `json:"strategy"`
	Providers []SemanticReviewProvider `json:"providers"`
}

func NormalizeSemanticReviewSelectionStrategy(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SemanticReviewStrategyRandom:
		return SemanticReviewStrategyRandom
	default:
		return SemanticReviewStrategyRoundRobin
	}
}

func NormalizeSemanticReviewProviderPool(pool SemanticReviewProviderPool) SemanticReviewProviderPool {
	pool.Strategy = NormalizeSemanticReviewSelectionStrategy(pool.Strategy)
	providers := make([]SemanticReviewProvider, 0, len(pool.Providers))
	seenIDs := make(map[string]int, len(pool.Providers))
	for index, provider := range pool.Providers {
		provider.ID = strings.TrimSpace(provider.ID)
		provider.Name = strings.TrimSpace(provider.Name)
		provider.BaseURL = strings.TrimRight(strings.TrimSpace(provider.BaseURL), "/")
		provider.Model = strings.TrimSpace(provider.Model)
		provider.APIKey = strings.TrimSpace(provider.APIKey)
		provider.APIKeyConfigured = provider.APIKeyConfigured || provider.APIKey != ""
		if provider.ID == "" {
			provider.ID = semanticReviewGeneratedProviderID(provider, index)
		}
		if count := seenIDs[provider.ID]; count > 0 {
			seenIDs[provider.ID] = count + 1
			provider.ID = fmt.Sprintf("%s-%d", provider.ID, count+1)
		} else {
			seenIDs[provider.ID] = 1
		}
		if provider.Name == "" {
			provider.Name = provider.ID
		}
		if provider.BaseURL == "" {
			provider.BaseURL = "https://api.openai.com/v1"
		}
		if provider.Model == "" {
			provider.Model = semanticReviewDefaultModel
		}
		provider.TimeoutMS = clampSemanticReviewInt(provider.TimeoutMS, 100, 30000)
		if provider.TimeoutMS == 100 && pool.Providers[index].TimeoutMS <= 0 {
			provider.TimeoutMS = semanticReviewDefaultTimeoutMS
		}
		provider.MaxConcurrency = clampSemanticReviewInt(provider.MaxConcurrency, 1, 100)
		if provider.MaxConcurrency == 1 && pool.Providers[index].MaxConcurrency <= 0 {
			provider.MaxConcurrency = int(semanticReviewDefaultMaxConcurrency)
		}
		providers = append(providers, provider)
	}
	if providers == nil {
		providers = []SemanticReviewProvider{}
	}
	pool.Providers = providers
	return pool
}

func ParseSemanticReviewProviderPool(raw string) (SemanticReviewProviderPool, error) {
	if strings.TrimSpace(raw) == "" {
		return NormalizeSemanticReviewProviderPool(SemanticReviewProviderPool{}), nil
	}
	var pool SemanticReviewProviderPool
	if err := json.Unmarshal([]byte(raw), &pool); err != nil {
		return SemanticReviewProviderPool{}, fmt.Errorf("parse semantic review provider pool: %w", err)
	}
	return NormalizeSemanticReviewProviderPool(pool), nil
}

func MarshalSemanticReviewProviderPool(pool SemanticReviewProviderPool) (string, error) {
	normalized := NormalizeSemanticReviewProviderPool(pool)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal semantic review provider pool: %w", err)
	}
	return string(encoded), nil
}

func semanticReviewGeneratedProviderID(provider SemanticReviewProvider, index int) string {
	material := strings.TrimSpace(provider.Name) + "\n" + strings.TrimSpace(provider.BaseURL) + "\n" + strings.TrimSpace(provider.Model)
	if strings.TrimSpace(material) == "" {
		return fmt.Sprintf("provider-%d", index+1)
	}
	sum := sha256.Sum256([]byte(material))
	return "provider-" + hex.EncodeToString(sum[:4])
}

func semanticReviewLegacyProvider(cfg semanticReviewConfig) SemanticReviewProvider {
	timeoutMS := int(cfg.Timeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = semanticReviewDefaultTimeoutMS
	}
	maxConcurrency := int(cfg.MaxConcurrency)
	if maxConcurrency <= 0 {
		maxConcurrency = int(semanticReviewDefaultMaxConcurrency)
	}
	return NormalizeSemanticReviewProviderPool(SemanticReviewProviderPool{
		Providers: []SemanticReviewProvider{{
			ID:               "legacy",
			Name:             "Legacy semantic reviewer",
			Enabled:          true,
			BaseURL:          cfg.BaseURL,
			Model:            cfg.Model,
			APIKey:           cfg.APIKey,
			APIKeyConfigured: strings.TrimSpace(cfg.APIKey) != "",
			TimeoutMS:        timeoutMS,
			MaxConcurrency:   maxConcurrency,
		}},
	}).Providers[0]
}

func semanticReviewPoolForConfig(cfg semanticReviewConfig) SemanticReviewProviderPool {
	pool := NormalizeSemanticReviewProviderPool(cfg.ProviderPool)
	if len(pool.Providers) == 0 && !cfg.ProviderPoolConfigured {
		pool.Providers = []SemanticReviewProvider{semanticReviewLegacyProvider(cfg)}
	}
	return pool
}

func semanticReviewProviderReady(provider SemanticReviewProvider) bool {
	return provider.Enabled && strings.TrimSpace(provider.APIKey) != "" && strings.TrimSpace(provider.BaseURL) != "" && strings.TrimSpace(provider.Model) != ""
}

func semanticReviewPoolReady(cfg semanticReviewConfig) bool {
	for _, provider := range semanticReviewPoolForConfig(cfg).Providers {
		if semanticReviewProviderReady(provider) {
			return true
		}
	}
	return false
}

type semanticReviewProviderState struct {
	inFlight      atomic.Int64
	cooldownUntil atomic.Int64
}

var (
	semanticReviewProviderStates sync.Map
	semanticReviewPoolStates     sync.Map
)

type semanticReviewPoolState struct {
	cursor atomic.Uint64
}

func resetSemanticReviewProviderRuntimeState() {
	semanticReviewProviderStates.Range(func(key, _ any) bool {
		semanticReviewProviderStates.Delete(key)
		return true
	})
	semanticReviewPoolStates.Range(func(key, _ any) bool {
		semanticReviewPoolStates.Delete(key)
		return true
	})
}

func semanticReviewPoolStateFor(pool SemanticReviewProviderPool) *semanticReviewPoolState {
	key := semanticReviewPoolIdentity(pool)
	state, _ := semanticReviewPoolStates.LoadOrStore(key, &semanticReviewPoolState{})
	return state.(*semanticReviewPoolState)
}

func semanticReviewProviderStateFor(provider SemanticReviewProvider) *semanticReviewProviderState {
	key := semanticReviewProviderIdentity(provider)
	state, _ := semanticReviewProviderStates.LoadOrStore(key, &semanticReviewProviderState{})
	return state.(*semanticReviewProviderState)
}

func semanticReviewProviderIdentity(provider SemanticReviewProvider) string {
	keyHash := sha256.Sum256([]byte(provider.APIKey))
	material := strings.Join([]string{
		provider.ID,
		provider.BaseURL,
		provider.Model,
		hex.EncodeToString(keyHash[:]),
		strconv.Itoa(provider.TimeoutMS),
		strconv.Itoa(provider.MaxConcurrency),
	}, "\n")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func semanticReviewPoolIdentity(pool SemanticReviewProviderPool) string {
	pool = NormalizeSemanticReviewProviderPool(pool)
	var builder strings.Builder
	builder.WriteString(pool.Strategy)
	for _, provider := range pool.Providers {
		builder.WriteByte('\n')
		builder.WriteString(semanticReviewProviderIdentity(provider))
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatBool(provider.Enabled))
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func semanticReviewProviderOrder(pool SemanticReviewProviderPool) []SemanticReviewProvider {
	ready := make([]SemanticReviewProvider, 0, len(pool.Providers))
	for _, provider := range pool.Providers {
		if semanticReviewProviderReady(provider) {
			ready = append(ready, provider)
		}
	}
	if len(ready) < 2 {
		return ready
	}
	var start int
	if NormalizeSemanticReviewSelectionStrategy(pool.Strategy) == SemanticReviewStrategyRandom {
		start = rand.IntN(len(ready))
	} else {
		cursor := &semanticReviewPoolStateFor(pool).cursor
		start = int((cursor.Add(1) - 1) % uint64(len(ready)))
	}
	ordered := make([]SemanticReviewProvider, 0, len(ready))
	ordered = append(ordered, ready[start:]...)
	ordered = append(ordered, ready[:start]...)
	return ordered
}

func acquireSemanticReviewProvider(provider SemanticReviewProvider) (*semanticReviewProviderState, bool) {
	state := semanticReviewProviderStateFor(provider)
	if until := state.cooldownUntil.Load(); until > time.Now().UnixNano() {
		return state, false
	}
	limit := int64(provider.MaxConcurrency)
	if limit <= 0 {
		limit = semanticReviewDefaultMaxConcurrency
	}
	for {
		current := state.inFlight.Load()
		if current >= limit {
			return state, false
		}
		if state.inFlight.CompareAndSwap(current, current+1) {
			return state, true
		}
	}
}

func releaseSemanticReviewProvider(state *semanticReviewProviderState) {
	if state != nil {
		state.inFlight.Add(-1)
	}
}

type semanticReviewProviderHTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *semanticReviewProviderHTTPError) Error() string {
	return fmt.Sprintf("semantic review request failed with status %d", e.StatusCode)
}

func semanticReviewRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func semanticReviewProviderCooldown(err error) time.Duration {
	if err == nil {
		return 0
	}
	var statusErr *semanticReviewProviderHTTPError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusTooManyRequests:
			cooldown := statusErr.RetryAfter
			if cooldown <= 0 {
				cooldown = semanticReviewProviderCooldownDefault
			}
			if cooldown > semanticReviewProviderCooldownMax {
				cooldown = semanticReviewProviderCooldownMax
			}
			return cooldown
		case http.StatusUnauthorized, http.StatusForbidden:
			return semanticReviewProviderCooldownAuth
		default:
			if statusErr.StatusCode >= 500 {
				return semanticReviewProviderCooldownDefault
			}
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return semanticReviewProviderCooldownDefault
	}
	return 0
}

func markSemanticReviewProviderFailure(state *semanticReviewProviderState, err error) {
	if state == nil {
		return
	}
	cooldown := semanticReviewProviderCooldown(err)
	if cooldown <= 0 {
		return
	}
	until := time.Now().Add(cooldown).UnixNano()
	for {
		current := state.cooldownUntil.Load()
		if current >= until || state.cooldownUntil.CompareAndSwap(current, until) {
			return
		}
	}
}

func runSemanticReviewPool(ctx context.Context, cfg semanticReviewConfig, endpoint string, model string, text string) (semanticReviewResult, error) {
	pool := semanticReviewPoolForConfig(cfg)
	cacheKey := semanticReviewCacheKeyForPool(pool, endpoint, model, text)
	if cached, ok := semanticReviewCacheState.get(cacheKey); ok {
		cached.Cached = true
		return cached, nil
	}

	providers := semanticReviewProviderOrder(pool)
	if len(providers) == 0 {
		return semanticReviewResult{Model: cfg.Model}, fmt.Errorf("semantic review has no enabled configured provider")
	}
	poolCtx, cancel := context.WithTimeout(ctx, semanticReviewPoolTimeout(cfg, providers))
	defer cancel()
	errorsByProvider := make([]string, 0, len(providers))
	attempted := 0
	for index, provider := range providers {
		state, acquired := acquireSemanticReviewProvider(provider)
		if !acquired {
			continue
		}
		attempted++
		attemptProvider := provider
		if deadline, ok := poolCtx.Deadline(); ok {
			remainingProviders := len(providers) - index
			attemptBudget := time.Until(deadline) / time.Duration(remainingProviders)
			configuredTimeout := time.Duration(provider.TimeoutMS) * time.Millisecond
			if configuredTimeout <= 0 || configuredTimeout > attemptBudget {
				if attemptBudget < time.Millisecond {
					attemptBudget = time.Millisecond
				}
				attemptProvider.TimeoutMS = int(attemptBudget / time.Millisecond)
			}
		}
		result, err := callSemanticReviewProvider(poolCtx, attemptProvider, endpoint, model, text)
		releaseSemanticReviewProvider(state)
		if err == nil {
			result.ProviderID = provider.ID
			result.ProviderName = provider.Name
			if strings.TrimSpace(result.Model) == "" {
				result.Model = provider.Model
			}
			if cfg.CacheTTL > 0 {
				semanticReviewCacheState.set(cacheKey, result, cfg.CacheTTL)
			}
			return result, nil
		}
		if ctx.Err() != nil {
			return semanticReviewResult{Model: provider.Model, ProviderID: provider.ID, ProviderName: provider.Name}, ctx.Err()
		}
		markSemanticReviewProviderFailure(state, err)
		errorsByProvider = append(errorsByProvider, fmt.Sprintf("%s: %v", semanticReviewProviderLabel(provider), err))
		if poolCtx.Err() != nil {
			break
		}
	}
	if attempted == 0 {
		return semanticReviewResult{Model: cfg.Model}, fmt.Errorf("semantic review providers are busy or cooling down")
	}
	if poolCtx.Err() != nil {
		return semanticReviewResult{Model: cfg.Model}, fmt.Errorf("semantic review provider pool deadline exceeded: %s", strings.Join(errorsByProvider, "; "))
	}
	return semanticReviewResult{Model: cfg.Model}, fmt.Errorf("all semantic review providers failed: %s", strings.Join(errorsByProvider, "; "))
}

func semanticReviewPoolTimeout(cfg semanticReviewConfig, providers []SemanticReviewProvider) time.Duration {
	longest := cfg.Timeout
	for _, provider := range providers {
		timeout := time.Duration(provider.TimeoutMS) * time.Millisecond
		if timeout > longest {
			longest = timeout
		}
	}
	if longest <= 0 {
		longest = time.Duration(semanticReviewDefaultTimeoutMS) * time.Millisecond
	}
	budget := longest * 2
	minimumForAttempts := time.Duration(len(providers)) * 100 * time.Millisecond
	if budget < minimumForAttempts {
		budget = minimumForAttempts
	}
	if budget < semanticReviewPoolTimeoutMin {
		budget = semanticReviewPoolTimeoutMin
	}
	if budget > semanticReviewPoolTimeoutMax {
		budget = semanticReviewPoolTimeoutMax
	}
	return budget
}

func semanticReviewProviderLabel(provider SemanticReviewProvider) string {
	if strings.TrimSpace(provider.Name) != "" {
		return provider.Name
	}
	if strings.TrimSpace(provider.ID) != "" {
		return provider.ID
	}
	return "provider"
}

func semanticReviewCacheKeyForPool(pool SemanticReviewProviderPool, endpoint string, model string, text string) string {
	sum := sha256.Sum256([]byte(semanticReviewPoolIdentity(pool) + "\n" + endpoint + "\n" + model + "\n" + text))
	return hex.EncodeToString(sum[:])
}
