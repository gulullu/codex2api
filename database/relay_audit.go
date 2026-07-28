package database

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	RelayAuditCaseRelayRoute   = "relay_route"
	RelayAuditCaseOAuthCyber   = "oauth_cyber"
	RelayAuditCaseRelayCyber   = "relay_cyber"
	RelayAuditCaseContinuation = "continuation"
	RelayAuditCaseSessionBleed = "session_bleed"

	RelayAuditFullTextMaxRunes = 32000
	relayAuditErrorMaxRunes    = 4000
	relayAuditMetadataMaxRunes = 4000

	relayAuditQueueCapacity = 2048
	relayAuditQueueMaxBytes = 32 * 1024 * 1024
	relayAuditWriteTimeout  = 3 * time.Second
	relayAuditRetention     = 30 * 24 * time.Hour
	relayAuditCleanupEvery  = 6 * time.Hour
)

// RelayAuditRequestInput creates or enriches one logical routing audit case.
// Request content belongs exclusively to rb_route_requests; the Prompt Filter
// and canonical usage schemas are deliberately not involved.
type RelayAuditRequestInput struct {
	RequestID             string
	CreatedAt             time.Time
	Endpoint              string
	Model                 string
	APIKeyID              int64
	APIKeyName            string
	APIKeyMasked          string
	ClientIP              string
	TextPreview           string
	FullText              string
	PayloadBytes          int64
	ScannedBytes          int64
	ScanTruncated         bool
	ScanDetails           string
	RouteSource           string
	RouteReason           string
	RouteSignals          string
	RouteGroupID          int64
	HasPreviousResponseID bool
	ReplayStatus          string
	ReplaySource          string
	StateFallbackReason   string
	DetectorMiss          bool
	RouteViolation        bool
	GroupExhausted        bool
}

// RelayAuditAttemptInput records account selection before the upstream call.
// Account names/types are snapshots so historical case files remain readable
// after an account is renamed or removed.
type RelayAuditAttemptInput struct {
	RequestID        string
	AttemptIndex     int
	SelectionMode    string
	AccountID        int64
	AccountName      string
	AccountType      string
	UpstreamEndpoint string
	Transport        string
	ViaWebsocket     bool
	StatusCode       int
	ErrorKind        string
	ErrorMessage     string
	SelectedAt       time.Time
	CompletedAt      time.Time
}

// RelayAuditOutcomeInput completes an upstream attempt and, when Final is set,
// the logical request. It is safe to call even when the begin event was lost:
// a minimal request shell is created first.
type RelayAuditOutcomeInput struct {
	RequestID        string
	AttemptIndex     int
	AccountID        int64
	AccountName      string
	AccountType      string
	UpstreamEndpoint string
	Transport        string
	ViaWebsocket     bool
	StatusCode       int
	ErrorKind        string
	ErrorMessage     string
	CompletedAt      time.Time
	Final            bool
	DetectorMiss     bool
}

// RelayAuditStateInput updates request-level operational signals that do not
// necessarily have an upstream account attempt.
type RelayAuditStateInput struct {
	RequestID           string
	ReplayStatus        string
	ReplaySource        string
	StateFallbackReason string
	DetectorMiss        bool
	RouteViolation      bool
	GroupExhausted      bool
	StatusCode          int
	ErrorKind           string
	ErrorMessage        string
	CompletedAt         time.Time
	Final               bool
}

type relayAuditJobKind uint8

const (
	relayAuditJobRequest relayAuditJobKind = iota
	relayAuditJobAttempt
	relayAuditJobOutcome
	relayAuditJobState
	relayAuditJobCYBMissSample
)

type relayAuditJob struct {
	kind      relayAuditJobKind
	bytes     int64
	request   RelayAuditRequestInput
	attempt   RelayAuditAttemptInput
	outcome   RelayAuditOutcomeInput
	state     RelayAuditStateInput
	cybSample RelayCYBMissSampleInput
}

type relayAuditQueue struct {
	db             *DB
	jobs           chan relayAuditJob
	stop           chan struct{}
	done           chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	closed         atomic.Bool
	cleanupEnabled bool

	enqueueMu sync.RWMutex
	pending   atomic.Int64
	retained  atomic.Int64
	enqueued  atomic.Uint64
	completed atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64
}

type RelayAuditWriterStats struct {
	Enqueued      uint64 `json:"enqueued"`
	Completed     uint64 `json:"completed"`
	Dropped       uint64 `json:"dropped"`
	Failed        uint64 `json:"failed"`
	Pending       int64  `json:"pending"`
	RetainedBytes int64  `json:"retained_bytes"`
}

func newRelayAuditQueue(db *DB) *relayAuditQueue {
	return newRelayAuditQueueWithCleanup(db, true)
}

func newRelayCYBSampleQueue(db *DB) *relayAuditQueue {
	return newRelayAuditQueueWithCleanup(db, false)
}

func newRelayAuditQueueWithCleanup(db *DB, cleanupEnabled bool) *relayAuditQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &relayAuditQueue{
		db:             db,
		jobs:           make(chan relayAuditJob, relayAuditQueueCapacity),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
		cleanupEnabled: cleanupEnabled,
	}
}

func (q *relayAuditQueue) start() {
	if q == nil || q.db == nil {
		return
	}
	go q.worker()
}

func (q *relayAuditQueue) close(timeout time.Duration) {
	if q == nil {
		return
	}
	q.enqueueMu.Lock()
	if !q.closed.CompareAndSwap(false, true) {
		q.enqueueMu.Unlock()
		return
	}
	close(q.stop)
	q.enqueueMu.Unlock()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-q.done:
	case <-timer.C:
		log.Printf("relay audit writer did not drain within %s; cancelling remaining writes", timeout)
		q.cancel()
		<-q.done
	}
	q.cancel()
}

func (q *relayAuditQueue) enqueue(job relayAuditJob) bool {
	if q == nil || q.db == nil {
		return false
	}
	q.enqueueMu.RLock()
	defer q.enqueueMu.RUnlock()
	if q.closed.Load() {
		q.dropped.Add(1)
		return false
	}
	if job.bytes < 0 || job.bytes > relayAuditQueueMaxBytes {
		q.dropped.Add(1)
		return false
	}
	for {
		current := q.retained.Load()
		if current+job.bytes > relayAuditQueueMaxBytes {
			q.dropped.Add(1)
			return false
		}
		if q.retained.CompareAndSwap(current, current+job.bytes) {
			break
		}
	}
	q.pending.Add(1)
	select {
	case q.jobs <- job:
		q.enqueued.Add(1)
		return true
	default:
		q.pending.Add(-1)
		q.retained.Add(-job.bytes)
		q.dropped.Add(1)
		return false
	}
}

func (q *relayAuditQueue) worker() {
	defer close(q.done)
	var cleanupTicker *time.Ticker
	var cleanup <-chan time.Time
	if q.cleanupEnabled {
		cleanupTicker = time.NewTicker(relayAuditCleanupEvery)
		cleanup = cleanupTicker.C
		defer cleanupTicker.Stop()
		q.cleanup()
	}
	for {
		select {
		case job := <-q.jobs:
			q.run(job)
		case <-cleanup:
			q.cleanup()
		case <-q.stop:
			q.drain()
			return
		case <-q.ctx.Done():
			q.discardPending()
			return
		}
	}
}

func (q *relayAuditQueue) drain() {
	for {
		select {
		case job := <-q.jobs:
			if q.ctx.Err() != nil {
				q.discard(job)
				continue
			}
			q.run(job)
		default:
			return
		}
	}
}

func (q *relayAuditQueue) discardPending() {
	for {
		select {
		case job := <-q.jobs:
			q.discard(job)
		default:
			return
		}
	}
}

func (q *relayAuditQueue) discard(job relayAuditJob) {
	q.pending.Add(-1)
	q.retained.Add(-job.bytes)
	q.dropped.Add(1)
}

func (q *relayAuditQueue) run(job relayAuditJob) {
	defer q.pending.Add(-1)
	defer q.retained.Add(-job.bytes)
	maxAttempts := 1
	if job.kind == relayAuditJobCYBMissSample {
		maxAttempts = 3
	}
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(q.ctx, relayAuditWriteTimeout)
		switch job.kind {
		case relayAuditJobRequest:
			err = q.db.WriteRelayAuditRequest(ctx, &job.request)
		case relayAuditJobAttempt:
			err = q.db.WriteRelayAuditAttempt(ctx, &job.attempt)
		case relayAuditJobOutcome:
			err = q.db.WriteRelayAuditOutcome(ctx, &job.outcome)
		case relayAuditJobState:
			err = q.db.WriteRelayAuditState(ctx, &job.state)
		case relayAuditJobCYBMissSample:
			err = q.db.WriteRelayCYBMissSample(ctx, &job.cybSample)
		default:
			err = fmt.Errorf("unknown relay audit job kind %d", job.kind)
		}
		cancel()
		if err == nil || attempt == maxAttempts || q.ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(time.Duration(attempt) * 100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-q.ctx.Done():
			timer.Stop()
		}
	}
	if err != nil {
		q.failed.Add(1)
		log.Printf("relay audit persist failed: %v", err)
		return
	}
	q.completed.Add(1)
}

func (q *relayAuditQueue) cleanup() {
	if q == nil || q.db == nil || q.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.ctx, relayAuditWriteTimeout)
	defer cancel()
	if err := q.db.CleanupRelayAuditBefore(ctx, time.Now().Add(-relayAuditRetention)); err != nil && q.ctx.Err() == nil {
		log.Printf("relay audit retention cleanup failed: %v", err)
	}
}

func relayAuditRequestBytes(input RelayAuditRequestInput) int64 {
	return int64(len(input.RequestID) + len(input.Endpoint) + len(input.Model) +
		len(input.APIKeyName) + len(input.APIKeyMasked) + len(input.ClientIP) +
		len(input.TextPreview) + len(input.FullText) + len(input.ScanDetails) +
		len(input.RouteSource) + len(input.RouteReason) + len(input.RouteSignals) +
		len(input.ReplayStatus) + len(input.ReplaySource) + len(input.StateFallbackReason))
}

func relayAuditAttemptBytes(input RelayAuditAttemptInput) int64 {
	return int64(len(input.RequestID) + len(input.SelectionMode) + len(input.AccountName) +
		len(input.AccountType) + len(input.UpstreamEndpoint) + len(input.Transport) +
		len(input.ErrorKind) + len(input.ErrorMessage))
}

func relayAuditOutcomeBytes(input RelayAuditOutcomeInput) int64 {
	return int64(len(input.RequestID) + len(input.AccountName) + len(input.AccountType) +
		len(input.UpstreamEndpoint) + len(input.Transport) + len(input.ErrorKind) +
		len(input.ErrorMessage))
}

func relayAuditStateBytes(input RelayAuditStateInput) int64 {
	return int64(len(input.RequestID) + len(input.ReplayStatus) + len(input.ReplaySource) + len(input.StateFallbackReason) +
		len(input.ErrorKind) + len(input.ErrorMessage))
}

func (db *DB) EnqueueRelayAuditRequest(input *RelayAuditRequestInput) bool {
	if db == nil || db.relayAudit == nil || input == nil {
		return false
	}
	normalized := normalizeRelayAuditRequestInput(*input)
	cloneRelayAuditRequestInput(&normalized)
	return db.relayAudit.enqueue(relayAuditJob{
		kind: relayAuditJobRequest, request: normalized, bytes: relayAuditRequestBytes(normalized),
	})
}

func (db *DB) EnqueueRelayAuditAttempt(input *RelayAuditAttemptInput) bool {
	if db == nil || db.relayAudit == nil || input == nil {
		return false
	}
	normalized := normalizeRelayAuditAttemptInput(*input)
	cloneRelayAuditAttemptInput(&normalized)
	return db.relayAudit.enqueue(relayAuditJob{
		kind: relayAuditJobAttempt, attempt: normalized, bytes: relayAuditAttemptBytes(normalized),
	})
}

func (db *DB) EnqueueRelayAuditOutcome(input *RelayAuditOutcomeInput) bool {
	if db == nil || db.relayAudit == nil || input == nil {
		return false
	}
	normalized := normalizeRelayAuditOutcomeInput(*input)
	cloneRelayAuditOutcomeInput(&normalized)
	return db.relayAudit.enqueue(relayAuditJob{
		kind: relayAuditJobOutcome, outcome: normalized, bytes: relayAuditOutcomeBytes(normalized),
	})
}

func (db *DB) EnqueueRelayAuditState(input *RelayAuditStateInput) bool {
	if db == nil || db.relayAudit == nil || input == nil {
		return false
	}
	normalized := normalizeRelayAuditStateInput(*input)
	cloneRelayAuditStateInput(&normalized)
	return db.relayAudit.enqueue(relayAuditJob{
		kind: relayAuditJobState, state: normalized, bytes: relayAuditStateBytes(normalized),
	})
}

func (db *DB) EnqueueRelayCYBMissSample(input *RelayCYBMissSampleInput) bool {
	if db == nil || db.relayCYBSamples == nil || input == nil {
		return false
	}
	normalized := normalizeRelayCYBMissSampleInput(*input)
	cloneRelayCYBMissSampleInput(&normalized)
	return db.relayCYBSamples.enqueue(relayAuditJob{
		kind: relayAuditJobCYBMissSample, cybSample: normalized, bytes: relayCYBMissSampleBytes(normalized),
	})
}

func (db *DB) RelayAuditWriterStats() RelayAuditWriterStats {
	if db == nil || db.relayAudit == nil {
		return RelayAuditWriterStats{}
	}
	return relayAuditQueueStats(db.relayAudit)
}

func (db *DB) RelayCYBSampleWriterStats() RelayAuditWriterStats {
	if db == nil || db.relayCYBSamples == nil {
		return RelayAuditWriterStats{}
	}
	return relayAuditQueueStats(db.relayCYBSamples)
}

func relayAuditQueueStats(q *relayAuditQueue) RelayAuditWriterStats {
	if q == nil {
		return RelayAuditWriterStats{}
	}
	return RelayAuditWriterStats{
		Enqueued: q.enqueued.Load(), Completed: q.completed.Load(), Dropped: q.dropped.Load(),
		Failed: q.failed.Load(), Pending: q.pending.Load(), RetainedBytes: q.retained.Load(),
	}
}

func (db *DB) WaitRelayAuditIdle(ctx context.Context) bool {
	if db == nil {
		return true
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		routeIdle := db.relayAudit == nil || db.relayAudit.pending.Load() == 0
		sampleIdle := db.relayCYBSamples == nil || db.relayCYBSamples.pending.Load() == 0
		if routeIdle && sampleIdle {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func NewRelayAuditRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "rb-" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("rb-%d", time.Now().UnixNano())
}

// BoundRelayAuditText keeps an exact, searchable request-body prefix without
// retaining an unbounded backing allocation in the asynchronous queue.
func BoundRelayAuditText(value string) (preview string, full string, truncated bool) {
	value = strings.TrimSpace(value)
	full, truncated = truncateRelayAuditRunes(value, RelayAuditFullTextMaxRunes)
	preview, _ = truncateRelayAuditRunes(full, 500)
	return preview, full, truncated
}

func truncateRelayAuditRunes(value string, maxRunes int) (string, bool) {
	if maxRunes <= 0 || value == "" {
		return "", value != ""
	}
	count := 0
	for index := range value {
		if count == maxRunes {
			return value[:index], true
		}
		count++
	}
	return value, false
}

func normalizeRelayAuditRequestInput(input RelayAuditRequestInput) RelayAuditRequestInput {
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.Model = strings.TrimSpace(input.Model)
	input.APIKeyName = strings.TrimSpace(input.APIKeyName)
	input.APIKeyMasked = strings.TrimSpace(input.APIKeyMasked)
	input.ClientIP = strings.TrimSpace(input.ClientIP)
	input.RouteSource = strings.TrimSpace(input.RouteSource)
	input.RouteReason = strings.TrimSpace(input.RouteReason)
	input.ReplayStatus = strings.TrimSpace(input.ReplayStatus)
	input.ReplaySource = strings.TrimSpace(input.ReplaySource)
	input.StateFallbackReason = strings.TrimSpace(input.StateFallbackReason)
	if input.RouteSignals = strings.TrimSpace(input.RouteSignals); input.RouteSignals == "" {
		input.RouteSignals = "[]"
	}
	if input.ScanDetails = strings.TrimSpace(input.ScanDetails); input.ScanDetails == "" {
		input.ScanDetails = "{}"
	}
	if bounded, truncated := truncateRelayAuditRunes(input.RouteSignals, relayAuditMetadataMaxRunes); truncated {
		input.RouteSignals = "[]"
	} else {
		input.RouteSignals = bounded
	}
	if bounded, truncated := truncateRelayAuditRunes(input.ScanDetails, relayAuditMetadataMaxRunes); truncated {
		input.ScanDetails = `{"truncated":true}`
	} else {
		input.ScanDetails = bounded
	}
	input.RouteReason, _ = truncateRelayAuditRunes(input.RouteReason, relayAuditMetadataMaxRunes)
	input.ReplayStatus, _ = truncateRelayAuditRunes(input.ReplayStatus, 64)
	input.ReplaySource, _ = truncateRelayAuditRunes(input.ReplaySource, 64)
	input.StateFallbackReason, _ = truncateRelayAuditRunes(input.StateFallbackReason, relayAuditMetadataMaxRunes)
	preview, full, truncated := BoundRelayAuditText(input.FullText)
	input.FullText = full
	if strings.TrimSpace(input.TextPreview) == "" {
		input.TextPreview = preview
	} else {
		input.TextPreview, _, _ = BoundRelayAuditText(input.TextPreview)
	}
	input.ScanTruncated = input.ScanTruncated || truncated
	if input.PayloadBytes <= 0 {
		input.PayloadBytes = int64(len(input.FullText))
	}
	if input.ScannedBytes < 0 {
		input.ScannedBytes = 0
	}
	if !input.CreatedAt.IsZero() {
		input.CreatedAt = input.CreatedAt.UTC()
	}
	return input
}

func normalizeRelayAuditAttemptInput(input RelayAuditAttemptInput) RelayAuditAttemptInput {
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.SelectionMode = strings.TrimSpace(input.SelectionMode)
	input.AccountName = strings.TrimSpace(input.AccountName)
	input.AccountType = strings.TrimSpace(input.AccountType)
	input.UpstreamEndpoint = strings.TrimSpace(input.UpstreamEndpoint)
	input.Transport = strings.TrimSpace(input.Transport)
	input.ErrorKind = strings.TrimSpace(input.ErrorKind)
	input.ErrorMessage = strings.TrimSpace(input.ErrorMessage)
	input.ErrorMessage, _ = truncateRelayAuditRunes(input.ErrorMessage, relayAuditErrorMaxRunes)
	if input.AttemptIndex <= 0 {
		input.AttemptIndex = 1
	}
	if !input.SelectedAt.IsZero() {
		input.SelectedAt = input.SelectedAt.UTC()
	}
	if !input.CompletedAt.IsZero() {
		input.CompletedAt = input.CompletedAt.UTC()
	}
	return input
}

func normalizeRelayAuditOutcomeInput(input RelayAuditOutcomeInput) RelayAuditOutcomeInput {
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.AccountName = strings.TrimSpace(input.AccountName)
	input.AccountType = strings.TrimSpace(input.AccountType)
	input.UpstreamEndpoint = strings.TrimSpace(input.UpstreamEndpoint)
	input.Transport = strings.TrimSpace(input.Transport)
	input.ErrorKind = strings.TrimSpace(input.ErrorKind)
	input.ErrorMessage = strings.TrimSpace(input.ErrorMessage)
	input.ErrorMessage, _ = truncateRelayAuditRunes(input.ErrorMessage, relayAuditErrorMaxRunes)
	if input.AttemptIndex <= 0 {
		input.AttemptIndex = 1
	}
	if !input.CompletedAt.IsZero() {
		input.CompletedAt = input.CompletedAt.UTC()
	}
	return input
}

func normalizeRelayAuditStateInput(input RelayAuditStateInput) RelayAuditStateInput {
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.ReplayStatus = strings.TrimSpace(input.ReplayStatus)
	input.ReplaySource = strings.TrimSpace(input.ReplaySource)
	input.StateFallbackReason = strings.TrimSpace(input.StateFallbackReason)
	input.ErrorKind = strings.TrimSpace(input.ErrorKind)
	input.ErrorMessage = strings.TrimSpace(input.ErrorMessage)
	input.ErrorMessage, _ = truncateRelayAuditRunes(input.ErrorMessage, relayAuditErrorMaxRunes)
	input.ReplayStatus, _ = truncateRelayAuditRunes(input.ReplayStatus, 64)
	input.ReplaySource, _ = truncateRelayAuditRunes(input.ReplaySource, 64)
	input.StateFallbackReason, _ = truncateRelayAuditRunes(input.StateFallbackReason, relayAuditMetadataMaxRunes)
	if !input.CompletedAt.IsZero() {
		input.CompletedAt = input.CompletedAt.UTC()
	}
	return input
}

func cloneRelayAuditRequestInput(input *RelayAuditRequestInput) {
	if input == nil {
		return
	}
	input.RequestID = strings.Clone(input.RequestID)
	input.Endpoint = strings.Clone(input.Endpoint)
	input.Model = strings.Clone(input.Model)
	input.APIKeyName = strings.Clone(input.APIKeyName)
	input.APIKeyMasked = strings.Clone(input.APIKeyMasked)
	input.ClientIP = strings.Clone(input.ClientIP)
	input.TextPreview = strings.Clone(input.TextPreview)
	input.FullText = strings.Clone(input.FullText)
	input.ScanDetails = strings.Clone(input.ScanDetails)
	input.RouteSource = strings.Clone(input.RouteSource)
	input.RouteReason = strings.Clone(input.RouteReason)
	input.RouteSignals = strings.Clone(input.RouteSignals)
	input.ReplayStatus = strings.Clone(input.ReplayStatus)
	input.ReplaySource = strings.Clone(input.ReplaySource)
	input.StateFallbackReason = strings.Clone(input.StateFallbackReason)
}

func cloneRelayAuditAttemptInput(input *RelayAuditAttemptInput) {
	if input == nil {
		return
	}
	input.RequestID = strings.Clone(input.RequestID)
	input.SelectionMode = strings.Clone(input.SelectionMode)
	input.AccountName = strings.Clone(input.AccountName)
	input.AccountType = strings.Clone(input.AccountType)
	input.UpstreamEndpoint = strings.Clone(input.UpstreamEndpoint)
	input.Transport = strings.Clone(input.Transport)
	input.ErrorKind = strings.Clone(input.ErrorKind)
	input.ErrorMessage = strings.Clone(input.ErrorMessage)
}

func cloneRelayAuditOutcomeInput(input *RelayAuditOutcomeInput) {
	if input == nil {
		return
	}
	input.RequestID = strings.Clone(input.RequestID)
	input.AccountName = strings.Clone(input.AccountName)
	input.AccountType = strings.Clone(input.AccountType)
	input.UpstreamEndpoint = strings.Clone(input.UpstreamEndpoint)
	input.Transport = strings.Clone(input.Transport)
	input.ErrorKind = strings.Clone(input.ErrorKind)
	input.ErrorMessage = strings.Clone(input.ErrorMessage)
}

func cloneRelayAuditStateInput(input *RelayAuditStateInput) {
	if input == nil {
		return
	}
	input.RequestID = strings.Clone(input.RequestID)
	input.ReplayStatus = strings.Clone(input.ReplayStatus)
	input.ReplaySource = strings.Clone(input.ReplaySource)
	input.StateFallbackReason = strings.Clone(input.StateFallbackReason)
	input.ErrorKind = strings.Clone(input.ErrorKind)
	input.ErrorMessage = strings.Clone(input.ErrorMessage)
}

func (db *DB) migrateRelayAudit(ctx context.Context) error {
	if db == nil {
		return nil
	}
	requestsSQL := `
		CREATE TABLE IF NOT EXISTS rb_route_requests (
			request_id TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP NULL,
			endpoint TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			api_key_id BIGINT NOT NULL DEFAULT 0,
			api_key_name TEXT NOT NULL DEFAULT '',
			api_key_masked TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			text_preview TEXT NOT NULL DEFAULT '',
			full_text TEXT NOT NULL DEFAULT '',
			payload_bytes BIGINT NOT NULL DEFAULT 0,
			scanned_bytes BIGINT NOT NULL DEFAULT 0,
			scan_truncated BOOLEAN NOT NULL DEFAULT FALSE,
			scan_details TEXT NOT NULL DEFAULT '{}',
			route_source TEXT NOT NULL DEFAULT '',
			route_reason TEXT NOT NULL DEFAULT '',
			route_signals TEXT NOT NULL DEFAULT '[]',
			route_group_id BIGINT NOT NULL DEFAULT 0,
			has_previous_response_id BOOLEAN NOT NULL DEFAULT FALSE,
			replay_status TEXT NOT NULL DEFAULT '',
			replay_source TEXT NOT NULL DEFAULT '',
			state_fallback_reason TEXT NOT NULL DEFAULT '',
			detector_miss BOOLEAN NOT NULL DEFAULT FALSE,
			route_violation BOOLEAN NOT NULL DEFAULT FALSE,
			group_exhausted BOOLEAN NOT NULL DEFAULT FALSE,
			final_account_id BIGINT NOT NULL DEFAULT 0,
			final_account_name TEXT NOT NULL DEFAULT '',
			final_account_type TEXT NOT NULL DEFAULT '',
			final_status_code INTEGER NOT NULL DEFAULT 0,
			final_error_kind TEXT NOT NULL DEFAULT '',
			final_error_message TEXT NOT NULL DEFAULT '',
			final_transport TEXT NOT NULL DEFAULT '',
			attempt_count INTEGER NOT NULL DEFAULT 0
		)`
	attemptsSQL := `
		CREATE TABLE IF NOT EXISTS rb_route_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_id TEXT NOT NULL,
			attempt_index INTEGER NOT NULL DEFAULT 1,
			selection_mode TEXT NOT NULL DEFAULT '',
			account_id BIGINT NOT NULL DEFAULT 0,
			account_name TEXT NOT NULL DEFAULT '',
			account_type TEXT NOT NULL DEFAULT '',
			upstream_endpoint TEXT NOT NULL DEFAULT '',
			transport TEXT NOT NULL DEFAULT '',
			via_websocket BOOLEAN NOT NULL DEFAULT FALSE,
			status_code INTEGER NOT NULL DEFAULT 0,
			error_kind TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			selected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP NULL,
			UNIQUE(request_id, attempt_index)
		)`
	if !db.isSQLite() {
		requestsSQL = strings.ReplaceAll(requestsSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		attemptsSQL = strings.ReplaceAll(attemptsSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		attemptsSQL = strings.Replace(attemptsSQL, "id INTEGER PRIMARY KEY AUTOINCREMENT", "id BIGSERIAL PRIMARY KEY", 1)
	}
	for _, statement := range []string{
		requestsSQL,
		attemptsSQL,
		`CREATE INDEX IF NOT EXISTS idx_rb_route_requests_created_at ON rb_route_requests(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_route_requests_source_created ON rb_route_requests(route_source, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_route_requests_error_created ON rb_route_requests(final_error_kind, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_route_attempts_request_attempt ON rb_route_attempts(request_id, attempt_index)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_route_attempts_account_selected ON rb_route_attempts(account_id, selected_at)`,
	} {
		if _, err := db.conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if db.isSQLite() {
		columns, err := db.sqliteTableColumns(ctx, "rb_route_requests")
		if err != nil {
			return err
		}
		for _, column := range []string{"replay_status", "replay_source"} {
			if _, exists := columns[column]; exists {
				continue
			}
			if _, err := db.conn.ExecContext(ctx,
				"ALTER TABLE rb_route_requests ADD COLUMN "+column+" TEXT NOT NULL DEFAULT ''",
			); err != nil {
				return err
			}
		}
	} else {
		if _, err := db.conn.ExecContext(ctx, `
			ALTER TABLE rb_route_requests ADD COLUMN IF NOT EXISTS replay_status TEXT NOT NULL DEFAULT '';
			ALTER TABLE rb_route_requests ADD COLUMN IF NOT EXISTS replay_source TEXT NOT NULL DEFAULT '';
		`); err != nil {
			return err
		}
	}
	return nil
}

const relayAuditCleanupBatchSize = 500

// CleanupRelayAuditBefore commits small bounded batches so a large history
// cannot hold the SQLite writer or a PostgreSQL transaction for the full
// retention sweep. A later run resumes from the remaining oldest row.
func (db *DB) CleanupRelayAuditBefore(ctx context.Context, cutoff time.Time) error {
	if db == nil || db.conn == nil || cutoff.IsZero() {
		return nil
	}
	cutoff = cutoff.UTC()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deleted, err := db.cleanupRelayAuditRequestBatch(ctx, cutoff, relayAuditCleanupBatchSize)
		if err != nil {
			return err
		}
		if deleted == 0 {
			break
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deleted, err := db.cleanupRelayAuditOrphanBatch(ctx, relayAuditCleanupBatchSize)
		if err != nil {
			return err
		}
		if deleted == 0 {
			break
		}
	}
	return db.withSQLiteWriteLock(ctx, func() error {
		_, err := db.conn.ExecContext(ctx,
			`DELETE FROM rb_cyb_learning_events WHERE created_at < $1`,
			db.timeArg(cutoff),
		)
		return err
	})
}

func (db *DB) cleanupRelayAuditRequestBatch(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	deleted := 0
	err := db.withSQLiteWriteLock(ctx, func() error {
		tx, err := db.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		rows, err := tx.QueryContext(ctx, `
			SELECT request_id
			FROM rb_route_requests
			WHERE created_at < $1
			ORDER BY created_at, request_id
			LIMIT $2
		`, db.timeArg(cutoff), limit)
		if err != nil {
			return err
		}
		requestIDs := make([]string, 0, limit)
		for rows.Next() {
			var requestID string
			if err := rows.Scan(&requestID); err != nil {
				rows.Close()
				return err
			}
			requestIDs = append(requestIDs, requestID)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(requestIDs) == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		}
		placeholders := make([]string, len(requestIDs))
		args := make([]any, len(requestIDs))
		for index, requestID := range requestIDs {
			placeholders[index] = fmt.Sprintf("$%d", index+1)
			args[index] = requestID
		}
		inClause := strings.Join(placeholders, ",")
		if _, err := tx.ExecContext(ctx, `DELETE FROM rb_cyb_miss_samples WHERE request_id IN (`+inClause+`)`, args...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM rb_route_attempts WHERE request_id IN (`+inClause+`)`, args...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM rb_route_requests WHERE request_id IN (`+inClause+`)`, args...); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		deleted = len(requestIDs)
		return nil
	})
	return deleted, err
}

func (db *DB) cleanupRelayAuditOrphanBatch(ctx context.Context, limit int) (int, error) {
	deleted := 0
	err := db.withSQLiteWriteLock(ctx, func() error {
		tx, err := db.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		rows, err := tx.QueryContext(ctx, `
			SELECT attempt.id
			FROM rb_route_attempts attempt
			LEFT JOIN rb_route_requests request ON request.request_id = attempt.request_id
			WHERE request.request_id IS NULL
			ORDER BY attempt.id
			LIMIT $1
		`, limit)
		if err != nil {
			return err
		}
		ids := make([]int64, 0, limit)
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			if err := tx.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		}
		placeholders := make([]string, len(ids))
		args := make([]any, len(ids))
		for index, id := range ids {
			placeholders[index] = fmt.Sprintf("$%d", index+1)
			args[index] = id
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM rb_route_attempts WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		deleted = len(ids)
		return nil
	})
	return deleted, err
}

func ensureRelayAuditRequestWith(ctx context.Context, execer sqlExecer, requestID string, timeValue any) error {
	if execer == nil {
		return fmt.Errorf("relay audit database executor is nil")
	}
	_, err := execer.ExecContext(ctx, `
		INSERT INTO rb_route_requests (request_id, created_at, updated_at)
		VALUES ($1, $2, $2)
		ON CONFLICT(request_id) DO NOTHING
	`, requestID, timeValue)
	return err
}

func (db *DB) withRelayAuditTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("relay audit database is nil")
	}
	return db.withSQLiteWriteLock(ctx, func() error {
		tx, err := db.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		if err := fn(tx); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	})
}

func (db *DB) enrichRelayAuditAccount(ctx context.Context, accountID int64, accountName *string, accountType *string) {
	if db == nil || db.conn == nil || accountID <= 0 || accountName == nil || accountType == nil {
		return
	}
	if strings.TrimSpace(*accountName) != "" && strings.TrimSpace(*accountType) != "" {
		return
	}
	var storedName, storedType string
	if err := db.conn.QueryRowContext(ctx, `
		SELECT COALESCE(name, ''), COALESCE(type, '')
		FROM accounts
		WHERE id = $1
	`, accountID).Scan(&storedName, &storedType); err != nil {
		return
	}
	if strings.TrimSpace(*accountName) == "" {
		*accountName = strings.TrimSpace(storedName)
	}
	if strings.TrimSpace(*accountType) == "" {
		*accountType = strings.TrimSpace(storedType)
	}
}

func (db *DB) writeRelayAuditAttemptWith(ctx context.Context, execer sqlExecer, input RelayAuditAttemptInput) error {
	var completedAt any
	if !input.CompletedAt.IsZero() {
		completedAt = db.timeArg(input.CompletedAt)
	}
	_, err := execer.ExecContext(ctx, `
		INSERT INTO rb_route_attempts (
			request_id, attempt_index, selection_mode, account_id, account_name, account_type,
			upstream_endpoint, transport, via_websocket, status_code, error_kind, error_message,
			selected_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT(request_id, attempt_index) DO UPDATE SET
			selection_mode = CASE WHEN excluded.selection_mode <> '' THEN excluded.selection_mode ELSE rb_route_attempts.selection_mode END,
			account_id = CASE WHEN excluded.account_id > 0 THEN excluded.account_id ELSE rb_route_attempts.account_id END,
			account_name = CASE WHEN excluded.account_name <> '' THEN excluded.account_name ELSE rb_route_attempts.account_name END,
			account_type = CASE WHEN excluded.account_type <> '' THEN excluded.account_type ELSE rb_route_attempts.account_type END,
			upstream_endpoint = CASE WHEN excluded.upstream_endpoint <> '' THEN excluded.upstream_endpoint ELSE rb_route_attempts.upstream_endpoint END,
			transport = CASE WHEN excluded.transport <> '' THEN excluded.transport ELSE rb_route_attempts.transport END,
			via_websocket = rb_route_attempts.via_websocket OR excluded.via_websocket,
			status_code = CASE WHEN excluded.status_code > 0 THEN excluded.status_code ELSE rb_route_attempts.status_code END,
			error_kind = CASE WHEN excluded.error_kind <> '' THEN excluded.error_kind ELSE rb_route_attempts.error_kind END,
			error_message = CASE WHEN excluded.error_message <> '' THEN excluded.error_message ELSE rb_route_attempts.error_message END,
			completed_at = COALESCE(excluded.completed_at, rb_route_attempts.completed_at)
	`, input.RequestID, input.AttemptIndex, input.SelectionMode, input.AccountID,
		input.AccountName, input.AccountType, input.UpstreamEndpoint, input.Transport,
		input.ViaWebsocket, input.StatusCode, input.ErrorKind, input.ErrorMessage,
		db.timeArg(input.SelectedAt), completedAt)
	return err
}

func (db *DB) WriteRelayAuditRequest(ctx context.Context, input *RelayAuditRequestInput) error {
	if db == nil || input == nil {
		return nil
	}
	normalized := normalizeRelayAuditRequestInput(*input)
	if normalized.RequestID == "" {
		return fmt.Errorf("relay audit request id is empty")
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now()
	}
	normalized.CreatedAt = normalized.CreatedAt.UTC()
	return db.withSQLiteWriteLock(ctx, func() error {
		_, err := db.conn.ExecContext(ctx, `
		INSERT INTO rb_route_requests (
			request_id, created_at, updated_at, endpoint, model,
			api_key_id, api_key_name, api_key_masked, client_ip,
				text_preview, full_text, payload_bytes, scanned_bytes, scan_truncated, scan_details,
				route_source, route_reason, route_signals, route_group_id, has_previous_response_id,
				replay_status, replay_source, state_fallback_reason,
				detector_miss, route_violation, group_exhausted
			) VALUES (
				$1, $2, $2, $3, $4,
				$5, $6, $7, $8,
				$9, $10, $11, $12, $13, $14,
				$15, $16, $17, $18, $19,
				$20, $21, $22, $23, $24, $25
		)
		ON CONFLICT(request_id) DO UPDATE SET
			updated_at = excluded.updated_at,
			endpoint = CASE WHEN excluded.endpoint <> '' THEN excluded.endpoint ELSE rb_route_requests.endpoint END,
			model = CASE WHEN excluded.model <> '' THEN excluded.model ELSE rb_route_requests.model END,
			api_key_id = CASE WHEN excluded.api_key_id > 0 THEN excluded.api_key_id ELSE rb_route_requests.api_key_id END,
			api_key_name = CASE WHEN excluded.api_key_name <> '' THEN excluded.api_key_name ELSE rb_route_requests.api_key_name END,
			api_key_masked = CASE WHEN excluded.api_key_masked <> '' THEN excluded.api_key_masked ELSE rb_route_requests.api_key_masked END,
			client_ip = CASE WHEN excluded.client_ip <> '' THEN excluded.client_ip ELSE rb_route_requests.client_ip END,
			text_preview = CASE WHEN excluded.text_preview <> '' THEN excluded.text_preview ELSE rb_route_requests.text_preview END,
			full_text = CASE WHEN excluded.full_text <> '' THEN excluded.full_text ELSE rb_route_requests.full_text END,
			payload_bytes = CASE WHEN excluded.payload_bytes > 0 THEN excluded.payload_bytes ELSE rb_route_requests.payload_bytes END,
			scanned_bytes = CASE WHEN excluded.scanned_bytes > 0 THEN excluded.scanned_bytes ELSE rb_route_requests.scanned_bytes END,
			scan_truncated = rb_route_requests.scan_truncated OR excluded.scan_truncated,
			scan_details = CASE WHEN excluded.scan_details NOT IN ('', '{}') THEN excluded.scan_details ELSE rb_route_requests.scan_details END,
			route_source = CASE WHEN excluded.route_source <> '' THEN excluded.route_source ELSE rb_route_requests.route_source END,
			route_reason = CASE WHEN excluded.route_reason <> '' THEN excluded.route_reason ELSE rb_route_requests.route_reason END,
				route_signals = CASE WHEN excluded.route_signals NOT IN ('', '[]') THEN excluded.route_signals ELSE rb_route_requests.route_signals END,
				route_group_id = CASE WHEN excluded.route_group_id > 0 THEN excluded.route_group_id ELSE rb_route_requests.route_group_id END,
				has_previous_response_id = rb_route_requests.has_previous_response_id OR excluded.has_previous_response_id,
				replay_status = CASE WHEN excluded.replay_status <> '' THEN excluded.replay_status ELSE rb_route_requests.replay_status END,
				replay_source = CASE WHEN excluded.replay_source <> '' THEN excluded.replay_source ELSE rb_route_requests.replay_source END,
				state_fallback_reason = CASE WHEN excluded.state_fallback_reason <> '' THEN excluded.state_fallback_reason ELSE rb_route_requests.state_fallback_reason END,
			detector_miss = rb_route_requests.detector_miss OR excluded.detector_miss,
			route_violation = rb_route_requests.route_violation OR excluded.route_violation,
			group_exhausted = rb_route_requests.group_exhausted OR excluded.group_exhausted
	`, normalized.RequestID, db.timeArg(normalized.CreatedAt), normalized.Endpoint, normalized.Model,
			normalized.APIKeyID, normalized.APIKeyName, normalized.APIKeyMasked, normalized.ClientIP,
			normalized.TextPreview, normalized.FullText, normalized.PayloadBytes, normalized.ScannedBytes,
			normalized.ScanTruncated, normalized.ScanDetails, normalized.RouteSource, normalized.RouteReason,
			normalized.RouteSignals, normalized.RouteGroupID, normalized.HasPreviousResponseID,
			normalized.ReplayStatus, normalized.ReplaySource, normalized.StateFallbackReason,
			normalized.DetectorMiss, normalized.RouteViolation,
			normalized.GroupExhausted)
		return err
	})
}

func (db *DB) WriteRelayAuditAttempt(ctx context.Context, input *RelayAuditAttemptInput) error {
	if db == nil || input == nil {
		return nil
	}
	normalized := normalizeRelayAuditAttemptInput(*input)
	if normalized.RequestID == "" {
		return fmt.Errorf("relay audit request id is empty")
	}
	if normalized.SelectedAt.IsZero() {
		normalized.SelectedAt = time.Now()
	}
	normalized.SelectedAt = normalized.SelectedAt.UTC()
	db.enrichRelayAuditAccount(ctx, normalized.AccountID, &normalized.AccountName, &normalized.AccountType)
	return db.withRelayAuditTransaction(ctx, func(tx *sql.Tx) error {
		if err := ensureRelayAuditRequestWith(
			ctx,
			tx,
			normalized.RequestID,
			db.timeArg(normalized.SelectedAt),
		); err != nil {
			return err
		}
		return db.writeRelayAuditAttemptWith(ctx, tx, normalized)
	})
}

func (db *DB) WriteRelayAuditOutcome(ctx context.Context, input *RelayAuditOutcomeInput) error {
	if db == nil || input == nil {
		return nil
	}
	normalized := normalizeRelayAuditOutcomeInput(*input)
	if normalized.RequestID == "" {
		return fmt.Errorf("relay audit request id is empty")
	}
	if normalized.CompletedAt.IsZero() {
		normalized.CompletedAt = time.Now()
	}
	normalized.CompletedAt = normalized.CompletedAt.UTC()
	db.enrichRelayAuditAccount(ctx, normalized.AccountID, &normalized.AccountName, &normalized.AccountType)
	attempt := normalizeRelayAuditAttemptInput(RelayAuditAttemptInput{
		RequestID: normalized.RequestID, AttemptIndex: normalized.AttemptIndex,
		AccountID: normalized.AccountID, AccountName: normalized.AccountName,
		AccountType: normalized.AccountType, UpstreamEndpoint: normalized.UpstreamEndpoint,
		Transport: normalized.Transport, ViaWebsocket: normalized.ViaWebsocket,
		StatusCode: normalized.StatusCode, ErrorKind: normalized.ErrorKind,
		ErrorMessage: normalized.ErrorMessage, SelectedAt: normalized.CompletedAt,
		CompletedAt: normalized.CompletedAt,
	})
	return db.withRelayAuditTransaction(ctx, func(tx *sql.Tx) error {
		if err := ensureRelayAuditRequestWith(
			ctx,
			tx,
			normalized.RequestID,
			db.timeArg(normalized.CompletedAt),
		); err != nil {
			return err
		}
		if err := db.writeRelayAuditAttemptWith(ctx, tx, attempt); err != nil {
			return err
		}
		if !normalized.Final {
			return nil
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE rb_route_requests SET
				updated_at = $2,
				completed_at = $2,
				final_account_id = CASE WHEN $3 > 0 THEN $3 ELSE final_account_id END,
				final_account_name = CASE WHEN $4 <> '' THEN $4 ELSE final_account_name END,
				final_account_type = CASE WHEN $5 <> '' THEN $5 ELSE final_account_type END,
				final_status_code = $6,
				final_error_kind = $7,
				final_error_message = $8,
				final_transport = $9,
				detector_miss = detector_miss OR $10
			WHERE request_id = $1
		`, normalized.RequestID, db.timeArg(normalized.CompletedAt), normalized.AccountID,
			normalized.AccountName, normalized.AccountType, normalized.StatusCode,
			normalized.ErrorKind, normalized.ErrorMessage, normalized.Transport,
			normalized.DetectorMiss)
		return err
	})
}

func (db *DB) WriteRelayAuditState(ctx context.Context, input *RelayAuditStateInput) error {
	if db == nil || input == nil {
		return nil
	}
	normalized := normalizeRelayAuditStateInput(*input)
	if normalized.RequestID == "" {
		return fmt.Errorf("relay audit request id is empty")
	}
	now := normalized.CompletedAt
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	var completedAt any
	if normalized.Final {
		completedAt = db.timeArg(now)
	}
	return db.withRelayAuditTransaction(ctx, func(tx *sql.Tx) error {
		if err := ensureRelayAuditRequestWith(ctx, tx, normalized.RequestID, db.timeArg(now)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE rb_route_requests SET
				updated_at = $2,
				replay_status = CASE WHEN $3 <> '' THEN $3 ELSE replay_status END,
				replay_source = CASE WHEN $4 <> '' THEN $4 ELSE replay_source END,
				state_fallback_reason = CASE WHEN $5 <> '' THEN $5 ELSE state_fallback_reason END,
				detector_miss = detector_miss OR $6,
				route_violation = route_violation OR $7,
				group_exhausted = group_exhausted OR $8,
				final_status_code = CASE WHEN $9 > 0 THEN $9 ELSE final_status_code END,
				final_error_kind = CASE WHEN $10 <> '' THEN $10 ELSE final_error_kind END,
				final_error_message = CASE WHEN $11 <> '' THEN $11 ELSE final_error_message END,
				completed_at = COALESCE($12, completed_at)
			WHERE request_id = $1
		`, normalized.RequestID, db.timeArg(now), normalized.ReplayStatus, normalized.ReplaySource,
			normalized.StateFallbackReason, normalized.DetectorMiss, normalized.RouteViolation, normalized.GroupExhausted,
			normalized.StatusCode, normalized.ErrorKind, normalized.ErrorMessage, completedAt)
		return err
	})
}

type RelayAuditQuery struct {
	Start         time.Time
	End           time.Time
	BucketMinutes int
}

type RelayAuditReport struct {
	WindowStart  time.Time                 `json:"window_start"`
	WindowEnd    time.Time                 `json:"window_end"`
	GeneratedAt  time.Time                 `json:"generated_at"`
	Summary      RelayAuditSummary         `json:"summary"`
	Timeline     []RelayAuditTimelinePoint `json:"timeline"`
	RouteSignals []RelayAuditSignalRow     `json:"route_signals"`
	RelayRoutes  []RelayAuditRouteRow      `json:"relay_routes"`
	Writer       RelayAuditWriterStats     `json:"writer"`
}

type RelayAuditSummary struct {
	LogicalRequests      int64 `json:"logical_requests"`
	RelayRequests        int64 `json:"relay_requests"`
	RouteAttempts        int64 `json:"route_attempts"`
	CYBRule              int64 `json:"cyb_rule"`
	Probe                int64 `json:"probe"`
	NoAffinitySplit      int64 `json:"no_affinity_split"`
	OAuthOverflow        int64 `json:"oauth_overflow"`
	Continuation         int64 `json:"relay_continuation"`
	Feedback             int64 `json:"cyb_feedback"`
	ReplayHits           int64 `json:"replay_hits"`
	ReplayMisses         int64 `json:"replay_misses"`
	ReplayUnavailable    int64 `json:"replay_unavailable"`
	Retries              int64 `json:"retries"`
	SameGroupSwitches    int64 `json:"same_group_switches"`
	GroupExhausted       int64 `json:"group_exhausted"`
	DetectorMisses       int64 `json:"detector_misses"`
	RelayCyberPolicies   int64 `json:"relay_cyber_policies"`
	OAuthCyberMisses     int64 `json:"oauth_cyber_misses"`
	RouteViolations      int64 `json:"route_violations"`
	StateFallbacks       int64 `json:"state_fallbacks"`
	RelaySuccesses       int64 `json:"relay_successes"`
	RelayFinalFailures   int64 `json:"relay_final_failures"`
	SessionBleed         int64 `json:"session_bleed"`
	RequestsWithPrevious int64 `json:"requests_with_previous_response_id"`
}

type RelayAuditTimelinePoint struct {
	Bucket             time.Time `json:"bucket"`
	RelayRequests      int64     `json:"relay_requests"`
	CYBRule            int64     `json:"cyb_rule"`
	Probe              int64     `json:"probe"`
	NoAffinitySplit    int64     `json:"no_affinity_split"`
	OAuthOverflow      int64     `json:"oauth_overflow"`
	Continuation       int64     `json:"relay_continuation"`
	Feedback           int64     `json:"cyb_feedback"`
	ReplayHits         int64     `json:"replay_hits"`
	ReplayMisses       int64     `json:"replay_misses"`
	OAuthCyberMisses   int64     `json:"oauth_cyber_misses"`
	RelayCyberPolicies int64     `json:"relay_cyber_policies"`
	FinalFailures      int64     `json:"final_failures"`
}

type RelayAuditSignalRow struct {
	Signal   string    `json:"signal"`
	Requests int64     `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
}

type RelayAuditRouteRow struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name"`
	AccountType string `json:"account_type"`
	RouteSource string `json:"route_source"`
	Requests    int64  `json:"requests"`
	Attempts    int64  `json:"attempts"`
	Successes   int64  `json:"successes"`
	Errors4xx   int64  `json:"errors_4xx"`
	Errors5xx   int64  `json:"errors_5xx"`
	CyberPolicy int64  `json:"cyber_policy"`
}

type RelayAuditCaseQuery struct {
	Kind     string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
	// SummaryOnly keeps paged responses lightweight. Full request text and the
	// attempt chain remain available from GetRelayAuditCaseDetail.
	SummaryOnly bool
}

type RelayAuditCasesPage struct {
	Items       []*RelayAuditCase `json:"items"`
	Total       int               `json:"total"`
	Page        int               `json:"page"`
	PageSize    int               `json:"page_size"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
}

type RelayAuditCaseDetail struct {
	Case    *RelayAuditCase     `json:"case"`
	CYBMiss *RelayCYBMissSample `json:"cyb_miss,omitempty"`
	Rule    *RelayCYBRule       `json:"rule,omitempty"`
}

type RelayAuditCase struct {
	RequestID             string                   `json:"request_id"`
	CreatedAt             time.Time                `json:"created_at"`
	UpdatedAt             time.Time                `json:"updated_at"`
	CompletedAt           *time.Time               `json:"completed_at,omitempty"`
	Endpoint              string                   `json:"endpoint"`
	Model                 string                   `json:"model"`
	APIKeyID              int64                    `json:"api_key_id"`
	APIKeyName            string                   `json:"api_key_name"`
	APIKeyMasked          string                   `json:"api_key_masked"`
	ClientIP              string                   `json:"client_ip"`
	TextPreview           string                   `json:"text_preview"`
	FullText              string                   `json:"full_text"`
	PayloadBytes          int64                    `json:"payload_bytes"`
	ScannedBytes          int64                    `json:"scanned_bytes"`
	ScanTruncated         bool                     `json:"scan_truncated"`
	ScanDetails           string                   `json:"scan_details"`
	RouteSource           string                   `json:"route_source"`
	RouteReason           string                   `json:"route_reason"`
	RouteSignals          string                   `json:"route_signals"`
	RouteGroupID          int64                    `json:"route_group_id"`
	HasPreviousResponseID bool                     `json:"has_previous_response_id"`
	ReplayStatus          string                   `json:"replay_status"`
	ReplaySource          string                   `json:"replay_source"`
	StateFallbackReason   string                   `json:"state_fallback_reason"`
	DetectorMiss          bool                     `json:"detector_miss"`
	RouteViolation        bool                     `json:"route_violation"`
	GroupExhausted        bool                     `json:"group_exhausted"`
	FinalAccountID        int64                    `json:"final_account_id"`
	FinalAccountName      string                   `json:"final_account_name"`
	FinalAccountType      string                   `json:"final_account_type"`
	FinalStatusCode       int                      `json:"final_status_code"`
	FinalErrorKind        string                   `json:"final_error_kind"`
	FinalErrorMessage     string                   `json:"final_error_message"`
	FinalTransport        string                   `json:"final_transport"`
	AttemptCount          int                      `json:"attempt_count"`
	Attempts              []RelayAuditAttempt      `json:"attempts"`
	CYBLearning           *RelayCYBLearningSummary `json:"cyb_learning,omitempty"`
}

type RelayAuditAttempt struct {
	ID               int64      `json:"id"`
	RequestID        string     `json:"request_id"`
	AttemptIndex     int        `json:"attempt_index"`
	SelectionMode    string     `json:"selection_mode"`
	AccountID        int64      `json:"account_id"`
	AccountName      string     `json:"account_name"`
	AccountType      string     `json:"account_type"`
	UpstreamEndpoint string     `json:"upstream_endpoint"`
	Transport        string     `json:"transport"`
	ViaWebsocket     bool       `json:"via_websocket"`
	StatusCode       int        `json:"status_code"`
	ErrorKind        string     `json:"error_kind"`
	ErrorMessage     string     `json:"error_message"`
	SelectedAt       time.Time  `json:"selected_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
}

const relayAuditClassifiedRequestsCTE = `
	WITH attempt_flags AS (
		SELECT a.request_id,
		       MAX(CASE
		             WHEN COALESCE(a.error_kind, '') = 'cyber_policy'
		              AND LOWER(TRIM(COALESCE(a.account_type, ''))) IN
		                  ('responses_api', 'openai_responses', 'relay', 'relay_style')
		             THEN 1 ELSE 0
		           END) AS relay_cyber,
		       MAX(CASE
		             WHEN COALESCE(a.error_kind, '') = 'cyber_policy'
		              AND LOWER(TRIM(COALESCE(a.account_type, ''))) NOT IN
		                  ('responses_api', 'openai_responses', 'relay', 'relay_style')
		             THEN 1 ELSE 0
		           END) AS oauth_cyber,
		       MAX(CASE
		             WHEN COALESCE(a.error_kind, '') = 'websocket_isolation_violation'
		             THEN 1 ELSE 0
		           END) AS session_bleed
		FROM rb_route_attempts a
		JOIN rb_route_requests request_window ON request_window.request_id = a.request_id
		WHERE request_window.created_at >= $1 AND request_window.created_at <= $2
		  AND COALESCE(a.error_kind, '') IN ('cyber_policy', 'websocket_isolation_violation')
		GROUP BY a.request_id
	),
	classified AS (
		SELECT r.created_at,
		       r.route_source,
		       r.route_group_id,
		       r.has_previous_response_id,
		       r.replay_status,
		       r.state_fallback_reason,
		       r.detector_miss,
		       r.route_violation,
		       r.group_exhausted,
		       r.final_status_code,
		       r.final_error_kind,
		       CASE
		         WHEN COALESCE(flags.oauth_cyber, 0) > 0
		           OR (
		             COALESCE(r.final_error_kind, '') = 'cyber_policy'
		             AND (COALESCE(r.route_group_id, 0) <= 0 OR COALESCE(r.detector_miss, FALSE))
		           )
		         THEN 1 ELSE 0
		       END AS oauth_cyber,
		       CASE
		         WHEN COALESCE(flags.relay_cyber, 0) > 0
		           OR (
		             COALESCE(r.final_error_kind, '') = 'cyber_policy'
		             AND COALESCE(r.route_group_id, 0) > 0
		           )
		         THEN 1 ELSE 0
		       END AS relay_cyber,
		       CASE
		         WHEN COALESCE(flags.session_bleed, 0) > 0
		           OR COALESCE(r.final_error_kind, '') = 'websocket_isolation_violation'
		         THEN 1 ELSE 0
		       END AS session_bleed
		FROM rb_route_requests r
		LEFT JOIN attempt_flags flags ON flags.request_id = r.request_id
		WHERE r.created_at >= $1 AND r.created_at <= $2
	)
`

func (db *DB) BuildRelayAuditReport(ctx context.Context, query RelayAuditQuery) (*RelayAuditReport, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	end := query.End
	if end.IsZero() {
		end = time.Now()
	}
	end = end.UTC()
	start := query.Start
	if start.IsZero() || !start.Before(end) {
		start = end.Add(-30 * time.Minute)
	}
	start = start.UTC()
	bucketMinutes := query.BucketMinutes
	if bucketMinutes <= 0 {
		bucketMinutes = 5
	}
	if bucketMinutes > 1440 {
		bucketMinutes = 1440
	}
	report := &RelayAuditReport{
		WindowStart: start, WindowEnd: end, GeneratedAt: time.Now(),
		Timeline: []RelayAuditTimelinePoint{}, RouteSignals: []RelayAuditSignalRow{},
		RelayRoutes: []RelayAuditRouteRow{}, Writer: db.RelayAuditWriterStats(),
	}
	startArg, endArg := db.timeRangeArgs(start, end)
	summarySQL := relayAuditClassifiedRequestsCTE + `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN COALESCE(route_group_id, 0) > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'cyb_rule' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'probe' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'no_affinity_split' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'oauth_overflow' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'relay_continuation' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'cyb_feedback' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(replay_status, '') = 'hit' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(replay_status, '') <> '' AND COALESCE(replay_status, '') <> 'hit'
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(final_error_kind, '') = 'continuation_replay_unavailable'
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(group_exhausted, FALSE) THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(detector_miss, FALSE) OR oauth_cyber > 0 THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN relay_cyber > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN oauth_cyber > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_violation, FALSE) THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(state_fallback_reason, '') <> '' THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(route_group_id, 0) > 0
		          AND COALESCE(final_status_code, 0) >= 200
		          AND COALESCE(final_status_code, 0) < 300
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(route_group_id, 0) > 0
		          AND COALESCE(final_status_code, 0) >= 400
		          AND relay_cyber = 0
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN session_bleed > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(has_previous_response_id, FALSE) THEN 1 ELSE 0
		       END), 0)
		FROM classified
	`
	if err := db.conn.QueryRowContext(ctx, summarySQL, startArg, endArg).Scan(
		&report.Summary.LogicalRequests,
		&report.Summary.RelayRequests,
		&report.Summary.CYBRule,
		&report.Summary.Probe,
		&report.Summary.NoAffinitySplit,
		&report.Summary.OAuthOverflow,
		&report.Summary.Continuation,
		&report.Summary.Feedback,
		&report.Summary.ReplayHits,
		&report.Summary.ReplayMisses,
		&report.Summary.ReplayUnavailable,
		&report.Summary.GroupExhausted,
		&report.Summary.DetectorMisses,
		&report.Summary.RelayCyberPolicies,
		&report.Summary.OAuthCyberMisses,
		&report.Summary.RouteViolations,
		&report.Summary.StateFallbacks,
		&report.Summary.RelaySuccesses,
		&report.Summary.RelayFinalFailures,
		&report.Summary.SessionBleed,
		&report.Summary.RequestsWithPrevious,
	); err != nil {
		return nil, err
	}

	bucketSeconds := int64(bucketMinutes) * 60
	bucketExpression := `FLOOR(EXTRACT(EPOCH FROM created_at) / $3)::BIGINT`
	if db.isSQLite() {
		bucketExpression = `CAST(CAST(strftime('%s', created_at) AS INTEGER) / $3 AS INTEGER)`
	}
	timelineSQL := relayAuditClassifiedRequestsCTE + fmt.Sprintf(`
		SELECT bucket_index,
		       COALESCE(SUM(CASE WHEN COALESCE(route_group_id, 0) > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'cyb_rule' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'probe' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'no_affinity_split' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'oauth_overflow' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'relay_continuation' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(route_source, '') = 'cyb_feedback' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(replay_status, '') = 'hit' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(replay_status, '') <> '' AND COALESCE(replay_status, '') <> 'hit'
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN oauth_cyber > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN relay_cyber > 0 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(route_group_id, 0) > 0
		          AND COALESCE(final_status_code, 0) >= 400
		          AND relay_cyber = 0
		         THEN 1 ELSE 0
		       END), 0)
		FROM (
			SELECT classified.*, %s AS bucket_index
			FROM classified
		) bucketed
		GROUP BY bucket_index
		ORDER BY bucket_index
	`, bucketExpression)
	rows, err := db.conn.QueryContext(ctx, timelineSQL, startArg, endArg, bucketSeconds)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var bucketIndex int64
		var point RelayAuditTimelinePoint
		if err := rows.Scan(
			&bucketIndex,
			&point.RelayRequests,
			&point.CYBRule,
			&point.Probe,
			&point.NoAffinitySplit,
			&point.OAuthOverflow,
			&point.Continuation,
			&point.Feedback,
			&point.ReplayHits,
			&point.ReplayMisses,
			&point.OAuthCyberMisses,
			&point.RelayCyberPolicies,
			&point.FinalFailures,
		); err != nil {
			rows.Close()
			return nil, err
		}
		point.Bucket = time.Unix(bucketIndex*bucketSeconds, 0).UTC()
		report.Timeline = append(report.Timeline, point)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type signalAggregate struct {
		count int64
		last  time.Time
	}
	signals := make(map[string]signalAggregate)
	rows, err = db.conn.QueryContext(ctx, `
		SELECT COALESCE(route_signals, '[]'), COUNT(*), MAX(created_at)
		FROM rb_route_requests
		WHERE created_at >= $1 AND created_at <= $2
		  AND COALESCE(route_signals, '') NOT IN ('', '[]')
		GROUP BY COALESCE(route_signals, '[]')
	`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rawSignals string
		var groupedRequests int64
		var lastRaw any
		if err := rows.Scan(&rawSignals, &groupedRequests, &lastRaw); err != nil {
			rows.Close()
			return nil, err
		}
		lastSeen, err := parseDBTimeValue(lastRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		var parsedSignals []string
		if json.Unmarshal([]byte(rawSignals), &parsedSignals) != nil {
			continue
		}
		seenSignals := make(map[string]struct{}, len(parsedSignals))
		for _, signal := range parsedSignals {
			signal = strings.TrimSpace(signal)
			if signal == "" {
				continue
			}
			if _, exists := seenSignals[signal]; exists {
				continue
			}
			seenSignals[signal] = struct{}{}
			aggregate := signals[signal]
			aggregate.count += groupedRequests
			if lastSeen.After(aggregate.last) {
				aggregate.last = lastSeen
			}
			signals[signal] = aggregate
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for signal, aggregate := range signals {
		report.RouteSignals = append(report.RouteSignals, RelayAuditSignalRow{
			Signal: signal, Requests: aggregate.count, LastSeen: aggregate.last,
		})
	}
	sort.Slice(report.RouteSignals, func(i, j int) bool {
		if report.RouteSignals[i].Requests == report.RouteSignals[j].Requests {
			return report.RouteSignals[i].Signal < report.RouteSignals[j].Signal
		}
		return report.RouteSignals[i].Requests > report.RouteSignals[j].Requests
	})

	if err := db.populateRelayAuditAttemptSummary(ctx, start, end, report); err != nil {
		return nil, err
	}
	return report, nil
}

func (db *DB) populateRelayAuditAttemptSummary(ctx context.Context, start, end time.Time, report *RelayAuditReport) error {
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(a.account_id, 0), COALESCE(a.account_name, ''),
		       COALESCE(a.account_type, ''), COALESCE(r.route_source, ''),
		       COUNT(DISTINCT a.request_id),
		       COUNT(*),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(a.status_code, 0) >= 200 AND COALESCE(a.status_code, 0) < 300
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(a.status_code, 0) >= 400 AND COALESCE(a.status_code, 0) < 500
		         THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(a.status_code, 0) >= 500 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(a.error_kind, '') = 'cyber_policy' THEN 1 ELSE 0
		       END), 0),
		       COALESCE(SUM(CASE WHEN COALESCE(a.attempt_index, 0) > 1 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE
		         WHEN COALESCE(a.selection_mode, '') = 'same_group_switch' THEN 1 ELSE 0
		       END), 0)
		FROM rb_route_attempts a
		JOIN rb_route_requests r ON r.request_id = a.request_id
		WHERE r.created_at >= $1 AND r.created_at <= $2
		GROUP BY COALESCE(a.account_id, 0), COALESCE(a.account_name, ''),
		         COALESCE(a.account_type, ''), COALESCE(r.route_source, '')
		ORDER BY COUNT(DISTINCT a.request_id) DESC,
		         COALESCE(a.account_name, ''), COALESCE(r.route_source, '')
	`, startArg, endArg)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item RelayAuditRouteRow
		var retries, sameGroupSwitches int64
		if err := rows.Scan(
			&item.AccountID,
			&item.AccountName,
			&item.AccountType,
			&item.RouteSource,
			&item.Requests,
			&item.Attempts,
			&item.Successes,
			&item.Errors4xx,
			&item.Errors5xx,
			&item.CyberPolicy,
			&retries,
			&sameGroupSwitches,
		); err != nil {
			return err
		}
		report.Summary.RouteAttempts += item.Attempts
		report.Summary.Retries += retries
		report.Summary.SameGroupSwitches += sameGroupSwitches
		report.RelayRoutes = append(report.RelayRoutes, item)
	}
	return rows.Err()
}

func (db *DB) ListRelayAuditCasesPage(ctx context.Context, query RelayAuditCaseQuery) (*RelayAuditCasesPage, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if !query.Start.Before(query.End) {
		return nil, fmt.Errorf("invalid relay audit case window")
	}
	query.Start = query.Start.UTC()
	query.End = query.End.UTC()
	whereKind, err := relayAuditCasePredicate(query.Kind)
	if err != nil {
		return nil, err
	}
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	startArg, endArg := db.timeRangeArgs(query.Start, query.End)
	where := `created_at >= $1 AND created_at <= $2 AND (` + whereKind + `)`
	var total int
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_route_requests WHERE `+where, startArg, endArg).Scan(&total); err != nil {
		return nil, err
	}
	fullTextExpression := `COALESCE(full_text, '')`
	if query.SummaryOnly {
		fullTextExpression = `''`
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT request_id, created_at, updated_at, completed_at,
		       COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(api_key_id, 0), COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''),
		       COALESCE(client_ip, ''), COALESCE(text_preview, ''), `+fullTextExpression+`,
		       COALESCE(payload_bytes, 0), COALESCE(scanned_bytes, 0), COALESCE(scan_truncated, FALSE),
		       COALESCE(scan_details, '{}'), COALESCE(route_source, ''), COALESCE(route_reason, ''),
		       COALESCE(route_signals, '[]'), COALESCE(route_group_id, 0),
		       COALESCE(has_previous_response_id, FALSE), COALESCE(replay_status, ''),
		       COALESCE(replay_source, ''), COALESCE(state_fallback_reason, ''),
		       COALESCE(detector_miss, FALSE), COALESCE(route_violation, FALSE), COALESCE(group_exhausted, FALSE),
		       COALESCE(final_account_id, 0), COALESCE(final_account_name, ''), COALESCE(final_account_type, ''),
		       COALESCE(final_status_code, 0), COALESCE(final_error_kind, ''), COALESCE(final_error_message, ''),
		       COALESCE(final_transport, ''),
		       (SELECT COUNT(*) FROM rb_route_attempts audit_attempt_count
		        WHERE audit_attempt_count.request_id = rb_route_requests.request_id)
		FROM rb_route_requests
		WHERE `+where+`
		ORDER BY created_at DESC, request_id DESC
		LIMIT $3 OFFSET $4
	`, startArg, endArg, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	items := make([]*RelayAuditCase, 0, pageSize)
	for rows.Next() {
		item := &RelayAuditCase{Attempts: []RelayAuditAttempt{}}
		var createdRaw, updatedRaw, completedRaw any
		if err := rows.Scan(
			&item.RequestID, &createdRaw, &updatedRaw, &completedRaw,
			&item.Endpoint, &item.Model, &item.APIKeyID, &item.APIKeyName, &item.APIKeyMasked,
			&item.ClientIP, &item.TextPreview, &item.FullText, &item.PayloadBytes, &item.ScannedBytes,
			&item.ScanTruncated, &item.ScanDetails, &item.RouteSource, &item.RouteReason,
			&item.RouteSignals, &item.RouteGroupID, &item.HasPreviousResponseID,
			&item.ReplayStatus, &item.ReplaySource, &item.StateFallbackReason,
			&item.DetectorMiss, &item.RouteViolation,
			&item.GroupExhausted, &item.FinalAccountID, &item.FinalAccountName,
			&item.FinalAccountType, &item.FinalStatusCode, &item.FinalErrorKind,
			&item.FinalErrorMessage, &item.FinalTransport, &item.AttemptCount,
		); err != nil {
			rows.Close()
			return nil, err
		}
		item.CreatedAt, err = parseDBTimeValue(createdRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		item.UpdatedAt, err = parseDBTimeValue(updatedRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		item.CompletedAt, err = parseOptionalRelayAuditTime(completedRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !query.SummaryOnly {
		if err := db.attachRelayAuditAttempts(ctx, items); err != nil {
			return nil, err
		}
	}
	if err := db.attachRelayCYBLearningSummaries(ctx, items); err != nil {
		return nil, err
	}
	return &RelayAuditCasesPage{
		Items: items, Total: total, Page: page, PageSize: pageSize,
		WindowStart: query.Start, WindowEnd: query.End,
	}, nil
}

func (db *DB) GetRelayAuditCaseDetail(ctx context.Context, requestID string) (*RelayAuditCaseDetail, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, sql.ErrNoRows
	}
	item := &RelayAuditCase{Attempts: []RelayAuditAttempt{}}
	var createdRaw, updatedRaw, completedRaw any
	err := db.conn.QueryRowContext(ctx, `
		SELECT request_id, created_at, updated_at, completed_at,
		       COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(api_key_id, 0), COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''),
		       COALESCE(client_ip, ''), COALESCE(text_preview, ''), COALESCE(full_text, ''),
		       COALESCE(payload_bytes, 0), COALESCE(scanned_bytes, 0), COALESCE(scan_truncated, FALSE),
		       COALESCE(scan_details, '{}'), COALESCE(route_source, ''), COALESCE(route_reason, ''),
		       COALESCE(route_signals, '[]'), COALESCE(route_group_id, 0),
		       COALESCE(has_previous_response_id, FALSE), COALESCE(replay_status, ''),
		       COALESCE(replay_source, ''), COALESCE(state_fallback_reason, ''),
		       COALESCE(detector_miss, FALSE), COALESCE(route_violation, FALSE), COALESCE(group_exhausted, FALSE),
		       COALESCE(final_account_id, 0), COALESCE(final_account_name, ''), COALESCE(final_account_type, ''),
		       COALESCE(final_status_code, 0), COALESCE(final_error_kind, ''), COALESCE(final_error_message, ''),
		       COALESCE(final_transport, ''),
		       (SELECT COUNT(*) FROM rb_route_attempts audit_attempt_count
		        WHERE audit_attempt_count.request_id = rb_route_requests.request_id)
		FROM rb_route_requests
		WHERE request_id = $1
	`, requestID).Scan(
		&item.RequestID, &createdRaw, &updatedRaw, &completedRaw,
		&item.Endpoint, &item.Model, &item.APIKeyID, &item.APIKeyName, &item.APIKeyMasked,
		&item.ClientIP, &item.TextPreview, &item.FullText, &item.PayloadBytes, &item.ScannedBytes,
		&item.ScanTruncated, &item.ScanDetails, &item.RouteSource, &item.RouteReason,
		&item.RouteSignals, &item.RouteGroupID, &item.HasPreviousResponseID,
		&item.ReplayStatus, &item.ReplaySource, &item.StateFallbackReason,
		&item.DetectorMiss, &item.RouteViolation, &item.GroupExhausted,
		&item.FinalAccountID, &item.FinalAccountName, &item.FinalAccountType,
		&item.FinalStatusCode, &item.FinalErrorKind, &item.FinalErrorMessage,
		&item.FinalTransport, &item.AttemptCount,
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt, err = parseDBTimeValue(createdRaw)
	if err != nil {
		return nil, err
	}
	item.UpdatedAt, err = parseDBTimeValue(updatedRaw)
	if err != nil {
		return nil, err
	}
	item.CompletedAt, err = parseOptionalRelayAuditTime(completedRaw)
	if err != nil {
		return nil, err
	}
	if err := db.attachRelayAuditAttempts(ctx, []*RelayAuditCase{item}); err != nil {
		return nil, err
	}
	if err := db.attachRelayCYBLearningSummaries(ctx, []*RelayAuditCase{item}); err != nil {
		return nil, err
	}
	detail := &RelayAuditCaseDetail{Case: item}
	sample, err := db.GetRelayCYBMissSample(ctx, requestID)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == nil {
		detail.CYBMiss = sample
		if sample.RuleID > 0 {
			rule, ruleErr := db.GetRelayCYBRule(ctx, sample.RuleID)
			if ruleErr != nil && ruleErr != sql.ErrNoRows {
				return nil, ruleErr
			}
			detail.Rule = rule
		}
	}
	return detail, nil
}

func relayAuditCasePredicate(kind string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", RelayAuditCaseRelayRoute:
		return `route_group_id > 0`, nil
	case RelayAuditCaseOAuthCyber:
		return `(
			detector_miss = TRUE OR
			(final_error_kind = 'cyber_policy' AND route_group_id <= 0) OR
			EXISTS (
				SELECT 1 FROM rb_route_attempts audit_attempt
				WHERE audit_attempt.request_id = rb_route_requests.request_id
				  AND audit_attempt.error_kind = 'cyber_policy'
				  AND LOWER(COALESCE(audit_attempt.account_type, '')) NOT IN
				      ('responses_api', 'openai_responses', 'relay', 'relay_style')
			)
		)`, nil
	case RelayAuditCaseRelayCyber:
		return `(
			(final_error_kind = 'cyber_policy' AND route_group_id > 0) OR
			EXISTS (
				SELECT 1 FROM rb_route_attempts audit_attempt
				WHERE audit_attempt.request_id = rb_route_requests.request_id
				  AND audit_attempt.error_kind = 'cyber_policy'
				  AND LOWER(COALESCE(audit_attempt.account_type, '')) IN
				      ('responses_api', 'openai_responses', 'relay', 'relay_style')
			)
		)`, nil
	case RelayAuditCaseContinuation:
		return `has_previous_response_id = TRUE`, nil
	case RelayAuditCaseSessionBleed:
		return `(
			final_error_kind = 'websocket_isolation_violation' OR
			EXISTS (
				SELECT 1 FROM rb_route_attempts audit_attempt
				WHERE audit_attempt.request_id = rb_route_requests.request_id
				  AND audit_attempt.error_kind = 'websocket_isolation_violation'
			)
		)`, nil
	default:
		return "", fmt.Errorf("unsupported relay audit case kind %q", kind)
	}
}

func (db *DB) attachRelayAuditAttempts(ctx context.Context, items []*RelayAuditCase) error {
	if len(items) == 0 {
		return nil
	}
	byID := make(map[string]*RelayAuditCase, len(items))
	args := make([]any, 0, len(items))
	placeholders := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil || item.RequestID == "" {
			continue
		}
		byID[item.RequestID] = item
		args = append(args, item.RequestID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return nil
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, request_id, COALESCE(attempt_index, 0), COALESCE(selection_mode, ''),
		       COALESCE(account_id, 0), COALESCE(account_name, ''), COALESCE(account_type, ''),
		       COALESCE(upstream_endpoint, ''), COALESCE(transport, ''), COALESCE(via_websocket, FALSE),
		       COALESCE(status_code, 0), COALESCE(error_kind, ''), COALESCE(error_message, ''),
		       selected_at, completed_at
		FROM rb_route_attempts
		WHERE request_id IN (`+strings.Join(placeholders, ",")+`)
		ORDER BY request_id, attempt_index, id
	`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item RelayAuditAttempt
		var selectedRaw, completedRaw any
		if err := rows.Scan(
			&item.ID, &item.RequestID, &item.AttemptIndex, &item.SelectionMode,
			&item.AccountID, &item.AccountName, &item.AccountType, &item.UpstreamEndpoint,
			&item.Transport, &item.ViaWebsocket, &item.StatusCode, &item.ErrorKind,
			&item.ErrorMessage, &selectedRaw, &completedRaw,
		); err != nil {
			return err
		}
		item.SelectedAt, err = parseDBTimeValue(selectedRaw)
		if err != nil {
			return err
		}
		item.CompletedAt, err = parseOptionalRelayAuditTime(completedRaw)
		if err != nil {
			return err
		}
		if parent := byID[item.RequestID]; parent != nil {
			parent.Attempts = append(parent.Attempts, item)
			parent.AttemptCount = len(parent.Attempts)
		}
	}
	return rows.Err()
}

func parseOptionalRelayAuditTime(raw any) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}
	if value, ok := raw.(string); ok && strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := parseDBTimeValue(raw)
	if err != nil {
		return nil, err
	}
	if parsed.IsZero() {
		return nil, nil
	}
	return &parsed, nil
}
