package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrRelayCYBLearningClaimStale  = errors.New("relay CYB learning claim is stale")
	ErrRelayCYBLearnedRuleDisabled = errors.New("relay CYB learned rule was disabled")
)

const (
	RelayCYBLearningStatusQueued     = "queued"
	RelayCYBLearningStatusProcessing = "processing"
	RelayCYBLearningStatusRetry      = "retry"
	RelayCYBLearningStatusApplied    = "applied"
	RelayCYBLearningStatusMerged     = "merged"
	RelayCYBLearningStatusRejected   = "rejected"
	RelayCYBLearningStatusFailed     = "failed"

	DefaultRelayCYBLearningModel = "gpt-5.4"

	relayCYBMissRequestMaxRunes   = 512 * 1024
	relayCYBMissUserTextMaxRunes  = 128 * 1024
	relayCYBRulePatternMaxRunes   = 2048
	relayCYBRuleRationaleMaxRunes = 4000
)

// RelayCYBMissSampleInput is written only after an OAuth account actually
// returns cyber_policy. It is deliberately separate from Prompt Filter logs:
// the sample exists to explain and learn Relay routing, never to block traffic.
type RelayCYBMissSampleInput struct {
	RequestID        string
	CreatedAt        time.Time
	AccountID        int64
	AccountName      string
	AccountType      string
	RedactedRequest  string
	UserText         string
	RequestTruncated bool
	ContentHash      string
}

type RelayCYBMissSample struct {
	RequestID        string     `json:"request_id"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	AccountID        int64      `json:"account_id"`
	AccountName      string     `json:"account_name"`
	AccountType      string     `json:"account_type"`
	RedactedRequest  string     `json:"redacted_request"`
	UserText         string     `json:"user_text"`
	RequestTruncated bool       `json:"request_truncated"`
	ContentHash      string     `json:"-"`
	LearningStatus   string     `json:"learning_status"`
	LearningModel    string     `json:"learning_model"`
	LearningAttempts int        `json:"learning_attempts"`
	NextAttemptAt    *time.Time `json:"next_attempt_at,omitempty"`
	LearningError    string     `json:"learning_error"`
	RuleID           int64      `json:"rule_id"`
	LearnedAt        *time.Time `json:"learned_at,omitempty"`
}

type RelayCYBLearningSummary struct {
	Status           string    `json:"status"`
	Model            string    `json:"model"`
	Attempts         int       `json:"attempts"`
	Message          string    `json:"message"`
	RuleID           int64     `json:"rule_id"`
	RuleName         string    `json:"rule_name"`
	UpdatedAt        time.Time `json:"updated_at"`
	AccountID        int64     `json:"account_id"`
	AccountName      string    `json:"account_name"`
	AccountType      string    `json:"account_type"`
	RequestTruncated bool      `json:"request_truncated"`
}

type RelayCYBLearningSettings struct {
	Enabled   bool      `json:"enabled"`
	Model     string    `json:"model"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RelayCYBRule struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Pattern         string    `json:"pattern"`
	Rationale       string    `json:"rationale"`
	SourceRequestID string    `json:"source_request_id"`
	Model           string    `json:"model"`
	Enabled         bool      `json:"enabled"`
	DisabledReason  string    `json:"disabled_reason"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RelayCYBRulePage struct {
	Items    []RelayCYBRule `json:"items"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

type RelayCYBLearningStats struct {
	Queued     int64 `json:"queued"`
	Processing int64 `json:"processing"`
	Retry      int64 `json:"retry"`
	Applied    int64 `json:"applied"`
	Merged     int64 `json:"merged"`
	Rejected   int64 `json:"rejected"`
	Failed     int64 `json:"failed"`
	Rules      int64 `json:"rules"`
}

type RelayCYBLearningNotification struct {
	ID        int64     `json:"id"`
	EventType string    `json:"event_type"`
	RuleID    int64     `json:"rule_id"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	CreatedAt time.Time `json:"created_at"`
}

type RelayCYBRuleHitWindow struct {
	TotalRequests int64
	HitsByRule    map[string]int64
}

func (db *DB) migrateRelayCYBLearning(ctx context.Context) error {
	if db == nil || db.conn == nil {
		return nil
	}
	rulesSQL := `
		CREATE TABLE IF NOT EXISTS rb_cyb_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT '',
			pattern TEXT NOT NULL UNIQUE,
			rationale TEXT NOT NULL DEFAULT '',
			source_request_id TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			disabled_reason TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`
	samplesSQL := `
		CREATE TABLE IF NOT EXISTS rb_cyb_miss_samples (
			request_id TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			oauth_account_id BIGINT NOT NULL DEFAULT 0,
			oauth_account_name TEXT NOT NULL DEFAULT '',
			oauth_account_type TEXT NOT NULL DEFAULT '',
			redacted_request TEXT NOT NULL DEFAULT '',
			user_text TEXT NOT NULL DEFAULT '',
			request_truncated BOOLEAN NOT NULL DEFAULT FALSE,
			content_hash TEXT NOT NULL DEFAULT '',
			learning_status TEXT NOT NULL DEFAULT 'queued',
			learning_model TEXT NOT NULL DEFAULT '',
			learning_attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at TIMESTAMP NULL,
			learning_error TEXT NOT NULL DEFAULT '',
			rule_id BIGINT NOT NULL DEFAULT 0,
			learned_at TIMESTAMP NULL
		)`
	settingsSQL := `
		CREATE TABLE IF NOT EXISTS rb_cyb_learning_settings (
			id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			model TEXT NOT NULL DEFAULT 'gpt-5.4',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`
	eventsSQL := `
		CREATE TABLE IF NOT EXISTS rb_cyb_learning_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL DEFAULT '',
			rule_id BIGINT NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT '',
			message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`
	if !db.isSQLite() {
		rulesSQL = strings.ReplaceAll(rulesSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		rulesSQL = strings.Replace(rulesSQL, "id INTEGER PRIMARY KEY AUTOINCREMENT", "id BIGSERIAL PRIMARY KEY", 1)
		samplesSQL = strings.ReplaceAll(samplesSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		settingsSQL = strings.ReplaceAll(settingsSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		eventsSQL = strings.ReplaceAll(eventsSQL, " TIMESTAMP ", " TIMESTAMPTZ ")
		eventsSQL = strings.Replace(eventsSQL, "id INTEGER PRIMARY KEY AUTOINCREMENT", "id BIGSERIAL PRIMARY KEY", 1)
	}
	for _, statement := range []string{
		rulesSQL,
		samplesSQL,
		settingsSQL,
		eventsSQL,
		`CREATE INDEX IF NOT EXISTS idx_rb_cyb_samples_status_next ON rb_cyb_miss_samples(learning_status, next_attempt_at, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_cyb_samples_hash ON rb_cyb_miss_samples(content_hash, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_cyb_rules_enabled_created ON rb_cyb_rules(enabled, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_rb_cyb_events_created ON rb_cyb_learning_events(created_at)`,
		`INSERT INTO rb_cyb_learning_settings (id) VALUES (1) ON CONFLICT(id) DO NOTHING`,
	} {
		if _, err := db.conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRelayCYBMissSampleInput(input RelayCYBMissSampleInput) RelayCYBMissSampleInput {
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.AccountName = strings.TrimSpace(input.AccountName)
	input.AccountType = strings.TrimSpace(input.AccountType)
	input.ContentHash = strings.TrimSpace(input.ContentHash)
	input.RedactedRequest, input.RequestTruncated = boundRelayCYBText(
		input.RedactedRequest,
		relayCYBMissRequestMaxRunes,
		input.RequestTruncated,
	)
	input.UserText, _ = boundRelayCYBText(input.UserText, relayCYBMissUserTextMaxRunes, false)
	if !input.CreatedAt.IsZero() {
		input.CreatedAt = input.CreatedAt.UTC()
	}
	return input
}

func cloneRelayCYBMissSampleInput(input *RelayCYBMissSampleInput) {
	if input == nil {
		return
	}
	input.RequestID = strings.Clone(input.RequestID)
	input.AccountName = strings.Clone(input.AccountName)
	input.AccountType = strings.Clone(input.AccountType)
	input.RedactedRequest = strings.Clone(input.RedactedRequest)
	input.UserText = strings.Clone(input.UserText)
	input.ContentHash = strings.Clone(input.ContentHash)
}

func relayCYBMissSampleBytes(input RelayCYBMissSampleInput) int64 {
	return int64(len(input.RequestID) + len(input.AccountName) + len(input.AccountType) +
		len(input.RedactedRequest) + len(input.UserText) + len(input.ContentHash))
}

func boundRelayCYBText(value string, maxRunes int, alreadyTruncated bool) (string, bool) {
	value = strings.TrimSpace(value)
	bounded, truncated := truncateRelayAuditRunes(value, maxRunes)
	return bounded, alreadyTruncated || truncated
}

func (db *DB) WriteRelayCYBMissSample(ctx context.Context, input *RelayCYBMissSampleInput) error {
	if db == nil || input == nil {
		return nil
	}
	normalized := normalizeRelayCYBMissSampleInput(*input)
	if normalized.RequestID == "" {
		return fmt.Errorf("relay CYB miss request id is empty")
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = time.Now().UTC()
	}
	db.enrichRelayAuditAccount(ctx, normalized.AccountID, &normalized.AccountName, &normalized.AccountType)
	return db.withRelayAuditTransaction(ctx, func(tx *sql.Tx) error {
		if err := ensureRelayAuditRequestWith(ctx, tx, normalized.RequestID, db.timeArg(normalized.CreatedAt)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO rb_cyb_miss_samples (
				request_id, created_at, updated_at,
				oauth_account_id, oauth_account_name, oauth_account_type,
				redacted_request, user_text, request_truncated, content_hash
			) VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT(request_id) DO UPDATE SET
				updated_at = excluded.updated_at,
				oauth_account_id = CASE WHEN excluded.oauth_account_id > 0 THEN excluded.oauth_account_id ELSE rb_cyb_miss_samples.oauth_account_id END,
				oauth_account_name = CASE WHEN excluded.oauth_account_name <> '' THEN excluded.oauth_account_name ELSE rb_cyb_miss_samples.oauth_account_name END,
				oauth_account_type = CASE WHEN excluded.oauth_account_type <> '' THEN excluded.oauth_account_type ELSE rb_cyb_miss_samples.oauth_account_type END,
				redacted_request = CASE WHEN excluded.redacted_request <> '' THEN excluded.redacted_request ELSE rb_cyb_miss_samples.redacted_request END,
				user_text = CASE WHEN excluded.user_text <> '' THEN excluded.user_text ELSE rb_cyb_miss_samples.user_text END,
				request_truncated = rb_cyb_miss_samples.request_truncated OR excluded.request_truncated,
				content_hash = CASE WHEN excluded.content_hash <> '' THEN excluded.content_hash ELSE rb_cyb_miss_samples.content_hash END
		`, normalized.RequestID, db.timeArg(normalized.CreatedAt), normalized.AccountID,
			normalized.AccountName, normalized.AccountType, normalized.RedactedRequest,
			normalized.UserText, normalized.RequestTruncated, normalized.ContentHash)
		return err
	})
}

func (db *DB) GetRelayCYBMissSample(ctx context.Context, requestID string) (*RelayCYBMissSample, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, sql.ErrNoRows
	}
	return scanRelayCYBMissSample(db.conn.QueryRowContext(ctx, `
		SELECT request_id, created_at, updated_at,
		       COALESCE(oauth_account_id, 0), COALESCE(oauth_account_name, ''), COALESCE(oauth_account_type, ''),
		       COALESCE(redacted_request, ''), COALESCE(user_text, ''), COALESCE(request_truncated, FALSE),
		       COALESCE(content_hash, ''), COALESCE(learning_status, 'queued'), COALESCE(learning_model, ''),
		       COALESCE(learning_attempts, 0), next_attempt_at, COALESCE(learning_error, ''),
		       COALESCE(rule_id, 0), learned_at
		FROM rb_cyb_miss_samples
		WHERE request_id = $1
	`, requestID))
}

func (db *DB) attachRelayCYBLearningSummaries(ctx context.Context, items []*RelayAuditCase) error {
	if len(items) == 0 {
		return nil
	}
	byID := make(map[string]*RelayAuditCase, len(items))
	args := make([]any, 0, len(items))
	placeholders := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil || strings.TrimSpace(item.RequestID) == "" {
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
		SELECT sample.request_id, COALESCE(sample.learning_status, 'queued'),
		       COALESCE(sample.learning_model, ''), COALESCE(sample.learning_attempts, 0),
		       COALESCE(sample.learning_error, ''), COALESCE(sample.rule_id, 0),
		       COALESCE(rule.name, ''), sample.updated_at,
		       COALESCE(sample.oauth_account_id, 0), COALESCE(sample.oauth_account_name, ''),
		       COALESCE(sample.oauth_account_type, ''), COALESCE(sample.request_truncated, FALSE)
		FROM rb_cyb_miss_samples sample
		LEFT JOIN rb_cyb_rules rule ON rule.id = sample.rule_id
		WHERE sample.request_id IN (`+strings.Join(placeholders, ",")+`)
	`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var requestID string
		var summary RelayCYBLearningSummary
		var updatedRaw any
		if err := rows.Scan(
			&requestID, &summary.Status, &summary.Model, &summary.Attempts,
			&summary.Message, &summary.RuleID, &summary.RuleName, &updatedRaw,
			&summary.AccountID, &summary.AccountName, &summary.AccountType,
			&summary.RequestTruncated,
		); err != nil {
			return err
		}
		summary.UpdatedAt, err = parseDBTimeValue(updatedRaw)
		if err != nil {
			return err
		}
		if item := byID[requestID]; item != nil {
			item.CYBLearning = &summary
		}
	}
	return rows.Err()
}

type relayCYBRowScanner interface {
	Scan(dest ...any) error
}

func scanRelayCYBMissSample(row relayCYBRowScanner) (*RelayCYBMissSample, error) {
	var sample RelayCYBMissSample
	var createdRaw, updatedRaw, nextRaw, learnedRaw any
	if err := row.Scan(
		&sample.RequestID, &createdRaw, &updatedRaw,
		&sample.AccountID, &sample.AccountName, &sample.AccountType,
		&sample.RedactedRequest, &sample.UserText, &sample.RequestTruncated,
		&sample.ContentHash, &sample.LearningStatus, &sample.LearningModel,
		&sample.LearningAttempts, &nextRaw, &sample.LearningError,
		&sample.RuleID, &learnedRaw,
	); err != nil {
		return nil, err
	}
	var err error
	sample.CreatedAt, err = parseDBTimeValue(createdRaw)
	if err != nil {
		return nil, err
	}
	sample.UpdatedAt, err = parseDBTimeValue(updatedRaw)
	if err != nil {
		return nil, err
	}
	sample.NextAttemptAt, err = parseOptionalRelayAuditTime(nextRaw)
	if err != nil {
		return nil, err
	}
	sample.LearnedAt, err = parseOptionalRelayAuditTime(learnedRaw)
	if err != nil {
		return nil, err
	}
	return &sample, nil
}

func (db *DB) ClaimNextRelayCYBMissSample(ctx context.Context, model string) (*RelayCYBMissSample, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	model = strings.TrimSpace(model)
	now := time.Now().UTC()
	var claimed *RelayCYBMissSample
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
		if _, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, next_attempt_at = $2, updated_at = $2
			WHERE learning_status = $3 AND updated_at < $4
		`, RelayCYBLearningStatusRetry, db.timeArg(now),
			RelayCYBLearningStatusProcessing, db.timeArg(now.Add(-10*time.Minute))); err != nil {
			return err
		}
		duplicateRows, err := tx.QueryContext(ctx, `
			SELECT pending.request_id, applied.rule_id
			FROM rb_cyb_miss_samples pending
			JOIN rb_cyb_miss_samples applied
			  ON applied.content_hash = pending.content_hash
			 AND applied.learning_status = $1
			 AND applied.rule_id > 0
			JOIN rb_cyb_rules rule
			  ON rule.id = applied.rule_id
			 AND rule.enabled = TRUE
			WHERE pending.learning_status IN ($2, $3)
			  AND COALESCE(pending.content_hash, '') <> ''
			LIMIT 100
		`, RelayCYBLearningStatusApplied, RelayCYBLearningStatusQueued, RelayCYBLearningStatusRetry)
		if err != nil {
			return err
		}
		duplicates := make([]struct {
			requestID string
			ruleID    int64
		}, 0)
		for duplicateRows.Next() {
			var duplicate struct {
				requestID string
				ruleID    int64
			}
			if err := duplicateRows.Scan(&duplicate.requestID, &duplicate.ruleID); err != nil {
				duplicateRows.Close()
				return err
			}
			duplicates = append(duplicates, duplicate)
		}
		if err := duplicateRows.Close(); err != nil {
			return err
		}
		for _, duplicate := range duplicates {
			if _, err := tx.ExecContext(ctx, `
				UPDATE rb_cyb_miss_samples
				SET learning_status = $1, rule_id = $2, learned_at = $3,
				    learning_error = '', next_attempt_at = NULL, updated_at = $3
				WHERE request_id = $4 AND learning_status IN ($5, $6)
			`, RelayCYBLearningStatusMerged, duplicate.ruleID, db.timeArg(now),
				duplicate.requestID, RelayCYBLearningStatusQueued, RelayCYBLearningStatusRetry); err != nil {
				return err
			}
		}
		row := tx.QueryRowContext(ctx, `
			SELECT request_id, created_at, updated_at,
			       COALESCE(oauth_account_id, 0), COALESCE(oauth_account_name, ''), COALESCE(oauth_account_type, ''),
			       COALESCE(redacted_request, ''), COALESCE(user_text, ''), COALESCE(request_truncated, FALSE),
			       COALESCE(content_hash, ''), COALESCE(learning_status, 'queued'), COALESCE(learning_model, ''),
			       COALESCE(learning_attempts, 0), next_attempt_at, COALESCE(learning_error, ''),
			       COALESCE(rule_id, 0), learned_at
			FROM rb_cyb_miss_samples
			WHERE learning_status IN ($1, $2)
			  AND (next_attempt_at IS NULL OR next_attempt_at <= $3)
			ORDER BY created_at, request_id
			LIMIT 1
		`, RelayCYBLearningStatusQueued, RelayCYBLearningStatusRetry, db.timeArg(now))
		sample, err := scanRelayCYBMissSample(row)
		if err != nil {
			if err == sql.ErrNoRows {
				if err := tx.Commit(); err != nil {
					return err
				}
				committed = true
				return nil
			}
			return err
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, learning_model = $2,
			    learning_attempts = learning_attempts + 1,
			    learning_error = '', next_attempt_at = NULL, updated_at = $3
			WHERE request_id = $4 AND learning_status IN ($5, $6)
		`, RelayCYBLearningStatusProcessing, model, db.timeArg(now), sample.RequestID,
			RelayCYBLearningStatusQueued, RelayCYBLearningStatusRetry)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			if err := tx.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		sample.LearningStatus = RelayCYBLearningStatusProcessing
		sample.LearningModel = model
		sample.LearningAttempts++
		sample.UpdatedAt = now
		sample.NextAttemptAt = nil
		sample.LearningError = ""
		claimed = sample
		return nil
	})
	return claimed, err
}

func (db *DB) MarkRelayCYBLearningRetry(
	ctx context.Context,
	requestID string,
	expectedAttempt int,
	message string,
	nextAttempt time.Time,
	terminal bool,
) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("database is nil")
	}
	status := RelayCYBLearningStatusRetry
	var next any = db.timeArg(nextAttempt.UTC())
	if terminal {
		status = RelayCYBLearningStatusFailed
		next = nil
	}
	message, _ = truncateRelayAuditRunes(strings.TrimSpace(message), relayAuditErrorMaxRunes)
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
		now := time.Now().UTC()
		result, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, learning_error = $2,
			    next_attempt_at = $3, updated_at = $4
			WHERE request_id = $5
			  AND learning_status = $6
			  AND learning_attempts = $7
		`, status, message, next, db.timeArg(now),
			strings.TrimSpace(requestID), RelayCYBLearningStatusProcessing, expectedAttempt)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return ErrRelayCYBLearningClaimStale
		}
		if terminal {
			if err := insertRelayCYBLearningEventWith(
				ctx,
				tx,
				"failed",
				0,
				"CYB 自动学习失败",
				"一个漏放样本已达到最大重试次数，请在审计案卷中查看原因。",
				now,
			); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	})
}

func (db *DB) MarkRelayCYBLearningRejected(
	ctx context.Context,
	requestID string,
	expectedAttempt int,
	message string,
) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("database is nil")
	}
	message, _ = truncateRelayAuditRunes(strings.TrimSpace(message), relayAuditErrorMaxRunes)
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
		now := time.Now().UTC()
		result, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, learning_error = $2,
			    next_attempt_at = NULL, updated_at = $3
			WHERE request_id = $4
			  AND learning_status = $5
			  AND learning_attempts = $6
		`, RelayCYBLearningStatusRejected, message, db.timeArg(now),
			strings.TrimSpace(requestID), RelayCYBLearningStatusProcessing, expectedAttempt)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return ErrRelayCYBLearningClaimStale
		}
		if err := insertRelayCYBLearningEventWith(
			ctx,
			tx,
			"rejected",
			0,
			"CYB 候选规则未启用",
			"一个候选规则未通过本地机械校验，不会影响线上分流。",
			now,
		); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	})
}

func insertRelayCYBLearningEventWith(
	ctx context.Context,
	exec sqlExecer,
	eventType string,
	ruleID int64,
	title string,
	message string,
	createdAt time.Time,
) error {
	if exec == nil {
		return fmt.Errorf("event writer is nil")
	}
	eventType, _ = truncateRelayAuditRunes(strings.TrimSpace(eventType), 64)
	title, _ = truncateRelayAuditRunes(strings.TrimSpace(title), 200)
	message, _ = truncateRelayAuditRunes(strings.TrimSpace(message), 1000)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := exec.ExecContext(ctx, `
		INSERT INTO rb_cyb_learning_events (
			event_type, rule_id, title, message, created_at
		) VALUES ($1, $2, $3, $4, $5)
	`, eventType, ruleID, title, message, createdAt.UTC())
	return err
}

func (db *DB) ApplyRelayCYBLearnedRule(
	ctx context.Context,
	requestID string,
	expectedAttempt int,
	name, pattern, rationale, model string,
) (*RelayCYBRule, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	requestID = strings.TrimSpace(requestID)
	name, _ = truncateRelayAuditRunes(strings.TrimSpace(name), 120)
	pattern, _ = truncateRelayAuditRunes(strings.TrimSpace(pattern), relayCYBRulePatternMaxRunes)
	rationale, _ = truncateRelayAuditRunes(strings.TrimSpace(rationale), relayCYBRuleRationaleMaxRunes)
	model, _ = truncateRelayAuditRunes(strings.TrimSpace(model), 120)
	now := time.Now().UTC()
	var ruleID int64
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
		settingsQuery := `
			SELECT COALESCE(enabled, TRUE), COALESCE(model, '')
			FROM rb_cyb_learning_settings
			WHERE id = 1
		`
		sampleQuery := `
			SELECT COALESCE(learning_status, ''), COALESCE(learning_model, ''),
			       COALESCE(learning_attempts, 0)
			FROM rb_cyb_miss_samples
			WHERE request_id = $1
		`
		if !db.isSQLite() {
			settingsQuery += ` FOR UPDATE`
			sampleQuery += ` FOR UPDATE`
		}
		var learningEnabled bool
		var configuredModel string
		if err := tx.QueryRowContext(ctx, settingsQuery).Scan(&learningEnabled, &configuredModel); err != nil {
			return err
		}
		if !learningEnabled || !strings.EqualFold(strings.TrimSpace(configuredModel), model) {
			return ErrRelayCYBLearningClaimStale
		}
		var learningStatus, claimedModel string
		var claimedAttempt int
		if err := tx.QueryRowContext(ctx, sampleQuery, requestID).Scan(
			&learningStatus,
			&claimedModel,
			&claimedAttempt,
		); err != nil {
			return err
		}
		if learningStatus != RelayCYBLearningStatusProcessing ||
			!strings.EqualFold(strings.TrimSpace(claimedModel), model) ||
			claimedAttempt != expectedAttempt {
			return ErrRelayCYBLearningClaimStale
		}
		insertResult, err := tx.ExecContext(ctx, `
			INSERT INTO rb_cyb_rules (
				name, pattern, rationale, source_request_id, model,
				enabled, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, TRUE, $6, $6)
			ON CONFLICT(pattern) DO NOTHING
		`, name, pattern, rationale, requestID, model, db.timeArg(now))
		if err != nil {
			return err
		}
		inserted, err := insertResult.RowsAffected()
		if err != nil {
			return err
		}
		var ruleEnabled bool
		if err := tx.QueryRowContext(ctx, `
			SELECT id, COALESCE(enabled, FALSE)
			FROM rb_cyb_rules
			WHERE pattern = $1
		`, pattern).Scan(&ruleID, &ruleEnabled); err != nil {
			return err
		}
		if inserted == 0 && !ruleEnabled {
			return ErrRelayCYBLearnedRuleDisabled
		}
		sampleStatus := RelayCYBLearningStatusMerged
		if inserted == 1 {
			sampleStatus = RelayCYBLearningStatusApplied
		}
		updateResult, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_miss_samples
			SET learning_status = $1, learning_error = '', rule_id = $2,
			    learned_at = $3, next_attempt_at = NULL, updated_at = $3
			WHERE request_id = $4
			  AND learning_status = $5
			  AND LOWER(TRIM(learning_model)) = LOWER(TRIM($6))
			  AND learning_attempts = $7
		`, sampleStatus, ruleID, db.timeArg(now), requestID,
			RelayCYBLearningStatusProcessing, model, expectedAttempt)
		if err != nil {
			return err
		}
		affected, err := updateResult.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return ErrRelayCYBLearningClaimStale
		}
		if inserted == 1 {
			if err := insertRelayCYBLearningEventWith(
				ctx,
				tx,
				"applied",
				ruleID,
				"新的 CYB 分流规则已自动启用",
				"一个新规则已通过本地验证并热加载；通知不包含请求或账号内容。",
				now,
			); err != nil {
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return db.GetRelayCYBRule(ctx, ruleID)
}

func (db *DB) GetRelayCYBRule(ctx context.Context, id int64) (*RelayCYBRule, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	return scanRelayCYBRule(db.conn.QueryRowContext(ctx, `
		SELECT id, COALESCE(name, ''), COALESCE(pattern, ''), COALESCE(rationale, ''),
		       COALESCE(source_request_id, ''), COALESCE(model, ''), COALESCE(enabled, FALSE),
		       COALESCE(disabled_reason, ''), created_at, updated_at
		FROM rb_cyb_rules WHERE id = $1
	`, id))
}

func scanRelayCYBRule(row relayCYBRowScanner) (*RelayCYBRule, error) {
	var rule RelayCYBRule
	var createdRaw, updatedRaw any
	if err := row.Scan(
		&rule.ID, &rule.Name, &rule.Pattern, &rule.Rationale,
		&rule.SourceRequestID, &rule.Model, &rule.Enabled,
		&rule.DisabledReason, &createdRaw, &updatedRaw,
	); err != nil {
		return nil, err
	}
	var err error
	rule.CreatedAt, err = parseDBTimeValue(createdRaw)
	if err != nil {
		return nil, err
	}
	rule.UpdatedAt, err = parseDBTimeValue(updatedRaw)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (db *DB) ListEnabledRelayCYBRules(ctx context.Context) ([]RelayCYBRule, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, COALESCE(name, ''), COALESCE(pattern, ''), COALESCE(rationale, ''),
		       COALESCE(source_request_id, ''), COALESCE(model, ''), COALESCE(enabled, FALSE),
		       COALESCE(disabled_reason, ''), created_at, updated_at
		FROM rb_cyb_rules
		WHERE enabled = TRUE
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := make([]RelayCYBRule, 0)
	for rows.Next() {
		rule, err := scanRelayCYBRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, *rule)
	}
	return rules, rows.Err()
}

func (db *DB) ListRelayCYBRulesPage(ctx context.Context, page, pageSize int) (*RelayCYBRulePage, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	var total int
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_cyb_rules`).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, COALESCE(name, ''), COALESCE(pattern, ''), COALESCE(rationale, ''),
		       COALESCE(source_request_id, ''), COALESCE(model, ''), COALESCE(enabled, FALSE),
		       COALESCE(disabled_reason, ''), created_at, updated_at
		FROM rb_cyb_rules
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2
	`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RelayCYBRule, 0, pageSize)
	for rows.Next() {
		rule, err := scanRelayCYBRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &RelayCYBRulePage{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (db *DB) GetRelayCYBLearningSettings(ctx context.Context) (*RelayCYBLearningSettings, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	var settings RelayCYBLearningSettings
	var updatedRaw any
	if err := db.conn.QueryRowContext(ctx, `
		SELECT COALESCE(enabled, TRUE), COALESCE(model, $1), updated_at
		FROM rb_cyb_learning_settings WHERE id = 1
	`, DefaultRelayCYBLearningModel).Scan(&settings.Enabled, &settings.Model, &updatedRaw); err != nil {
		return nil, err
	}
	var err error
	settings.UpdatedAt, err = parseDBTimeValue(updatedRaw)
	if err != nil {
		return nil, err
	}
	settings.Model = strings.TrimSpace(settings.Model)
	if settings.Model == "" {
		settings.Model = DefaultRelayCYBLearningModel
	}
	return &settings, nil
}

func (db *DB) UpdateRelayCYBLearningSettings(ctx context.Context, enabled bool, model string) (*RelayCYBLearningSettings, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	model, _ = truncateRelayAuditRunes(strings.TrimSpace(model), 120)
	if model == "" {
		return nil, fmt.Errorf("learning model is empty")
	}
	now := time.Now().UTC()
	if err := db.withSQLiteWriteLock(ctx, func() error {
		_, err := db.conn.ExecContext(ctx, `
			INSERT INTO rb_cyb_learning_settings (id, enabled, model, updated_at)
			VALUES (1, $1, $2, $3)
			ON CONFLICT(id) DO UPDATE SET
				enabled = excluded.enabled,
				model = excluded.model,
				updated_at = excluded.updated_at
		`, enabled, model, db.timeArg(now))
		return err
	}); err != nil {
		return nil, err
	}
	return db.GetRelayCYBLearningSettings(ctx)
}

func (db *DB) GetRelayCYBLearningStats(ctx context.Context) (RelayCYBLearningStats, error) {
	var stats RelayCYBLearningStats
	if db == nil || db.conn == nil {
		return stats, fmt.Errorf("database is nil")
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(learning_status, 'queued'), COUNT(*)
		FROM rb_cyb_miss_samples
		GROUP BY COALESCE(learning_status, 'queued')
	`)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return stats, err
		}
		switch status {
		case RelayCYBLearningStatusQueued:
			stats.Queued = count
		case RelayCYBLearningStatusProcessing:
			stats.Processing = count
		case RelayCYBLearningStatusRetry:
			stats.Retry = count
		case RelayCYBLearningStatusApplied:
			stats.Applied = count
		case RelayCYBLearningStatusMerged:
			stats.Merged = count
		case RelayCYBLearningStatusRejected:
			stats.Rejected = count
		case RelayCYBLearningStatusFailed:
			stats.Failed = count
		}
	}
	if err := rows.Close(); err != nil {
		return stats, err
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}
	if err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM rb_cyb_rules WHERE enabled = TRUE`).Scan(&stats.Rules); err != nil {
		return stats, err
	}
	return stats, nil
}

func (db *DB) ListRelayCYBLearningNotifications(
	ctx context.Context,
	since time.Time,
	limit int,
) ([]RelayCYBLearningNotification, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, COALESCE(event_type, ''), COALESCE(rule_id, 0),
		       COALESCE(title, ''), COALESCE(message, ''), created_at
		FROM rb_cyb_learning_events
		WHERE created_at >= $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, db.timeArg(since.UTC()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RelayCYBLearningNotification, 0, limit)
	for rows.Next() {
		var item RelayCYBLearningNotification
		var createdRaw any
		if err := rows.Scan(
			&item.ID,
			&item.EventType,
			&item.RuleID,
			&item.Title,
			&item.Message,
			&createdRaw,
		); err != nil {
			return nil, err
		}
		item.CreatedAt, err = parseDBTimeValue(createdRaw)
		if err != nil {
			return nil, err
		}
		item.Count = 1
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListRecentOfficialDefaultAuditTexts(
	ctx context.Context,
	limit int,
) ([]string, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(full_text, '')
		FROM rb_route_requests
		WHERE COALESCE(route_source, '') = 'official_default'
		  AND COALESCE(detector_miss, FALSE) = FALSE
		  AND COALESCE(full_text, '') <> ''
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0, limit)
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, err
		}
		if text = strings.TrimSpace(text); text != "" {
			items = append(items, text)
		}
	}
	return items, rows.Err()
}

func (db *DB) RelayCYBRuleHitsSince(ctx context.Context, since time.Time) (RelayCYBRuleHitWindow, error) {
	window := RelayCYBRuleHitWindow{HitsByRule: make(map[string]int64)}
	if db == nil || db.conn == nil {
		return window, fmt.Errorf("database is nil")
	}
	if err := db.conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM rb_route_requests WHERE created_at >= $1
	`, db.timeArg(since.UTC())).Scan(&window.TotalRequests); err != nil {
		return window, err
	}
	rows, err := db.conn.QueryContext(ctx, `
		SELECT COALESCE(route_signals, '[]')
		FROM rb_route_requests
		WHERE created_at >= $1
		  AND COALESCE(route_source, '') = 'cyb_rule'
		  AND COALESCE(route_signals, '') LIKE '%learned_rule:%'
	`, db.timeArg(since.UTC()))
	if err != nil {
		return window, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return window, err
		}
		var signals []string
		if json.Unmarshal([]byte(raw), &signals) != nil {
			continue
		}
		seen := make(map[string]struct{})
		for _, signal := range signals {
			signal = strings.TrimSpace(signal)
			if !strings.HasPrefix(strings.ToLower(signal), "learned_rule:") {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(signal[len("learned_rule:"):]))
			if name == "" {
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			window.HitsByRule[name]++
		}
	}
	return window, rows.Err()
}

func (db *DB) DisableRelayCYBRule(ctx context.Context, id int64, reason string) (bool, error) {
	if db == nil || db.conn == nil {
		return false, fmt.Errorf("database is nil")
	}
	reason, _ = truncateRelayAuditRunes(strings.TrimSpace(reason), 1000)
	now := time.Now().UTC()
	disabled := false
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
		var name string
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(name, '') FROM rb_cyb_rules
			WHERE id = $1 AND enabled = TRUE
		`, id).Scan(&name); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE rb_cyb_rules
			SET enabled = FALSE, disabled_reason = $1, updated_at = $2
			WHERE id = $3 AND enabled = TRUE
		`, reason, db.timeArg(now), id)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected == 0 {
			return err
		}
		if err := insertRelayCYBLearningEventWith(
			ctx,
			tx,
			"auto_disabled",
			id,
			"CYB 自动规则已触发保险丝并停用",
			"规则 "+strings.TrimSpace(name)+" 的短时命中比例异常，已仅停用该规则。",
			now,
		); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		committed = true
		disabled = true
		return nil
	})
	return disabled, err
}
