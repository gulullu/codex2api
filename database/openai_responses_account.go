package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const DefaultOpenAIResponsesBaseConcurrency int64 = 10000

type OpenAIResponsesAccountConfig struct {
	ScoreBiasOverride       *int64
	BaseConcurrencyOverride int64
	SkipWarmTier            bool
	Tags                    []string
	GroupIDs                []int64
}

// InsertOpenAIResponsesAccountWithConfig inserts the account and its group
// memberships in one transaction. This keeps the add/copy flow from leaving a
// partially configured account when the metadata write fails.
func (db *DB) InsertOpenAIResponsesAccountWithConfig(ctx context.Context, name string, credentials map[string]interface{}, proxyURL string, config OpenAIResponsesAccountConfig) (int64, error) {
	if credentials == nil {
		credentials = map[string]interface{}{}
	}
	credentialJSON, err := json.Marshal(credentials)
	if err != nil {
		return 0, err
	}
	if config.BaseConcurrencyOverride <= 0 {
		config.BaseConcurrencyOverride = DefaultOpenAIResponsesBaseConcurrency
	}
	if config.BaseConcurrencyOverride > DefaultOpenAIResponsesBaseConcurrency {
		return 0, fmt.Errorf("base_concurrency_override must be <= %d for responses_api accounts", DefaultOpenAIResponsesBaseConcurrency)
	}
	var scoreBias interface{}
	if config.ScoreBiasOverride != nil {
		scoreBias = *config.ScoreBiasOverride
	}
	tagsJSON := string(encodeTagsJSON(config.Tags))

	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var id int64
	if db.isSQLite() {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO accounts (name, platform, type, credentials, proxy_url, score_bias_override, base_concurrency_override, skip_warm_tier, tags)
			VALUES (?, 'openai', 'responses_api', ?, ?, ?, ?, ?, ?)`,
			name, credentialJSON, proxyURL, scoreBias, config.BaseConcurrencyOverride, config.SkipWarmTier, tagsJSON)
		if err != nil {
			return 0, err
		}
		id, err = result.LastInsertId()
		if err != nil {
			return 0, err
		}
	} else {
		err = tx.QueryRowContext(ctx, `
			INSERT INTO accounts (name, platform, type, credentials, proxy_url, score_bias_override, base_concurrency_override, skip_warm_tier, tags)
			VALUES ($1, 'openai', 'responses_api', $2, $3, $4, $5, $6, $7::jsonb)
			RETURNING id`,
			name, credentialJSON, proxyURL, scoreBias, config.BaseConcurrencyOverride, config.SkipWarmTier, tagsJSON).Scan(&id)
		if err != nil {
			return 0, err
		}
	}

	for _, groupID := range normalizeIDSlice(config.GroupIDs) {
		existsQuery := `SELECT 1 FROM account_groups WHERE id = $1`
		if db.isSQLite() {
			existsQuery = `SELECT 1 FROM account_groups WHERE id = ?`
		}
		var exists int
		if err := tx.QueryRowContext(ctx, existsQuery, groupID).Scan(&exists); err != nil {
			return 0, fmt.Errorf("account group %d does not exist: %w", groupID, err)
		}
		query := `INSERT INTO account_group_members (account_id, group_id) VALUES ($1, $2)`
		if db.isSQLite() {
			query = `INSERT INTO account_group_members (account_id, group_id) VALUES (?, ?)`
		}
		if _, err := tx.ExecContext(ctx, query, id, groupID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) FindNonResponsesAPIAccountIDs(ctx context.Context, ids []int64) ([]int64, error) {
	ids = normalizeIDSlice(ids)
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := dbPlaceholders(db.isSQLite(), 1, len(ids))
	query := fmt.Sprintf(`
		SELECT id FROM accounts
		WHERE status <> 'deleted'
		  AND COALESCE(error_message, '') <> 'deleted'
		  AND COALESCE(type, '') <> 'responses_api'
		  AND id IN (%s)
		ORDER BY id`, strings.Join(placeholders, ","))
	rows, err := db.conn.QueryContext(ctx, query, argsFromInt64s(ids)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}
