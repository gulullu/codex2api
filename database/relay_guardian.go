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

var ErrRelayGuardianAccountNotFound = errors.New("relay guardian account not found")

type RelayGuardianEvent struct {
	ID                    int64     `json:"id"`
	CreatedAt             time.Time `json:"created_at"`
	AccountID             int64     `json:"account_id"`
	AccountName           string    `json:"account_name"`
	EventType             string    `json:"event_type"`
	FromState             string    `json:"from_state"`
	ToState               string    `json:"to_state"`
	Actor                 string    `json:"actor"`
	Reason                string    `json:"reason"`
	TriggerSource         string    `json:"trigger_source"`
	WindowSeconds         int       `json:"window_seconds"`
	FailureCount          int       `json:"failure_count"`
	UserVisibleFailures   int       `json:"user_visible_failures"`
	StrongGatewayFailures int       `json:"strong_gateway_failures"`
	QuarantineSeconds     int       `json:"quarantine_seconds"`
	Generation            uint64    `json:"generation"`
	LogicalRequestIDs     []string  `json:"logical_request_ids"`
	Details               any       `json:"details"`
}

type RelayGuardianEventPage struct {
	Items    []RelayGuardianEvent `json:"items"`
	Total    int64                `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	Start    time.Time            `json:"start,omitempty"`
	End      time.Time            `json:"end,omitempty"`
}

func (db *DB) InsertRelayGuardianEvent(ctx context.Context, event *RelayGuardianEvent) error {
	if db == nil || event == nil {
		return nil
	}
	eventTime := event.CreatedAt
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	logical, _ := json.Marshal(event.LogicalRequestIDs)
	details := []byte("{}")
	if event.Details != nil {
		if encoded, err := json.Marshal(event.Details); err == nil {
			details = encoded
		}
	}
	query := `INSERT INTO relay_guardian_events (
		created_at, account_id, account_name, event_type, from_state, to_state, actor, reason, trigger_source,
		window_seconds, failure_count, user_visible_failures, strong_gateway_failures,
		quarantine_seconds, generation, logical_request_ids, details
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	_, err := db.conn.ExecContext(ctx, query, db.timeArg(eventTime), event.AccountID, event.AccountName, event.EventType,
		event.FromState, event.ToState, event.Actor, event.Reason, event.TriggerSource,
		event.WindowSeconds, event.FailureCount, event.UserVisibleFailures, event.StrongGatewayFailures,
		event.QuarantineSeconds, event.Generation, string(logical), string(details))
	return err
}

func (db *DB) DeleteRelayGuardianEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if db == nil || cutoff.IsZero() {
		return 0, nil
	}
	result, err := db.conn.ExecContext(ctx, `DELETE FROM relay_guardian_events WHERE created_at < $1`, db.timeArg(cutoff))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) ListRelayGuardianEvents(ctx context.Context, page, pageSize int, start, end time.Time) (*RelayGuardianEventPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	where := []string{"1=1"}
	args := make([]any, 0, 4)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if !start.IsZero() {
		add("e.created_at >= $%d", db.timeArg(start))
	}
	if !end.IsZero() {
		add("e.created_at <= $%d", db.timeArg(end))
	}
	condition := strings.Join(where, " AND ")
	var total int64
	if err := db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM relay_guardian_events e WHERE "+condition, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	query := fmt.Sprintf(`SELECT e.id, e.created_at, e.account_id,
		COALESCE(NULLIF(TRIM(a.name), ''), e.account_name), e.event_type, e.from_state, e.to_state,
		e.actor, e.reason, e.trigger_source, e.window_seconds, e.failure_count, e.user_visible_failures,
		e.strong_gateway_failures, e.quarantine_seconds, e.generation, e.logical_request_ids, e.details
		FROM relay_guardian_events e LEFT JOIN accounts a ON a.id = e.account_id
		WHERE %s ORDER BY e.created_at DESC, e.id DESC LIMIT $%d OFFSET $%d`, condition, len(args)-1, len(args))
	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &RelayGuardianEventPage{Items: make([]RelayGuardianEvent, 0), Total: total, Page: page, PageSize: pageSize, Start: start, End: end}
	for rows.Next() {
		var event RelayGuardianEvent
		var createdRaw any
		var logicalRaw, detailsRaw string
		if err := rows.Scan(&event.ID, &createdRaw, &event.AccountID, &event.AccountName, &event.EventType, &event.FromState, &event.ToState, &event.Actor, &event.Reason, &event.TriggerSource, &event.WindowSeconds, &event.FailureCount, &event.UserVisibleFailures, &event.StrongGatewayFailures, &event.QuarantineSeconds, &event.Generation, &logicalRaw, &detailsRaw); err != nil {
			return nil, err
		}
		event.CreatedAt, _ = parseDBTimeValue(createdRaw)
		_ = json.Unmarshal([]byte(logicalRaw), &event.LogicalRequestIDs)
		var details any
		if json.Unmarshal([]byte(detailsRaw), &details) == nil {
			event.Details = details
		}
		result.Items = append(result.Items, event)
	}
	return result, rows.Err()
}

type RelayGuardianUsageRow struct {
	ID                  int64
	CreatedAt           time.Time
	AccountID           int64
	LogicalRequestID    string
	StatusCode          int
	UpstreamErrorKind   string
	ErrorMessage        string
	RouteClass          string
	RouteSource         string
	RouteGroupID        int64
	UpstreamAccountType string
	GuardianAttemptOnly bool
}

func (db *DB) ListRelayGuardianUsage(ctx context.Context, groupID int64, start, end time.Time, limit int) ([]RelayGuardianUsageRow, error) {
	if db == nil || groupID <= 0 || !end.After(start) {
		return nil, nil
	}
	if limit < 1 {
		limit = 20000
	}
	if limit > 100000 {
		limit = 100000
	}
	startArg, endArg := db.timeRangeArgs(start, end)
	rows, err := db.conn.QueryContext(ctx, `SELECT id, created_at, account_id, logical_request_id, status_code,
		COALESCE(upstream_error_kind,''), COALESCE(error_message,''), COALESCE(route_class,''), COALESCE(route_source,''),
		COALESCE(route_group_id,0), COALESCE(upstream_account_type,''), COALESCE(guardian_attempt_only, false)
		FROM usage_logs WHERE created_at >= $1 AND created_at <= $2 AND route_group_id = $3
		AND route_class = 'cyb_relay' AND upstream_account_type = 'openai_responses'
		AND logical_request_id <> '' ORDER BY id ASC LIMIT $4`, startArg, endArg, groupID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RelayGuardianUsageRow, 0)
	for rows.Next() {
		var row RelayGuardianUsageRow
		var createdRaw any
		if err := rows.Scan(&row.ID, &createdRaw, &row.AccountID, &row.LogicalRequestID, &row.StatusCode, &row.UpstreamErrorKind, &row.ErrorMessage, &row.RouteClass, &row.RouteSource, &row.RouteGroupID, &row.UpstreamAccountType, &row.GuardianAttemptOnly); err != nil {
			return nil, err
		}
		row.CreatedAt, _ = parseDBTimeValue(createdRaw)
		result = append(result, row)
	}
	return result, rows.Err()
}

func (db *DB) UpdateRelayGuardianMode(ctx context.Context, mode string) error {
	mode = NormalizeRelayGuardianMode(mode)
	res, err := db.conn.ExecContext(ctx, `UPDATE system_settings SET relay_guardian_mode = $1 WHERE id = 1`, mode)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	_, err = db.conn.ExecContext(ctx, `INSERT INTO system_settings (id, relay_guardian_mode) VALUES (1, $1)`, mode)
	return err
}

func NormalizeRelayGuardianMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "monitor":
		return "monitor"
	case "enforce":
		return "enforce"
	default:
		return "off"
	}
}

func (db *DB) RelayGuardianEventCount(ctx context.Context) (int64, error) {
	var count int64
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM relay_guardian_events`).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return count, err
}
