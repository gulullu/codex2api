package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type PromptFilterLog struct {
	ID                  int64               `json:"id"`
	CreatedAt           time.Time           `json:"created_at"`
	Source              string              `json:"source"`
	Endpoint            string              `json:"endpoint"`
	Model               string              `json:"model"`
	Action              string              `json:"action"`
	Mode                string              `json:"mode"`
	Score               int                 `json:"score"`
	Threshold           int                 `json:"threshold"`
	MatchedPatterns     string              `json:"matched_patterns"`
	TextPreview         string              `json:"text_preview"`
	FullText            string              `json:"full_text"`
	APIKeyID            int64               `json:"api_key_id"`
	APIKeyName          string              `json:"api_key_name"`
	APIKeyMasked        string              `json:"api_key_masked"`
	ClientIP            string              `json:"client_ip"`
	ErrorCode           string              `json:"error_code"`
	ReviewModel         string              `json:"review_model"`
	ReviewFlagged       bool                `json:"review_flagged"`
	ReviewError         string              `json:"review_error"`
	ClientRequestID     string              `json:"client_request_id"`
	LogicalRequestID    string              `json:"logical_request_id"`
	AccountID           int64               `json:"account_id"`
	AccountName         string              `json:"account_name,omitempty"`
	RouteClass          string              `json:"route_class"`
	RouteReason         string              `json:"route_reason"`
	RouteSource         string              `json:"route_source"`
	RouteSignals        string              `json:"route_signals"`
	PinKind             string              `json:"pin_kind"`
	RouteGroupID        int64               `json:"route_group_id"`
	RoutePinned         bool                `json:"route_pinned"`
	UpstreamAccountType string              `json:"upstream_account_type"`
	PayloadBytes        int64               `json:"payload_bytes"`
	ScannedBytes        int64               `json:"scanned_bytes"`
	ScanTruncated       bool                `json:"scan_truncated"`
	ScanDetails         string              `json:"scan_details"`
	AuditAttempts       []CodexAuditAttempt `json:"audit_attempts,omitempty"`
}

type PromptFilterLogInput struct {
	ClientRequestID     string
	LogicalRequestID    string
	Source              string
	Endpoint            string
	Model               string
	Action              string
	Mode                string
	Score               int
	Threshold           int
	MatchedPatterns     string
	TextPreview         string
	FullText            string
	APIKeyID            int64
	APIKeyName          string
	APIKeyMasked        string
	ClientIP            string
	ErrorCode           string
	ReviewModel         string
	ReviewFlagged       bool
	ReviewError         string
	AccountID           int64
	RouteClass          string
	RouteReason         string
	RouteSource         string
	RouteSignals        string
	PinKind             string
	RouteGroupID        int64
	RoutePinned         bool
	UpstreamAccountType string
	PayloadBytes        int64
	ScannedBytes        int64
	ScanTruncated       bool
	ScanDetails         string
}

type PromptFilterLogQuery struct {
	Page                int
	PageSize            int
	Limit               int
	Source              string
	Action              string
	Endpoint            string
	Model               string
	APIKeyID            int64
	Query               string
	LogicalRequestID    string
	RouteClass          string
	RouteSource         string
	UpstreamAccountType string
	CyberScope          string
	Start               time.Time
	End                 time.Time
}

func (db *DB) InsertPromptFilterLog(ctx context.Context, input *PromptFilterLogInput) error {
	if db == nil || input == nil {
		return nil
	}
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO prompt_filter_logs (
			source, endpoint, model, action, mode, score, threshold_value, matched_patterns, text_preview,
			api_key_id, api_key_name, api_key_masked, client_ip, error_code, review_model, review_flagged, review_error, full_text, client_request_id,
			account_id, route_class, route_reason, route_source, route_signals, pin_kind, route_group_id, route_pinned, upstream_account_type,
			logical_request_id, payload_bytes, scanned_bytes, scan_truncated, scan_details
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33)
	`, input.Source, input.Endpoint, input.Model, input.Action, input.Mode, input.Score, input.Threshold,
		input.MatchedPatterns, input.TextPreview, input.APIKeyID, input.APIKeyName, input.APIKeyMasked, input.ClientIP, input.ErrorCode,
		input.ReviewModel, input.ReviewFlagged, input.ReviewError, input.FullText, input.ClientRequestID,
		input.AccountID, input.RouteClass, input.RouteReason, input.RouteSource, input.RouteSignals, input.PinKind,
		input.RouteGroupID, input.RoutePinned, input.UpstreamAccountType, input.LogicalRequestID,
		input.PayloadBytes, input.ScannedBytes, input.ScanTruncated, input.ScanDetails)
	return err
}

func (db *DB) ListPromptFilterLogs(ctx context.Context, limit int) ([]*PromptFilterLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	result, _, err := db.ListPromptFilterLogsPage(ctx, PromptFilterLogQuery{Page: 1, PageSize: limit})
	return result, err
}

func (db *DB) ListPromptFilterLogsPage(ctx context.Context, query PromptFilterLogQuery) ([]*PromptFilterLog, int, error) {
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = query.Limit
	}
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 100
	}
	page := query.Page
	if page <= 0 {
		page = 1
	}

	where, args := db.promptFilterLogWhere(query)
	countSQL := `SELECT COUNT(*) FROM prompt_filter_logs` + where
	var total int
	if err := db.conn.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, created_at, COALESCE(source, ''), COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(action, ''), COALESCE(mode, ''), COALESCE(score, 0), COALESCE(threshold_value, 0),
		       COALESCE(matched_patterns, '[]'), COALESCE(text_preview, ''), COALESCE(api_key_id, 0),
		       COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''), COALESCE(client_ip, ''), COALESCE(error_code, ''),
		       COALESCE(review_model, ''), COALESCE(review_flagged, false), COALESCE(review_error, ''), COALESCE(full_text, ''),
		       COALESCE(client_request_id, ''), COALESCE(logical_request_id, ''),
		       COALESCE(account_id, 0), COALESCE(route_class, ''), COALESCE(route_reason, ''),
		       COALESCE(route_source, ''), COALESCE(route_signals, '[]'), COALESCE(pin_kind, ''), COALESCE(route_group_id, 0),
		       COALESCE(route_pinned, false), COALESCE(upstream_account_type, ''),
		       COALESCE(payload_bytes, 0), COALESCE(scanned_bytes, 0), COALESCE(scan_truncated, false), COALESCE(scan_details, '{}')
		FROM prompt_filter_logs
		`+where+`
		ORDER BY id DESC
		LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args))+`
	`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]*PromptFilterLog, 0)
	for rows.Next() {
		item := &PromptFilterLog{}
		var createdAtRaw interface{}
		if err := rows.Scan(&item.ID, &createdAtRaw, &item.Source, &item.Endpoint, &item.Model, &item.Action, &item.Mode,
			&item.Score, &item.Threshold, &item.MatchedPatterns, &item.TextPreview, &item.APIKeyID, &item.APIKeyName,
			&item.APIKeyMasked, &item.ClientIP, &item.ErrorCode, &item.ReviewModel, &item.ReviewFlagged, &item.ReviewError, &item.FullText,
			&item.ClientRequestID, &item.LogicalRequestID,
			&item.AccountID, &item.RouteClass, &item.RouteReason, &item.RouteSource, &item.RouteSignals, &item.PinKind,
			&item.RouteGroupID, &item.RoutePinned, &item.UpstreamAccountType,
			&item.PayloadBytes, &item.ScannedBytes, &item.ScanTruncated, &item.ScanDetails); err != nil {
			return nil, 0, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			return nil, 0, err
		}
		item.CreatedAt = createdAt
		logs = append(logs, item)
	}
	return logs, total, rows.Err()
}

func (db *DB) promptFilterLogWhere(query PromptFilterLogQuery) (string, []any) {
	clauses := make([]string, 0, 8)
	args := make([]any, 0, 8)
	addExact := func(column, value string) {
		value = strings.TrimSpace(value)
		if value == "" || value == "all" {
			return
		}
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addExact("source", query.Source)
	addExact("action", query.Action)
	addExact("endpoint", query.Endpoint)
	addExact("model", query.Model)
	addExact("logical_request_id", query.LogicalRequestID)
	addExact("route_class", query.RouteClass)
	addExact("route_source", query.RouteSource)
	addExact("upstream_account_type", query.UpstreamAccountType)
	if !query.Start.IsZero() {
		args = append(args, db.timeArg(query.Start))
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.End.IsZero() {
		args = append(args, db.timeArg(query.End))
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if query.APIKeyID > 0 {
		args = append(args, query.APIKeyID)
		clauses = append(clauses, fmt.Sprintf("api_key_id = $%d", len(args)))
	}
	if q := strings.TrimSpace(query.Query); q != "" {
		args = append(args, "%"+strings.ToLower(q)+"%")
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf(`(
			LOWER(COALESCE(text_preview, '')) LIKE $%d OR
			LOWER(COALESCE(full_text, '')) LIKE $%d OR
			LOWER(COALESCE(matched_patterns, '')) LIKE $%d OR
			LOWER(COALESCE(error_code, '')) LIKE $%d OR
			LOWER(COALESCE(review_error, '')) LIKE $%d OR
			LOWER(COALESCE(api_key_name, '')) LIKE $%d OR
			LOWER(COALESCE(api_key_masked, '')) LIKE $%d OR
			LOWER(COALESCE(route_class, '')) LIKE $%d OR
			LOWER(COALESCE(route_reason, '')) LIKE $%d OR
			LOWER(COALESCE(route_source, '')) LIKE $%d OR
			LOWER(COALESCE(route_signals, '')) LIKE $%d OR
			LOWER(COALESCE(pin_kind, '')) LIKE $%d OR
			LOWER(COALESCE(upstream_account_type, '')) LIKE $%d
		)`, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx))
	}
	switch strings.ToLower(strings.TrimSpace(query.CyberScope)) {
	case "oauth":
		clauses = append(clauses, "COALESCE(upstream_account_type, '') = 'oauth'")
	case "relay":
		clauses = append(clauses, "COALESCE(upstream_account_type, '') = 'openai_responses' AND COALESCE(route_class, '') = 'cyb_relay' AND COALESCE(route_group_id, 0) > 0")
	case "unknown":
		clauses = append(clauses, "COALESCE(upstream_account_type, '') = ''")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// FindNearestPromptFilterLog 返回与给定时间 at 最接近的一条提示词过滤日志，用于把
// 「使用统计」里的某次报错关联到对应的拦截记录（含完整请求内容）。按 source /
// api_key_id 过滤，时间窗口内取最接近的一条；endpoint 仅作为同等时间下的优先项。
func (db *DB) FindNearestPromptFilterLog(ctx context.Context, at time.Time, source, endpoint string, apiKeyID int64, windowSeconds int) (*PromptFilterLog, error) {
	if db == nil {
		return nil, nil
	}
	if windowSeconds <= 0 {
		windowSeconds = 10
	}
	startArg, endArg := db.timeRangeArgs(at.Add(-time.Duration(windowSeconds)*time.Second), at.Add(time.Duration(windowSeconds)*time.Second))
	clauses := []string{"created_at >= $1", "created_at <= $2"}
	args := []any{startArg, endArg}
	if s := strings.TrimSpace(source); s != "" {
		args = append(args, s)
		clauses = append(clauses, fmt.Sprintf("source = $%d", len(args)))
	}
	if apiKeyID > 0 {
		args = append(args, apiKeyID)
		clauses = append(clauses, fmt.Sprintf("api_key_id = $%d", len(args)))
	}

	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, created_at, COALESCE(source, ''), COALESCE(endpoint, ''), COALESCE(model, ''),
		       COALESCE(action, ''), COALESCE(mode, ''), COALESCE(score, 0), COALESCE(threshold_value, 0),
		       COALESCE(matched_patterns, '[]'), COALESCE(text_preview, ''), COALESCE(api_key_id, 0),
		       COALESCE(api_key_name, ''), COALESCE(api_key_masked, ''), COALESCE(client_ip, ''), COALESCE(error_code, ''),
		       COALESCE(review_model, ''), COALESCE(review_flagged, false), COALESCE(review_error, ''), COALESCE(full_text, ''),
		       COALESCE(client_request_id, ''), COALESCE(logical_request_id, ''),
		       COALESCE(account_id, 0), COALESCE(route_class, ''), COALESCE(route_reason, ''),
		       COALESCE(route_source, ''), COALESCE(route_signals, '[]'), COALESCE(pin_kind, ''), COALESCE(route_group_id, 0),
		       COALESCE(route_pinned, false), COALESCE(upstream_account_type, '')
		FROM prompt_filter_logs
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY id DESC
		LIMIT 50
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var best *PromptFilterLog
	var bestDelta time.Duration
	for rows.Next() {
		item := &PromptFilterLog{}
		var createdAtRaw interface{}
		if err := rows.Scan(&item.ID, &createdAtRaw, &item.Source, &item.Endpoint, &item.Model, &item.Action, &item.Mode,
			&item.Score, &item.Threshold, &item.MatchedPatterns, &item.TextPreview, &item.APIKeyID, &item.APIKeyName,
			&item.APIKeyMasked, &item.ClientIP, &item.ErrorCode, &item.ReviewModel, &item.ReviewFlagged, &item.ReviewError, &item.FullText,
			&item.ClientRequestID, &item.LogicalRequestID,
			&item.AccountID, &item.RouteClass, &item.RouteReason, &item.RouteSource, &item.RouteSignals, &item.PinKind,
			&item.RouteGroupID, &item.RoutePinned, &item.UpstreamAccountType); err != nil {
			return nil, err
		}
		createdAt, err := parseDBTimeValue(createdAtRaw)
		if err != nil {
			continue
		}
		item.CreatedAt = createdAt
		delta := at.Sub(createdAt)
		if delta < 0 {
			delta = -delta
		}
		// endpoint 一致时给一点优先（减小有效距离），保证同一时刻多条时选对端点。
		if endpoint != "" && item.Endpoint == endpoint {
			if delta >= time.Second {
				delta -= time.Second
			} else {
				delta = 0
			}
		}
		if best == nil || delta < bestDelta {
			best = item
			bestDelta = delta
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return best, nil
}

func (db *DB) ClearPromptFilterLogs(ctx context.Context) error {
	if db == nil {
		return nil
	}
	if db.isSQLite() {
		if _, err := db.conn.ExecContext(ctx, `DELETE FROM prompt_filter_logs`); err != nil {
			return err
		}
		_, err := db.conn.ExecContext(ctx, `DELETE FROM sqlite_sequence WHERE name = 'prompt_filter_logs'`)
		return err
	}
	_, err := db.conn.ExecContext(ctx, `TRUNCATE TABLE prompt_filter_logs RESTART IDENTITY`)
	return err
}

func (db *DB) DeleteSemanticPromptFilterLogsBefore(ctx context.Context, before time.Time) (int64, error) {
	if db == nil {
		return 0, nil
	}
	result, err := db.conn.ExecContext(ctx, `
		DELETE FROM prompt_filter_logs
		WHERE created_at < $1
		  AND source IN ('semantic_review', 'semantic_review_disagreement')
	`, db.timeArg(before))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rows, nil
}
