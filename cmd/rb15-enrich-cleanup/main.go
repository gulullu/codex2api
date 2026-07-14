package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lib/pq"
)

const (
	targetTable        = `public.prompt_filter_logs`
	toolVersion        = "rb15-v1"
	advisoryLockKey    = int64(5927309398729187913)
	defaultBatchSize   = 200
	maxBatchSize       = 500
	defaultStmtTimeout = 5 * time.Second
	defaultLockTimeout = 2 * time.Second
	minimumCandidateID = int64(-1 << 63)
)

var identifierPart = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

type options struct {
	backupTable             string
	backupTableSQL          string
	execute                 bool
	operation               operation
	batchSize               int
	statementTimeout        time.Duration
	lockTimeout             time.Duration
	expectedRows            int
	expectedCandidateDigest string
}

type candidateMeta struct {
	id         int64
	fullMD5    sql.NullString
	previewMD5 sql.NullString
	markerPair bool
}

type candidateSnapshot struct {
	Count  int    `json:"count"`
	Digest string `json:"digest_sha256"`
}

type phaseReport struct {
	Total             int            `json:"total"`
	Counts            map[string]int `json:"counts"`
	CleanSuffixDigest string         `json:"clean_suffix_digest_sha256"`
}

type report struct {
	ToolVersion       string            `json:"tool_version"`
	Mode              string            `json:"mode"`
	BackupTable       string            `json:"backup_table"`
	TargetTable       string            `json:"target_table"`
	CandidateSnapshot candidateSnapshot `json:"candidate_snapshot"`
	Preflight         *phaseReport      `json:"preflight,omitempty"`
	WriteReady        bool              `json:"write_ready"`
	Mutated           int               `json:"mutated"`
	Postflight        *phaseReport      `json:"postflight,omitempty"`
	Completed         bool              `json:"completed"`
}

type backupLiveRow struct {
	id                  int64
	source              string
	markerPair          bool
	originalFullText    sql.NullString
	originalTextPreview sql.NullString
	originalFullMD5     sql.NullString
	originalPreviewMD5  sql.NullString
	liveID              sql.NullInt64
	liveFullText        sql.NullString
	liveTextPreview     sql.NullString
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "rb15-enrich-cleanup: %v\n", err)
		os.Exit(2)
	}

	result, runErr := run(ctx, opts)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil && runErr == nil {
		runErr = fmt.Errorf("encode report: %w", err)
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "rb15-enrich-cleanup: %v\n", runErr)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("rb15-enrich-cleanup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var opts options
	var rollback bool
	fs.StringVar(&opts.backupTable, "backup-table", "", "explicit frozen backup table")
	fs.BoolVar(&opts.execute, "execute", false, "apply the selected operation; default is dry-run")
	fs.BoolVar(&rollback, "rollback", false, "select restore-from-backup operation; still dry-run unless --execute")
	fs.IntVar(&opts.batchSize, "batch-size", defaultBatchSize, "rows per transaction")
	fs.DurationVar(&opts.statementTimeout, "statement-timeout", defaultStmtTimeout, "PostgreSQL statement timeout")
	fs.DurationVar(&opts.lockTimeout, "lock-timeout", defaultLockTimeout, "PostgreSQL lock timeout")
	fs.IntVar(&opts.expectedRows, "expected-rows", 0, "required exact candidate count for writes")
	fs.StringVar(&opts.expectedCandidateDigest, "expected-candidate-digest", "", "required dry-run candidate digest for writes")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(opts.backupTable) == "" {
		return options{}, errors.New("--backup-table is required")
	}
	quoted, err := quoteQualifiedIdentifier(opts.backupTable)
	if err != nil {
		return options{}, fmt.Errorf("invalid --backup-table: %w", err)
	}
	opts.backupTableSQL = quoted
	if strings.EqualFold(strings.TrimSpace(opts.backupTable), targetTable) {
		return options{}, errors.New("backup table cannot be the target table")
	}
	if rollback {
		opts.operation = operationRollback
	} else {
		opts.operation = operationCleanup
	}
	if opts.batchSize < 1 || opts.batchSize > maxBatchSize {
		return options{}, fmt.Errorf("--batch-size must be between 1 and %d", maxBatchSize)
	}
	if opts.statementTimeout < 100*time.Millisecond || opts.statementTimeout > 60*time.Second {
		return options{}, errors.New("--statement-timeout must be between 100ms and 60s")
	}
	if opts.lockTimeout < 100*time.Millisecond || opts.lockTimeout > 30*time.Second {
		return options{}, errors.New("--lock-timeout must be between 100ms and 30s")
	}
	if opts.execute {
		if opts.expectedRows < 1 {
			return options{}, errors.New("writes require --expected-rows from a successful dry-run")
		}
		opts.expectedCandidateDigest = strings.ToLower(strings.TrimSpace(opts.expectedCandidateDigest))
		if len(opts.expectedCandidateDigest) != 64 {
			return options{}, errors.New("writes require a 64-character --expected-candidate-digest from a successful dry-run")
		}
		if _, err := hex.DecodeString(opts.expectedCandidateDigest); err != nil {
			return options{}, errors.New("--expected-candidate-digest must be hexadecimal")
		}
	}
	return opts, nil
}

func quoteQualifiedIdentifier(value string) (string, error) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) == 1 {
		parts = []string{"public", parts[0]}
	}
	if len(parts) != 2 {
		return "", errors.New("expected table or schema.table")
	}
	for _, part := range parts {
		if !identifierPart.MatchString(part) {
			return "", errors.New("identifier contains unsupported characters")
		}
	}
	return pq.QuoteIdentifier(parts[0]) + "." + pq.QuoteIdentifier(parts[1]), nil
}

func run(ctx context.Context, opts options) (report, error) {
	mode := opts.operation.String() + "-dry-run"
	if opts.execute {
		mode = opts.operation.String() + "-execute"
	}
	result := report{
		ToolVersion: toolVersion,
		Mode:        mode,
		BackupTable: opts.backupTable,
		TargetTable: targetTable,
	}

	dsn, err := databaseDSNFromEnv()
	if err != nil {
		return result, err
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return result, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("reserve database connection: %w", err)
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		return result, fmt.Errorf("database ping: %w", err)
	}

	if opts.execute {
		locked, err := tryAdvisoryLock(ctx, conn)
		if err != nil {
			return result, err
		}
		if !locked {
			return result, errors.New("another rb15 enrichment cleanup process holds the advisory lock")
		}
		defer releaseAdvisoryLock(context.Background(), conn)
	}

	snapshot, err := loadCandidateSnapshot(ctx, conn, opts)
	if err != nil {
		return result, err
	}
	result.CandidateSnapshot = snapshot
	if snapshot.Count == 0 {
		return result, errors.New("backup table contains no candidate rows")
	}
	if opts.execute {
		if snapshot.Count != opts.expectedRows {
			return result, fmt.Errorf("candidate count changed: got %d, expected %d", snapshot.Count, opts.expectedRows)
		}
		if snapshot.Digest != opts.expectedCandidateDigest {
			return result, errors.New("candidate digest changed since dry-run")
		}
	}

	preflight, err := scanPhase(ctx, conn, opts)
	result.Preflight = &preflight
	if err != nil {
		return result, err
	}
	if preflight.Total != snapshot.Count {
		return result, fmt.Errorf("preflight candidate count mismatch: scanned %d, snapshot %d", preflight.Total, snapshot.Count)
	}
	preflightErr := validateWritablePreflight(preflight, opts.operation)
	result.WriteReady = preflightErr == nil
	if !opts.execute {
		result.Completed = preflightErr == nil
		return result, preflightErr
	}
	if preflightErr != nil {
		return result, preflightErr
	}

	mutated, err := mutate(ctx, conn, opts)
	result.Mutated = mutated
	if err != nil {
		return result, err
	}

	postSnapshot, err := loadCandidateSnapshot(ctx, conn, opts)
	if err != nil {
		return result, err
	}
	if postSnapshot != snapshot {
		return result, errors.New("backup candidate set changed during execution")
	}
	postflight, err := scanPhase(ctx, conn, opts)
	result.Postflight = &postflight
	if err != nil {
		return result, err
	}
	if postflight.Total != snapshot.Count {
		return result, fmt.Errorf("postflight candidate count mismatch: scanned %d, snapshot %d", postflight.Total, snapshot.Count)
	}
	if err := validatePostflight(postflight, opts.operation); err != nil {
		return result, err
	}
	if preflight.CleanSuffixDigest != postflight.CleanSuffixDigest {
		return result, errors.New("clean suffix digest changed during execution")
	}
	result.Completed = true
	return result, nil
}

func databaseDSNFromEnv() (string, error) {
	if raw := strings.TrimSpace(os.Getenv("RB15_DATABASE_URL")); raw != "" {
		return raw, nil
	}
	host := strings.TrimSpace(os.Getenv("DATABASE_HOST"))
	user := strings.TrimSpace(os.Getenv("DATABASE_USER"))
	password := os.Getenv("DATABASE_PASSWORD")
	database := strings.TrimSpace(os.Getenv("DATABASE_NAME"))
	if host == "" || user == "" || password == "" || database == "" {
		return "", errors.New("set RB15_DATABASE_URL or DATABASE_HOST/DATABASE_USER/DATABASE_PASSWORD/DATABASE_NAME")
	}
	port := strings.TrimSpace(os.Getenv("DATABASE_PORT"))
	if port == "" {
		port = "5432"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("DATABASE_PORT is invalid")
	}
	sslMode := strings.TrimSpace(os.Getenv("DATABASE_SSLMODE"))
	if sslMode == "" {
		sslMode = "disable"
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + database,
	}
	query := u.Query()
	query.Set("sslmode", sslMode)
	query.Set("application_name", "codex2api-rb15-enrich-cleanup")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func tryAdvisoryLock(ctx context.Context, conn *sql.Conn) (bool, error) {
	var locked bool
	if err := conn.QueryRowContext(ctx, `select pg_try_advisory_lock($1)`, advisoryLockKey).Scan(&locked); err != nil {
		return false, fmt.Errorf("acquire advisory lock: %w", err)
	}
	return locked, nil
}

func releaseAdvisoryLock(ctx context.Context, conn *sql.Conn) {
	var released bool
	_ = conn.QueryRowContext(ctx, `select pg_advisory_unlock($1)`, advisoryLockKey).Scan(&released)
}

func loadCandidateSnapshot(ctx context.Context, conn *sql.Conn, opts options) (candidateSnapshot, error) {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return candidateSnapshot{}, fmt.Errorf("begin candidate snapshot: %w", err)
	}
	defer tx.Rollback()
	if err := setLocalTimeouts(ctx, tx, opts); err != nil {
		return candidateSnapshot{}, err
	}
	query := fmt.Sprintf(`select id, original_full_md5, original_preview_md5, marker_pair from %s order by id`, opts.backupTableSQL)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return candidateSnapshot{}, fmt.Errorf("read candidate snapshot: %w", err)
	}
	defer rows.Close()
	var candidates []candidateMeta
	for rows.Next() {
		var item candidateMeta
		if err := rows.Scan(&item.id, &item.fullMD5, &item.previewMD5, &item.markerPair); err != nil {
			return candidateSnapshot{}, fmt.Errorf("scan candidate snapshot: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		return candidateSnapshot{}, fmt.Errorf("iterate candidate snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return candidateSnapshot{}, fmt.Errorf("commit candidate snapshot: %w", err)
	}
	for i := 1; i < len(candidates); i++ {
		if candidates[i-1].id == candidates[i].id {
			return candidateSnapshot{}, fmt.Errorf("backup table contains duplicate id %d", candidates[i].id)
		}
	}
	h := sha256.New()
	for _, item := range candidates {
		writeDigestInt64(h, item.id)
		writeDigestNullable(h, item.fullMD5)
		writeDigestNullable(h, item.previewMD5)
		if item.markerPair {
			_, _ = io.WriteString(h, "1\n")
		} else {
			_, _ = io.WriteString(h, "0\n")
		}
	}
	return candidateSnapshot{Count: len(candidates), Digest: hex.EncodeToString(h.Sum(nil))}, nil
}

func scanPhase(ctx context.Context, conn *sql.Conn, opts options) (phaseReport, error) {
	report := phaseReport{Counts: make(map[string]int)}
	h := sha256.New()
	lastID := minimumCandidateID
	for {
		batch, err := loadBatch(ctx, conn, opts, lastID, true)
		if err != nil {
			return report, err
		}
		if len(batch) == 0 {
			break
		}
		for _, item := range batch {
			decision := decideRecord(toRecordInput(item), opts.operation)
			report.Total++
			report.Counts[decision.category]++
			if decision.cleanFullMD5 != "" && decision.cleanPreviewMD5 != "" {
				writeDigestInt64(h, item.id)
				_, _ = io.WriteString(h, decision.cleanFullMD5)
				_, _ = io.WriteString(h, "\x00")
				_, _ = io.WriteString(h, decision.cleanPreviewMD5)
				_, _ = io.WriteString(h, "\n")
			}
			lastID = item.id
		}
	}
	report.CleanSuffixDigest = hex.EncodeToString(h.Sum(nil))
	return report, nil
}

func loadBatch(ctx context.Context, conn *sql.Conn, opts options, lastID int64, readOnly bool) ([]backupLiveRow, error) {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return nil, fmt.Errorf("begin batch read: %w", err)
	}
	defer tx.Rollback()
	if err := setLocalTimeouts(ctx, tx, opts); err != nil {
		return nil, err
	}
	items, err := queryBatch(ctx, tx, opts, lastID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit batch read: %w", err)
	}
	return items, nil
}

func queryBatch(ctx context.Context, tx *sql.Tx, opts options, lastID int64) ([]backupLiveRow, error) {
	query := fmt.Sprintf(`
select b.id, coalesce(b.source, ''), b.marker_pair,
       b.original_full_text, b.original_text_preview,
       b.original_full_md5, b.original_preview_md5,
       p.id, p.full_text, p.text_preview
from %s b
left join public.prompt_filter_logs p on p.id = b.id
where b.id > $1
order by b.id
limit $2`, opts.backupTableSQL)
	rows, err := tx.QueryContext(ctx, query, lastID, opts.batchSize)
	if err != nil {
		return nil, fmt.Errorf("read candidate batch: %w", err)
	}
	defer rows.Close()
	items := make([]backupLiveRow, 0, opts.batchSize)
	for rows.Next() {
		var item backupLiveRow
		if err := rows.Scan(
			&item.id, &item.source, &item.markerPair,
			&item.originalFullText, &item.originalTextPreview,
			&item.originalFullMD5, &item.originalPreviewMD5,
			&item.liveID, &item.liveFullText, &item.liveTextPreview,
		); err != nil {
			return nil, fmt.Errorf("scan candidate batch: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate candidate batch: %w", err)
	}
	return items, nil
}

func toRecordInput(item backupLiveRow) recordInput {
	return recordInput{
		source:               item.source,
		markerPair:           item.markerPair,
		originalFullValid:    item.originalFullText.Valid,
		originalFullText:     item.originalFullText.String,
		originalPreviewValid: item.originalTextPreview.Valid,
		originalTextPreview:  item.originalTextPreview.String,
		originalFullMD5:      item.originalFullMD5.String,
		originalPreviewMD5:   item.originalPreviewMD5.String,
		liveExists:           item.liveID.Valid,
		liveFullText:         item.liveFullText.String,
		liveTextPreview:      item.liveTextPreview.String,
	}
}

func validateWritablePreflight(report phaseReport, op operation) error {
	allowed := map[string]bool{}
	if op == operationCleanup {
		allowed["pending_cleanup"] = true
		allowed["already_clean"] = true
	} else {
		allowed["pending_rollback"] = true
		allowed["already_restored"] = true
	}
	for category, count := range report.Counts {
		if count > 0 && !allowed[category] {
			return fmt.Errorf("preflight rejected %d rows in category %s", count, category)
		}
	}
	return nil
}

func validatePostflight(report phaseReport, op operation) error {
	expected := "already_clean"
	if op == operationRollback {
		expected = "already_restored"
	}
	if report.Counts[expected] != report.Total {
		return fmt.Errorf("postflight expected all %d rows in category %s", report.Total, expected)
	}
	return nil
}

func mutate(ctx context.Context, conn *sql.Conn, opts options) (int, error) {
	lastID := minimumCandidateID
	mutated := 0
	for {
		tx, err := conn.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			return mutated, fmt.Errorf("begin mutation batch: %w", err)
		}
		if err := setLocalTimeouts(ctx, tx, opts); err != nil {
			tx.Rollback()
			return mutated, err
		}
		batch, err := queryBatch(ctx, tx, opts, lastID)
		if err != nil {
			tx.Rollback()
			return mutated, err
		}
		if len(batch) == 0 {
			tx.Rollback()
			break
		}

		decisions := make([]recordDecision, len(batch))
		for i, item := range batch {
			decisions[i] = decideRecord(toRecordInput(item), opts.operation)
			if !isWritableCategory(decisions[i].category, opts.operation) {
				tx.Rollback()
				return mutated, fmt.Errorf("mutation batch rejected id %d in category %s", item.id, decisions[i].category)
			}
		}

		batchMutated := 0
		for i, item := range batch {
			decision := decisions[i]
			if isAlreadyCategory(decision.category, opts.operation) {
				continue
			}
			fromFullMD5, fromPreviewMD5 := decision.originalFullMD5, decision.originalPreviewMD5
			toFull, toPreview := decision.cleanFullText, decision.cleanTextPreview
			expectedToFullMD5, expectedToPreviewMD5 := decision.cleanFullMD5, decision.cleanPreviewMD5
			if opts.operation == operationRollback {
				fromFullMD5, fromPreviewMD5 = decision.cleanFullMD5, decision.cleanPreviewMD5
				toFull, toPreview = item.originalFullText.String, item.originalTextPreview.String
				expectedToFullMD5, expectedToPreviewMD5 = decision.originalFullMD5, decision.originalPreviewMD5
			}
			var returnedFullMD5, returnedPreviewMD5 string
			err := tx.QueryRowContext(ctx, `
update public.prompt_filter_logs
set full_text = $1, text_preview = $2
where id = $3
  and md5(coalesce(full_text, '')) = $4
  and md5(coalesce(text_preview, '')) = $5
returning md5(coalesce(full_text, '')), md5(coalesce(text_preview, ''))`,
				toFull, toPreview, item.id, fromFullMD5, fromPreviewMD5,
			).Scan(&returnedFullMD5, &returnedPreviewMD5)
			if errors.Is(err, sql.ErrNoRows) {
				tx.Rollback()
				return mutated, fmt.Errorf("conditional update conflict for id %d", item.id)
			}
			if err != nil {
				tx.Rollback()
				return mutated, fmt.Errorf("update id %d: %w", item.id, err)
			}
			if returnedFullMD5 != expectedToFullMD5 || returnedPreviewMD5 != expectedToPreviewMD5 {
				tx.Rollback()
				return mutated, fmt.Errorf("suffix hash assertion failed for id %d", item.id)
			}
			batchMutated++
		}
		if err := tx.Commit(); err != nil {
			return mutated, fmt.Errorf("commit mutation batch: %w", err)
		}
		mutated += batchMutated
		lastID = batch[len(batch)-1].id
	}
	return mutated, nil
}

func isWritableCategory(category string, op operation) bool {
	if op == operationCleanup {
		return category == "pending_cleanup" || category == "already_clean"
	}
	return category == "pending_rollback" || category == "already_restored"
}

func isAlreadyCategory(category string, op operation) bool {
	if op == operationCleanup {
		return category == "already_clean"
	}
	return category == "already_restored"
}

func setLocalTimeouts(ctx context.Context, tx *sql.Tx, opts options) error {
	if _, err := tx.ExecContext(ctx, `select set_config('statement_timeout', $1, true)`, postgresDuration(opts.statementTimeout)); err != nil {
		return fmt.Errorf("set statement timeout: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `select set_config('lock_timeout', $1, true)`, postgresDuration(opts.lockTimeout)); err != nil {
		return fmt.Errorf("set lock timeout: %w", err)
	}
	return nil
}

func postgresDuration(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func writeDigestInt64(w io.Writer, value int64) {
	_, _ = io.WriteString(w, strconv.FormatInt(value, 10))
	_, _ = io.WriteString(w, "\x00")
}

func writeDigestNullable(w io.Writer, value sql.NullString) {
	if !value.Valid {
		_, _ = io.WriteString(w, "0:\x00")
		return
	}
	_, _ = io.WriteString(w, "1:")
	_, _ = io.WriteString(w, value.String)
	_, _ = io.WriteString(w, "\x00")
}
