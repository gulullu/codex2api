package database

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresUsageLogOnlineMigrationSQLSafety(t *testing.T) {
	schemaSQL := strings.ToLower(postgresUsageLogOnlineSchemaSQL)
	if strings.Contains(schemaSQL, "update usage_logs") {
		t.Fatal("PostgreSQL 在线增列 SQL 不得 UPDATE usage_logs")
	}
	if !strings.Contains(schemaSQL, "default 'codex'") {
		t.Fatal("channel 必须使用 codex 常量默认值，以启用 PostgreSQL fast default")
	}
	if strings.Contains(schemaSQL, "create index") {
		t.Fatal("大表索引不得混入启动增列事务")
	}

	indexSQL := strings.ToLower(postgresUsageLogChannelIndexConcurrentSQL)
	if !strings.Contains(indexSQL, "create index concurrently") {
		t.Fatal("channel+created_at 索引必须使用 CREATE INDEX CONCURRENTLY")
	}
	if !strings.Contains(indexSQL, "if not exists") {
		t.Fatal("在线索引 SQL 必须幂等")
	}
}

// TestPostgresUsageLogOnlineMigrationIntegration 只在显式提供一个可丢弃的
// PostgreSQL 测试库时运行。它会清空 public schema，禁止指向共享或生产库。
func TestPostgresUsageLogOnlineMigrationIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CODEX2API_TEST_POSTGRES_MIGRATION_DSN"))
	if dsn == "" {
		t.Skip("CODEX2API_TEST_POSTGRES_MIGRATION_DSN 未设置")
	}

	ctx := context.Background()
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open(postgres): %v", err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("重置可丢弃测试库: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `
		CREATE TABLE usage_logs (
			id SERIAL PRIMARY KEY,
			account_id INT DEFAULT 0,
			endpoint VARCHAR(100) DEFAULT '',
			model VARCHAR(100) DEFAULT '',
			prompt_tokens INT DEFAULT 0,
			completion_tokens INT DEFAULT 0,
			total_tokens INT DEFAULT 0,
			status_code INT DEFAULT 0,
			duration_ms INT DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		INSERT INTO usage_logs (account_id, status_code)
		SELECT 0, 200 FROM generate_series(1, 5000)
	`); err != nil {
		t.Fatalf("准备旧版 usage_logs: %v", err)
	}

	var beforeRelNode int64
	var beforeCTID string
	if err := raw.QueryRowContext(ctx, `SELECT pg_relation_filenode('usage_logs'::regclass)`).Scan(&beforeRelNode); err != nil {
		t.Fatalf("读取迁移前 relfilenode: %v", err)
	}
	if err := raw.QueryRowContext(ctx, `SELECT ctid::text FROM usage_logs WHERE id = 1`).Scan(&beforeCTID); err != nil {
		t.Fatalf("读取迁移前 ctid: %v", err)
	}

	db, err := New("postgres", dsn)
	if err != nil {
		t.Fatalf("New(postgres) 执行在线迁移: %v", err)
	}
	defer db.Close()

	settings := &SystemSettings{
		MaxConcurrency:               2,
		TestConcurrency:              1,
		TestModel:                    "gpt-5.4",
		CodexWSIdleReclaimEnabled:    true,
		CodexWSIdleReclaimPercent:    5,
		CodexWSIdleReclaimIdleSec:    600,
		CodexContinueMaxRounds:       8,
		CodexWSSilentMaxRetries:      2,
		CodexWSBusyPatienceSec:       2,
		CodexWSBusyAcquireMaxWaitSec: 30,
	}
	if err := db.UpdateSystemSettings(ctx, settings); err != nil {
		t.Fatalf("PostgreSQL UpdateSystemSettings placeholder/column roundtrip: %v", err)
	}
	storedSettings, err := db.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("PostgreSQL GetSystemSettings scan roundtrip: %v", err)
	}
	if !storedSettings.CodexWSIdleReclaimEnabled || storedSettings.CodexWSIdleReclaimPercent != 5 || storedSettings.CodexWSIdleReclaimIdleSec != 600 {
		t.Fatalf("PostgreSQL idle reclaim roundtrip = enabled:%v percent:%d idle:%d, want true/5/600", storedSettings.CodexWSIdleReclaimEnabled, storedSettings.CodexWSIdleReclaimPercent, storedSettings.CodexWSIdleReclaimIdleSec)
	}

	var afterRelNode int64
	var afterCTID string
	if err := raw.QueryRowContext(ctx, `SELECT pg_relation_filenode('usage_logs'::regclass)`).Scan(&afterRelNode); err != nil {
		t.Fatalf("读取迁移后 relfilenode: %v", err)
	}
	if err := raw.QueryRowContext(ctx, `SELECT ctid::text FROM usage_logs WHERE id = 1`).Scan(&afterCTID); err != nil {
		t.Fatalf("读取迁移后 ctid: %v", err)
	}
	if afterRelNode != beforeRelNode || afterCTID != beforeCTID {
		t.Fatalf("usage_logs 发生了堆表重写/全表更新: relfilenode %d->%d, ctid %s->%s", beforeRelNode, afterRelNode, beforeCTID, afterCTID)
	}

	for _, column := range []struct {
		name        string
		wantCount   int
		wantValue   string
		wantMissing string
	}{
		{name: "channel", wantCount: 5000, wantValue: "codex", wantMissing: "{codex}"},
		{name: "ws_acquire_ms", wantCount: 5000, wantValue: "0", wantMissing: "{0}"},
	} {
		var hasMissing bool
		var missingValue string
		if err := raw.QueryRowContext(ctx, `
			SELECT atthasmissing, attmissingval::text
			FROM pg_attribute
			WHERE attrelid = 'usage_logs'::regclass AND attname = $1
		`, column.name).Scan(&hasMissing, &missingValue); err != nil {
			t.Fatalf("读取 %s fast default 元数据: %v", column.name, err)
		}
		if !hasMissing || missingValue != column.wantMissing {
			t.Fatalf("%s fast default = (%v,%q), want (true,%q)", column.name, hasMissing, missingValue, column.wantMissing)
		}

		var count int
		query := `SELECT COUNT(*) FROM usage_logs WHERE ` + column.name + `::text = $1`
		if err := raw.QueryRowContext(ctx, query, column.wantValue).Scan(&count); err != nil {
			t.Fatalf("验证 %s 存量值: %v", column.name, err)
		}
		if count != column.wantCount {
			t.Fatalf("%s 存量默认值行数 = %d, want %d", column.name, count, column.wantCount)
		}
	}

	var migrationMarkers int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM data_migrations WHERE version = $1`, dataMigrationUsageLogChannelV1).Scan(&migrationMarkers); err != nil {
		t.Fatalf("读取 channel migration 标记: %v", err)
	}
	if migrationMarkers != 1 {
		t.Fatalf("channel migration 标记数 = %d, want 1", migrationMarkers)
	}

	// 启动迁移不得在大表上普通建索引；索引由部署前 CONCURRENTLY 步骤预建。
	var channelIndex interface{}
	if err := raw.QueryRowContext(ctx, `SELECT to_regclass('idx_usage_logs_channel_created_at')`).Scan(&channelIndex); err != nil {
		t.Fatalf("检查 channel 索引: %v", err)
	}
	if channelIndex != nil {
		t.Fatalf("启动迁移意外创建了 channel 索引: %v", channelIndex)
	}
	if _, err := raw.ExecContext(ctx, postgresUsageLogChannelIndexConcurrentSQL); err != nil {
		t.Fatalf("独立在线创建 channel 索引: %v", err)
	}
	// 幂等重跑必须直接成功。
	if _, err := raw.ExecContext(ctx, postgresUsageLogChannelIndexConcurrentSQL); err != nil {
		t.Fatalf("幂等重跑 channel 索引 SQL: %v", err)
	}
	var indexReady, indexValid bool
	if err := raw.QueryRowContext(ctx, `
		SELECT i.indisready, i.indisvalid
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.oid = 'idx_usage_logs_channel_created_at'::regclass
	`).Scan(&indexReady, &indexValid); err != nil {
		t.Fatalf("验证 channel 索引: %v", err)
	}
	if !indexReady || !indexValid {
		t.Fatalf("channel 索引 ready/valid = %v/%v, want true/true", indexReady, indexValid)
	}

	// 模拟回滚到 rb28：旧写入语句不携新列仍得到 codex/0 默认值。
	var oldWriterChannel string
	var oldWriterWSAcquire int
	if err := raw.QueryRowContext(ctx, `
		INSERT INTO usage_logs (account_id, status_code) VALUES (0, 200)
		RETURNING channel, ws_acquire_ms
	`).Scan(&oldWriterChannel, &oldWriterWSAcquire); err != nil {
		t.Fatalf("模拟旧版写入: %v", err)
	}
	if oldWriterChannel != UpstreamChannelCodex || oldWriterWSAcquire != 0 {
		t.Fatalf("旧版写入默认值 = (%q,%d), want (codex,0)", oldWriterChannel, oldWriterWSAcquire)
	}

	// 持有一个业务写事务时，增列不得排队等到业务释放锁。
	blockingTx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开始模拟业务写事务: %v", err)
	}
	if _, err := blockingTx.ExecContext(ctx, `INSERT INTO usage_logs (account_id, status_code) VALUES (0, 200)`); err != nil {
		blockingTx.Rollback()
		t.Fatalf("持有 usage_logs 写锁: %v", err)
	}
	lockTestCtx, cancel := context.WithTimeout(ctx, 6*postgresUsageLogSchemaLockTimeout)
	defer cancel()
	started := time.Now()
	lockErr := db.migratePostgresUsageLogOnlineSchema(lockTestCtx)
	elapsed := time.Since(started)
	if err := blockingTx.Rollback(); err != nil {
		t.Fatalf("释放模拟业务写事务: %v", err)
	}
	if lockErr == nil {
		t.Fatal("业务写锁存在时在线增列意外成功")
	}
	maxExpected := time.Duration(postgresUsageLogSchemaMaxAttempts+2) * postgresUsageLogSchemaLockTimeout
	if elapsed >= maxExpected {
		t.Fatalf("在线增列等锁过久: %s, want < %s; err=%v", elapsed, maxExpected, lockErr)
	}
	if err := db.migratePostgresUsageLogOnlineSchema(ctx); err != nil {
		t.Fatalf("锁释放后重试在线增列: %v", err)
	}
}
