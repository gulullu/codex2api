package main

import (
	"strings"
	"testing"
)

func legacyBlock(source, suffix string, withNewAPI bool) (string, string) {
	typ := legacyLocalType
	if source == "upstream_cyber_policy" {
		typ = legacyMissType
	}
	newAPILine := ""
	previewTag := "alice"
	if withNewAPI {
		newAPILine = "new-api 用户: bob (id=7 bob@example.test) 【多候选,存疑】\n"
		previewTag += "→na:bob"
	}
	full := "【归属】\n" +
		"sub2 用户: alice alice@example.test\n" +
		newAPILine +
		"池子账号: pool@example.test\n" +
		"类型: " + typ + "\n\n" + suffix
	preview := "『sub2:" + previewTag + "』 " + suffix
	return full, preview
}

func TestStripLegacyEnrichment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		source     string
		withNewAPI bool
	}{
		{name: "local", source: "local_filter"},
		{name: "upstream miss", source: "upstream_cyber_policy"},
		{name: "new api line", source: "semantic_review_disagreement", withNewAPI: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full, preview := legacyBlock(tc.source, "original prompt", tc.withNewAPI)
			got, err := stripLegacyEnrichment(tc.source, full, preview)
			if err != nil {
				t.Fatalf("stripLegacyEnrichment() error = %v", err)
			}
			if got.cleanFullText != "original prompt" || got.cleanTextPreview != "original prompt" {
				t.Fatalf("clean suffix mismatch")
			}
			if got.cleanFullMD5 != md5String("original prompt") || got.cleanPreviewMD5 != md5String("original prompt") {
				t.Fatalf("clean hashes mismatch")
			}
		})
	}
}

func TestStripLegacyEnrichmentRejectsNonExactMarkers(t *testing.T) {
	validFull, validPreview := legacyBlock("local_filter", "payload", false)
	tests := []struct {
		name    string
		full    string
		preview string
		source  string
	}{
		{name: "marker in middle", full: "prefix" + validFull, preview: validPreview, source: "local_filter"},
		{name: "preview in middle", full: validFull, preview: "prefix" + validPreview, source: "local_filter"},
		{name: "source type mismatch", full: validFull, preview: validPreview, source: "upstream_cyber_policy"},
		{name: "unknown line", full: strings.Replace(validFull, "池子账号: ", "账号: ", 1), preview: validPreview, source: "local_filter"},
		{name: "missing separator", full: strings.Replace(validFull, "\n\npayload", "\npayload", 1), preview: validPreview, source: "local_filter"},
		{name: "oversized block", full: "【归属】\nsub2 用户: " + strings.Repeat("x", maxLegacyFullPrefix) + "\n池子账号: x\n类型: " + legacyLocalType + "\n\npayload", preview: validPreview, source: "local_filter"},
		{name: "oversized tag", full: validFull, preview: "『sub2:" + strings.Repeat("x", maxLegacyPreviewPrefix) + "』 payload", source: "local_filter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := stripLegacyEnrichment(tc.source, tc.full, tc.preview); err == nil {
				t.Fatalf("stripLegacyEnrichment() unexpectedly succeeded")
			}
		})
	}
}

func TestDecideRecordCleanupAndRollback(t *testing.T) {
	full, preview := legacyBlock("upstream_cyber_policy", "payload", false)
	base := recordInput{
		source:               "upstream_cyber_policy",
		markerPair:           true,
		originalFullValid:    true,
		originalFullText:     full,
		originalPreviewValid: true,
		originalTextPreview:  preview,
		originalFullMD5:      md5String(full),
		originalPreviewMD5:   md5String(preview),
		liveExists:           true,
		liveFullText:         full,
		liveTextPreview:      preview,
	}
	if got := decideRecord(base, operationCleanup); got.category != "pending_cleanup" {
		t.Fatalf("cleanup category = %q", got.category)
	}
	if got := decideRecord(base, operationRollback); got.category != "already_restored" {
		t.Fatalf("rollback category = %q", got.category)
	}

	base.liveFullText = "payload"
	base.liveTextPreview = "payload"
	if got := decideRecord(base, operationCleanup); got.category != "already_clean" {
		t.Fatalf("idempotent cleanup category = %q", got.category)
	}
	if got := decideRecord(base, operationRollback); got.category != "pending_rollback" {
		t.Fatalf("rollback category = %q", got.category)
	}

	base.liveFullText = "changed after backup"
	if got := decideRecord(base, operationCleanup); got.category != "live_content_drift" {
		t.Fatalf("drift category = %q", got.category)
	}
}

func TestDecideRecordRejectsUnsafeBackup(t *testing.T) {
	full, preview := legacyBlock("local_filter", "payload", false)
	base := recordInput{
		markerPair:           true,
		originalFullValid:    true,
		originalFullText:     full,
		originalPreviewValid: true,
		originalTextPreview:  preview,
		originalFullMD5:      md5String(full),
		originalPreviewMD5:   md5String(preview),
		liveExists:           true,
		liveFullText:         full,
		liveTextPreview:      preview,
	}

	cases := []struct {
		name string
		edit func(*recordInput)
		want string
	}{
		{name: "marker pair false", edit: func(v *recordInput) { v.markerPair = false }, want: "backup_marker_pair_false"},
		{name: "null backup", edit: func(v *recordInput) { v.originalFullValid = false }, want: "backup_content_null"},
		{name: "hash mismatch", edit: func(v *recordInput) { v.originalFullMD5 = strings.Repeat("0", 32) }, want: "backup_hash_mismatch"},
		{name: "missing target", edit: func(v *recordInput) { v.liveExists = false }, want: "target_missing"},
		{name: "invalid marker", edit: func(v *recordInput) {
			v.originalFullText = "not a marker"
			v.originalFullMD5 = md5String(v.originalFullText)
		}, want: "marker_signature_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := base
			tc.edit(&input)
			if got := decideRecord(input, operationCleanup); got.category != tc.want {
				t.Fatalf("category = %q, want %q", got.category, tc.want)
			}
		})
	}
}

func TestParseOptionsDefaultsToDryRun(t *testing.T) {
	opts, err := parseOptions([]string{"--backup-table", "public.ops_rb15_enrich_backup_20260715_031815"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if opts.execute || opts.operation != operationCleanup {
		t.Fatalf("unexpected defaults: execute=%v operation=%v", opts.execute, opts.operation)
	}
}

func TestParseOptionsWriteGuards(t *testing.T) {
	base := []string{"--backup-table", "ops_backup", "--execute"}
	if _, err := parseOptions(base); err == nil {
		t.Fatalf("execute without frozen snapshot unexpectedly succeeded")
	}
	args := append(append([]string{}, base...), "--expected-rows", "2", "--expected-candidate-digest", strings.Repeat("a", 64))
	opts, err := parseOptions(args)
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if !opts.execute || opts.operation != operationCleanup {
		t.Fatalf("unexpected execute options")
	}

	rollback := append(args, "--rollback")
	opts, err = parseOptions(rollback)
	if err != nil {
		t.Fatalf("rollback parseOptions() error = %v", err)
	}
	if opts.operation != operationRollback {
		t.Fatalf("rollback operation = %v", opts.operation)
	}
}

func TestQuoteQualifiedIdentifier(t *testing.T) {
	if got, err := quoteQualifiedIdentifier("ops_backup"); err != nil || got != `"public"."ops_backup"` {
		t.Fatalf("quoteQualifiedIdentifier() = %q, %v", got, err)
	}
	for _, value := range []string{"public.a.b", "public.bad-name", "public.prompt_filter_logs;drop table x"} {
		if _, err := quoteQualifiedIdentifier(value); err == nil {
			t.Fatalf("unsafe identifier %q unexpectedly accepted", value)
		}
	}
}

func TestValidateWritablePreflight(t *testing.T) {
	if err := validateWritablePreflight(phaseReport{
		Total:  2,
		Counts: map[string]int{"pending_cleanup": 1, "already_clean": 1},
	}, operationCleanup); err != nil {
		t.Fatalf("safe cleanup preflight rejected: %v", err)
	}
	if err := validateWritablePreflight(phaseReport{
		Total:  2,
		Counts: map[string]int{"pending_cleanup": 1, "live_content_drift": 1},
	}, operationCleanup); err == nil {
		t.Fatalf("unsafe cleanup preflight accepted")
	}
}
