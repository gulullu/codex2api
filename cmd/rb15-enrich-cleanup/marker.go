package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	legacyFullHeader        = "【归属】\n"
	legacyPreviewHeader     = "『sub2:"
	legacyPreviewTerminator = "』 "
	maxLegacyFullPrefix     = 4096
	maxLegacyPreviewPrefix  = 2048

	legacyMissType  = "真漏放(上游拦→账号风险)"
	legacyLocalType = "本地拦(我们拦下,返回官方文案)"
)

type stripResult struct {
	cleanFullText    string
	cleanTextPreview string
	cleanFullMD5     string
	cleanPreviewMD5  string
}

// stripLegacyEnrichment removes only the exact prefix emitted by the legacy
// scripts/enrich_misses.py job. It never searches for a marker in the middle
// of prompt text.
func stripLegacyEnrichment(source, fullText, textPreview string) (stripResult, error) {
	if !utf8.ValidString(fullText) || !utf8.ValidString(textPreview) {
		return stripResult{}, errors.New("invalid_utf8")
	}
	if !strings.HasPrefix(fullText, legacyFullHeader) {
		return stripResult{}, errors.New("full_marker_not_at_start")
	}

	searchEnd := len(fullText)
	if searchEnd > maxLegacyFullPrefix {
		searchEnd = maxLegacyFullPrefix
	}
	separatorOffset := strings.Index(fullText[len(legacyFullHeader):searchEnd], "\n\n")
	if separatorOffset < 0 {
		return stripResult{}, errors.New("full_marker_terminator_missing_or_out_of_bounds")
	}
	separator := len(legacyFullHeader) + separatorOffset
	blockLines := strings.Split(fullText[len(legacyFullHeader):separator], "\n")
	if len(blockLines) != 3 && len(blockLines) != 4 {
		return stripResult{}, errors.New("full_marker_line_count_invalid")
	}
	if !validLegacyLine(blockLines[0], "sub2 用户: ", true) {
		return stripResult{}, errors.New("sub2_line_invalid")
	}

	poolIndex := 1
	if len(blockLines) == 4 {
		if !validLegacyLine(blockLines[1], "new-api 用户: ", true) {
			return stripResult{}, errors.New("new_api_line_invalid")
		}
		poolIndex = 2
	}
	if !validLegacyLine(blockLines[poolIndex], "池子账号: ", false) {
		return stripResult{}, errors.New("pool_line_invalid")
	}

	typePrefix := "类型: "
	typeLine := blockLines[poolIndex+1]
	if !strings.HasPrefix(typeLine, typePrefix) {
		return stripResult{}, errors.New("type_line_invalid")
	}
	legacyType := strings.TrimPrefix(typeLine, typePrefix)
	expectedType := legacyLocalType
	if source == "upstream_cyber_policy" {
		expectedType = legacyMissType
	}
	if legacyType != expectedType {
		return stripResult{}, errors.New("type_source_mismatch")
	}

	fullPrefixEnd := separator + len("\n\n")
	if fullPrefixEnd > maxLegacyFullPrefix {
		return stripResult{}, errors.New("full_marker_out_of_bounds")
	}
	cleanFull := fullText[fullPrefixEnd:]
	if legacyFullHeader+strings.Join(blockLines, "\n")+"\n\n"+cleanFull != fullText {
		return stripResult{}, errors.New("full_suffix_recomposition_failed")
	}

	if !strings.HasPrefix(textPreview, legacyPreviewHeader) {
		return stripResult{}, errors.New("preview_marker_not_at_start")
	}
	previewSearchEnd := len(textPreview)
	if previewSearchEnd > maxLegacyPreviewPrefix {
		previewSearchEnd = maxLegacyPreviewPrefix
	}
	terminatorOffset := strings.Index(textPreview[len(legacyPreviewHeader):previewSearchEnd], legacyPreviewTerminator)
	if terminatorOffset < 0 {
		return stripResult{}, errors.New("preview_marker_terminator_missing_or_out_of_bounds")
	}
	previewTerminator := len(legacyPreviewHeader) + terminatorOffset
	tagValue := textPreview[len(legacyPreviewHeader):previewTerminator]
	if containsLineBreakOrNUL(tagValue) {
		return stripResult{}, errors.New("preview_tag_invalid")
	}
	previewPrefixEnd := previewTerminator + len(legacyPreviewTerminator)
	if previewPrefixEnd > maxLegacyPreviewPrefix {
		return stripResult{}, errors.New("preview_marker_out_of_bounds")
	}
	cleanPreview := textPreview[previewPrefixEnd:]
	if legacyPreviewHeader+tagValue+legacyPreviewTerminator+cleanPreview != textPreview {
		return stripResult{}, errors.New("preview_suffix_recomposition_failed")
	}

	return stripResult{
		cleanFullText:    cleanFull,
		cleanTextPreview: cleanPreview,
		cleanFullMD5:     md5String(cleanFull),
		cleanPreviewMD5:  md5String(cleanPreview),
	}, nil
}

func validLegacyLine(line, prefix string, allowEmpty bool) bool {
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	value := strings.TrimPrefix(line, prefix)
	if !allowEmpty && value == "" {
		return false
	}
	return !containsLineBreakOrNUL(value)
}

func containsLineBreakOrNUL(value string) bool {
	return strings.ContainsAny(value, "\r\n\x00")
}

func md5String(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

type operation int

const (
	operationCleanup operation = iota
	operationRollback
)

func (o operation) String() string {
	switch o {
	case operationCleanup:
		return "cleanup"
	case operationRollback:
		return "rollback"
	default:
		return fmt.Sprintf("operation(%d)", int(o))
	}
}

type recordInput struct {
	source               string
	markerPair           bool
	originalFullValid    bool
	originalFullText     string
	originalPreviewValid bool
	originalTextPreview  string
	originalFullMD5      string
	originalPreviewMD5   string
	liveExists           bool
	liveFullText         string
	liveTextPreview      string
}

type recordDecision struct {
	category           string
	cleanFullText      string
	cleanTextPreview   string
	originalFullMD5    string
	originalPreviewMD5 string
	cleanFullMD5       string
	cleanPreviewMD5    string
}

func decideRecord(input recordInput, op operation) recordDecision {
	if !input.markerPair {
		return recordDecision{category: "backup_marker_pair_false"}
	}
	if !input.originalFullValid || !input.originalPreviewValid {
		return recordDecision{category: "backup_content_null"}
	}
	originalFullMD5 := md5String(input.originalFullText)
	originalPreviewMD5 := md5String(input.originalTextPreview)
	if originalFullMD5 != strings.ToLower(input.originalFullMD5) ||
		originalPreviewMD5 != strings.ToLower(input.originalPreviewMD5) {
		return recordDecision{category: "backup_hash_mismatch"}
	}

	stripped, err := stripLegacyEnrichment(input.source, input.originalFullText, input.originalTextPreview)
	if err != nil {
		return recordDecision{category: "marker_signature_invalid"}
	}
	decision := recordDecision{
		cleanFullText:      stripped.cleanFullText,
		cleanTextPreview:   stripped.cleanTextPreview,
		originalFullMD5:    originalFullMD5,
		originalPreviewMD5: originalPreviewMD5,
		cleanFullMD5:       stripped.cleanFullMD5,
		cleanPreviewMD5:    stripped.cleanPreviewMD5,
	}
	if !input.liveExists {
		decision.category = "target_missing"
		return decision
	}

	liveFullMD5 := md5String(input.liveFullText)
	livePreviewMD5 := md5String(input.liveTextPreview)
	liveIsOriginal := liveFullMD5 == originalFullMD5 && livePreviewMD5 == originalPreviewMD5
	liveIsClean := liveFullMD5 == stripped.cleanFullMD5 && livePreviewMD5 == stripped.cleanPreviewMD5

	switch op {
	case operationCleanup:
		switch {
		case liveIsOriginal:
			decision.category = "pending_cleanup"
		case liveIsClean:
			decision.category = "already_clean"
		default:
			decision.category = "live_content_drift"
		}
	case operationRollback:
		switch {
		case liveIsClean:
			decision.category = "pending_rollback"
		case liveIsOriginal:
			decision.category = "already_restored"
		default:
			decision.category = "live_content_drift"
		}
	default:
		decision.category = "invalid_operation"
	}
	return decision
}
