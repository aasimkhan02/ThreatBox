package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseStringListAcceptsStringAndArray(t *testing.T) {
	gotString := parseStringList(json.RawMessage(`"single finding"`))
	if len(gotString) != 1 || gotString[0] != "single finding" {
		t.Fatalf("string response parsed incorrectly: %#v", gotString)
	}

	gotArray := parseStringList(json.RawMessage(` ["one", "two"] `))
	if len(gotArray) != 2 || gotArray[0] != "one" || gotArray[1] != "two" {
		t.Fatalf("array response parsed incorrectly: %#v", gotArray)
	}
}

func TestDeduplicateReportStringsRemovesRephrasedSameFinding(t *testing.T) {
	items := []string{
		"The process created alpha.txt in the ThreatBoxAccuracy temporary directory, which is not suspicious.",
		"The process was observed creating alpha.txt in the ThreatBoxAccuracy temporary directory, which is not suspicious.",
		"The process deleted beta.txt in the temporary directory.",
	}
	got := deduplicateReportStrings(items, 6, maxFindingRunes)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct findings after deduplication, got %d: %#v", len(got), got)
	}
}

func TestBoundedEvidencePreservesEventTypeDiversity(t *testing.T) {
	types := []string{"created", "modified", "deleted", "renamed"}
	items := make([]map[string]any, 0, 24)
	for i := 0; i < 24; i++ {
		items = append(items, map[string]any{
			"type": types[i%len(types)],
			"path": strings.Repeat(string(rune('a'+i%26)), 180) + ".txt",
		})
	}
	encoded := boundedEvidence(items)
	var preview struct {
		TotalItems    int               `json:"total_items"`
		IncludedItems int               `json:"included_items"`
		Truncated     bool              `json:"truncated"`
		Items         []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(encoded, &preview); err != nil {
		t.Fatalf("bounded evidence is invalid JSON: %v; %s", err, encoded)
	}
	if preview.TotalItems != len(items) || !preview.Truncated || preview.IncludedItems == 0 {
		t.Fatalf("bounded evidence metadata is incorrect: %#v", preview)
	}
	seen := map[string]bool{}
	for _, raw := range preview.Items {
		var item struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			t.Fatal(err)
		}
		seen[item.Type] = true
	}
	for _, kind := range types {
		if !seen[kind] {
			t.Errorf("preview lost event type %q: %v", kind, seen)
		}
	}
}

func TestReportClaimGuardRejectsUnsupportedPrivilegeAndVerdict(t *testing.T) {
	ctx := reportGuardContext{scoreKnown: true, score: 0, lowSignal: true}
	for _, claim := range []string{
		"The process ran with elevated privileges because it had PID 2592.",
		"This is a benign process.",
		"This is malware.",
	} {
		if !reportClaimUnsupported(claim, ctx) {
			t.Errorf("expected unsupported claim to be rejected: %q", claim)
		}
	}
	for _, claim := range []string{
		"The process created alpha.txt in a temporary directory.",
		"Temporary file creation is not by itself evidence of malicious behavior.",
	} {
		if reportClaimUnsupported(claim, ctx) {
			t.Errorf("expected evidence-grounded or qualified statement to pass: %q", claim)
		}
	}
}
