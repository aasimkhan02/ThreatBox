package scoring

import "testing"

// TestHighRiskSyntheticTechniques verifies the scorer's 80–90 point range
// using synthetic technique IDs only. It does not execute a sample, write
// registry keys, load DLLs, or make network connections.
func TestHighRiskSyntheticTechniques(t *testing.T) {
	techniqueIDs := []string{
		"T1547.001", // 30 points: registry Run-key persistence rule
		"T1574.002", // 35 points: DLL side-loading correlation rule
		"T1071.004", // 20 points: suspicious DNS rule
	}

	got := Calculate(techniqueIDs)

	if got.Score != 85 {
		t.Fatalf("score = %d, want 85; reasons = %#v", got.Score, got.Reasons)
	}
	if got.Severity != "Critical" {
		t.Fatalf("severity = %q, want Critical", got.Severity)
	}
	if len(got.Reasons) != 3 {
		t.Fatalf("got %d reasons, want 3: %#v", len(got.Reasons), got.Reasons)
	}
}
