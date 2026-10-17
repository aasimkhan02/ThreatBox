package sandbox

import (
	"testing"
)

func TestValidateJobID(t *testing.T) {
	tests := []struct {
		name    string
		jobID   string
		wantErr bool
	}{
		{name: "UUID-like ID", jobID: "f793fb0f-1b67-4e38-9852-fe43c79466ca"},
		{name: "simple ID", jobID: "test_job-123"},
		{name: "empty ID", jobID: "", wantErr: true},
		{name: "path traversal", jobID: "../outside", wantErr: true},
		{name: "spaces", jobID: "bad job ID", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJobID(tt.jobID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateJobID(%q) error = %v, wantErr %v",
					tt.jobID, err, tt.wantErr)
			}
		})
	}
}

func TestAgentStatusRoundTrip(t *testing.T) {
	dir := t.TempDir()
	exitCode := 0

	original := AgentStatus{
		JobID:          "test-job-123",
		Phase:          PhaseCompleted,
		Message:        "completed",
		SampleExitCode: &exitCode,
	}

	if err := WriteAgentStatus(dir, original); err != nil {
		t.Fatalf("WriteAgentStatus: %v", err)
	}

	got, err := ReadAgentStatus(dir)
	if err != nil {
		t.Fatalf("ReadAgentStatus: %v", err)
	}

	if got.JobID != original.JobID || got.Phase != original.Phase {
		t.Fatalf("status mismatch: got %+v", got)
	}
	if got.SampleExitCode == nil || *got.SampleExitCode != 0 {
		t.Fatalf("sample exit code was not preserved: %+v", got.SampleExitCode)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt was not populated")
	}
}
