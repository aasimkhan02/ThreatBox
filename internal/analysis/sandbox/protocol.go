package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	GuestSampleDir  = `C:\ThreatBox\sample`
	GuestSamplePath = `C:\ThreatBox\sample\sample.exe`
	GuestOutputDir  = `C:\ThreatBox\output`
	GuestToolsDir   = `C:\ThreatBox\tools`

	AgentExeName     = "sandbox-agent.exe"
	CollectorExeName = "etw-collector.exe"

	EventsFileName        = "events.jsonl"
	ReadyFileName         = "etw-ready"
	StopCollectorFileName = "collector.stop"
	StatusFileName        = "status.json"

	AgentLogFileName     = "agent.log"
	CollectorLogFileName = "etw-collector.log"
	SampleLogFileName    = "sample-console.log"
)

const (
	PhaseAgentStarted      = "agent_started"
	PhaseCollectorStarting = "collector_starting"
	PhaseCollectorReady    = "collector_ready"
	PhaseSampleRunning     = "sample_running"
	PhaseSampleExited      = "sample_exited"
	PhaseCollectorStopped  = "collector_stopped"
	PhaseCompleted         = "completed"
	PhaseFailed            = "failed"
)

type AgentStatus struct {
	JobID          string    `json:"job_id"`
	Phase          string    `json:"phase"`
	UpdatedAt      time.Time `json:"updated_at"`
	Message        string    `json:"message,omitempty"`
	Error          string    `json:"error,omitempty"`
	CollectorPID   int       `json:"collector_pid,omitempty"`
	SamplePID      int       `json:"sample_pid,omitempty"`
	SampleExitCode *int      `json:"sample_exit_code,omitempty"`
}

func ValidateJobID(jobID string) error {
	if jobID == "" || len(jobID) > 128 {
		return fmt.Errorf("invalid job ID length")
	}

	for _, ch := range jobID {
		valid := ch >= 'a' && ch <= 'z' ||
			ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_'

		if !valid {
			return fmt.Errorf("job ID contains an unsafe character")
		}
	}

	return nil
}

func WriteAgentStatus(outputDir string, status AgentStatus) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create status directory: %w", err)
	}

	status.UpdatedAt = time.Now().UTC()

	data, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode guest status: %w", err)
	}

	path := filepath.Join(outputDir, StatusFileName)

	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return fmt.Errorf("open guest status file: %w", err)
	}

	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()

	if writeErr != nil {
		return fmt.Errorf("write guest status: %w", writeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("flush guest status: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close guest status: %w", closeErr)
	}

	return nil
}

func ReadAgentStatus(outputDir string) (AgentStatus, error) {
	var status AgentStatus

	path := filepath.Join(outputDir, StatusFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return status, err
	}

	if err := json.Unmarshal(data, &status); err != nil {
		return AgentStatus{}, fmt.Errorf("decode guest status: %w", err)
	}

	return status, nil
}
