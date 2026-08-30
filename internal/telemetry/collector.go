package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type ProcessEvent struct {
	Type      string `json:"type"`
	PID       uint64 `json:"pid"`
	PPID      uint64 `json:"ppid,omitempty"`
	SessionID uint64 `json:"session_id,omitempty"`
	Image     string `json:"image,omitempty"`
	Command   string `json:"command,omitempty"`
	ExitCode  int64  `json:"exit_code,omitempty"`
	Time      string `json:"time"`
}

func ReadSandboxEvents(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open sandbox events: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var event ProcessEvent

		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			fmt.Printf("invalid event: %v\n", err)
			continue
		}

		fmt.Printf(
			"THREATBOX EVENT | %s | PID=%d | Image=%s\n",
			event.Type,
			event.PID,
			event.Image,
		)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read sandbox events: %w", err)
	}

	return nil
}