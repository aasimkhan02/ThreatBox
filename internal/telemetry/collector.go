package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
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

// WatchSandboxEvents watches the host-side Sandbox telemetry file
// and processes only events appended after ThreatBox starts.
func WatchSandboxEvents(path string) error {
	var offset int64
	started := false

	for {
		file, err := os.Open(path)
		if err != nil {
			// The file may not exist yet or may temporarily be unavailable.
			time.Sleep(200 * time.Millisecond)
			continue
		}

		info, err := file.Stat()
		if err != nil {
			file.Close()
			time.Sleep(200 * time.Millisecond)
			continue
		}

		// On the first successful open, ignore everything already
		// in the file. We only want new events.
		if !started {
			offset = info.Size()
			started = true
			file.Close()

			fmt.Printf(
				"Sandbox telemetry watcher started at byte %d\n",
				offset,
			)

			time.Sleep(200 * time.Millisecond)
			continue
		}

		// If the collector recreated/truncated the file,
		// start reading from the beginning again.
		if info.Size() < offset {
			offset = 0
		}

		// No new data.
		if info.Size() <= offset {
			file.Close()
			time.Sleep(200 * time.Millisecond)
			continue
		}

		// Move to the first unread byte.
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			time.Sleep(200 * time.Millisecond)
			continue
		}

		reader := bufio.NewReader(file)

		for {
			line, err := reader.ReadBytes('\n')

			// Only consume complete JSONL lines.
			if err == nil {
				offset += int64(len(line))

				var event ProcessEvent

				if json.Unmarshal(line, &event) == nil {
					fmt.Printf(
						"THREATBOX EVENT | %s | PID=%d | Image=%s\n",
						event.Type,
						event.PID,
						event.Image,
					)
				}

				continue
			}

			if err == io.EOF {
				// Incomplete trailing line stays unread.
				break
			}

			// Any temporary read problem: retry on the next poll.
			break
		}

		file.Close()

		time.Sleep(200 * time.Millisecond)
	}
}

