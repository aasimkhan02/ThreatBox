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

type ProcessTracker struct {
	tracked map[uint64]bool
}

// WatchSandboxEvents watches the host-side Sandbox telemetry file
// and processes only events appended after ThreatBox starts.
func WatchSandboxEvents(path string) error {
	var offset int64
	started := false

	tracker := ProcessTracker{
		tracked: make(map[uint64]bool),
	}

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

					// Start tracking when the malware sample itself appears.
					if event.Type == "process_start" &&
						event.Image == "sample.exe" {

						tracker.tracked[event.PID] = true

						fmt.Printf(
							"THREATBOX EVENT | %s | PID=%d | Image=%s\\n",
							event.Type,
							event.PID,
							event.Image,
						)

						continue
					}

					// Keep children of tracked processes.
					if event.Type == "process_start" &&
						tracker.tracked[event.PPID] {

						tracker.tracked[event.PID] = true

						fmt.Printf(
							"THREATBOX EVENT | %s | PID=%d | Image=%s\\n",
							event.Type,
							event.PID,
							event.Image,
						)

						continue
					}

					// Keep stop events for tracked processes.
					if event.Type == "process_stop" &&
						tracker.tracked[event.PID] {

						fmt.Printf(
							"THREATBOX EVENT | %s | PID=%d | Image=%s\\n",
							event.Type,
							event.PID,
							event.Image,
						)

						delete(tracker.tracked, event.PID)
					}
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

