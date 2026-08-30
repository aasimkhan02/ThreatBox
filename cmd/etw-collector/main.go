package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tekert/goetw/etw"
)

type Event struct {
	Type      string `json:"type"`
	PID       uint64 `json:"pid"`
	PPID      uint64 `json:"ppid,omitempty"`
	SessionID uint64 `json:"session_id,omitempty"`
	Image     string `json:"image,omitempty"`
	Command   string `json:"command,omitempty"`
	ExitCode  int64  `json:"exit_code,omitempty"`
	Time      string `json:"time"`
}

func main() {
	output := `C:\ThreatBox\output\events.jsonl`

	file, err := os.Create(output)
	if err != nil {
		fmt.Println("output:", err)
		return
	}
	defer file.Close()

	flags := etw.GetKernelProviderFlags("Process")

	session := etw.NewKernelRealTimeSession(flags)
	defer session.Stop()

	if err := session.Start(); err != nil {
		fmt.Println("session:", err)
		return
	}

	fmt.Println("ETW collector started")

	consumer := etw.NewConsumer(context.Background())
	defer consumer.Stop()

	consumer.FromSessions(session)

	consumer.EventPreparedCallback = func(
		h *etw.EventRecordHelper,
	) error {
		var event Event

		event.PID, _ = h.GetPropertyUint("ProcessId")
		event.Time = h.Timestamp().Format(time.RFC3339Nano)

		switch h.EventID() {
		case 1:
			event.Type = "process_start"

			event.PPID, _ = h.GetPropertyUint("ParentId")
			event.SessionID, _ = h.GetPropertyUint("SessionId")
			event.Image, _ = h.GetPropertyString("ImageFileName")
			event.Command, _ = h.GetPropertyString("CommandLine")

		case 2:
			event.Type = "process_stop"

			event.ExitCode, _ = h.GetPropertyInt("ExitStatus")
			event.Image, _ = h.GetPropertyString("ImageFileName")

		default:
			return nil
		}

		data, err := json.Marshal(event)
		if err != nil {
			return err
		}

		if _, err := file.Write(append(data, '\n')); err != nil {
			return err
		}

		file.Sync()

		fmt.Println(string(data))

		return nil
	}

	if err := consumer.Start(); err != nil {
		fmt.Println("consumer:", err)
		return
	}

	// Keep collector alive while Sandbox is running.
	select {}
}