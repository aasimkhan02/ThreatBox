package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
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

const outputPath = `C:\ThreatBox\output\events.jsonl`

var writeMu sync.Mutex

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procFlushFileBuffers = kernel32.NewProc("FlushFileBuffers")
)

func flushFile(file *os.File) error {
	r1, _, err := procFlushFileBuffers.Call(file.Fd())

	if r1 == 0 {
		return fmt.Errorf("FlushFileBuffers failed: %w", err)
	}

	return nil
}

func writeEvent(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	file, err := os.OpenFile(
		outputPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return fmt.Errorf("open events.jsonl: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write events.jsonl: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync events.jsonl: %w", err)
	}

	if err := flushFile(file); err != nil {
		return err
	}

	return nil
}

func main() {
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("output:", err)
		return
	}
	file.Close()

	fmt.Println("ETW collector started")
	fmt.Println("Output:", outputPath)

	flags := etw.GetKernelProviderFlags("Process")

	session := etw.NewKernelRealTimeSession(flags)
	defer session.Stop()

	if err := session.Start(); err != nil {
		fmt.Println("session:", err)
		return
	}

	fmt.Println("ETW kernel session started")

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

		if err := writeEvent(event); err != nil {
			fmt.Printf(
				"WRITE ERROR | PID=%d | Image=%s | %v\n",
				event.PID,
				event.Image,
				err,
			)
			return nil
		}

		data, _ := json.Marshal(event)

		fmt.Printf("ETW EVENT | %s\n", string(data))

		return nil
	}

	if err := consumer.Start(); err != nil {
		fmt.Println("consumer:", err)
		return
	}

	fmt.Println("ETW consumer running")

	select {}
}