package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tekert/goetw/etw"
)

type Event struct {
	Type    string `json:"type"`
	Time    string `json:"time"`
	EventID uint16 `json:"event_id"`

	PID       uint64 `json:"pid,omitempty"`
	PPID      uint64 `json:"ppid,omitempty"`
	SessionID uint64 `json:"session_id,omitempty"`
	Image     string `json:"image,omitempty"`
	Command   string `json:"command,omitempty"`
	ExitCode  int64  `json:"exit_code,omitempty"`

	FileName   string `json:"file_name,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
	FileObject uint64 `json:"file_object,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	IoSize     uint64 `json:"io_size,omitempty"`
	InfoClass  uint64 `json:"info_class,omitempty"`

	LostEvents uint64 `json:"lost_events,omitempty"`
}

const (
	outputPath     = `C:\ThreatBox\output\events.jsonl`
	readyPath      = `C:\ThreatBox\output\etw-ready`
	flushEvery     = 500 * time.Millisecond
	lostCheckEvery = 2 * time.Second
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procFlushFileBuffers = kernel32.NewProc("FlushFileBuffers")
)

// eventWriter owns the single, persistent handle to events.jsonl and batches
// writes through a buffered writer so high-volume FileIO traffic can't force
// a syscall (and an fsync) per event.
type eventWriter struct {
	mu   sync.Mutex
	file *os.File
	buf  *bufio.Writer
}

func newEventWriter(path string) (*eventWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &eventWriter{file: f, buf: bufio.NewWriterSize(f, 256*1024)}, nil
}

func (w *eventWriter) write(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.buf.Write(data)
	return err
}

func (w *eventWriter) flush(durable bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.buf.Flush(); err != nil {
		return fmt.Errorf("flush buffer: %w", err)
	}
	if !durable {
		return nil
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}
	r1, _, err := procFlushFileBuffers.Call(w.file.Fd())
	if r1 == 0 {
		return fmt.Errorf("FlushFileBuffers: %w", err)
	}
	return nil
}

func (w *eventWriter) close() error {
	if err := w.flush(true); err != nil {
		return err
	}
	return w.file.Close()
}

// fileNameCache correlates the kernel FileObject handle carried by most
// FileIo sub-events to the path learned from Create/Name events, since
// events like Read, Write, Cleanup, Close, SetInfo, etc. never carry a
// filename of their own.
type fileNameCache struct {
	mu    sync.RWMutex
	names map[uint64]string
}

func newFileNameCache() *fileNameCache {
	return &fileNameCache{names: make(map[uint64]string, 4096)}
}

func (c *fileNameCache) put(fileObject uint64, name string) {
	if fileObject == 0 || name == "" {
		return
	}
	c.mu.Lock()
	c.names[fileObject] = name
	c.mu.Unlock()
}

func (c *fileNameCache) get(fileObject uint64) string {
	if fileObject == 0 {
		return ""
	}
	c.mu.RLock()
	name := c.names[fileObject]
	c.mu.RUnlock()
	return name
}

func (c *fileNameCache) forget(fileObject uint64) {
	if fileObject == 0 {
		return
	}
	c.mu.Lock()
	delete(c.names, fileObject)
	c.mu.Unlock()
}

// fileObjectOrKey reads whichever of FileObject/FileKey is present; several
// FileIo sub-event classes only populate one of the two.
func fileObjectOrKey(h *etw.EventRecordHelper) uint64 {
	if v, err := h.GetPropertyUint("FileObject"); err == nil && v != 0 {
		return v
	}
	v, _ := h.GetPropertyUint("FileKey")
	return v
}

func main() {
	writer, err := newEventWriter(outputPath)
	if err != nil {
		fmt.Println("output:", err)
		return
	}
	defer writer.close()

	_ = os.Remove(readyPath)

	fmt.Println("ETW collector started")
	fmt.Println("Output:", outputPath)

	// "FileIo" enables completed file operations (create/read/write/etc.);
	// "DiskFileIo" is the flag that actually turns on FileObject->name
	// resolution (rundown + name events), and is required for any FileIo
	// class events to be emitted at all.
	flags := etw.GetKernelProviderFlags("Process", "FileIo", "DiskFileIo")

	session := etw.NewKernelRealTimeSession(flags)
	defer session.Stop()

	if err := session.Start(); err != nil {
		fmt.Println("session:", err)
		return
	}
	fmt.Println("ETW kernel session started")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	consumer := etw.NewConsumer(ctx)
	defer consumer.Stop()
	consumer.FromSessions(session)

	names := newFileNameCache()

	consumer.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
		opcode := h.EventID()
		providerID := h.EventRec.EventHeader.ProviderId

		if providerID == *etw.ProcessKernelGuid {
			if opcode == 1 || opcode == 2 {
				handleProcessEvent(writer, h, opcode)
			}
			return nil
		}

		if providerID == *etw.FileIoKernelGuid {
			if event, ok := buildFileEvent(h, opcode, names); ok {
				if err := writer.write(event); err != nil {
					fmt.Printf("WRITE ERROR: %v\n", err)
				}
			}
		}

		return nil
	}

	if err := consumer.Start(); err != nil {
		fmt.Println("consumer:", err)
		return
	}

	if err := os.WriteFile(readyPath, []byte("ready\n"), 0644); err != nil {
		fmt.Println("ready signal:", err)
		return
	}
	fmt.Println("ETW READY")
	fmt.Println("ETW consumer running")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	flushTicker := time.NewTicker(flushEvery)
	defer flushTicker.Stop()

	lostTicker := time.NewTicker(lostCheckEvery)
	defer lostTicker.Stop()

	var lastLost uint64

	for {
		select {
		case <-sigCh:
			fmt.Println("shutting down")
			consumer.Stop()
			session.Stop()
			if err := writer.close(); err != nil {
				fmt.Println("final flush:", err)
			}
			return

		case <-flushTicker.C:
			if err := writer.flush(true); err != nil {
				fmt.Println("flush error:", err)
			}

		case <-lostTicker.C:
			var total uint64
			for _, t := range consumer.GetTraces() {
				total += t.RTLostEvents.Load()
			}
			if total != lastLost {
				lastLost = total
				fmt.Printf("ETW LOST EVENTS: %d\n", total)
				_ = writer.write(Event{
					Type:       "etw_lost_events",
					Time:       time.Now().UTC().Format(time.RFC3339Nano),
					LostEvents: total,
				})
			}
		}
	}
}

func handleProcessEvent(writer *eventWriter, h *etw.EventRecordHelper, opcode uint16) {
	var event Event
	event.EventID = opcode
	event.Time = h.Timestamp().Format(time.RFC3339Nano)
	event.PID, _ = h.GetPropertyUint("ProcessId")

	switch opcode {
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
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("WRITE ERROR: %v\n", err)
		return
	}
	// Process lifecycle events are low volume and high value: push them to
	// disk immediately instead of waiting for the periodic flush tick.
	if err := writer.flush(false); err != nil {
		fmt.Printf("FLUSH ERROR: %v\n", err)
	}

	data, _ := json.Marshal(event)
	fmt.Printf("ETW EVENT | %s\n", string(data))
}

// buildFileEvent maps a raw classic-MOF FileIo opcode to an Event, using the
// documented FileIo_* sub-classes (see learn.microsoft.com/windows/win32/etw/fileio)
// rather than the modern manifest-based Kernel-File event IDs, since the
// classic "NT Kernel Logger" session used here reports opcodes, not those IDs.
func buildFileEvent(h *etw.EventRecordHelper, opcode uint16, names *fileNameCache) (Event, bool) {
	var event Event
	event.EventID = opcode
	event.Time = h.Timestamp().Format(time.RFC3339Nano)
	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	switch opcode {

	case 0, 32, 35, 36: // Name, Create(name-form), Delete(name-form), Rundown
		event.FileObject, _ = h.GetPropertyUint("FileObject")
		event.FileName, _ = h.GetPropertyString("FileName")
		names.put(event.FileObject, event.FileName)
		switch opcode {
		case 0:
			event.Type = "file_name"
		case 32:
			event.Type = "file_create"
		case 35:
			event.Type = "file_delete"
			names.forget(event.FileObject)
		case 36:
			event.Type = "file_rundown"
		}

	case 64: // Create (init), carries the full requested path
		event.Type = "file_create_init"
		event.FileObject, _ = h.GetPropertyUint("FileObject")
		event.FileName, _ = h.GetPropertyString("OpenPath")
		names.put(event.FileObject, event.FileName)

	case 65, 66, 73: // Cleanup, Close, Flush
		event.FileObject = fileObjectOrKey(h)
		event.FileName = names.get(event.FileObject)
		switch opcode {
		case 65:
			event.Type = "file_cleanup"
		case 66:
			event.Type = "file_close"
			names.forget(event.FileObject)
		case 73:
			event.Type = "file_flush"
		}

	case 67, 68: // Read, Write
		event.FileObject = fileObjectOrKey(h)
		event.FileName = names.get(event.FileObject)
		event.Offset, _ = h.GetPropertyUint("Offset")
		event.IoSize, _ = h.GetPropertyUint("IoSize")
		if opcode == 67 {
			event.Type = "file_read"
		} else {
			event.Type = "file_write"
		}

	case 69, 70, 71, 74, 75: // SetInfo, Delete, Rename, QueryInfo, FSControl
		event.FileObject = fileObjectOrKey(h)
		event.FileName = names.get(event.FileObject)
		event.InfoClass, _ = h.GetPropertyUint("InfoClass")
		switch opcode {
		case 69:
			event.Type = "file_set_information"
		case 70:
			event.Type = "file_delete_information"
			names.forget(event.FileObject)
		case 71:
			// Classic ETW does not carry the destination name for renames,
			// only that a rename occurred on this file.
			event.Type = "file_rename"
		case 74:
			event.Type = "file_query_information"
		case 75:
			event.Type = "file_fsctl"
		}

	case 72, 76, 77: // DirEnum, OpEnd, DirNotify
		switch opcode {
		case 72, 77:
			dirObject, _ := h.GetPropertyUint("FileObject")
			event.FileName, _ = h.GetPropertyString("FileName")
			event.ParentPath = names.get(dirObject)
			if opcode == 72 {
				event.Type = "file_dir_enum"
			} else {
				event.Type = "file_dir_notify"
			}
		case 76:
			event.Type = "file_operation_end"
		}

	default:
		return Event{}, false
	}

	return event, true
}