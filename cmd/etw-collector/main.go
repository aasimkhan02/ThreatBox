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
	Type       string `json:"type"`
	Time       string `json:"time"`
	EventID    uint16 `json:"event_id"`
	PID        uint64 `json:"pid,omitempty"`
	ThreadID   uint64 `json:"thread_id,omitempty"`
	PPID       uint64 `json:"ppid,omitempty"`
	SessionID  uint64 `json:"session_id,omitempty"`
	Image      string `json:"image,omitempty"`
	Command    string `json:"command,omitempty"`
	ExitCode   int64  `json:"exit_code,omitempty"`

	FileName   string `json:"file_name,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
	FileObject uint64 `json:"file_object,omitempty"`
	FileKey    uint64 `json:"file_key,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	IoSize     uint64 `json:"io_size,omitempty"`
	InfoClass  uint64 `json:"info_class,omitempty"`

	// Network
	SourceIP   string `json:"source_ip,omitempty"`
	SourcePort uint64 `json:"source_port,omitempty"`
	DestIP     string `json:"dest_ip,omitempty"`
	DestPort   uint64 `json:"dest_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

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

	tcpIPGuid = etw.MustParseGUID("{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}")
)

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

	return &eventWriter{
		file: f,
		buf:  bufio.NewWriterSize(f, 256*1024),
	}, nil
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

type fileNameCache struct {
	mu    sync.RWMutex
	names map[uint64]string
}

func newFileNameCache() *fileNameCache {
	return &fileNameCache{
		names: make(map[uint64]string, 4096),
	}
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

func (c *fileNameCache) putBoth(fileObject, fileKey uint64, name string) {
	if name == "" {
		return
	}

	c.mu.Lock()

	if fileObject != 0 {
		c.names[fileObject] = name
	}

	if fileKey != 0 {
		c.names[fileKey] = name
	}

	c.mu.Unlock()
}

func (c *fileNameCache) forgetBoth(fileObject, fileKey uint64) {
	c.mu.Lock()

	if fileObject != 0 {
		delete(c.names, fileObject)
	}

	if fileKey != 0 && fileKey != fileObject {
		delete(c.names, fileKey)
	}

	c.mu.Unlock()
}

func (c *fileNameCache) forget(fileObject uint64) {
	if fileObject == 0 {
		return
	}

	c.mu.Lock()
	delete(c.names, fileObject)
	c.mu.Unlock()
}

func fileObjectAndKey(h *etw.EventRecordHelper) (uint64, uint64) {
	fileObject, _ := h.GetPropertyUint("FileObject")
	fileKey, _ := h.GetPropertyUint("FileKey")

	return fileObject, fileKey
}

func fileObjectOrKey(h *etw.EventRecordHelper) uint64 {
	fileObject, fileKey := fileObjectAndKey(h)

	if fileObject != 0 {
		return fileObject
	}

	return fileKey
}

// fileIoDiag tracks raw FileIo traffic reaching our callback.
type fileIoDiag struct {
	mu           sync.Mutex
	totalSeen    uint64
	byOpcode     map[uint16]uint64
	unhandledOps map[uint16]uint64
}

func newFileIoDiag() *fileIoDiag {
	return &fileIoDiag{
		byOpcode:     make(map[uint16]uint64),
		unhandledOps: make(map[uint16]uint64),
	}
}

func (d *fileIoDiag) seen(opcode uint16) {
	d.mu.Lock()
	d.totalSeen++
	d.byOpcode[opcode]++
	d.mu.Unlock()
}

func (d *fileIoDiag) unhandled(opcode uint16) {
	d.mu.Lock()
	d.unhandledOps[opcode]++
	d.mu.Unlock()
}

func (d *fileIoDiag) report() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.totalSeen == 0 {
		fmt.Println(
			"FILEIO DIAG: 0 FileIo-provider events reached the callback in this interval " +
				"(this points at the session/flags, not at buildFileEvent, if it stays 0 while sample.exe touches files)",
		)
		return
	}

	fmt.Printf(
		"FILEIO DIAG: %d raw FileIo events seen | by opcode: %v",
		d.totalSeen,
		d.byOpcode,
	)

	if len(d.unhandledOps) > 0 {
		fmt.Printf(
			" | unhandled opcodes (not in buildFileEvent's switch): %v",
			d.unhandledOps,
		)
	}

	fmt.Println()

	d.totalSeen = 0
	d.byOpcode = make(map[uint16]uint64)
	d.unhandledOps = make(map[uint16]uint64)
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

	// Session 1: NT Kernel Logger
	// Process + Thread + TCP/IP events.
	kernelFlags := etw.KernelNtFlag(
		etw.EVENT_TRACE_FLAG_PROCESS |
			etw.EVENT_TRACE_FLAG_THREAD |
			etw.EVENT_TRACE_FLAG_NETWORK_TCPIP,
	)

	kernelSession := etw.NewKernelRealTimeSession(kernelFlags)
	defer kernelSession.Stop()

	if err := kernelSession.Start(); err != nil {
		fmt.Println("kernel session:", err)
		return
	}

	fmt.Println("ETW kernel session started")

	// Session 2: Microsoft-Windows-Kernel-File
	fileSession := etw.NewRealTimeSession("ThreatBox-Kernel-File")
	defer fileSession.Stop()

	fileProvider, err := etw.ParseProvider(
		"Microsoft-Windows-Kernel-File:0xff:10,11,12,15,16,26,27,30:0x1f90",
	)
	if err != nil {
		fmt.Println("kernel-file provider:", err)
		return
	}

	if err := fileSession.EnableProvider(fileProvider); err != nil {
		fmt.Println("kernel-file enable:", err)
		return
	}

	if err := fileSession.Start(); err != nil {
		fmt.Println("kernel-file session:", err)
		return
	}

	fmt.Println("ETW kernel-file session started")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Consumer for Process + Thread + Network events.
	kernelConsumer := etw.NewConsumer(ctx)
	defer kernelConsumer.Stop()
	kernelConsumer.FromSessions(kernelSession)

	// Consumer for File events.
	fileConsumer := etw.NewConsumer(ctx)
	defer fileConsumer.Stop()
	fileConsumer.FromSessions(fileSession)

	kernelConsumer.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
		opcode := h.EventID()
		providerID := h.EventRec.EventHeader.ProviderId

		if providerID == *etw.ProcessKernelGuid {
			if opcode == 1 || opcode == 2 {
				handleProcessEvent(writer, h, opcode)
			}
			return nil
		}

		if providerID == *tcpIPGuid {
			handleNetworkEvent(writer, h)
			return nil
		}

		if providerID == *etw.ThreadKernelGuid {
			if opcode >= 1 && opcode <= 4 {
				handleThreadEvent(writer, h, opcode)
			}
			return nil
		}

		return nil
	}

	names := newFileNameCache()

	fileConsumer.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
		if event, ok := buildManifestFileEvent(h, names); ok {
			if err := writer.write(event); err != nil {
				fmt.Printf("WRITE ERROR: %v\n", err)
			}
		}

		return nil
	}

	if err := kernelConsumer.Start(); err != nil {
		fmt.Println("kernel consumer:", err)
		return
	}

	if err := fileConsumer.Start(); err != nil {
		fmt.Println("file consumer:", err)
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

			fileConsumer.Stop()
			kernelConsumer.Stop()

			fileSession.Stop()
			kernelSession.Stop()

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

			for _, t := range kernelConsumer.GetTraces() {
				total += t.RTLostEvents.Load()
			}

			for _, t := range fileConsumer.GetTraces() {
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

	if err := writer.flush(false); err != nil {
		fmt.Printf("FLUSH ERROR: %v\n", err)
	}

	data, _ := json.Marshal(event)
	fmt.Printf("ETW EVENT | %s\n", string(data))
}

func handleNetworkEvent(writer *eventWriter, h *etw.EventRecordHelper) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	// For kernel TCP/IP events, the event header identifies the process.
	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	switch event.EventID {
	case 12:
		event.Type = "network_connect"
		event.Protocol = "TCP"

	case 15:
		event.Type = "network_accept"
		event.Protocol = "TCP"

	default:
		return
	}

	// Try the normal named-property helpers first.
	event.SourceIP = getStringAny(h, "saddr", "SourceAddress")
	event.DestIP = getStringAny(h, "daddr", "DestinationAddress")
	event.SourcePort = getUintAny(h, "sport", "SourcePort")
	event.DestPort = getUintAny(h, "dport", "DestinationPort")

	if err := writer.write(event); err != nil {
		fmt.Printf("NETWORK WRITE ERROR: %v\n", err)
		return
	}

	data, _ := json.Marshal(event)
	fmt.Printf("NETWORK EVENT | %s\n", string(data))
}

func handleThreadEvent(writer *eventWriter, h *etw.EventRecordHelper, opcode uint16) {
	var event Event

	event.EventID = opcode
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	threadID, err := h.GetPropertyUint("TThreadId")
	if err != nil || threadID == 0 {
		return
	}

	pid, err := h.GetPropertyUint("ProcessId")
	if err != nil || pid == 0 {
		return
	}

	event.ThreadID = threadID
	event.PID = pid

	switch opcode {
	case 1:
		event.Type = "thread_start"
	case 2:
		event.Type = "thread_stop"
	case 3:
		event.Type = "thread_dc_start"
	case 4:
		event.Type = "thread_dc_stop"
	default:
		return
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("WRITE ERROR: %v\n", err)
	}
}

// getUintAny tolerates version differences in the manifest schema.
func getUintAny(h *etw.EventRecordHelper, names ...string) uint64 {
	for _, name := range names {
		if value, err := h.GetPropertyUint(name); err == nil {
			return value
		}
	}

	return 0
}

// getStringAny tolerates version differences in the manifest schema.
func getStringAny(h *etw.EventRecordHelper, names ...string) string {
	for _, name := range names {
		if value, err := h.GetPropertyString(name); err == nil {
			return value
		}
	}

	return ""
}

func buildManifestFileEvent(h *etw.EventRecordHelper, names *fileNameCache) (Event, bool) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	// Microsoft-Windows-Kernel-File is a manifest provider,
	// so the event header PID is the process that issued the operation.
	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	// Versioned schemas use either ThreadId or IssuingThreadId.
	event.ThreadID = getUintAny(h, "ThreadId", "IssuingThreadId")

	switch event.EventID {
	case 10, 11:
		// NameCreate / NameDelete: seed FileKey -> path correlation.
		event.FileKey = getUintAny(h, "FileKey")
		event.FileName = getStringAny(h, "FileName")

		if event.FileKey == 0 || event.FileName == "" {
			return Event{}, false
		}

		names.put(event.FileKey, event.FileName)

		if event.EventID == 10 {
			event.Type = "file_name"
		} else {
			event.Type = "file_name_delete"
		}

	case 12:
		// Create.
		event.FileObject = getUintAny(h, "FileObject")
		event.FileKey = getUintAny(h, "FileKey")
		event.FileName = getStringAny(h, "FileName", "OpenPath")

		if event.FileName != "" {
			names.putBoth(event.FileObject, event.FileKey, event.FileName)
		}

		event.Type = "file_create"

	case 15:
		// Read.
		event.FileObject, event.FileKey = fileObjectAndKey(h)
		event.FileName = getStringAny(h, "FileName")

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Offset = getUintAny(h, "ByteOffset", "Offset")
		event.IoSize = getUintAny(h, "IOSize", "IoSize", "Length")
		event.Type = "file_read"

	case 16:
		// Write.
		event.FileObject, event.FileKey = fileObjectAndKey(h)
		event.FileName = getStringAny(h, "FileName")

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Offset = getUintAny(h, "ByteOffset", "Offset")
		event.IoSize = getUintAny(h, "IOSize", "IoSize", "Length")
		event.Type = "file_write"

	case 26:
		// DeletePath carries the actual path inline.
		event.FileObject, event.FileKey = fileObjectAndKey(h)
		event.FileName = getStringAny(h, "FilePath", "FileName")

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Type = "file_delete_information"

	case 27:
		// RenamePath carries the actual path inline.
		event.FileObject, event.FileKey = fileObjectAndKey(h)
		event.FileName = getStringAny(h, "FilePath", "FileName")

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Type = "file_rename"

	case 30:
		// CreateNewFile also carries the filename inline.
		event.FileObject = getUintAny(h, "FileObject")
		event.FileName = getStringAny(h, "FileName")

		if event.FileName != "" {
			names.put(event.FileObject, event.FileName)
		}

		event.Type = "file_create"

	default:
		return Event{}, false
	}

	return event, true
}