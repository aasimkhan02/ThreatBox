package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
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

	// File
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

	// Registry
	RegistryKey    string `json:"registry_key,omitempty"`
	RegistryHandle uint64 `json:"registry_handle,omitempty"`
	RegistryStatus uint64 `json:"registry_status,omitempty"`
	RegistryIndex  uint64 `json:"registry_index,omitempty"`

	// DNS (Microsoft-Windows-DNS-Client)
	DNSQueryName   string   `json:"dns_query_name,omitempty"`
	DNSQueryType   uint64   `json:"dns_query_type,omitempty"`
	DNSQueryStatus uint64   `json:"dns_query_status,omitempty"`
	DNSResults     []string `json:"dns_results,omitempty"`

	// Image / DLL load. Reuses the Image field (already used for
	// process start/stop) to hold the loaded module's path.
	ImageBase     uint64 `json:"image_base,omitempty"`
	ImageSize     uint64 `json:"image_size,omitempty"`
	ImageChecksum uint64 `json:"image_checksum,omitempty"`

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

	tcpIPGuid = etw.MustParseGUID(
		"{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}",
	)

	// UDP/IP is a *separate* classic provider from TCP/IP even though
	// both are enabled by the same EVENT_TRACE_FLAG_NETWORK_TCPIP flag.
	udpIPGuid = etw.MustParseGUID(
		"{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}",
	)

	// Image/DLL load events. Enabled via EVENT_TRACE_FLAG_IMAGE_LOAD.
	imageLoadGuid = etw.MustParseGUID(
		"{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}",
	)

	// Manifest-based DNS client provider (user mode), enabled as an
	// extra provider on the file session.
	dnsClientGuid = etw.MustParseGUID(
		"{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}",
	)

	// Legacy Registry provider.
	registryGuid = etw.MustParseGUID(
		"{ae53722e-c863-11d2-8659-00c04fa321a1}",
	)

	// Modern System Registry provider.
	systemRegistryGuid = etw.MustParseGUID(
		"{16156bd9-fab4-4cfa-a232-89d1099058e3}",
	)
)

type eventWriter struct {
	mu   sync.Mutex
	file *os.File
	buf  *bufio.Writer
}

func newEventWriter(path string) (*eventWriter, error) {
	f, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
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

// handleNameCache maps an opaque kernel handle/object value (a file
// object, file key, or registry key handle) to the last name we saw
// associated with it. Many ETW event types only carry a handle and
// rely on an earlier event (e.g. NameCreate, RegCreateKey, RegOpenKey)
// to have already told us what that handle refers to.
type handleNameCache struct {
	mu    sync.RWMutex
	names map[uint64]string
}

func newHandleNameCache() *handleNameCache {
	return &handleNameCache{
		names: make(map[uint64]string, 4096),
	}
}

func (c *handleNameCache) put(handle uint64, name string) {
	if handle == 0 || name == "" {
		return
	}

	c.mu.Lock()
	c.names[handle] = name
	c.mu.Unlock()
}

func (c *handleNameCache) get(handle uint64) string {
	if handle == 0 {
		return ""
	}

	c.mu.RLock()
	name := c.names[handle]
	c.mu.RUnlock()

	return name
}

func (c *handleNameCache) putBoth(fileObject, fileKey uint64, name string) {
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

// delete removes a handle from the cache. Call this once a handle is
// known to be closed (e.g. registry Close/KCBDelete) so that if the
// kernel reuses the same handle value for an unrelated object later,
// we don't attribute its events to the wrong name.
func (c *handleNameCache) delete(handle uint64) {
	if handle == 0 {
		return
	}

	c.mu.Lock()
	delete(c.names, handle)
	c.mu.Unlock()
}

func fileObjectAndKey(h *etw.EventRecordHelper) (uint64, uint64) {
	fileObject, _ := h.GetPropertyUint("FileObject")
	fileKey, _ := h.GetPropertyUint("FileKey")

	return fileObject, fileKey
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
	// Process + Thread + TCP/IP + Registry events.
	kernelFlags := etw.KernelNtFlag(
		etw.EVENT_TRACE_FLAG_PROCESS |
			etw.EVENT_TRACE_FLAG_THREAD |
			etw.EVENT_TRACE_FLAG_NETWORK_TCPIP |
			etw.EVENT_TRACE_FLAG_REGISTRY |
			etw.EVENT_TRACE_FLAG_IMAGE_LOAD,
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

	// DNS-Client is a lightweight manifest provider; ride along on the
	// same real-time session instead of paying for a third session
	// and consumer. 3006 = query issued, 3008 = query completed
	// (carries the resolved IPs).
	dnsProvider, err := etw.ParseProvider(
		"Microsoft-Windows-DNS-Client:0xff:3006,3008",
	)
	if err != nil {
		fmt.Println("dns-client provider:", err)
		return
	}

	if err := fileSession.EnableProvider(dnsProvider); err != nil {
		fmt.Println("dns-client enable:", err)
		return
	}

	if err := fileSession.Start(); err != nil {
		fmt.Println("kernel-file session:", err)
		return
	}

	fmt.Println("ETW kernel-file session started")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Consumer for Process + Thread + Network + Registry events.
	kernelConsumer := etw.NewConsumer(ctx)
	defer kernelConsumer.Stop()
	kernelConsumer.FromSessions(kernelSession)

	// Consumer for File events.
	fileConsumer := etw.NewConsumer(ctx)
	defer fileConsumer.Stop()
	fileConsumer.FromSessions(fileSession)

	fileNames := newHandleNameCache()
	registryNames := newHandleNameCache()

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

		if providerID == *udpIPGuid {
			handleUDPEvent(writer, h)
			return nil
		}

		if providerID == *imageLoadGuid {
			if opcode == 10 || opcode == 2 || opcode == 3 || opcode == 4 {
				handleImageEvent(writer, h, opcode)
			}
			return nil
		}

		// Registry events may appear under either the legacy
		// Registry provider or the modern System Registry provider.
		if providerID == *registryGuid || providerID == *systemRegistryGuid {
			handleRegistryEvent(writer, h, registryNames)
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

	fileConsumer.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
		if h.EventRec.EventHeader.ProviderId == *dnsClientGuid {
			handleDNSEvent(writer, h)
			return nil
		}

		if event, ok := buildManifestFileEvent(h, fileNames); ok {
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

func handleProcessEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
	opcode uint16,
) {
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

	default:
		return
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

func handleNetworkEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

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

// handleUDPEvent handles the classic UdpIp provider ({bf3a50c5-...}),
// enabled by the same EVENT_TRACE_FLAG_NETWORK_TCPIP flag as TCP but
// delivered under its own provider GUID with its own event types.
func handleUDPEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	// Per Microsoft's docs for TcpIp/UdpIp: because some network events
	// are logged by a separate worker thread, EVENT_TRACE_HEADER's
	// ProcessId can be wrong for these events. The schema carries the
	// correct originating PID in its own "PID" property, so prefer
	// that and only fall back to the header if it's missing.
	event.PID = getUintAny(h, "PID")
	if event.PID == 0 {
		event.PID = uint64(h.EventRec.EventHeader.ProcessId)
	}

	switch event.EventID {
	case 10:
		event.Type = "network_udp_send"
		event.Protocol = "UDP"

	case 11:
		event.Type = "network_udp_receive"
		event.Protocol = "UDP"

	case 26:
		event.Type = "network_udp_send"
		event.Protocol = "UDP6"

	case 27:
		event.Type = "network_udp_receive"
		event.Protocol = "UDP6"

	default:
		return
	}

	event.SourceIP = getStringAny(h, "saddr", "SourceAddress")
	event.DestIP = getStringAny(h, "daddr", "DestinationAddress")
	event.SourcePort = getUintAny(h, "sport", "SourcePort")
	event.DestPort = getUintAny(h, "dport", "DestinationPort")

	if err := writer.write(event); err != nil {
		fmt.Printf("UDP WRITE ERROR: %v\n", err)
		return
	}

	data, _ := json.Marshal(event)
	fmt.Printf("UDP EVENT | %s\n", string(data))
}

// handleDNSEvent handles the Microsoft-Windows-DNS-Client manifest
// provider. 3006 fires when a query is issued; 3008 fires when it
// completes and carries the resolved addresses in QueryResults as a
// semicolon-separated list.
func handleDNSEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)
	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	switch event.EventID {
	case 3006:
		event.Type = "dns_query"

	case 3008:
		event.Type = "dns_query_result"

	default:
		return
	}

	event.DNSQueryName = getStringAny(h, "QueryName")
	event.DNSQueryType = getUintAny(h, "QueryType")

	if event.EventID == 3008 {
		event.DNSQueryStatus = getUintAny(h, "QueryStatus")

		if results := getStringAny(h, "QueryResults"); results != "" {
			for _, ip := range strings.Split(results, ";") {
				ip = strings.TrimSpace(ip)
				if ip != "" {
					event.DNSResults = append(event.DNSResults, ip)
				}
			}
		}
	}

	// Nothing useful without at least the domain being queried.
	if event.DNSQueryName == "" {
		return
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("DNS WRITE ERROR: %v\n", err)
		return
	}

	data, _ := json.Marshal(event)
	fmt.Printf("DNS EVENT | %s\n", string(data))
}

// handleImageEvent handles the classic Image/ImageLoad provider
// ({2cb15d1d-...}), enabled via EVENT_TRACE_FLAG_IMAGE_LOAD. Fires for
// both executable and DLL loads/unloads, and for the load-state
// rundown Windows performs at trace start (DCStart) and end (DCEnd).
func handleImageEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
	opcode uint16,
) {
	var event Event

	event.EventID = opcode
	event.Time = h.Timestamp().Format(time.RFC3339Nano)
	event.PID = getUintAny(h, "ProcessId")

	switch opcode {
	case 10:
		event.Type = "image_load"

	case 2:
		event.Type = "image_unload"

	case 3:
		event.Type = "image_dc_start"

	case 4:
		event.Type = "image_dc_end"

	default:
		return
	}

	event.Image = getStringAny(h, "FileName")
	event.ImageBase = getUintAny(h, "ImageBase")
	event.ImageSize = getUintAny(h, "ImageSize")
	event.ImageChecksum = getUintAny(h, "ImageChecksum")

	// Nothing useful without a path.
	if event.Image == "" {
		return
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("IMAGE WRITE ERROR: %v\n", err)
		return
	}

	data, _ := json.Marshal(event)
	fmt.Printf("IMAGE EVENT | %s\n", string(data))
}

func handleRegistryEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
	names *handleNameCache,
) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	// Only Create/Open/EnumerateKey/KCBCreate/KCBRundown events carry a
	// full KeyName in the Registry_TypeGroup1 schema. Everything else
	// (SetValue, DeleteValue, QueryValue, EnumerateValueKey, Flush,
	// Close, ...) only carries the KeyHandle of an already-open key, so
	// we track handle->name ourselves and resolve it below. This is the
	// same pattern already used for file events via fileNames/handleNameCache.
	nameCarrying := false

	switch event.EventID {
	case 10:
		event.Type = "registry_create"
		nameCarrying = true

	case 11:
		event.Type = "registry_open"
		nameCarrying = true

	case 12:
		event.Type = "registry_delete"

	case 13:
		event.Type = "registry_query"

	case 14:
		event.Type = "registry_set_value"

	case 15:
		event.Type = "registry_delete_value"

	case 16:
		event.Type = "registry_query_value"

	case 17:
		event.Type = "registry_enumerate_key"
		nameCarrying = true

	case 18:
		event.Type = "registry_enumerate_value"

	case 19:
		event.Type = "registry_query_multiple_value"

	case 20:
		event.Type = "registry_set_information"

	case 21:
		event.Type = "registry_flush"

	case 22:
		event.Type = "registry_kcb_create"
		nameCarrying = true

	case 23:
		event.Type = "registry_kcb_delete"

	case 24:
		event.Type = "registry_kcb_rundown_begin"
		nameCarrying = true

	case 25:
		event.Type = "registry_kcb_rundown_end"
		nameCarrying = true

	case 26:
		event.Type = "registry_virtualize"

	case 27:
		event.Type = "registry_close"

	default:
		return
	}

	event.RegistryKey = getStringAny(h, "KeyName")
	event.RegistryHandle = getUintAny(h, "KeyHandle")
	event.RegistryStatus = getUintAny(h, "Status")
	event.RegistryIndex = getUintAny(h, "Index")

	if nameCarrying {
		// Remember this handle's name for later handle-only events
		// (SetValue, QueryValue, Close, ...) on the same key.
		names.put(event.RegistryHandle, event.RegistryKey)
	} else if event.RegistryKey == "" {
		// This event type doesn't carry a name on the wire; resolve
		// it from a prior Create/Open/KCBCreate on the same handle.
		event.RegistryKey = names.get(event.RegistryHandle)
	}

	// The handle is being torn down; stop tracking it so a reused
	// handle value doesn't get attributed to the wrong key later.
	if event.EventID == 23 || event.EventID == 27 {
		names.delete(event.RegistryHandle)
	}

	// Only drop the event if we have neither a key name nor a handle
	// to identify what it was about (e.g. the schema gave us nothing
	// usable). Don't drop handle-only events just because we haven't
	// seen (or missed) the matching Create/Open for that handle.
	if event.RegistryKey == "" && event.RegistryHandle == 0 {
		return
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("REGISTRY WRITE ERROR: %v\n", err)
		return
	}

	data, _ := json.Marshal(event)
	fmt.Printf("REGISTRY EVENT | %s\n", string(data))
}

func handleThreadEvent(
	writer *eventWriter,
	h *etw.EventRecordHelper,
	opcode uint16,
) {
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

func getUintAny(
	h *etw.EventRecordHelper,
	names ...string,
) uint64 {
	for _, name := range names {
		if value, err := h.GetPropertyUint(name); err == nil {
			return value
		}
	}

	return 0
}

func getStringAny(
	h *etw.EventRecordHelper,
	names ...string,
) string {
	for _, name := range names {
		if value, err := h.GetPropertyString(name); err == nil {
			return value
		}
	}

	return ""
}

func buildManifestFileEvent(
	h *etw.EventRecordHelper,
	names *handleNameCache,
) (Event, bool) {
	var event Event

	event.EventID = h.EventID()
	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	// Microsoft-Windows-Kernel-File is a manifest provider,
	// so the event header PID is the process that issued the operation.
	event.PID = uint64(h.EventRec.EventHeader.ProcessId)

	// Versioned schemas use either ThreadId or IssuingThreadId.
	event.ThreadID = getUintAny(
		h,
		"ThreadId",
		"IssuingThreadId",
	)

	switch event.EventID {
	case 10, 11:
		// NameCreate / NameDelete.
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
		event.FileName = getStringAny(
			h,
			"FileName",
			"OpenPath",
		)

		if event.FileName != "" {
			names.putBoth(
				event.FileObject,
				event.FileKey,
				event.FileName,
			)
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

		event.Offset = getUintAny(
			h,
			"ByteOffset",
			"Offset",
		)

		event.IoSize = getUintAny(
			h,
			"IOSize",
			"IoSize",
			"Length",
		)

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

		event.Offset = getUintAny(
			h,
			"ByteOffset",
			"Offset",
		)

		event.IoSize = getUintAny(
			h,
			"IOSize",
			"IoSize",
			"Length",
		)

		event.Type = "file_write"

	case 26:
		// DeletePath.
		event.FileObject, event.FileKey = fileObjectAndKey(h)

		event.FileName = getStringAny(
			h,
			"FilePath",
			"FileName",
		)

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Type = "file_delete_information"

	case 27:
		// RenamePath.
		event.FileObject, event.FileKey = fileObjectAndKey(h)

		event.FileName = getStringAny(
			h,
			"FilePath",
			"FileName",
		)

		if event.FileName == "" {
			event.FileName = names.get(event.FileObject)
		}

		if event.FileName == "" {
			event.FileName = names.get(event.FileKey)
		}

		event.Type = "file_rename"

	case 30:
		// CreateNewFile.
		event.FileObject = getUintAny(h, "FileObject")
		event.FileName = getStringAny(h, "FileName")

		if event.FileName != "" {
			names.put(
				event.FileObject,
				event.FileName,
			)
		}

		event.Type = "file_create"

	default:
		return Event{}, false
	}

	return event, true
}