package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tekert/goetw/etw"
)

type Event struct {
	Type      string `json:"type"`
	Time      string `json:"time"`
	EventID   uint16 `json:"event_id"`
	PID       uint64 `json:"pid,omitempty"`
	ThreadID  uint64 `json:"thread_id,omitempty"`
	PPID      uint64 `json:"ppid,omitempty"`
	SessionID uint64 `json:"session_id,omitempty"`
	Image     string `json:"image,omitempty"`
	Command   string `json:"command,omitempty"`
	ExitCode  int64  `json:"exit_code,omitempty"`

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
	stopPath       = `C:\ThreatBox\output\collector.stop`
	flushEvery     = 500 * time.Millisecond
	lostCheckEvery = 2 * time.Second
	stopCheckEvery = 250 * time.Millisecond
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

	// Kernel-File provider, consumed only by the file consumer.
	kernelFileGuid = etw.MustParseGUID(
		"{edd08927-9cc4-4e65-b970-c2560fb5c289}",
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
	mu     sync.Mutex
	file   *os.File
	buf    *bufio.Writer
	closed bool

	diagMu       sync.Mutex
	diagActive   int
	diagStarted  uint64
	diagFinished uint64
	diagLastOp   string
	diagLastAt   time.Time
}

// beginDiagnosticOp records an in-flight writer operation without using the
// writer mutex, so the heartbeat can still inspect it if a write/flush blocks.
func (w *eventWriter) beginDiagnosticOp(name string) func() {
	w.diagMu.Lock()
	w.diagActive++
	w.diagStarted++
	w.diagLastOp = name
	w.diagLastAt = time.Now()
	w.diagMu.Unlock()

	return func() {
		w.diagMu.Lock()
		w.diagActive--
		w.diagFinished++
		w.diagMu.Unlock()
	}
}

func (w *eventWriter) diagnosticSnapshot() string {
	w.diagMu.Lock()
	defer w.diagMu.Unlock()
	if w.diagActive == 0 {
		return fmt.Sprintf("active=0 started=%d finished=%d last=%q", w.diagStarted, w.diagFinished, w.diagLastOp)
	}
	return fmt.Sprintf("active=%d started=%d finished=%d last=%q lastAge=%s",
		w.diagActive, w.diagStarted, w.diagFinished, w.diagLastOp,
		time.Since(w.diagLastAt).Round(time.Millisecond))
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
	defer w.beginDiagnosticOp("write")()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("write after event writer closed")
	}
	_, err = w.buf.Write(data)
	return err
}

func (w *eventWriter) flush(durable bool) error {
	defer w.beginDiagnosticOp("flush")()
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("flush after event writer closed")
	}
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
	defer w.beginDiagnosticOp("close")()
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	var closeErr error
	if err := w.buf.Flush(); err != nil {
		closeErr = fmt.Errorf("flush buffer during close: %w", err)
	} else if err := w.file.Sync(); err != nil {
		closeErr = fmt.Errorf("sync file during close: %w", err)
	} else if r1, _, err := procFlushFileBuffers.Call(w.file.Fd()); r1 == 0 {
		closeErr = fmt.Errorf("FlushFileBuffers during close: %w", err)
	}

	// Mark closed while holding the mutex so no callback can write after the
	// final flush begins or race the file close.
	w.closed = true
	if err := w.file.Close(); err != nil && closeErr == nil {
		closeErr = fmt.Errorf("close event file: %w", err)
	}
	return closeErr
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

func stopConsumerBounded(name string, stop func(), timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		fmt.Printf("DIAG: %s consumer stop returned\n", name)
		return true
	case <-timer.C:
		fmt.Printf("DIAG: %s consumer stop timed out after %s; continuing bounded shutdown\n", name, timeout)
		return false
	}
}

const goroutineDumpPath = `C:\ThreatBox\output\collector-goroutines.txt`

var shutdownStart time.Time
var timestampSampleMu sync.Mutex
var timestampSampleCount int

func stage(name string) func() {
	t0 := time.Now()
	fmt.Printf("DIAG %s +%v %s: started\n",
		t0.Format("15:04:05.000"), t0.Sub(shutdownStart).Round(time.Millisecond), name)
	return func() {
		fmt.Printf("DIAG %s +%v %s: returned (took %v)\n",
			time.Now().Format("15:04:05.000"),
			time.Since(shutdownStart).Round(time.Millisecond), name,
			time.Since(t0).Round(time.Millisecond))
	}
}

// eventProgress distinguishes raw event delivery from successful arrival at
// EventPreparedCallback. If raw advances but prepared stalls, goetw is stuck
// before the application's event handler (for this consumer).
type eventProgress struct {
	name          string
	raw           uint64
	prepared      uint64
	skipped       uint64
	mu            sync.Mutex
	currentHeader etw.EventHeader
	hasHeader     bool
	currentStage  string
	currentAt     time.Time
}

func newEventProgress(name string) *eventProgress { return &eventProgress{name: name} }

// describeEventHeader formats the saved header only when a heartbeat is emitted,
// rather than formatting every incoming ETW event and perturbing event throughput.
func describeEventHeader(h etw.EventHeader) string {
	return fmt.Sprintf("provider=%v descriptor=%+v pid=%d tid=%d rawTimestamp=%v",
		h.ProviderId, h.EventDescriptor, h.ProcessId, h.ThreadId, h.TimeStamp)
}

func sameEventHeader(a, b etw.EventHeader) bool {
	return a.ProviderId == b.ProviderId && a.EventDescriptor == b.EventDescriptor &&
		a.ProcessId == b.ProcessId && a.ThreadId == b.ThreadId && a.TimeStamp == b.TimeStamp
}

func (p *eventProgress) onRaw(er *etw.EventRecord, decode bool) bool {
	seq := atomic.AddUint64(&p.raw, 1)
	var header etw.EventHeader
	if er != nil {
		header = er.EventHeader
	}
	p.mu.Lock()
	p.currentHeader = header
	p.hasHeader = er != nil
	if decode {
		p.currentStage = fmt.Sprintf("raw-to-TDH-decode #%d", seq)
	} else {
		atomic.AddUint64(&p.skipped, 1)
		p.currentStage = fmt.Sprintf("raw-filter-skipped #%d", seq)
	}
	p.currentAt = time.Now()
	p.mu.Unlock()
	return decode
}

func (p *eventProgress) onPrepared(h *etw.EventRecordHelper) {
	seq := atomic.AddUint64(&p.prepared, 1)
	var header etw.EventHeader
	if h != nil && h.EventRec != nil {
		header = h.EventRec.EventHeader
	}
	p.mu.Lock()
	p.currentHeader = header
	p.hasHeader = h != nil && h.EventRec != nil
	p.currentStage = fmt.Sprintf("EventPreparedCallback #%d", seq)
	p.currentAt = time.Now()
	p.mu.Unlock()
}

func (p *eventProgress) onCallbackDone(h *etw.EventRecordHelper) {
	var header etw.EventHeader
	if h != nil && h.EventRec != nil {
		header = h.EventRec.EventHeader
	}
	p.mu.Lock()
	if p.currentStage != "" && strings.HasPrefix(p.currentStage, "EventPreparedCallback") &&
		p.hasHeader == (h != nil && h.EventRec != nil) && (!p.hasHeader || sameEventHeader(p.currentHeader, header)) {
		p.currentStage = ""
		p.hasHeader = false
		p.currentAt = time.Time{}
	}
	p.mu.Unlock()
}

func (p *eventProgress) snapshot() string {
	raw := atomic.LoadUint64(&p.raw)
	prepared := atomic.LoadUint64(&p.prepared)
	skipped := atomic.LoadUint64(&p.skipped)
	pending := raw - prepared - skipped
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.currentStage == "" {
		return fmt.Sprintf("raw=%d prepared=%d skipped=%d pending=%d inFlight=none", raw, prepared, skipped, pending)
	}
	identity := "<nil event>"
	if p.hasHeader {
		identity = describeEventHeader(p.currentHeader)
	}
	return fmt.Sprintf("raw=%d prepared=%d skipped=%d pending=%d stage=%q age=%s event={%s}",
		raw, prepared, skipped, pending, p.currentStage,
		time.Since(p.currentAt).Round(time.Millisecond), identity)
}

func writeGoroutineSnapshot(path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("DIAG: create goroutine snapshot %s: %v\n", path, err)
		return
	}
	if p := pprof.Lookup("goroutine"); p != nil {
		if err := p.WriteTo(f, 2); err != nil {
			fmt.Printf("DIAG: write goroutine snapshot %s: %v\n", path, err)
		}
	}
	if err := f.Sync(); err != nil {
		fmt.Printf("DIAG: sync goroutine snapshot %s: %v\n", path, err)
	}
	if err := f.Close(); err != nil {
		fmt.Printf("DIAG: close goroutine snapshot %s: %v\n", path, err)
	}
	fmt.Printf("DIAG: goroutine snapshot written: %s\n", path)
}

// startWatchdogSnapshots takes multiple snapshots while shutdown is blocked.
// The first snapshot keeps the old filename for compatibility.
func startWatchdogSnapshots(path string, intervals []time.Duration, progress func()) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		started := time.Now()
		for i, after := range intervals {
			t := time.NewTimer(time.Until(started.Add(after)))
			select {
			case <-done:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				return
			case <-t.C:
			}
			if progress != nil {
				progress()
			}
			out := path
			if i > 0 {
				out = strings.TrimSuffix(path, ".txt") + fmt.Sprintf("-%02ds.txt", int(after.Seconds()))
			}
			writeGoroutineSnapshot(out)
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func startProgressHeartbeat(done <-chan struct{}, report func()) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				report()
			}
		}
	}()
}

// Log the raw ETW timestamp alongside goetw's converted timestamp for the
// first five events. The library already logs each consumer trace's ClockType.
func logTimestampSample(h *etw.EventRecordHelper) {
	timestampSampleMu.Lock()
	if timestampSampleCount >= 5 {
		timestampSampleMu.Unlock()
		return
	}
	timestampSampleCount++
	n := timestampSampleCount
	timestampSampleMu.Unlock()

	fmt.Printf("DIAG timestamp sample=%d raw=%v converted=%s now=%s provider=%v eventID=%d\n",
		n,
		h.EventRec.EventHeader.TimeStamp,
		h.Timestamp().Format(time.RFC3339Nano),
		time.Now().Format(time.RFC3339Nano),
		h.EventRec.EventHeader.ProviderId,
		h.EventID(),
	)
}

func reportProgress(writer *eventWriter, kernelProgress, fileProgress *eventProgress) {
	fmt.Printf("DIAG PROGRESS shutdown+%s kernel={%s} file={%s} writer={%s}\n",
		time.Since(shutdownStart).Round(time.Millisecond),
		kernelProgress.snapshot(), fileProgress.snapshot(), writer.diagnosticSnapshot())
}

// Decode only providers this consumer actually handles. EventRecordCallback runs
// before goetw calls TdhGetEventInformation, so returning false here avoids
// schema decoding for unrelated events.
func shouldDecodeKernelEvent(er *etw.EventRecord) bool {
	if er == nil {
		return false
	}
	provider := er.EventHeader.ProviderId
	return provider == *etw.ProcessKernelGuid ||
		provider == *etw.ThreadKernelGuid ||
		provider == *tcpIPGuid ||
		provider == *udpIPGuid ||
		provider == *imageLoadGuid ||
		provider == *registryGuid ||
		provider == *systemRegistryGuid
}

func shouldDecodeFileEvent(er *etw.EventRecord) bool {
	if er == nil {
		return false
	}
	provider := er.EventHeader.ProviderId
	return provider == *kernelFileGuid || provider == *dnsClientGuid
}

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	writer, err := newEventWriter(outputPath)
	if err != nil {
		fmt.Println("output:", err)
		return 1
	}
	defer func() {
		if err := writer.close(); err != nil {
			fmt.Printf("DIAG: deferred event writer close failed: %v\n", err)
			exitCode = 1
		}
	}()

	// Clear stale control markers for this run before advertising readiness.
	_ = os.Remove(readyPath)
	_ = os.Remove(stopPath)

	fmt.Println("DIAG BUILD: etw-stage-probe-v1; observations=3s,8s,15s,30s,45s,60s,75s,90s,105s,120s; consumer-stop-cap=65s")
	fmt.Println("ETW collector started")
	fmt.Println("Output:", outputPath)

	// Session 1: NT Kernel Logger
	// Process + Thread + TCP/IP + Registry events.
	kernelFlags := etw.KernelNtFlag(
		etw.EVENT_TRACE_FLAG_PROCESS |
			etw.EVENT_TRACE_FLAG_THREAD |
			etw.EVENT_TRACE_FLAG_NETWORK_TCPIP |
			// etw.EVENT_TRACE_FLAG_REGISTRY |
			etw.EVENT_TRACE_FLAG_IMAGE_LOAD,
	)

	kernelSession := etw.NewKernelRealTimeSession(kernelFlags)
	var stopKernelSessionOnce sync.Once
	stopKernelSession := func() {
		stopKernelSessionOnce.Do(func() {
			fmt.Println("DIAG: stopping NT Kernel Logger session")
			if err := kernelSession.Stop(); err != nil {
				fmt.Println("DIAG: stopping NT Kernel Logger session:", err)
			}
			fmt.Println("DIAG: NT Kernel Logger session stop returned")
		})
	}
	defer stopKernelSession()

	if err := kernelSession.Start(); err != nil {
		fmt.Println("kernel session:", err)
		exitCode = 1
		return
	}

	fmt.Println("ETW kernel session started")

	fmt.Println("DIAG: entering file-session setup")
	// Session 2: Microsoft-Windows-Kernel-File.
	// Use explicit GUIDs to avoid provider-name enumeration in the guest.
	fileSession := etw.NewRealTimeSession("ThreatBox-Kernel-File")
	var stopFileSessionOnce sync.Once
	stopFileSession := func() {
		stopFileSessionOnce.Do(func() {
			fmt.Println("DIAG: stopping ThreatBox-Kernel-File session")
			if err := fileSession.Stop(); err != nil {
				fmt.Println("DIAG: stopping ThreatBox-Kernel-File session:", err)
			}
			fmt.Println("DIAG: ThreatBox-Kernel-File session stop returned")
		})
	}
	defer stopFileSession()

	fmt.Println("DIAG: configuring Kernel-File provider by GUID")
	fileProvider := etw.Provider{
		GUID:             *kernelFileGuid,
		Name:             "Microsoft-Windows-Kernel-File",
		EnableLevel:      0xff,
		MatchAnyKeyword:  0x1f90,
		MatchAllKeyword:  0,
		EnableProperties: etw.EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
		Filters: []etw.ProviderFilter{
			etw.NewEventIDFilter(true, 10, 11, 12, 15, 16, 26, 27, 30),
		},
	}

	fmt.Println("DIAG: enabling Kernel-File provider")
	if err := fileSession.EnableProvider(fileProvider); err != nil {
		fmt.Println("kernel-file enable:", err)
		exitCode = 1
		return
	}
	fmt.Println("DIAG: Kernel-File provider enabled")

	dnsProvider := etw.Provider{
		GUID:             *etw.MustParseGUID("{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}"),
		Name:             "Microsoft-Windows-DNS-Client",
		EnableLevel:      0xff,
		MatchAnyKeyword:  0xffffffffffffffff,
		MatchAllKeyword:  0,
		EnableProperties: etw.EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
		Filters: []etw.ProviderFilter{
			etw.NewEventIDFilter(true, 3006, 3008),
		},
	}

	fmt.Println("DIAG: enabling DNS provider")
	if err := fileSession.EnableProvider(dnsProvider); err != nil {
		fmt.Println("dns-client enable:", err)
		exitCode = 1
		return
	}
	fmt.Println("DIAG: DNS provider enabled")

	fmt.Println("DIAG: starting file session")
	if err := fileSession.Start(); err != nil {
		fmt.Println("kernel-file session:", err)
		exitCode = 1
		return
	}

	fmt.Println("DIAG: file session started successfully")
	fmt.Println("ETW kernel-file session started")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Consumer for Process + Thread + Network + Registry events.
	kernelConsumer := etw.NewConsumer(ctx)
	kernelConsumer.FromSessions(kernelSession)

	// Consumer for File events.
	fileConsumer := etw.NewConsumer(ctx)
	fileConsumer.FromSessions(fileSession)

	fileNames := newHandleNameCache()
	registryNames := newHandleNameCache()
	kernelProgress := newEventProgress("kernel")
	fileProgress := newEventProgress("file")

	// This callback runs before goetw's schema decoding. If raw advances while
	// prepared stops, inspect the active helper/TDH calls in the DIAG PROGRESS heartbeat.
	kernelConsumer.EventRecordCallback = func(er *etw.EventRecord) bool {
		return kernelProgress.onRaw(er, shouldDecodeKernelEvent(er))
	}
	fileConsumer.EventRecordCallback = func(er *etw.EventRecord) bool {
		return fileProgress.onRaw(er, shouldDecodeFileEvent(er))
	}

	kernelConsumer.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
		kernelProgress.onPrepared(h)
		defer kernelProgress.onCallbackDone(h)
		logTimestampSample(h)
		opcode := h.EventID()
		providerID := h.EventRec.EventHeader.ProviderId

		if providerID == *etw.ProcessKernelGuid {
			// Capture process rundown (DCStart/DCEnd) as well as normal
			// start/stop events. DCStart lets analysis learn about processes
			// that were already alive when the ETW session began. DCEnd is
			// a trace rundown event, not proof that the process exited.
			if opcode >= 1 && opcode <= 4 {
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
		fileProgress.onPrepared(h)
		defer fileProgress.onCallbackDone(h)
		logTimestampSample(h)
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

	fmt.Println("DIAG: starting kernel consumer")
	if err := kernelConsumer.Start(); err != nil {
		fmt.Println("kernel consumer:", err)
		exitCode = 1
		return
	}

	fmt.Println("DIAG: kernel consumer succeeded; starting file consumer")
	if err := fileConsumer.Start(); err != nil {
		fmt.Println("file consumer:", err)
		exitCode = 1
		return
	}

	fmt.Println("DIAG: consumers started; writing readiness marker")
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0644); err != nil {
		fmt.Println("ready signal:", err)
		exitCode = 1
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

	stopTicker := time.NewTicker(stopCheckEvery)
	defer stopTicker.Stop()

	var lastLost uint64
	shuttingDown := false
	shutdown := func(reason string) {
		if shuttingDown {
			return
		}
		shuttingDown = true
		shutdownStart = time.Now()
		stopWatchdog := startWatchdogSnapshots(goroutineDumpPath,
			[]time.Duration{3 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second, 45 * time.Second, 60 * time.Second, 75 * time.Second, 90 * time.Second, 105 * time.Second, 120 * time.Second},
			func() { reportProgress(writer, kernelProgress, fileProgress) })
		defer stopWatchdog()
		heartbeatDone := make(chan struct{})
		startProgressHeartbeat(heartbeatDone, func() { reportProgress(writer, kernelProgress, fileProgress) })
		defer close(heartbeatDone)
		fmt.Printf("DIAG shutdown reason=%q started at %s\n", reason, shutdownStart.Format(time.RFC3339Nano))

		func() { defer stage("cancel consumer context")(); cancel() }()
		func() { defer stage("stop file ETW session")(); stopFileSession() }()
		func() { defer stage("stop kernel ETW session")(); stopKernelSession() }()

		fileStopped := false
		func() {
			defer stage("stop file consumer")()
			fileStopped = stopConsumerBounded("file", func() { fileConsumer.Stop() }, 65*time.Second)
		}()
		kernelStopped := false
		func() {
			defer stage("stop kernel consumer")()
			kernelStopped = stopConsumerBounded("kernel", func() { kernelConsumer.Stop() }, 65*time.Second)
		}()

		if !fileStopped || !kernelStopped {
			fmt.Println("DIAG WARNING: one or more consumers are still active; events.jsonl may be incomplete. Writer has a closed-state guard to prevent file-close races.")
		}
		func() {
			defer stage("flush and close event writer")()
			if err := writer.close(); err != nil {
				fmt.Printf("DIAG: event writer close failed: %v\n", err)
				exitCode = 1
			}
		}()
		if !fileStopped || !kernelStopped {
			fmt.Printf("DIAG: shutdown incomplete: fileConsumerStopped=%t kernelConsumerStopped=%t\n", fileStopped, kernelStopped)
			exitCode = 1
		}
		reportProgress(writer, kernelProgress, fileProgress)
		fmt.Printf("DIAG shutdown finished after %s (exitCode=%d)\n", time.Since(shutdownStart).Round(time.Millisecond), exitCode)
	}

	for {
		select {
		case <-sigCh:
			shutdown("signal")
			return

		case <-stopTicker.C:
			if _, err := os.Stat(stopPath); err == nil {
				fmt.Println("collector stop requested")
				shutdown("stop marker")
				return
			} else if !os.IsNotExist(err) {
				fmt.Println("stop marker check:", err)
			}

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
	event.PID = getUintAny(h, "ProcessId")

	switch opcode {
	case 1:
		event.Type = "process_start"
	case 2:
		event.Type = "process_stop"
	case 3:
		event.Type = "process_rundown"
	case 4:
		event.Type = "process_rundown_end"
	default:
		return
	}

	// Start and DCStart records carry the best available process identity.
	// Stop/DCEnd records may carry a subset, so best-effort property reads
	// are deliberately non-fatal.
	if opcode == 1 || opcode == 3 {
		event.PPID, _ = h.GetPropertyUint("ParentId")
		event.SessionID, _ = h.GetPropertyUint("SessionId")
		event.Image, _ = h.GetPropertyString("ImageFileName")
		event.Command, _ = h.GetPropertyString("CommandLine")
	} else {
		event.ExitCode, _ = h.GetPropertyInt("ExitStatus")
		event.Image, _ = h.GetPropertyString("ImageFileName")
	}

	if err := writer.write(event); err != nil {
		fmt.Printf("WRITE ERROR: %v\n", err)
		return
	}

	// Keep the existing eager flush for actual lifecycle transitions. A
	// process rundown can contain hundreds of snapshot records; the regular
	// writer ticker and final close durably flush those without forcing a
	// separate buffer flush for every snapshot item.
	if opcode == 1 || opcode == 2 {
		if err := writer.flush(false); err != nil {
			fmt.Printf("FLUSH ERROR: %v\n", err)
		}
	}

	// Rundown records are high-volume snapshots. Persist them, but avoid
	// flooding sample-console.log with hundreds or thousands of infrastructure
	// processes; actual start/stop records retain the existing diagnostic log.
	if opcode == 3 || opcode == 4 {
		return
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

	if event.EventID == 12 || event.EventID == 15 {
		fmt.Printf(
			"TCP SCHEMA | eventID=%d | headerPID=%d | properties=%q\n",
			event.EventID,
			h.EventRec.EventHeader.ProcessId,
			h.GetEventPropertyNames(),
		)
	}

	event.Time = h.Timestamp().Format(time.RFC3339Nano)

	event.PID = getUintAny(h, "PID")
	if event.PID == 0 {
		event.PID = uint64(h.EventRec.EventHeader.ProcessId)
		if event.PID == 0xffffffff {
			event.PID = 0
		}
	}

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
	event.SourcePort = normalizeNetworkPort(
		getUintAny(h, "sport", "SourcePort"),
	)
	event.DestPort = normalizeNetworkPort(
		getUintAny(h, "dport", "DestinationPort"),
	)

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

func normalizeNetworkPort(port uint64) uint64 {
	if port > 0xffff {
		return port
	}

	p := uint16(port)
	return uint64((p << 8) | (p >> 8))
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
