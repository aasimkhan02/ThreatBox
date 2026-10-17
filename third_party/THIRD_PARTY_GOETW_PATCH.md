# Local patch to github.com/tekert/goetw v0.9.11

**Location:** `third_party/goetw` (wired in with `replace github.com/tekert/goetw => ./third_party/goetw`).
**Changed file:** `etw/etw_helpers.go`, function `newEventRecordHelper`, "Stage 2". Nothing else differs from v0.9.11.

## What changed
For classic MOF kernel events (`er.IsMof()`) on a schema-cache miss, the library now tries its own
`buildTraceInfoFromMof` first. If that returns an error (class/version not registered) it falls through to
the original `TdhGetEventInformation` path, whose existing MOF fallback is unchanged.

## Why
`TdhGetEventInformation` on the first classic Process event (v4, opcode 3, DCStart) blocked inside native TDH
for ~42 s (success run) and >70 s (failed run) in the Windows Sandbox guest. It runs on the ProcessTrace thread,
so no kernel events were delivered and `Consumer.Stop()` waited on it. The generator needs no native call.

## Verified by reading the source
- `Process_V4_TypeGroup1` (version 4, EventTypes 1,2,3,4,39) is registered and has ProcessId, ParentId,
  SessionId, ExitStatus, ImageFileName, CommandLine (the properties `main.go` reads).
- Thread V2/V3/V4, Image_Load V3, TcpIp V2 and UdpIp V2 classes are registered (property names the collector
  reads: TThreadId, ProcessId, ImageBase/ImageSize/ImageChecksum/FileName, PID/saddr/daddr/sport/dport).
- The generated template sets `DecodingSource = DecodingSourceWbem`, so every `TraceInfo.IsMof()` branch
  behaves as with a TDH-produced schema.
- Process V4's variable-size properties (ANSI/Unicode strings, WBEM SID) are sized in Go; `TdhGetPropertySize`
  is only a fallback.

## NOT verified (needs a Windows run)
- That generated schemas decode these events identically to TDH on this guest.
- That no later TDH call (e.g. `TdhFormatProperty`, in a file not reviewed) re-enters the same slow resolver.
- Classes/versions the guest emits that are not registered still use TDH and could still stall.

## Updating / removing
Re-apply `goetw-mof-first.patch` to a new upstream version, or delete `third_party/goetw`, run
`go mod edit -dropreplace github.com/tekert/goetw`, and rebuild.
