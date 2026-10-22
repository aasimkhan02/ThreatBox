package engine

import (
	"testing"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
)

func eventTimeForTest(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestNormalizeETWPIDSentinels(t *testing.T) {
	for _, pid := range []uint64{0xffffffff, ^uint64(0)} {
		if got := normalizeETWPID(pid); got != 0 {
			t.Errorf("normalizeETWPID(%#x) = %d, want 0", pid, got)
		}
	}
	if got := normalizeETWPID(1234); got != 1234 {
		t.Fatalf("valid PID changed: got %d, want 1234", got)
	}
}

func TestProcessPIDReuseUsesEventTimestamp(t *testing.T) {
	telemetry := &telemetry{ProcessEvents: []*analysis.Event{
		{Type: "process_start", Time: "2026-10-20T10:00:00Z", PID: 42, Image: "first.exe"},
		{Type: "process_stop", Time: "2026-10-20T10:00:10Z", PID: 42},
		{Type: "process_start", Time: "2026-10-20T10:00:20Z", PID: 42, Image: "second.exe"},
	}}
	buildProcessHistory(telemetry)

	first := processLifetimeAt(telemetry, 42, eventTimeForTest("2026-10-20T10:00:05Z"), true)
	if first == nil || first.Node.Image != "first.exe" {
		t.Fatalf("old event matched %+v, want first.exe instance", first)
	}
	second := processLifetimeAt(telemetry, 42, eventTimeForTest("2026-10-20T10:00:25Z"), true)
	if second == nil || second.Node.Image != "second.exe" {
		t.Fatalf("new event matched %+v, want second.exe instance", second)
	}
}

func TestThreadIDReuseUsesHistoricalOwner(t *testing.T) {
	telemetry := &telemetry{
		ProcessEvents: []*analysis.Event{
			{Type: "process_start", Time: "2026-10-20T10:00:00Z", PID: 10, Image: "parent.exe"},
			{Type: "process_start", Time: "2026-10-20T10:00:20Z", PID: 20, Image: "child.exe"},
		},
		ThreadEvents: []*analysis.Event{
			{Type: "thread_start", Time: "2026-10-20T10:00:01Z", PID: 10, ThreadID: 7},
			{Type: "thread_stop", Time: "2026-10-20T10:00:10Z", PID: 10, ThreadID: 7},
			{Type: "thread_start", Time: "2026-10-20T10:00:21Z", PID: 20, ThreadID: 7},
		},
	}
	buildProcessHistory(telemetry)
	buildThreadHistory(telemetry)

	oldOwner := threadLifetimeAt(telemetry, 7, eventTimeForTest("2026-10-20T10:00:05Z"), true)
	if oldOwner == nil || oldOwner.PID != 10 {
		t.Fatalf("old TID event owner = %+v, want PID 10", oldOwner)
	}
	newOwner := threadLifetimeAt(telemetry, 7, eventTimeForTest("2026-10-20T10:00:25Z"), true)
	if newOwner == nil || newOwner.PID != 20 {
		t.Fatalf("reused TID event owner = %+v, want PID 20", newOwner)
	}
}

func TestProcessRundownProvidesInstanceForAlreadyRunningPID(t *testing.T) {
	telemetry := &telemetry{ProcessEvents: []*analysis.Event{
		{Type: "process_rundown", Time: "2026-10-20T10:00:00Z", PID: 77, PPID: 4, Image: "already-running.exe"},
	}}
	buildProcessHistory(telemetry)
	got := processLifetimeAt(telemetry, 77, eventTimeForTest("2026-10-20T10:00:03Z"), true)
	if got == nil || got.Node.Image != "already-running.exe" {
		t.Fatalf("rundown PID was not resolvable: %+v", got)
	}
}

func TestUnknownPIDCanFallbackToTimestampedThreadOwner(t *testing.T) {
	telemetry := &telemetry{
		ProcessEvents: []*analysis.Event{
			{Type: "process_start", Time: "2026-10-20T10:00:00Z", PID: 10, Image: "sample.exe", Command: `C:\ThreatBox\sample\sample.exe`},
		},
		ThreadEvents: []*analysis.Event{
			{Type: "thread_start", Time: "2026-10-20T10:00:01Z", PID: 10, ThreadID: 99},
		},
	}
	buildProcessHistory(telemetry)
	buildThreadHistory(telemetry)
	fileEvent := &analysis.Event{
		Type: "file_write", Time: "2026-10-20T10:00:02Z", PID: 0xffffffff,
		ThreadID: 99, FileName: `C:\Temp\marker.txt`,
	}
	telemetry.FileEvents = []*analysis.Event{fileEvent}
	telemetry.RelevantInstances = map[*processLifetime]bool{telemetry.ProcessHistory[0]: true}
	resolveEventOwnership(telemetry)
	if fileEvent.PID != 10 {
		t.Fatalf("invalid ETW PID fallback = %d, want PID 10", fileEvent.PID)
	}
	if telemetry.EventOwners[fileEvent] != telemetry.ProcessHistory[0] {
		t.Fatal("event was not bound to the timestamp-matched sample process instance")
	}
}
