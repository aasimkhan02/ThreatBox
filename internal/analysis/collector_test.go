package analysis

import (
	"errors"
	"testing"
)

func TestCollect_BasicFileFlow(t *testing.T) {
	raw := `1234  openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT, 0644) = 3
1234  write(3, "hello", 5) = 5
1234  close(3) = 0
1234  brk(NULL) = 0x55d2a1a3b000
`

	events, err := Collect(raw)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	// brk is unsupported and should be silently skipped.
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d: %+v", len(events), events)
	}

	open := events[0]
	if open.Type != EventFileOpen || open.Target != "/tmp/test.txt" || open.PID != 1234 {
		t.Errorf("unexpected open event: %+v", open)
	}

	write := events[1]
	if write.Type != EventFileWrite || write.Target != "3" || write.Metadata["data"] != "hello" {
		t.Errorf("unexpected write event: %+v", write)
	}

	closeEv := events[2]
	if closeEv.Type != EventFileClose || closeEv.Target != "3" {
		t.Errorf("unexpected close event: %+v", closeEv)
	}
}

func TestParse_EmptyLine(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Fatal("expected error for empty line")
	}
}

func TestParse_UnsupportedSyscall(t *testing.T) {
	_, err := Parse(`1234  brk(NULL) = 0x55d2a1a3b000`)
	if err == nil {
		t.Fatal("expected error for unsupported syscall")
	}
	if !errors.Is(err, ErrUnsupportedSyscall) {
		t.Fatalf("expected ErrUnsupportedSyscall, got %v", err)
	}
}