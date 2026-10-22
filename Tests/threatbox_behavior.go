// ThreatBox benign behavioral telemetry fixture.
// Build on Windows with: go build -o threatbox-behavior-test.exe threatbox_behavior_test.go
// It performs reversible/local file operations and runs harmless command echoes.
// It does NOT modify the registry, contact external hosts, install persistence,
// load custom DLLs, disable security controls, or delete user data.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	fmt.Println("ThreatBox benign behavior test starting")
	fmt.Printf("OS=%s PID=%d\n", runtime.GOOS, os.Getpid())

	root, err := os.MkdirTemp(os.TempDir(), "threatbox-benign-test-")
	if err != nil {
		fail("create temp directory", err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			fmt.Printf("cleanup warning: %v\n", err)
		} else {
			fmt.Println("temporary test directory cleaned up")
		}
	}()

	original := filepath.Join(root, "sample-alpha.txt")
	renamed := filepath.Join(root, "sample-alpha-renamed.txt")

	if err := os.WriteFile(original, []byte("ThreatBox benign test: initial content\n"), 0o600); err != nil {
		fail("create test file", err)
	}
	fmt.Println("FILE_CREATE: sample-alpha.txt")

	f, err := os.OpenFile(original, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fail("open test file for append", err)
	}
	_, writeErr := f.WriteString("append-only test activity\n")
	closeErr := f.Close()
	if writeErr != nil {
		fail("append test file", writeErr)
	}
	if closeErr != nil {
		fail("close test file", closeErr)
	}
	fmt.Println("FILE_WRITE: sample-alpha.txt")

	if _, err := os.ReadFile(original); err != nil {
		fail("read test file", err)
	}
	fmt.Println("FILE_READ: sample-alpha.txt")

	if err := os.Rename(original, renamed); err != nil {
		fail("rename test file", err)
	}
	fmt.Println("FILE_RENAME: sample-alpha.txt -> sample-alpha-renamed.txt")

	if runtime.GOOS == "windows" {
		// Harmless shell execution intended to exercise process telemetry.
		cmd := exec.Command("cmd.exe", "/d", "/c", "echo", "ThreatBox benign cmd telemetry")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("cmd telemetry step unavailable: %v\n", err)
		} else {
			fmt.Println("CHILD_PROCESS: cmd.exe completed")
		}

		// No scripts, downloads, encoded commands, or system changes.
		ps := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Write-Output 'ThreatBox benign PowerShell telemetry'")
		ps.Stdout = os.Stdout
		ps.Stderr = os.Stderr
		if err := ps.Run(); err != nil {
			fmt.Printf("PowerShell telemetry step unavailable: %v\n", err)
		} else {
			fmt.Println("CHILD_PROCESS: powershell.exe completed")
		}
	}

	// Leave the renamed file present briefly so collectors can observe it.
	time.Sleep(1500 * time.Millisecond)
	if err := os.Remove(renamed); err != nil {
		fail("delete test file", err)
	}
	fmt.Println("FILE_DELETE: sample-alpha-renamed.txt")
	fmt.Println("ThreatBox benign behavior test completed")
}

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}
