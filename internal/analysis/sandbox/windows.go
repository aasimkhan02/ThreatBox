package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type WindowsSandbox struct {
	ConfigPath string
	SamplePath string
	OutputPath string
	cmd        *exec.Cmd

	// MaxExecutionTime is a safety ceiling, not a completion signal.
	// Normal completion is detected via the guest shutting itself down
	// (see Execute) plus the analysis.done sentinel it writes before
	// doing so. This only fires if the sandbox hangs and never reaches
	// that point (e.g. the sample threw up a blocking dialog).
	MaxExecutionTime time.Duration
}

const (
	runtimeSampleDir = `C:\ThreatBox\runtime\sample`
	runtimeOutputDir = `C:\ThreatBox\runtime\output`

	sentinelFileName    = "analysis.done"
	startSampleFileName = "start-sample"
	etwReadyFileName    = "etw-ready"
	defaultMaxExecution = 15 * time.Minute

	// etwReadyPollInterval controls how often we check for the
	// etw-ready sentinel while waiting for the collector to come up.
	etwReadyPollInterval = 250 * time.Millisecond

	// etwReadyTimeout is a ceiling in case the collector never comes
	// up at all (crashed, provider enable failed, etc). This is a
	// fallback safety bound, not the normal-path signal - the normal
	// path is polling for etwReadyFileName below.
	etwReadyTimeout = 90 * time.Second
)

func (s *WindowsSandbox) Create() error {
	if _, err := os.Stat(s.ConfigPath); err != nil {
		return fmt.Errorf("sandbox config not found: %w", err)
	}

	if err := os.MkdirAll(runtimeSampleDir, 0755); err != nil {
		return fmt.Errorf("create sandbox sample directory: %w", err)
	}
	if err := os.MkdirAll(runtimeOutputDir, 0755); err != nil {
		return fmt.Errorf("create sandbox output directory: %w", err)
	}

	cmd := exec.Command("WindowsSandbox.exe", s.ConfigPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Windows Sandbox: %w", err)
	}

	s.cmd = cmd
	return nil
}

func (s *WindowsSandbox) CopySample(samplePath string) error {
	info, err := os.Stat(samplePath)
	if err != nil {
		return fmt.Errorf("sample not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("sample path is a directory")
	}

	if err := os.MkdirAll(runtimeSampleDir, 0755); err != nil {
		return fmt.Errorf("create sandbox sample directory: %w", err)
	}

	// Each job gets a clean host-side sample directory. The WSB file maps this
	// directory to C:\ThreatBox\sample and the sample is always presented to
	// the guest as sample.exe so the existing analyzer can identify it.
	entries, err := os.ReadDir(runtimeSampleDir)
	if err != nil {
		return fmt.Errorf("read sandbox sample directory: %w", err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(runtimeSampleDir, entry.Name())); err != nil {
			return fmt.Errorf("clean previous sample: %w", err)
		}
	}

	dest := filepath.Join(runtimeSampleDir, "sample.exe")
	if err := copyFile(samplePath, dest); err != nil {
		return fmt.Errorf("copy sample into sandbox runtime: %w", err)
	}

	s.SamplePath = dest
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}

// Execute waits for the sandbox to finish running the sample and shut
// itself down.
//
// Completion detection works like this:
//  1. The WSB LogonCommand runs sample.exe WITHOUT "start", so the guest's
//     cmd.exe blocks until the sample process itself exits. That is the
//     real "sample is done" event.
//  2. Immediately after, the LogonCommand kills the ETW collector, writes
//     an analysis.done sentinel into the mapped output folder, and issues
//     a guest shutdown.
//  3. The guest shutdown terminates WindowsSandbox.exe on the host, which
//     is exactly the process s.cmd wraps - so cmd.Wait() returning IS the
//     real completion signal, not a guess based on timing or file size.
//  4. MaxExecutionTime is only a safety ceiling in case the guest never
//     reaches step 2 (e.g. the sample blocks on a UI dialog forever). It
//     is not used to decide "the sample is probably done" - it only
//     decides "something is stuck, give up and clean up."
//  5. After cmd.Wait() returns, we still check for the sentinel file. If
//     WindowsSandbox.exe exited for some other reason (crash, manual
//     close, host issue) without the sentinel present, that is treated
//     as a failure rather than a false "success".
func (s *WindowsSandbox) Execute() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return fmt.Errorf("sandbox has not been started")
	}

	if s.SamplePath == "" {
		return fmt.Errorf("no sample configured")
	}

	if _, err := os.Stat(s.SamplePath); err != nil {
		return fmt.Errorf("sample not found: %w", err)
	}

	if s.OutputPath == "" {
		return fmt.Errorf("output path not configured")
	}

	timeout := s.MaxExecutionTime
	if timeout <= 0 {
		timeout = defaultMaxExecution
	}

	// Wait for the ETW collector to actually finish starting up before
	// releasing the sample. The collector (main.go) only writes this
	// file once both ETW sessions and both consumers are live - that
	// is the real "safe to run the sample" signal. A fixed sleep here
	// is a race: on a slow guest boot the sample can start and exit
	// before the kernel session is actually capturing process-start
	// events, which silently drops the one event Analyze() depends on
	// ("no sample.exe process found").
	if err := s.waitForETWReady(etwReadyTimeout); err != nil {
		return fmt.Errorf("ETW collector did not become ready: %w", err)
	}

	// Signal the guest to launch sample.exe.
	trigger := filepath.Join(s.OutputPath, startSampleFileName)

	if err := os.WriteFile(trigger, []byte("run\n"), 0644); err != nil {
		return fmt.Errorf("signal sample start: %w", err)
	}

	fmt.Println("sample start signal sent")

	// Now wait for the Sandbox to finish:
	// sample → stop ETW → analysis.done → shutdown.
	waitErr := make(chan error, 1)

	go func() {
		waitErr <- s.cmd.Wait()
	}()

	select {
	case err := <-waitErr:
		if err != nil {
			fmt.Printf("Windows Sandbox process exited: %v\n", err)
		}

	case <-time.After(timeout):
		_ = s.forceKill()

		return fmt.Errorf(
			"sandbox did not signal completion within safety timeout (%s); "+
				"the sample or guest likely hung",
			timeout,
		)
	}

	sentinel := filepath.Join(s.OutputPath, sentinelFileName)

	if _, err := os.Stat(sentinel); err != nil {
		return fmt.Errorf(
			"sandbox exited without writing completion sentinel %s: %w",
			sentinel,
			err,
		)
	}

	return nil
}
// waitForETWReady polls for the etw-ready sentinel that the collector
// writes once its kernel sessions and consumers are actually running.
// This replaces a fixed sleep, which was a race: it guessed a duration
// instead of checking the real signal the collector already emits.
func (s *WindowsSandbox) waitForETWReady(timeout time.Duration) error {
	readyFile := filepath.Join(s.OutputPath, etwReadyFileName)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(etwReadyPollInterval)
	defer ticker.Stop()

	for {
		if _, err := os.Stat(readyFile); err == nil {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf(
				"timed out after %s waiting for %s",
				timeout,
				readyFile,
			)
		}

		<-ticker.C
	}
}

// forceKill is only used on the safety-timeout failure path, never on
// the normal completion path (where the guest has already shut itself
// down and the host process is already gone).
func (s *WindowsSandbox) forceKill() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	// If Wait() already returned, the process is already reaped and its
	// handle already closed by os/exec - Kill() on Windows surfaces that
	// as "invalid argument" rather than os.ErrProcessDone. Treat both as
	// "already gone", not a failure.
	if s.cmd.ProcessState != nil {
		return nil
	}
	if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("failed to force-kill sandbox: %w", err)
	}
	return nil
}

func (s *WindowsSandbox) Collect() (string, error) {
	if s.OutputPath == "" {
		return "", fmt.Errorf("output path not configured")
	}

	telemetryPath := filepath.Join(s.OutputPath, "events.jsonl")
	data, err := os.ReadFile(telemetryPath)
	if err != nil {
		return "", fmt.Errorf("failed to read telemetry: %w", err)
	}

	return string(data), nil
}

// Destroy is a safety net. On the normal path the guest has already shut
// itself down and WindowsSandbox.exe is already gone, so this is a no-op
// (Kill returns os.ErrProcessDone, which is treated as success). It only
// does real work on the timeout/failure path.
func (s *WindowsSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Normal path: Execute() already awaited Wait() and the guest already
	// shut itself down, so the process is already reaped. Nothing to do.
	if s.cmd.ProcessState != nil {
		s.cmd = nil
		return nil
	}

	if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("failed to destroy sandbox: %w", err)
	}

	s.cmd = nil
	return nil
}