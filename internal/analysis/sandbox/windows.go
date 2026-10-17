package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type WindowsSandbox struct {
	ConfigPath       string
	SampleDir        string
	SamplePath       string
	OutputPath       string
	ToolsPath        string
	JobID            string
	MaxExecutionTime time.Duration

	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.RWMutex
	exited  bool
	exitErr error
}

const (
	defaultMaxExecution = 17 * time.Minute
	pollInterval        = 250 * time.Millisecond
	shutdownGrace       = 20 * time.Second
	destroyGrace        = 5 * time.Second
)

func (s *WindowsSandbox) Create() error {
	if s.cmd != nil {
		return fmt.Errorf("Sandbox has already been started")
	}
	if s.ConfigPath == "" {
		return fmt.Errorf("Sandbox configuration path is empty")
	}
	if s.OutputPath == "" {
		return fmt.Errorf("Sandbox output path is empty")
	}
	if s.JobID == "" {
		return fmt.Errorf("job ID is empty")
	}

	if _, err := os.Stat(s.ConfigPath); err != nil {
		return fmt.Errorf("Sandbox configuration unavailable: %w", err)
	}

	if err := os.MkdirAll(s.OutputPath, 0755); err != nil {
		return fmt.Errorf("create job output directory: %w", err)
	}

	hostLogPath := filepath.Join(
		filepath.Dir(s.OutputPath),
		"sandbox-host.log",
	)

	hostLog, err := os.OpenFile(
		hostLogPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return fmt.Errorf("create host Sandbox log: %w", err)
	}

	cmd := exec.Command("WindowsSandbox.exe", s.ConfigPath)
	cmd.Stdout = hostLog
	cmd.Stderr = hostLog

	if err := cmd.Start(); err != nil {
		_ = hostLog.Close()
		return fmt.Errorf("launch Windows Sandbox: %w", err)
	}

	s.cmd = cmd
	s.done = make(chan struct{})

	go func() {
		err := cmd.Wait()

		_ = hostLog.Sync()
		_ = hostLog.Close()

		s.mu.Lock()
		s.exitErr = err
		s.exited = true
		s.mu.Unlock()

		close(s.done)
	}()

	return nil
}

func (s *WindowsSandbox) CopySample(samplePath string) error {
	if s.SampleDir == "" {
		return fmt.Errorf("sample directory is not configured")
	}

	info, err := os.Stat(samplePath)
	if err != nil {
		return fmt.Errorf("sample unavailable: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("sample path is a directory")
	}

	if err := os.MkdirAll(s.SampleDir, 0755); err != nil {
		return fmt.Errorf("create sample directory: %w", err)
	}

	destination := filepath.Join(s.SampleDir, "sample.exe")
	if err := copyFile(samplePath, destination); err != nil {
		return fmt.Errorf("copy sample into job workspace: %w", err)
	}

	s.SamplePath = destination
	return nil
}

func copyFile(src, dst string) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.Create(dst)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(output, input)
	syncErr := output.Sync()
	closeErr := output.Close()

	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (s *WindowsSandbox) Execute() error {
	if s.cmd == nil || s.done == nil {
		return fmt.Errorf("Sandbox has not been started")
	}
	if s.SamplePath == "" {
		return fmt.Errorf("no sample configured")
	}
	if _, err := os.Stat(s.SamplePath); err != nil {
		return fmt.Errorf("sample missing from host workspace: %w", err)
	}

	timeout := s.MaxExecutionTime
	if timeout <= 0 {
		timeout = defaultMaxExecution
	}

	overallTimer := time.NewTimer(timeout)
	defer overallTimer.Stop()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastPhase = "waiting_for_guest_agent"
	var completedAt time.Time
	var shutdownTimer *time.Timer
	var shutdownChannel <-chan time.Time

	for {
		status, statusErr := ReadAgentStatus(s.OutputPath)

		if statusErr == nil && status.JobID == s.JobID {
			lastPhase = status.Phase

			switch status.Phase {
			case PhaseFailed:
				return guestStatusError(status)

			case PhaseCompleted:
				if completedAt.IsZero() {
					completedAt = time.Now()
					shutdownTimer = time.NewTimer(shutdownGrace)
					shutdownChannel = shutdownTimer.C
				}
			}
		}

		select {
		case <-s.done:
			finalStatus, err := ReadAgentStatus(s.OutputPath)
			if err == nil && finalStatus.JobID == s.JobID {
				if finalStatus.Phase == PhaseCompleted {
					if shutdownTimer != nil {
						shutdownTimer.Stop()
					}
					return nil
				}
				if finalStatus.Phase == PhaseFailed {
					return guestStatusError(finalStatus)
				}
				lastPhase = finalStatus.Phase
			}

			return fmt.Errorf(
				"Windows Sandbox exited before successful completion "+
					"(last guest phase: %q; process exit: %v)",
				lastPhase,
				s.processExitError(),
			)

		case <-ticker.C:
			// Read status again on the next iteration.

		case <-overallTimer.C:
			return fmt.Errorf(
				"Sandbox timed out after %s (last guest phase: %q)",
				timeout,
				lastPhase,
			)

		case <-shutdownChannel:
			return fmt.Errorf(
				"guest reported completion but Windows Sandbox "+
					"did not exit within %s",
				shutdownGrace,
			)
		}
	}
}

func guestStatusError(status AgentStatus) error {
	if status.Error != "" {
		return fmt.Errorf(
			"guest agent failed during phase %q: %s",
			status.Phase,
			status.Error,
		)
	}
	return fmt.Errorf(
		"guest agent reported failure during phase %q: %s",
		status.Phase,
		status.Message,
	)
}

func (s *WindowsSandbox) processExitError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exitErr
}

func (s *WindowsSandbox) Collect() (string, error) {
	if s.OutputPath == "" {
		return "", fmt.Errorf("output directory is not configured")
	}

	path := filepath.Join(s.OutputPath, EventsFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read collected telemetry: %w", err)
	}

	return string(data), nil
}

func (s *WindowsSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil || s.done == nil {
		return nil
	}

	// The guest may already be shutting down after reporting completion
	// or failure. Give it a short grace period before attempting cleanup.
	timer := time.NewTimer(destroyGrace)
	defer timer.Stop()

	select {
	case <-s.done:
		return nil
	case <-timer.C:
	}

	s.mu.RLock()
	exited := s.exited
	s.mu.RUnlock()
	if exited {
		return nil
	}

	killErr := s.cmd.Process.Kill()

	// Even if Kill reports an error, the process may have exited during
	// the call. Prefer observing actual process termination if possible.
	select {
	case <-s.done:
		return nil
	case <-time.After(3 * time.Second):
	}

	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return fmt.Errorf("failed to stop Windows Sandbox: %w", killErr)
	}

	return fmt.Errorf("Windows Sandbox did not exit after cleanup")
}
