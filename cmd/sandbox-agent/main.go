package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/sandbox"
)

const (
	collectorReadyTimeout = 60 * time.Second
	collectorStopTimeout  = 150 * time.Second
	collectorKillTimeout  = 3 * time.Second
)

type collectorProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.RWMutex
	waitErr error
}

func (c *collectorProcess) exitError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.waitErr
}

type guestAgent struct {
	jobID     string
	outputDir string
	logger    *log.Logger
	status    sandbox.AgentStatus
	collector *collectorProcess
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (retErr error) {
	jobIDFlag := flag.String("job-id", "", "ThreatBox job ID")
	timeoutSecondsFlag := flag.Int(
		"timeout-seconds",
		900,
		"Maximum time to run the sample",
	)
	flag.Parse()

	outputDir := sandbox.GuestOutputDir
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		_ = shutdownGuest()
		return fmt.Errorf("create guest output directory: %w", err)
	}

	logPath := filepath.Join(outputDir, sandbox.AgentLogFileName)
	logFile, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		_ = shutdownGuest()
		return fmt.Errorf("open guest agent log: %w", err)
	}

	logger := log.New(logFile, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	agent := &guestAgent{
		jobID:     *jobIDFlag,
		outputDir: outputDir,
		logger:    logger,
		status: sandbox.AgentStatus{
			JobID: *jobIDFlag,
		},
	}

	defer func() {
		if retErr != nil {
			logger.Printf("FATAL: %v", retErr)

			if err := agent.stopCollector(); err != nil {
				logger.Printf("Collector cleanup error: %v", err)
			}

			if err := agent.setPhase(
				sandbox.PhaseFailed,
				"guest agent failed",
				retErr.Error(),
			); err != nil {
				logger.Printf("Cannot write failure status: %v", err)
			}
		}

		logger.Printf("Guest agent exiting")
		_ = logFile.Sync()
		_ = logFile.Close()

		// Let the mapped-folder write reach the host before shutdown.
		time.Sleep(750 * time.Millisecond)
		_ = shutdownGuest()
	}()

	if err := sandbox.ValidateJobID(agent.jobID); err != nil {
		return err
	}
	if *timeoutSecondsFlag <= 0 {
		return fmt.Errorf("timeout-seconds must be positive")
	}

	if err := agent.setPhase(
		sandbox.PhaseAgentStarted,
		"guest agent started",
		"",
	); err != nil {
		return err
	}

	return agent.execute(time.Duration(*timeoutSecondsFlag) * time.Second)
}

func (a *guestAgent) setPhase(phase, message, errorMessage string) error {
	a.status.Phase = phase
	a.status.Message = message
	a.status.Error = errorMessage

	if err := sandbox.WriteAgentStatus(a.outputDir, a.status); err != nil {
		return err
	}

	a.logger.Printf(
		"phase=%s message=%q error=%q",
		phase,
		message,
		errorMessage,
	)
	return nil
}

func (a *guestAgent) execute(sampleTimeout time.Duration) (retErr error) {
	if _, err := os.Stat(sandbox.GuestSamplePath); err != nil {
		return fmt.Errorf("sample is unavailable inside Sandbox: %w", err)
	}

	if err := a.setPhase(
		sandbox.PhaseCollectorStarting,
		"starting ETW collector",
		"",
	); err != nil {
		return err
	}

	collector, err := startCollector(a.outputDir, a.logger)
	if err != nil {
		return err
	}
	a.collector = collector
	a.status.CollectorPID = collector.cmd.Process.Pid

	if err := waitForCollectorReady(
		a.outputDir,
		collector,
		collectorReadyTimeout,
	); err != nil {
		return fmt.Errorf("ETW collector startup failed: %w", err)
	}

	if err := a.setPhase(
		sandbox.PhaseCollectorReady,
		"ETW collector ready",
		"",
	); err != nil {
		return err
	}

	sampleLogPath := filepath.Join(a.outputDir, sandbox.SampleLogFileName)
	sampleLog, err := os.OpenFile(
		sampleLogPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return fmt.Errorf("open sample console log: %w", err)
	}

	sampleCmd := exec.Command(sandbox.GuestSamplePath)
	sampleCmd.Dir = sandbox.GuestSampleDir
	sampleCmd.Stdout = sampleLog
	sampleCmd.Stderr = sampleLog

	if err := sampleCmd.Start(); err != nil {
		_ = sampleLog.Close()
		return fmt.Errorf("launch sample: %w", err)
	}

	a.status.SamplePID = sampleCmd.Process.Pid
	if err := a.setPhase(
		sandbox.PhaseSampleRunning,
		"sample started",
		"",
	); err != nil {
		_ = sampleCmd.Process.Kill()
		_ = sampleLog.Close()
		return err
	}

	sampleDone := make(chan error, 1)
	go func() {
		sampleDone <- sampleCmd.Wait()
	}()

	timeout := time.NewTimer(sampleTimeout)
	defer timeout.Stop()

	var sampleWaitErr error

	select {
	case sampleWaitErr = <-sampleDone:
		// ProcessState is populated by Wait before sampleDone is signalled.

	case <-a.collector.done:
		_ = sampleCmd.Process.Kill()
		select {
		case <-sampleDone:
		case <-time.After(2 * time.Second):
		}
		_ = sampleLog.Sync()
		_ = sampleLog.Close()
		return fmt.Errorf(
			"ETW collector exited while the sample was running: %v",
			collector.exitError(),
		)

	case <-timeout.C:
		_ = sampleCmd.Process.Kill()
		select {
		case <-sampleDone:
		case <-time.After(2 * time.Second):
		}

		_ = sampleLog.Sync()
		_ = sampleLog.Close()
		return fmt.Errorf("sample exceeded timeout %s", sampleTimeout)
	}

	_ = sampleLog.Sync()
	_ = sampleLog.Close()

	exitCode := -1
	if sampleCmd.ProcessState != nil {
		exitCode = sampleCmd.ProcessState.ExitCode()
	}

	a.status.SampleExitCode = &exitCode
	if sampleWaitErr != nil {
		a.logger.Printf(
			"Sample exited with code %d: %v",
			exitCode,
			sampleWaitErr,
		)
	}

	if err := a.setPhase(
		sandbox.PhaseSampleExited,
		fmt.Sprintf("sample exited with code %d", exitCode),
		"",
	); err != nil {
		return err
	}

	if err := a.stopCollector(); err != nil {
		return fmt.Errorf("stop ETW collector: %w", err)
	}

	if err := a.setPhase(
		sandbox.PhaseCollectorStopped,
		"ETW collector stopped and flushed",
		"",
	); err != nil {
		return err
	}

	return a.setPhase(
		sandbox.PhaseCompleted,
		"analysis telemetry collection completed",
		"",
	)
}

func startCollector(
	outputDir string,
	logger *log.Logger,
) (*collectorProcess, error) {
	readyPath := filepath.Join(outputDir, sandbox.ReadyFileName)
	stopPath := filepath.Join(outputDir, sandbox.StopCollectorFileName)

	_ = os.Remove(readyPath)
	_ = os.Remove(stopPath)

	collectorPath := filepath.Join(
		sandbox.GuestToolsDir,
		sandbox.CollectorExeName,
	)

	logPath := filepath.Join(outputDir, sandbox.CollectorLogFileName)
	logFile, err := os.OpenFile(
		logPath,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0644,
	)
	if err != nil {
		return nil, fmt.Errorf("open collector log: %w", err)
	}

	cmd := exec.Command(collectorPath)
	cmd.Dir = sandbox.GuestToolsDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("launch ETW collector: %w", err)
	}

	proc := &collectorProcess{
		cmd:  cmd,
		done: make(chan struct{}),
	}

	logger.Printf("ETW collector launched with PID %d", cmd.Process.Pid)

	go func() {
		waitErr := cmd.Wait()

		_ = logFile.Sync()
		_ = logFile.Close()

		proc.mu.Lock()
		proc.waitErr = waitErr
		proc.mu.Unlock()

		close(proc.done)
	}()

	return proc, nil
}

func waitForCollectorReady(
	outputDir string,
	proc *collectorProcess,
	timeout time.Duration,
) error {
	readyPath := filepath.Join(outputDir, sandbox.ReadyFileName)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		if _, err := os.Stat(readyPath); err == nil {
			return nil
		}

		select {
		case <-proc.done:
			return fmt.Errorf(
				"collector exited before readiness: %v",
				proc.exitError(),
			)

		case <-ticker.C:
			// Check marker and process again.

		case <-timer.C:
			return fmt.Errorf("timed out after %s waiting for %s", timeout, readyPath)
		}
	}
}

func (a *guestAgent) stopCollector() error {
	proc := a.collector
	if proc == nil {
		return nil
	}

	select {
	case <-proc.done:
		if err := proc.exitError(); err != nil {
			return fmt.Errorf("collector already exited with error: %w", err)
		}
		return nil
	default:
	}

	stopPath := filepath.Join(a.outputDir, sandbox.StopCollectorFileName)
	if err := os.WriteFile(stopPath, []byte("stop\n"), 0644); err != nil {
		return fmt.Errorf("write collector stop request: %w", err)
	}

	timer := time.NewTimer(collectorStopTimeout)
	defer timer.Stop()

	select {
	case <-proc.done:
		if err := proc.exitError(); err != nil {
			return fmt.Errorf("collector exited with error: %w", err)
		}
		return nil

	case <-timer.C:
		a.logger.Printf("Collector did not stop gracefully; terminating it")
	}

	if proc.cmd.Process != nil {
		if err := proc.cmd.Process.Kill(); err != nil &&
			!errors.Is(err, os.ErrProcessDone) {
			select {
			case <-proc.done:
				return nil
			default:
				return fmt.Errorf("terminate collector: %w", err)
			}
		}
	}

	select {
	case <-proc.done:
		return fmt.Errorf("collector required forced termination; telemetry may be incomplete")
	case <-time.After(collectorKillTimeout):
		return fmt.Errorf("collector did not exit after forced termination")
	}
}

func shutdownGuest() error {
	return exec.Command("shutdown.exe", "/s", "/t", "0", "/f").Run()
}
