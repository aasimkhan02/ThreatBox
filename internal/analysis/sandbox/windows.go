package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type WindowsSandbox struct {
	ConfigPath string
	SamplePath string
	OutputPath string
	cmd        *exec.Cmd
}

func (s *WindowsSandbox) Create() error {
	if _, err := os.Stat(s.ConfigPath); err != nil {
		return fmt.Errorf("sandbox config not found: %w", err)
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

	s.SamplePath = samplePath

	return nil
}

func (s *WindowsSandbox) Execute() error {
	if s.SamplePath == "" {
		return fmt.Errorf("no sample configured")
	}

	if _, err := os.Stat(s.SamplePath); err != nil {
		return fmt.Errorf("sample not found: %w", err)
	}

	return nil
}

func (s *WindowsSandbox) Collect() (string, error) {
	if s.OutputPath == "" {
		return "", fmt.Errorf("output path not configured")
	}

	stdoutPath := filepath.Join(s.OutputPath, "stdout.txt")
	stderrPath := filepath.Join(s.OutputPath, "stderr.txt")

	stdout, err := os.ReadFile(stdoutPath)
	if err != nil {
		return "", fmt.Errorf("failed to read stdout: %w", err)
	}

	stderr, err := os.ReadFile(stderrPath)
	if err != nil {
		return "", fmt.Errorf("failed to read stderr: %w", err)
	}

	return fmt.Sprintf(
		"STDOUT:\n%s\nSTDERR:\n%s",
		string(stdout),
		string(stderr),
	), nil
}

func (s *WindowsSandbox) Destroy() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	if err := s.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to destroy sandbox: %w", err)
	}

	s.cmd = nil

	return nil
}