package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/engine"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/sandbox"
	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

const (
	defaultRuntimeRoot      = `C:\ThreatBox\runtime\jobs`
	defaultSandboxTools     = `C:\ThreatBoxSandbox`
	defaultMaxExecMins      = 15
	sandboxStartupAllowance = 2 * time.Minute
)

func RunAnalysisForJob(
	sample storage.Sample,
	jobID string,
) (mitre.AnalysisOutput, error) {
	if err := sandbox.ValidateJobID(jobID); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("invalid job ID: %w", err)
	}

	if sample.StoragePath == "" {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"sample %s has no storage path",
			sample.SampleID,
		)
	}
	if _, err := os.Stat(sample.StoragePath); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"sample storage path is unavailable: %w",
			err,
		)
	}

	toolsDir := os.Getenv("THREATBOX_SANDBOX_TOOLS")
	if toolsDir == "" {
		toolsDir = defaultSandboxTools
	}

	for _, toolName := range []string{
		sandbox.AgentExeName,
		sandbox.CollectorExeName,
	} {
		toolPath := filepath.Join(toolsDir, toolName)
		if _, err := os.Stat(toolPath); err != nil {
			return mitre.AnalysisOutput{}, fmt.Errorf(
				"required Sandbox tool %s is missing at %s; "+
					"build and deploy Sandbox tools first: %w",
				toolName,
				toolPath,
				err,
			)
		}
	}

	runtimeRoot := os.Getenv("THREATBOX_RUNTIME_ROOT")
	if runtimeRoot == "" {
		runtimeRoot = defaultRuntimeRoot
	}

	// A timestamped directory keeps logs from different attempts separate.
	runName := jobID + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	jobRoot := filepath.Join(runtimeRoot, runName)

	sampleDir := filepath.Join(jobRoot, "sample")
	outputDir := filepath.Join(jobRoot, "output")
	configPath := filepath.Join(jobRoot, "sandbox.wsb")

	for _, dir := range []string{sampleDir, outputDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return mitre.AnalysisOutput{}, fmt.Errorf(
				"create job workspace %s: %w",
				dir,
				err,
			)
		}
	}

	sampleTimeout := sandboxSafetyTimeout()

	sb := &sandbox.WindowsSandbox{
		ConfigPath:       configPath,
		SampleDir:        sampleDir,
		OutputPath:       outputDir,
		ToolsPath:        toolsDir,
		JobID:            jobID,
		MaxExecutionTime: sampleTimeout + sandboxStartupAllowance,
	}

	if err := sb.CopySample(sample.StoragePath); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"prepare sample for Sandbox: %w",
			err,
		)
	}

	if err := sandbox.WriteConfig(
		configPath,
		sampleDir,
		outputDir,
		toolsDir,
		jobID,
		sampleTimeout,
	); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"create per-job Sandbox configuration: %w",
			err,
		)
	}

	fmt.Printf("Job %s workspace: %s\n", jobID, jobRoot)

	if err := sb.Create(); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"create Sandbox for job %s: %w",
			jobID,
			err,
		)
	}

	defer func() {
		if err := sb.Destroy(); err != nil {
			fmt.Printf(
				"Sandbox cleanup error for job %s: %v\n",
				jobID,
				err,
			)
		}
	}()

	if err := sb.Execute(); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"execute sample in Sandbox for job %s: %w",
			jobID,
			err,
		)
	}

	telemetry, err := sb.Collect()
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"collect telemetry for job %s: %w",
			jobID,
			err,
		)
	}
	if strings.TrimSpace(telemetry) == "" {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"job %s completed but telemetry is empty; workspace preserved at %s",
			jobID,
			jobRoot,
		)
	}

	telemetryPath := filepath.Join(outputDir, sandbox.EventsFileName)

	// The guest runs the copied executable as sample.exe; keep both the
	// uploaded filename and guest filename as identity hints.
	result, err := engine.Analyze(
		telemetryPath,
		nil,
		sample.OriginalFileName,
		"sample.exe",
	)
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"analysis failed for job %s (workspace: %s): %w",
			jobID,
			jobRoot,
			err,
		)
	}

	return result, nil
}

func sandboxSafetyTimeout() time.Duration {
	minutes := defaultMaxExecMins
	if raw := os.Getenv("THREATBOX_SANDBOX_TIMEOUT_MIN"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			minutes = parsed
		}
	}

	return time.Duration(minutes) * time.Minute
}
