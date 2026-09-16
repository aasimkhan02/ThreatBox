package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/engine"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/sandbox"
	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

const (
	defaultSandboxConfig = `C:\ThreatBox\sandbox.wsb`
	runtimeOutputPath    = `C:\ThreatBox\runtime\output`
	telemetryFileName    = "events.jsonl"
	defaultMaxExecMins   = 15
)

func RunAnalysisForJob(
	sample storage.Sample,
	jobID string,
) (mitre.AnalysisOutput, error) {

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

	configPath := os.Getenv("THREATBOX_SANDBOX_CONFIG")
	if configPath == "" {
		configPath = defaultSandboxConfig
	}

	if _, err := os.Stat(configPath); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"sandbox config is unavailable: %w",
			err,
		)
	}

	// Clean old telemetry AND any stale completion sentinel so this job
	// only ever sees fresh events and can't be fooled by a leftover
	// analysis.done from a previous run.
	if err := prepareRuntime(); err != nil {
		return mitre.AnalysisOutput{}, err
	}

	sb := &sandbox.WindowsSandbox{
		ConfigPath:       configPath,
		OutputPath:       runtimeOutputPath,
		MaxExecutionTime: sandboxSafetyTimeout(),
	}

	// Copy the uploaded sample into the sandbox runtime location
	// as C:\ThreatBox\sample\sample.exe.
	if err := sb.CopySample(sample.StoragePath); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"prepare sample for sandbox: %w",
			err,
		)
	}

	// Launch Windows Sandbox.
	if err := sb.Create(); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"create sandbox for job %s: %w",
			jobID,
			err,
		)
	}

	// Safety net only. On the normal path the guest has already shut
	// itself down by the time we get here (see windows.go Execute), so
	// this is a no-op. It only does real work if we returned early via
	// an error above/below (e.g. the safety timeout fired).
	defer func() {
		if err := sb.Destroy(); err != nil {
			fmt.Printf(
				"sandbox cleanup error for job %s: %v\n",
				jobID,
				err,
			)
		}
	}()

	// Blocks until the guest has: run sample.exe to completion, killed
	// the ETW collector, written the analysis.done sentinel, and shut
	// itself down. See the Execute() doc comment in windows.go for the
	// full completion-detection contract. This is NOT a fixed timeout -
	// MaxExecutionTime only bounds a hung/stuck sandbox.
	if err := sb.Execute(); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"execute sample in sandbox for job %s: %w",
			jobID,
			err,
		)
	}

	// Short settle time for the host filesystem to reflect the guest's
	// final writes to the mapped output folder. This is NOT how we
	// detect completion - completion was already confirmed by Execute()
	// via the sentinel file. This is purely an I/O-flush buffer.
	time.Sleep(1 * time.Second)

	if _, err := sb.Collect(); err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"collect telemetry for job %s: %w",
			jobID,
			err,
		)
	}

	telemetryPath := filepath.Join(
		runtimeOutputPath,
		telemetryFileName,
	)

	// Run the analyzer with the original uploaded filename as an additional
	// sample-identity hint. The sandbox may still present the guest copy as
	// sample.exe; the analyzer accepts either representation.
	result, err := engine.Analyze(telemetryPath, nil, sample.OriginalFileName)
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"analysis failed for job %s: %w",
			jobID,
			err,
		)
	}

	return result, nil
}

func prepareRuntime() error {
	if err := os.RemoveAll(runtimeOutputPath); err != nil {
		return fmt.Errorf(
			"clean runtime output directory: %w",
			err,
		)
	}

	if err := os.MkdirAll(runtimeOutputPath, 0755); err != nil {
		return fmt.Errorf(
			"create runtime output directory: %w",
			err,
		)
	}

	return nil
}

// sandboxSafetyTimeout lets you override the hang-detection ceiling via
// env without touching code, e.g. THREATBOX_SANDBOX_TIMEOUT_MIN=30 for a
// slow/known-heavy sample. Defaults to 15 minutes.
func sandboxSafetyTimeout() time.Duration {
	minutes := defaultMaxExecMins
	if raw := os.Getenv("THREATBOX_SANDBOX_TIMEOUT_MIN"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			minutes = parsed
		}
	}
	return time.Duration(minutes) * time.Minute
}
