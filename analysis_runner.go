package main

import (
	"fmt"
	"os"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/engine"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

const defaultTelemetryPath = `C:\ThreatBox\output\events.jsonl`

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

	telemetryPath := os.Getenv("THREATBOX_TELEMETRY_PATH")
	if telemetryPath == "" {
		telemetryPath = defaultTelemetryPath
	}

	result, err := engine.Analyze(telemetryPath, nil)
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf(
			"analysis failed for job %s: %w",
			jobID,
			err,
		)
	}

	return result, nil
}
