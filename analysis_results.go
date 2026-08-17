package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func ValidAnalysisResultTransition(currentStatus string, newStatus string) bool {
	switch currentStatus {
	case "pending":
		return newStatus == "running"

	case "running":
		return newStatus == "completed" || newStatus == "failed"

	case "completed":
		return false

	case "failed":
		return false

	default:
		return false
	}
}

func CreateAnalysisResult(
	db *pgxpool.Pool,
	result storage.AnalysisResult,
) error {

	_, err := db.Exec(
		context.Background(),
		`INSERT INTO analysis_results (
			job_id,
			sample_id,
			started_at,
			completed_at,
			status
		)
		VALUES ($1, $2, $3, $4, $5)`,
		result.JobID,
		result.SampleID,
		result.StartedAt,
		result.CompletedAt,
		result.Status,
	)

	return err
}

func UpdateAnalysisResultStatus(
	db *pgxpool.Pool,
	resultID string,
	status string,
) error {

	var currentStatus string

	err := db.QueryRow(
		context.Background(),
		`SELECT status
		 FROM analysis_results
		 WHERE result_id = $1`,
		resultID,
	).Scan(&currentStatus)

	if err != nil {
		return err
	}

	if !ValidAnalysisResultTransition(currentStatus, status) {
		return fmt.Errorf(
			"invalid analysis result status transition: %s -> %s",
			currentStatus,
			status,
		)
	}

	switch status {

	case "running":
		_, err = db.Exec(
			context.Background(),
			`UPDATE analysis_results
			 SET status = 'running',
			     started_at = NOW()
			 WHERE result_id = $1
			   AND status = $2`,
			resultID,
			currentStatus,
		)

	case "completed":
		_, err = db.Exec(
			context.Background(),
			`UPDATE analysis_results
			 SET status = 'completed',
			     completed_at = NOW()
			 WHERE result_id = $1
			   AND status = $2`,
			resultID,
			currentStatus,
		)

	case "failed":
		_, err = db.Exec(
			context.Background(),
			`UPDATE analysis_results
			 SET status = 'failed',
			     completed_at = NOW()
			 WHERE result_id = $1
			   AND status = $2`,
			resultID,
			currentStatus,
		)

	default:
		return fmt.Errorf(
			"unsupported analysis result status: %s",
			status,
		)
	}

	if err != nil {
		return err
	}

	return nil
}

func GetAnalysisResult(
	db *pgxpool.Pool,
	resultID string,
) (storage.AnalysisResult, error) {

	var result storage.AnalysisResult

	err := db.QueryRow(
		context.Background(),
		`SELECT
			result_id,
			job_id,
			sample_id,
			started_at,
			completed_at,
			status
		 FROM analysis_results
		 WHERE result_id = $1`,
		resultID,
	).Scan(
		&result.ResultID,
		&result.JobID,
		&result.SampleID,
		&result.StartedAt,
		&result.CompletedAt,
		&result.Status,
	)

	if err != nil {
		return storage.AnalysisResult{}, err
	}

	return result, nil
}