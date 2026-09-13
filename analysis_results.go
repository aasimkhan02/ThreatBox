package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func ValidAnalysisResultTransition(currentStatus, newStatus string) bool {
	switch currentStatus {
	case "pending":
		return newStatus == "running"

	case "running":
		return newStatus == "completed" || newStatus == "failed"

	case "completed", "failed":
		return false

	default:
		return false
	}
}

func CreateAnalysisResult(
	db *pgxpool.Pool,
	result storage.AnalysisResult,
) (string, error) {
	var resultID string

	err := db.QueryRow(
		context.Background(),
		`INSERT INTO analysis_results (
			job_id,
			sample_id,
			started_at,
			completed_at,
			status
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING result_id`,
		result.JobID,
		result.SampleID,
		result.StartedAt,
		result.CompletedAt,
		result.Status,
	).Scan(&resultID)

	if err != nil {
		return "", err
	}

	return resultID, nil
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

	var query string
	var args []interface{}

	switch status {
	case "running":
		query = `
			UPDATE analysis_results
			SET status = 'running',
			    started_at = NOW()
			WHERE result_id = $1
			  AND status = $2`
		args = []interface{}{resultID, currentStatus}

	case "completed":
		query = `
			UPDATE analysis_results
			SET status = 'completed',
			    completed_at = NOW()
			WHERE result_id = $1
			  AND status = $2`
		args = []interface{}{resultID, currentStatus}

	case "failed":
		query = `
			UPDATE analysis_results
			SET status = 'failed',
			    completed_at = NOW()
			WHERE result_id = $1
			  AND status = $2`
		args = []interface{}{resultID, currentStatus}

	default:
		return fmt.Errorf("unsupported analysis result status: %s", status)
	}

	result, err := db.Exec(context.Background(), query, args...)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("analysis result changed concurrently")
	}

	return nil
}
