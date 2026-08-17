package main

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func ValidTransition(currentStatus string, newStatus string) bool {

	switch currentStatus {
	case "pending":
		return newStatus == "running"

	case "running":
		return newStatus == "completed" || newStatus == "failed" ||
			newStatus == "pending"

	case "completed":
		return false

	case "failed":
		return false

	default:
		return false
	}
}

func UpdateStatus(db *pgxpool.Pool, jobID string, status string) error {

	job, err := GetJob(db, jobID)

	if err != nil {
		return err
	}

	allowed := ValidTransition(job.Status, status)

	if allowed == false {
		return fmt.Errorf("invalid status transition: %s -> %s", job.Status, status)
	}

	result, err := db.Exec(
		context.Background(),
		`UPDATE jobs 
		SET status = $1, 
			updated_at = NOW() 
		WHERE job_id = $2
		AND status = $3`,
		status,
		jobID,
		job.Status,
	)

	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("job status changed concurrently")
	}

	return nil
}

func GetJob(db *pgxpool.Pool, jobID string) (storage.Job, error) {
	var job storage.Job

	err := db.QueryRow(
		context.Background(),
		`SELECT job_id, file_id, type, status, attempt_count, error_message, created_at, updated_at
		FROM jobs
		WHERE job_id = $1`,
		jobID,
	).Scan(
		&job.JobID,
		&job.FileID,
		&job.Type,
		&job.Status,
		&job.JobAttempts,
		&job.ErrorMessage,
		&job.CreatedAt,
		&job.UpdatedAt,
	)

	if err != nil {
		return storage.Job{}, err
	}

	return job, nil
}

func GetMultipleJobs(db *pgxpool.Pool) ([]storage.Job, error) {
	rows, err := db.Query(
		context.Background(),
		`SELECT job_id, file_id, type, status, attempt_count, error_message, created_at, updated_at
		FROM Jobs
		ORDER BY created_at DESC`,
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []storage.Job

	for rows.Next() {
		var job storage.Job

		err := rows.Scan(
			&job.JobID,
			&job.FileID,
			&job.Type,
			&job.Status,
			&job.JobAttempts,
			&job.ErrorMessage,
			&job.CreatedAt,
			&job.UpdatedAt,
		)

		if err != nil {
			return nil, err
		}

		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return jobs, nil
}

func CreateResult(db *pgxpool.Pool, result storage.Result) error {
	_, err := db.Exec(
		context.Background(),
		`INSERT INTO results (
			job_id,
			filename,
			file_size,
			sha256,
			status
		)
		VALUES ($1, $2, $3, $4, $5)`,
		result.JobID,
		result.FileName,
		result.FileSize,
		result.SHA256,
		result.Status,
	)

	return err
}
