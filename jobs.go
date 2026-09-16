package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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

	if !ValidTransition(job.Status, status) {
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

type JobDashboardResponse struct {
	ID             string           `json:"id"`
	Filename       string           `json:"filename"`
	Status         string           `json:"status"`
	CreatedAt      time.Time        `json:"created_at"`
	Score          *int             `json:"score,omitempty"`
}

type JobDetailsResponse struct {
	JobDashboardResponse
	AnalysisResult *json.RawMessage `json:"analysis_result,omitempty"`
}

func GetJobDetails(db *pgxpool.Pool, jobID string) (JobDetailsResponse, error) {
	var resp JobDetailsResponse

	err := db.QueryRow(
		context.Background(),
		`SELECT j.job_id, s.original_filename, j.status, j.created_at
		 FROM jobs j
		 JOIN samples s ON j.file_id = s.sample_id
		 WHERE j.job_id = $1`,
		jobID,
	).Scan(
		&resp.ID,
		&resp.Filename,
		&resp.Status,
		&resp.CreatedAt,
	)

	if err != nil {
		return JobDetailsResponse{}, err
	}
	
	// Try to get analysis result data
	var resultData []byte
	err = db.QueryRow(
		context.Background(),
		`SELECT result_data
		 FROM analysis_results
		 WHERE job_id = $1
		 ORDER BY completed_at DESC NULLS LAST, started_at DESC NULLS LAST
		 LIMIT 1`,
		jobID,
	).Scan(&resultData)
	
	if err == nil && len(resultData) > 0 {
		raw := json.RawMessage(resultData)
		resp.AnalysisResult = &raw
		
		// Extract score from raw JSON to populate the embedded JobDashboardResponse's Score
		var temp struct {
			ThreatScore struct {
				Score int `json:"score"`
			} `json:"threat_score"`
		}
		if json.Unmarshal(resultData, &temp) == nil {
			resp.Score = &temp.ThreatScore.Score
		}
	}

	return resp, nil
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

func GetMultipleJobs(db *pgxpool.Pool) ([]JobDashboardResponse, error) {
	rows, err := db.Query(
		context.Background(),
		`SELECT j.job_id, s.original_filename, j.status, j.created_at, 
		        (ar.result_data->'threat_score'->>'score')::int as score
		 FROM jobs j
		 JOIN samples s ON j.file_id = s.sample_id
		 LEFT JOIN analysis_results ar ON ar.job_id = j.job_id
		 ORDER BY j.created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []JobDashboardResponse

	for rows.Next() {
		var job JobDashboardResponse

		err := rows.Scan(
			&job.ID,
			&job.Filename,
			&job.Status,
			&job.CreatedAt,
			&job.Score,
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

func SaveAnalysisResultData(
	db *pgxpool.Pool,
	resultID string,
	data json.RawMessage,
) error {
	_, err := db.Exec(
		context.Background(),
		`UPDATE analysis_results
		 SET result_data = $1
		 WHERE result_id = $2`,
		[]byte(data),
		resultID,
	)

	return err
}

func GetAnalysisResultByJobID(
	db *pgxpool.Pool,
	jobID string,
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
			status,
			result_data
		 FROM analysis_results
		 WHERE job_id = $1
		 ORDER BY completed_at DESC NULLS LAST, started_at DESC NULLS LAST
		 LIMIT 1`,
		jobID,
	).Scan(
		&result.ResultID,
		&result.JobID,
		&result.SampleID,
		&result.StartedAt,
		&result.CompletedAt,
		&result.Status,
		&result.ResultData,
	)

	if err != nil {
		return storage.AnalysisResult{}, err
	}

	return result, nil
}
