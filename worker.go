package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func StartWorker(db *pgxpool.Pool) error {
	if err := RecoverStaleJobs(db); err != nil {
		return fmt.Errorf("failed to recover stale jobs: %w", err)
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := RecoverStaleJobs(db); err != nil {
				log.Printf("RecoverStaleJobs error: %v", err)
			}
		}
	}()

	for {
		if err := ProcessNextJob(db); err != nil {
			log.Printf("ProcessNextJob error: %v", err)
		}

		time.Sleep(time.Second)
	}
}

const MaxAttempts = 3

func FailRunningJob(db *pgxpool.Pool, jobID string, cause error) error {
	job, err := GetJob(db, jobID)
	if err != nil {
		return fmt.Errorf("failed to get job for retry: %w", err)
	}

	if job.JobAttempts < MaxAttempts {
		_, err := db.Exec(
			context.Background(),
			`UPDATE jobs
			 SET status = 'pending',
			     error_message = $1,
			     updated_at = NOW()
			 WHERE job_id = $2
			   AND status = 'running'`,
			cause.Error(),
			jobID,
		)

		if err != nil {
			return fmt.Errorf("failed to retry job: %w", err)
		}

		log.Printf(
			"Job %s failed on attempt %d, retrying",
			jobID,
			job.JobAttempts,
		)

		return nil
	}

	_, err = db.Exec(
		context.Background(),
		`UPDATE jobs
		 SET status = 'failed',
		     error_message = $1,
		     updated_at = NOW()
		 WHERE job_id = $2
		   AND status = 'running'`,
		cause.Error(),
		jobID,
	)

	if err != nil {
		return fmt.Errorf("failed to permanently fail job: %w", err)
	}

	log.Printf(
		"Job %s permanently failed after %d attempts",
		jobID,
		job.JobAttempts,
	)

	return cause
}

func ProcessNextJob(db *pgxpool.Pool) error {
	var jobID string

	err := db.QueryRow(
		context.Background(),
		`WITH next_job AS (
			SELECT job_id
			FROM jobs
			WHERE status = 'pending'
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE jobs
		SET status = 'running',
			attempt_count = attempt_count + 1,
			updated_at = NOW()
		FROM next_job
		WHERE jobs.job_id = next_job.job_id
		RETURNING jobs.job_id`,
	).Scan(&jobID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Println("No pending jobs found")
			return nil
		}

		return err
	}

	log.Printf("Claimed job: %s", jobID)

	// Get job
	job, err := GetJob(db, jobID)
	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to get job: %w", err),
		)
	}

	// Get sample
	sample, err := GetSample(db, job.FileID)
	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to get sample: %w", err),
		)
	}

	// Create analysis result
	analysisResult := storage.AnalysisResult{
		JobID:    jobID,
		SampleID: sample.SampleID,
		Status:   "pending",
	}

	if err := CreateAnalysisResult(db, analysisResult); err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to create analysis result: %w", err),
		)
	}

	// Get the analysis result we just created
	var analysisResultID string

	err = db.QueryRow(
		context.Background(),
		`SELECT result_id
		 FROM analysis_results
		 WHERE job_id = $1
		   AND sample_id = $2
		   AND status = 'pending'
		 ORDER BY result_id DESC
		 LIMIT 1`,
		jobID,
		sample.SampleID,
	).Scan(&analysisResultID)

	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to get analysis result: %w", err),
		)
	}

	// Analysis starts
	if err := UpdateAnalysisResultStatus(
		db,
		analysisResultID,
		"running",
	); err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to start analysis result: %w", err),
		)
	}

	// =====================================================
	// ACTUAL MALWARE ANALYSIS WILL GO HERE
	// =====================================================

	result, err := ProcessSample(sample, jobID)

	if err != nil {
		// Analysis failed
		if analysisErr := UpdateAnalysisResultStatus(
			db,
			analysisResultID,
			"failed",
		); analysisErr != nil {
			log.Printf(
				"Failed to mark analysis result as failed: %v",
				analysisErr,
			)
		}

		return FailRunningJob(db, jobID, err)
	}

	// =====================================================
	// TEMPORARY:
	// Keep the old Stage 10 result for now.
	// =====================================================

	if err := CreateResult(db, result); err != nil {
		if analysisErr := UpdateAnalysisResultStatus(
			db,
			analysisResultID,
			"failed",
		); analysisErr != nil {
			log.Printf(
				"Failed to mark analysis result as failed: %v",
				analysisErr,
			)
		}

		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to create result: %w", err),
		)
	}

	// Analysis succeeded
	if err := UpdateAnalysisResultStatus(
		db,
		analysisResultID,
		"completed",
	); err != nil {
		return err
	}

	// Job succeeded
	if err := UpdateStatus(db, jobID, "completed"); err != nil {
		return err
	}

	log.Printf("Completed job: %s", jobID)
	log.Printf("Analysis result: %s", analysisResultID)

	return nil
}

func RecoverStaleJobs(db *pgxpool.Pool) error {
	result, err := db.Exec(
		context.Background(),
		`
		UPDATE jobs
		SET status = 'pending',
		    updated_at = NOW(),
		    error_message = NULL
		WHERE status = 'running'
		  AND updated_at < NOW() - INTERVAL '5 minutes'
		`,
	)

	if err != nil {
		return fmt.Errorf("failed to recover stale jobs: %w", err)
	}

	if result.RowsAffected() > 0 {
		log.Printf("Recovered %d stale jobs", result.RowsAffected())
	}

	return nil
}
