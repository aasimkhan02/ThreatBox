package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

const (
	jobHeartbeatInterval = 30 * time.Second
	jobHeartbeatTimeout  = 10 * time.Second
	staleJobMinutes      = 5
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

func keepJobLeaseAlive(
	ctx context.Context,
	db *pgxpool.Pool,
	jobID string,
) {
	ticker := time.NewTicker(jobHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			touchCtx, cancel := context.WithTimeout(
				ctx,
				jobHeartbeatTimeout,
			)

			tag, err := db.Exec(
				touchCtx,
				`UPDATE jobs
				 SET updated_at = NOW()
				 WHERE job_id = $1
				   AND status = 'running'`,
				jobID,
			)
			cancel()

			if err != nil {
				log.Printf(
					"Job %s heartbeat failed: %v",
					jobID,
					err,
				)
				continue
			}

			if tag.RowsAffected() == 0 {
				log.Printf(
					"Job %s heartbeat found no running job row",
					jobID,
				)
			}
		}
	}
}

func FailRunningJob(
	db *pgxpool.Pool,
	jobID string,
	cause error,
) error {
	_, err := db.Exec(
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
		return fmt.Errorf("failed to mark job as failed: %w", err)
	}

	log.Printf("Job %s FAILED: %v", jobID, cause)
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
			return nil
		}
		return err
	}

	log.Printf("Claimed job: %s", jobID)

	heartbeatCtx, stopHeartbeat := context.WithCancel(
		context.Background(),
	)
	defer stopHeartbeat()

	go keepJobLeaseAlive(heartbeatCtx, db, jobID)

	job, err := GetJob(db, jobID)
	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to get job: %w", err),
		)
	}

	sample, err := GetSample(db, job.FileID)
	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to get sample: %w", err),
		)
	}

	analysisRow := storage.AnalysisResult{
		JobID:    jobID,
		SampleID: sample.SampleID,
		Status:   "pending",
	}

	analysisResultID, err := CreateAnalysisResult(db, analysisRow)
	if err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to create analysis result: %w", err),
		)
	}

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

	// Preserve the existing metadata-processing step.
	legacyResult, err := ProcessSample(sample, jobID)
	if err != nil {
		_ = UpdateAnalysisResultStatus(db, analysisResultID, "failed")
		return FailRunningJob(db, jobID, err)
	}

	analysisOutput, err := RunAnalysisForJob(sample, jobID)
	if err != nil {
		if statusErr := UpdateAnalysisResultStatus(
			db,
			analysisResultID,
			"failed",
		); statusErr != nil {
			log.Printf("Failed to mark analysis result as failed: %v", statusErr)
		}

		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("analysis pipeline failed: %w", err),
		)
	}

	analysisData, err := json.Marshal(analysisOutput)
	if err != nil {
		_ = UpdateAnalysisResultStatus(db, analysisResultID, "failed")
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to marshal analysis output: %w", err),
		)
	}

	if err := SaveAnalysisResultData(
		db,
		analysisResultID,
		analysisData,
	); err != nil {
		_ = UpdateAnalysisResultStatus(db, analysisResultID, "failed")
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to save analysis result: %w", err),
		)
	}

	if err := CreateResult(db, legacyResult); err != nil {
		_ = UpdateAnalysisResultStatus(db, analysisResultID, "failed")
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to create result: %w", err),
		)
	}

	if err := UpdateAnalysisResultStatus(
		db,
		analysisResultID,
		"completed",
	); err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to complete analysis result: %w", err),
		)
	}

	if err := UpdateStatus(db, jobID, "completed"); err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to complete job: %w", err),
		)
	}

	log.Printf("Completed job: %s", jobID)
	log.Printf("Analysis result: %s", analysisResultID)
	return nil
}

func RecoverStaleJobs(db *pgxpool.Pool) error {
	result, err := db.Exec(
		context.Background(),
		`UPDATE jobs
		 SET status = 'pending',
		     updated_at = NOW(),
		     error_message = NULL
		 WHERE status = 'running'
		   AND updated_at < NOW() - ($1 * INTERVAL '1 minute')`,
		staleJobMinutes,
	)
	if err != nil {
		return fmt.Errorf("failed to recover stale jobs: %w", err)
	}

	if result.RowsAffected() > 0 {
		log.Printf("Recovered %d stale jobs", result.RowsAffected())
	}
	return nil
}
