package main

import (
	"context"
	"log"
	"time"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5"
)

func StartWorker(db *pgxpool.Pool) {
	for {
		err := ProcessNextJob(db)

		if err != nil {
			log.Println("Worker error:", err)
		}

		time.Sleep(2 * time.Second)
	}
}

func FailRunningJob(db *pgxpool.Pool, jobID string, cause error) error {
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

    return cause
}

func ProcessNextJob(db *pgxpool.Pool) error {
	var jobID string

	err := db.QueryRow(
		context.Background(),
		`UPDATE jobs
		SET status = 'running'
		WHERE job_id = (
			SELECT job_id
			FROM jobs
			WHERE status = 'pending'
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		) 
		RETURNING job_id`,
	).Scan(&jobID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Println("No pending jobs found")
			return nil
		}
		return err
	}

	log.Printf("Claimed job: %s", jobID)

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

	result, err := ProcessSample(sample, jobID)
	if err != nil {
		return FailRunningJob(db, jobID, err)
	}

	if err := CreateResult(db, result); err != nil {
		return FailRunningJob(
			db,
			jobID,
			fmt.Errorf("failed to create result: %w", err),
		)
	}

	if err := UpdateStatus(db, jobID, "completed"); err != nil {
		return err
	}

	log.Printf("Completed job: %s", jobID)
	log.Printf("Result: %v", result)

    return nil
}