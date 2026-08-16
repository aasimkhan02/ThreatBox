package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func CreateSample(
	w http.ResponseWriter,
	r *http.Request,
	db *pgxpool.Pool,
	storageService *storage.StorageService,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validation
	if header.Size == 0 || header.Size > 100*1024*1024 {
		http.Error(w, "Size not valid", http.StatusBadRequest)
		return
	}

	// Calculate SHA-256
	hash := sha256.New()

	_, err = io.Copy(hash, file)
	if err != nil {
		http.Error(w, "Failed to hash file", http.StatusInternalServerError)
		return
	}

	sum := hash.Sum(nil)
	sha256Hash := hex.EncodeToString(sum)

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		http.Error(w, "Failed to reset file", http.StatusInternalServerError)
		return
	}

	// Check duplicate
	var exists bool

	err = db.QueryRow(
		context.Background(),
		"SELECT EXISTS (SELECT 1 FROM samples WHERE sha256 = $1)",
		sha256Hash,
	).Scan(&exists)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists {
		http.Error(w, "Sample already exists", http.StatusConflict)
		return
	}

	// Save file
	err = os.MkdirAll("uploads", 0755)
	if err != nil {
		http.Error(w, "Failed to create uploads directory", http.StatusInternalServerError)
		return
	}

	storagePath, err := storageService.Save(file, sha256Hash)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Begin transaction
	tx, err := db.Begin(context.Background())
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// Insert sample
	var sampleID string

	err = tx.QueryRow(
		context.Background(),
		`INSERT INTO samples (
			original_filename,
			sha256,
			file_size,
			storage_path
		)
		VALUES ($1, $2, $3, $4)
		RETURNING sample_id`,
		header.Filename,
		sha256Hash,
		header.Size,
		storagePath,
	).Scan(&sampleID)

	if err != nil {
		http.Error(w, "Failed to save sample metadata", http.StatusInternalServerError)
		return
	}

	// Insert job
	var jobID string

	err = tx.QueryRow(
		context.Background(),
		`INSERT INTO jobs (
			file_id,
			type,
			status
		)
		VALUES ($1, $2, $3)
		RETURNING job_id`,
		sampleID,
		"malware_scan",
		"pending",
	).Scan(&jobID)

	if err != nil {
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	err = tx.Commit(context.Background())
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	// Response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Sample uploaded successfully",
		"sample_id":    sampleID,
		"job_id":       jobID,
		"sha256":       sha256Hash,
		"storage_path": storagePath,
	})

	if err != nil {
		return
	}
}

func ValidTransition(currentStatus string, newStatus string) bool {
	
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

func UpdateStatus(db *pgxpool.Pool, jobID string, status string) error{

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
		`SELECT job_id, file_id, type, status, error_message, created_at, updated_at
		FROM jobs
		WHERE job_id = $1`,
		jobID,
	).Scan(
		&job.JobID,
		&job.FileID,
		&job.Type,
		&job.Status,
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
		`SELECT job_id, file_id, type, status, error_message, created_at, updated_at
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

func GetMultipleJobsHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobs, err := GetMultipleJobs(db)

	if err != nil {
        http.Error(w, "Failed to fetch jobs", http.StatusInternalServerError)
        return
    }

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(jobs)
	if err != nil {
		return
	}
}

func GetJobHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, jobID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	job, err := GetJob(db, jobID)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Job not found", http.StatusNotFound)
			return
		}

		http.Error(w, "Failed to fetch job", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(job)

	if err != nil {
		return
	}
}	
func UpdateStatusHandler(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, jobID string) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type UpdateStatusRequest struct {
		Status string `json:"status"`
	}

	var req UpdateStatusRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status == "" {
		http.Error(w, "status is required", http.StatusBadRequest)
		return
	}

	err = UpdateStatus(db, jobID, req.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Job status updated successfully",
		"job_id":  jobID,
		"status":  req.Status,
	})

	if err != nil {
		return
	}
}

func GetSample(db *pgxpool.Pool, sampleID string) (storage.Sample, error) {
	var sample storage.Sample

	err := db.QueryRow(
		context.Background(),
		`SELECT sample_id, original_filename, sha256, file_size, storage_path, status, created_at
		FROM samples
		WHERE sample_id = $1`,
		sampleID,
	).Scan(
		&sample.SampleID,
		&sample.OriginalFileName,
		&sample.SHA256,
		&sample.FileSize,
		&sample.StoragePath,
		&sample.Status,
		&sample.CreatedAt,
	)

	if err != nil {
		return storage.Sample{}, err
	}

	return sample, nil
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


func ProcessSample(sample storage.Sample, jobID string) (storage.Result, error) {
	file, err := os.Open(sample.StoragePath)
	if err != nil {
		return storage.Result{}, fmt.Errorf(
			"failed to open sample: %w",
			err,
		)
	}
	defer file.Close()

	_, err = io.ReadAll(file)
	if err != nil {
		return storage.Result{}, fmt.Errorf(
			"failed to read sample: %w",
			err,
		)
	}

	result := storage.Result{
		JobID:     jobID,
		FileName:  sample.OriginalFileName,
		FileSize:  sample.FileSize,
		SHA256:    sample.SHA256,
		Status:    "processed",
	}

	log.Println("Processing sample:", sample.OriginalFileName)

	return result, nil
}