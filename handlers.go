package main

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
