package main

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aasimkhan02/ThreatBox/internal/storage"
)

func GetMultipleJobsHandler(
	w http.ResponseWriter,
	r *http.Request,
	db *pgxpool.Pool,
) {
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

	if err := json.NewEncoder(w).Encode(jobs); err != nil {
		return
	}
}

type jobDetailsResponse struct {
	storage.Job
	AnalysisResult *storage.AnalysisResult `json:"analysis_result,omitempty"`
}

func GetJobHandler(
	w http.ResponseWriter,
	r *http.Request,
	db *pgxpool.Pool,
	jobID string,
) {
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

	response := jobDetailsResponse{
		Job: job,
	}

	analysisResult, err := GetAnalysisResultByJobID(db, jobID)
	if err == nil {
		response.AnalysisResult = &analysisResult
	} else if err != pgx.ErrNoRows {
		http.Error(w, "Failed to fetch analysis result", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func UpdateStatusHandler(
	w http.ResponseWriter,
	r *http.Request,
	db *pgxpool.Pool,
	jobID string,
) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type UpdateStatusRequest struct {
		Status string `json:"status"`
	}

	var req UpdateStatusRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Status == "" {
		http.Error(w, "status is required", http.StatusBadRequest)
		return
	}

	if err := UpdateStatus(db, jobID, req.Status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Job status updated successfully",
		"job_id":  jobID,
		"status":  req.Status,
	}); err != nil {
		return
	}
}