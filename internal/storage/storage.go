package storage 

import (
	"time"
)

type Job struct {
	JobID string
	FileID string
	Type string
	Status string
	JobAttempts int64
	ErrorMessage *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Sample struct {
	SampleID string
	OriginalFileName string
	SHA256 string
	FileSize int64
	StoragePath string
	Status string
	CreatedAt time.Time
}

type Result struct {
	ResultID string
	JobID string
	FileName string
	FileSize int64
	SHA256 string
	Status string
	CreatedAT time.Time
}

type AnalysisResult struct {
	ResultID    string
	JobID       string
	SampleID    string
	StartedAt   *time.Time
	CompletedAt *time.Time
	Status      string
}

type Event struct {
	
}