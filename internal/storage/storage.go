package storage 

import (
	"time"
)

type Job struct {
	JobID string
	FileID string
	Type string
	Status string
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