package storage 

import (
	"time"
)

type Job struct {
	JobID string
	FileID string
	Type string
	Status string
	CreatedAt time.Time
	UpdatedAt time.Time
}