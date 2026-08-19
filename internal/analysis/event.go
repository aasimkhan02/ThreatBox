package analysis

import "time"

type EventType string

const (
	EventFileOpen       EventType = "file_open"
	EventFileWrite      EventType = "file_write"
	EventFileDelete      EventType = "file_delete"
	EventProcessCreate  EventType = "process_create"
	EventProcessExit    EventType = "process_exit"
	EventNetworkConnect EventType = "network_connect"
	EventExecution      EventType = "execution"
)

type Event struct {
	Timestamp time.Time
	PID int
	Process string
	Type EventType
	Target string
	Metadata  map[string]string
	Source    string  
}