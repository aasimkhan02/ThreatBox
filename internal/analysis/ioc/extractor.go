package ioc

import "github.com/aasimkhan02/ThreatBox/internal/analysis"

type IOCResult struct {
	Sample    SampleIOC    `json:"sample"`
	Files     []FileIOC    `json:"files"`
	Processes []ProcessIOC `json:"processes"`
}

type SampleIOC struct {
	Name string `json:"name"`
	PID  uint64 `json:"pid"`
}

type FileIOC struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	PID     uint64 `json:"pid"`
	Process string `json:"process"`
}

type ProcessIOC struct {
	Name string `json:"name"`
	PID  uint64 `json:"pid"`
}

func Extract(
	activities []analysis.FileActivity,
	processes map[uint64]*analysis.ProcessNode,
	relevantPIDs map[uint64]bool,
	sample *analysis.ProcessNode,
) IOCResult {

	result := IOCResult{
		Files:     make([]FileIOC, 0),
		Processes: make([]ProcessIOC, 0),
	}

	// Sample information
	if sample != nil {
		result.Sample = SampleIOC{
			Name: sample.Image,
			PID:  sample.PID,
		}
	}

	// File IOCs
	for _, activity := range activities {

		// Ignore unresolved/unknown file paths
		if activity.Path == `\FI_UNKNOWN` {
			continue
		}

		var fileType string

		switch activity.Action {
		case "CREATE":
			fileType = "created"

		case "WRITE":
			fileType = "modified"

		case "DELETE":
			fileType = "deleted"

		case "RENAME":
			fileType = "renamed"

		default:
			continue
		}

		result.Files = append(result.Files, FileIOC{
			Path:    activity.Path,
			Type:    fileType,
			PID:     activity.PID,
			Process: activity.Image,
		})
	}

	// Process activity
	// Only include processes belonging to the sample's process tree.
	for pid, process := range processes {

		if !relevantPIDs[pid] {
			continue
		}

		result.Processes = append(result.Processes, ProcessIOC{
			Name: process.Image,
			PID:  process.PID,
		})
	}

	return result
}