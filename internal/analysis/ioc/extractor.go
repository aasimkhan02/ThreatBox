package ioc

import "github.com/aasimkhan02/ThreatBox/internal/analysis"

type IOCResult struct {
	Sample    SampleIOC     `json:"sample"`
	Files     []FileIOC     `json:"files"`
	Processes []ProcessIOC  `json:"processes"`
	Network   []NetworkIOC  `json:"network"`
	Registry  []RegistryIOC `json:"registry"`
	DNS       []DNSIOC      `json:"dns"`
	Images    []ImageIOC    `json:"images"`
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

type NetworkIOC struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	DestIP   string `json:"dest_ip"`
	DestPort uint64 `json:"dest_port"`
	PID      uint64 `json:"pid"`
	Process  string `json:"process"`
}

type RegistryIOC struct {
	Action  string `json:"action"`
	Key     string `json:"key"`
	PID     uint64 `json:"pid"`
	Process string `json:"process"`
}

type DNSIOC struct {
	Domain  string   `json:"domain"`
	Results []string `json:"results,omitempty"`
	PID     uint64   `json:"pid"`
	Process string   `json:"process"`
}

type ImageIOC struct {
	Path     string `json:"path"`
	PID      uint64 `json:"pid"`
	Process  string `json:"process"`
	Checksum uint64 `json:"checksum,omitempty"`
}

type Activities struct {
	Files    []analysis.FileActivity
	Network  []analysis.NetworkActivity
	Registry []analysis.RegistryActivity
	DNS      []analysis.DNSActivity
	Images   []analysis.ImageActivity
}

func Extract(
	activities Activities,
	processes map[uint64]*analysis.ProcessNode,
	relevantPIDs map[uint64]bool,
	sample *analysis.ProcessNode,
) IOCResult {

	result := IOCResult{
		Files:     make([]FileIOC, 0),
		Processes: make([]ProcessIOC, 0),
		Network:   make([]NetworkIOC, 0),
		Registry:  make([]RegistryIOC, 0),
		DNS:       make([]DNSIOC, 0),
		Images:    make([]ImageIOC, 0),
	}

	// Sample information
	if sample != nil {
		result.Sample = SampleIOC{
			Name: sample.Image,
			PID:  sample.PID,
		}
	}

	// File IOCs
	for _, activity := range activities.Files {

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

	// Network IOCs
	for _, activity := range activities.Network {
		result.Network = append(result.Network, NetworkIOC{
			Type:     activity.Type,
			Protocol: activity.Protocol,
			DestIP:   activity.DestIP,
			DestPort: activity.DestPort,
			PID:      activity.PID,
			Process:  activity.Image,
		})
	}

	// Registry IOCs
	for _, activity := range activities.Registry {
		result.Registry = append(result.Registry, RegistryIOC{
			Action:  activity.Action,
			Key:     activity.Key,
			PID:     activity.PID,
			Process: activity.Image,
		})
	}

	// DNS IOCs
	for _, activity := range activities.DNS {
		result.DNS = append(result.DNS, DNSIOC{
			Domain:  activity.QueryName,
			Results: activity.Results,
			PID:     activity.PID,
			Process: activity.Image,
		})
	}

	// Image/DLL load IOCs
	for _, activity := range activities.Images {
		result.Images = append(result.Images, ImageIOC{
			Path:     activity.Path,
			PID:      activity.PID,
			Process:  activity.Image,
			Checksum: activity.ImageChecksum,
		})
	}


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