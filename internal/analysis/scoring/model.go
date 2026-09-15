package scoring

type ThreatScore struct {
	Score    int      `json:"score"`
	Severity string   `json:"severity"`
	Reasons  []string `json:"reasons"`
}

type Context struct {
	SuspiciousFileMutation  bool
	MassFileCreation        bool
	MassFileModification    bool
	ExternalNetworkActivity bool
	TelemetryLost           uint64
}
