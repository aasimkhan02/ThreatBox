package scoring

type ThreatScore struct {
    Score    int      `json:"score"`
    Severity string   `json:"severity"`
    Reasons  []string `json:"reasons"`
}