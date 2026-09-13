package mitre

import "github.com/aasimkhan02/ThreatBox/internal/analysis/scoring"

type Technique struct {
	ID          string
	Name        string
	Description string
	Tactic      string
}

type TechniqueMatch struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Evidence    string `json:"evidence"`
}

type AnalysisOutput struct {
	Sample      interface{}         `json:"sample"`
	Files       interface{}         `json:"files"`
	Processes   interface{}         `json:"processes"`
	Network     interface{}         `json:"network"`
	Registry    interface{}         `json:"registry"`
	DNS         interface{}         `json:"dns"`
	Images      interface{}         `json:"images"`
	Techniques  []TechniqueMatch    `json:"techniques"`
	ThreatScore scoring.ThreatScore `json:"threat_score"`
}