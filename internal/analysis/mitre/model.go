package mitre

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