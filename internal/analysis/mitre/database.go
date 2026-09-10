package mitre

import (
	"encoding/json"
	"fmt"
	"os"
)

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	ExternalReferences []externalReference `json:"external_references"`
	KillChainPhases    []killChainPhase     `json:"kill_chain_phases"`
}

type externalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type Database struct {
	Techniques map[string]Technique
}

func LoadDatabase(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MITRE database: %w", err)
	}

	var bundle stixBundle

	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse MITRE database: %w", err)
	}

	db := &Database{
		Techniques: make(map[string]Technique),
	}

	for _, object := range bundle.Objects {
		if object.Type != "attack-pattern" {
			continue
		}

		var techniqueID string

		for _, ref := range object.ExternalReferences {
			if ref.SourceName == "mitre-attack" {
				techniqueID = ref.ExternalID
				break
			}
		}

		if techniqueID == "" {
			continue
		}

		tactic := ""

		for _, phase := range object.KillChainPhases {
			if phase.KillChainName == "mitre-attack" {
				tactic = phase.PhaseName
				break
			}
		}

		db.Techniques[techniqueID] = Technique{
			ID:          techniqueID,
			Name:        object.Name,
			Description: object.Description,
			Tactic:      tactic,
		}
	}

	return db, nil
}

func (db *Database) GetTechnique(id string) (Technique, bool) {
	technique, ok := db.Techniques[id]
	return technique, ok
}