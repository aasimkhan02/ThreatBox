package mitre

import (
	"fmt"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func Map(result ioc.IOCResult, db *Database) []TechniqueMatch {
	matches := make([]TechniqueMatch, 0)

	for _, process := range result.Processes {
		techniqueID := MatchProcessName(process.Name)

		if techniqueID == "" {
			continue
		}

		technique, ok := db.GetTechnique(techniqueID)

		if !ok {
			continue
		}

		matches = append(matches, TechniqueMatch{
			TechniqueID: technique.ID,
			Name:        technique.Name,
			Tactic:      technique.Tactic,
			Evidence: fmt.Sprintf(
				"Observed process: %s (PID=%d)",
				process.Name,
				process.PID,
			),
		})
	}

	return matches
}