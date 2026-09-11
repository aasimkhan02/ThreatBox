package mitre

import (
	"fmt"
	"strings"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func Map(result ioc.IOCResult, db *Database) []TechniqueMatch {
	matches := make([]TechniqueMatch, 0)

	seen := make(map[string]bool)

	for _, process := range result.Processes {
		techniqueID := MatchProcessName(process.Name)

		if techniqueID == "" {
			continue
		}

		if seen[techniqueID] {
			continue
		}

		technique, ok := db.GetTechnique(techniqueID)

		if !ok {
			continue
		}

		seen[techniqueID] = true

		matches = append(matches, TechniqueMatch{
			TechniqueID: technique.ID,
			Name:        technique.Name,
			Tactic:      technique.Tactic,
			Evidence:    buildProcessEvidence(result, process.Name, process.PID),
		})
	}

	return matches
}

func buildProcessEvidence(
	result ioc.IOCResult,
	processName string,
	pid uint64,
) string {

	name := strings.ToLower(processName)

	switch name {
	case "powershell.exe":
		return fmt.Sprintf(
			"Observed PowerShell process: %s (PID=%d)",
			processName,
			pid,
		)

	case "cmd.exe":
		return fmt.Sprintf(
			"Observed Windows Command Shell process: %s (PID=%d)",
			processName,
			pid,
		)

	case "python.exe":
		return fmt.Sprintf(
			"Observed Python process: %s (PID=%d)",
			processName,
			pid,
		)

	default:
		return fmt.Sprintf(
			"Observed process: %s (PID=%d)",
			processName,
			pid,
		)
	}
}