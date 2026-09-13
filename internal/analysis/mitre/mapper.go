package mitre

import (
	"fmt"
	"strings"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func Map(result ioc.IOCResult, db *Database) []TechniqueMatch {
	matches := make([]TechniqueMatch, 0)
	seen := make(map[string]bool)

	addMatch := func(techniqueID, evidence string) {
		if techniqueID == "" || seen[techniqueID] {
			return
		}

		technique, ok := db.GetTechnique(techniqueID)
		if !ok {
			return
		}

		seen[techniqueID] = true

		matches = append(matches, TechniqueMatch{
			TechniqueID: technique.ID,
			Name:        technique.Name,
			Tactic:      technique.Tactic,
			Evidence:    evidence,
		})
	}

	for _, process := range result.Processes {
		techniqueID := MatchProcessName(process.Name)
		addMatch(techniqueID, buildProcessEvidence(result, process.Name, process.PID))
	}

	for _, reg := range result.Registry {
		techniqueID := MatchRegistryKey(reg.Key, reg.Action)
		addMatch(techniqueID, fmt.Sprintf(
			"Observed registry %s on %s by %s (PID=%d)",
			strings.ToLower(reg.Action),
			reg.Key,
			reg.Process,
			reg.PID,
		))
	}

	for _, conn := range result.Network {
		techniqueID := MatchNetworkConnection(conn.DestIP)
		addMatch(techniqueID, fmt.Sprintf(
			"Observed %s connection to %s:%d by %s (PID=%d)",
			conn.Protocol,
			conn.DestIP,
			conn.DestPort,
			conn.Process,
			conn.PID,
		))
	}

	for _, dns := range result.DNS {
		techniqueID := MatchDNSQuery(dns.Domain)

		evidence := fmt.Sprintf(
			"Observed DNS query for %s by %s (PID=%d)",
			dns.Domain,
			dns.Process,
			dns.PID,
		)
		if len(dns.Results) > 0 {
			evidence += fmt.Sprintf(", resolved to %s", strings.Join(dns.Results, ", "))
		}

		addMatch(techniqueID, evidence)
	}

	for _, img := range result.Images {
		techniqueID := MatchImagePath(img.Path)
		addMatch(techniqueID, fmt.Sprintf(
			"Observed module loaded from non-standard path %s by %s (PID=%d)",
			img.Path,
			img.Process,
			img.PID,
		))
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