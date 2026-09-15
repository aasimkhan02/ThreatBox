package scoring

func Calculate(techniqueIDs []string, ctx Context) ThreatScore {
	score := 0
	reasons := make([]string, 0)

	hasPowerShell := false
	hasCmd := false
	hasRunKey := false
	hasSuspiciousDNS := false
	hasSideLoading := false
	hasProxy := false

	for _, techniqueID := range techniqueIDs {
		for _, rule := range Rules {
			if techniqueID != rule.TechniqueID {
				continue
			}

			score += rule.Points
			reasons = append(reasons, rule.Reason)
			break
		}

		switch techniqueID {
		case "T1059.001":
			hasPowerShell = true
		case "T1059.003":
			hasCmd = true
		case "T1547.001":
			hasRunKey = true
		case "T1071.004":
			hasSuspiciousDNS = true
		case "T1574.002":
			hasSideLoading = true
		case "T1218.004", "T1218.005", "T1218.007", "T1218.010", "T1218.011":
			hasProxy = true
		}
	}

	if hasPowerShell && ctx.SuspiciousFileMutation {
		score += 10
		reasons = append(reasons, "PowerShell correlated with suspicious file mutation")
	}

	if hasCmd && ctx.SuspiciousFileMutation {
		score += 8
		reasons = append(reasons, "Command Shell correlated with suspicious file mutation")
	}

	if hasRunKey && ctx.SuspiciousFileMutation {
		score += 10
		reasons = append(reasons, "Persistence correlated with a suspicious file mutation")
	}

	if hasSuspiciousDNS && ctx.ExternalNetworkActivity {
		score += 10
		reasons = append(reasons, "Suspicious DNS behavior correlated with external network activity")
	}

	if hasProxy && ctx.ExternalNetworkActivity {
		score += 8
		reasons = append(reasons, "Proxy execution correlated with external network activity")
	}

	if hasSideLoading && ctx.SuspiciousFileMutation {
		score += 10
		reasons = append(reasons, "DLL side-loading correlated with payload file mutation")
	}

	if ctx.MassFileCreation {
		score += 12
		reasons = append(reasons, "Mass behavioral file creation detected")
	}

	if ctx.MassFileModification {
		score += 10
		reasons = append(reasons, "Mass behavioral file modification detected")
	}

	if score > 100 {
		score = 100
	}

	return ThreatScore{
		Score:    score,
		Severity: severity(score),
		Reasons:  reasons,
	}
}

func severity(score int) string {
	switch {
	case score >= 75:
		return "Critical"
	case score >= 50:
		return "High"
	case score >= 25:
		return "Medium"
	default:
		return "Low"
	}
}
