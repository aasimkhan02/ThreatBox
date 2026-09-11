package scoring

func Calculate(techniqueIDs []string) ThreatScore {
	score := 0
	reasons := make([]string, 0)

	for _, techniqueID := range techniqueIDs {
		for _, rule := range Rules {
			if techniqueID != rule.TechniqueID {
				continue
			}

			score += rule.Points
			reasons = append(reasons, rule.Reason)
			break
		}
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