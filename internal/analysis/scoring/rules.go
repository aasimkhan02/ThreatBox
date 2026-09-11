package scoring

type Rule struct {
	TechniqueID string
	Points      int
	Reason      string
}

var Rules = []Rule{
	{
		TechniqueID: "T1059.001",
		Points:      25,
		Reason:      "PowerShell execution detected",
	},
	{
		TechniqueID: "T1059.003",
		Points:      20,
		Reason:      "Windows Command Shell execution detected",
	},
	{
		TechniqueID: "T1059.006",
		Points:      10,
		Reason:      "Python execution detected",
	},
}