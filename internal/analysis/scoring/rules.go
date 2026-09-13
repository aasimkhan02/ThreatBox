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
	{
		TechniqueID: "T1547.001",
		Points:      30,
		Reason:      "Registry Run key persistence detected",
	},
	{
		TechniqueID: "T1071",
		Points:      15,
		Reason:      "Outbound network connection to a public address detected",
	},
	{
		TechniqueID: "T1071.004",
		Points:      10,
		Reason:      "DNS resolution activity detected",
	},
	{
		TechniqueID: "T1574.002",
		Points:      20,
		Reason:      "Module loaded from a non-standard path detected",
	},
}