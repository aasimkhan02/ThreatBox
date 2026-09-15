package scoring

type Rule struct {
	TechniqueID string
	Points      int
	Reason      string
}

var Rules = []Rule{
	{
		TechniqueID: "T1059.001",
		Points:      10,
		Reason:      "PowerShell execution observed",
	},
	{
		TechniqueID: "T1059.003",
		Points:      8,
		Reason:      "Windows Command Shell execution observed",
	},
	{
		TechniqueID: "T1059.006",
		Points:      8,
		Reason:      "Python execution observed",
	},
	{
		TechniqueID: "T1547.001",
		Points:      30,
		Reason:      "Registry Run key persistence behavior detected",
	},
	{
		TechniqueID: "T1218.004",
		Points:      18,
		Reason:      "InstallUtil proxy execution pattern detected",
	},
	{
		TechniqueID: "T1218.005",
		Points:      18,
		Reason:      "Mshta proxy execution pattern detected",
	},
	{
		TechniqueID: "T1218.007",
		Points:      18,
		Reason:      "Msiexec proxy execution pattern detected",
	},
	{
		TechniqueID: "T1218.010",
		Points:      18,
		Reason:      "Regsvr32 proxy execution pattern detected",
	},
	{
		TechniqueID: "T1218.011",
		Points:      18,
		Reason:      "Rundll32 proxy execution pattern detected",
	},
	{
		TechniqueID: "T1071.004",
		Points:      20,
		Reason:      "Suspicious DNS communication pattern detected",
	},
	{
		TechniqueID: "T1574.002",
		Points:      35,
		Reason:      "High-confidence DLL side-loading correlation detected",
	},
}
