package mitre

import "strings"

func MatchProcessName(name string) string {
	name = strings.ToLower(name)

	switch name {
	case "powershell.exe":
		return "T1059.001"

	case "cmd.exe":
		return "T1059.003"

	case "python.exe":
		return "T1059.006"

	default:
		return ""
	}
}