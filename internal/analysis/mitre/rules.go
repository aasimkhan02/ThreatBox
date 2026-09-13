package mitre

import (
	"net"
	"strings"
)

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

func MatchRegistryKey(key, action string) string {
	if action != "SET_VALUE" && action != "CREATE" {
		return ""
	}

	lower := strings.ToLower(key)
	if strings.Contains(lower, `\microsoft\windows\currentversion\run`) {
		return "T1547.001"
	}

	return ""
}


func MatchNetworkConnection(destIP string) string {
	if destIP == "" {
		return ""
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		return ""
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return ""
	}

	return "T1071"
}

func MatchDNSQuery(domain string) string {
	if domain == "" {
		return ""
	}

	return "T1071.004"
}


func MatchImagePath(path string) string {
	if path == "" {
		return ""
	}

	lower := strings.ToLower(path)

	trustedPrefixes := []string{
		`\windows\system32\`,
		`\windows\syswow64\`,
		`\windows\winsxs\`,
		`\program files\`,
		`\program files (x86)\`,
	}

	for _, prefix := range trustedPrefixes {
		if strings.Contains(lower, prefix) {
			return ""
		}
	}

	return "T1574.002"
}