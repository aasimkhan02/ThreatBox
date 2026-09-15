package mitre

import (
	"path"
	"strings"
	"unicode"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func MatchProcessName(name string) string {
	name = strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(name, "/", `\`))))

	switch name {
	case "powershell.exe", "pwsh.exe":
		return "T1059.001"
	case "cmd.exe":
		return "T1059.003"
	case "python.exe", "pythonw.exe":
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

// A public-IP connection is not by itself evidence of T1071. T1071 requires
// application-layer protocol semantics that our current telemetry does not
// expose reliably, so we intentionally do not map raw network connections.
func MatchNetworkConnection(destIP string) string {
	return ""
}

// Ordinary DNS resolution is common. Only an unusually long/generated-looking
// DNS name is treated as a candidate for T1071.004 with the current telemetry.
func MatchDNSQuery(domain string) string {
	if !isSuspiciousDNSDomain(domain) {
		return ""
	}
	return "T1071.004"
}

func isSuspiciousDNSDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	if len(domain) >= 80 {
		return true
	}

	maxLabelLen := 0
	longLabels := 0
	for _, label := range labels {
		if len(label) > maxLabelLen {
			maxLabelLen = len(label)
		}
		if len(label) >= 30 {
			longLabels++
		}
	}
	if maxLabelLen >= 40 || longLabels >= 2 {
		return true
	}

	// Look only at subdomain labels. Require a genuinely long label and a
	// strong generated/encoded shape rather than treating every long hostname
	// as malicious.
	for _, label := range labels[:len(labels)-2] {
		if len(label) < 24 {
			continue
		}
		if digitRatio(label) >= 0.50 || hasEncodedCharacterMix(label) {
			return true
		}
	}

	return false
}

func hasEncodedCharacterMix(value string) bool {
	if len(value) < 24 {
		return false
	}

	letters := 0
	digits := 0
	other := 0
	for _, r := range value {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		case r == '-' || r == '_':
			other++
		}
	}

	// Generated labels often mix alphabetic and numeric material heavily.
	return digits >= 8 && letters >= 8 && digits+letters+other == len([]rune(value))
}

func digitRatio(value string) float64 {
	if value == "" {
		return 0
	}

	digits := 0
	total := 0
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			total++
			if unicode.IsDigit(r) {
				digits++
			}
		}
	}

	if total == 0 {
		return 0
	}
	return float64(digits) / float64(total)
}

// MatchImagePath deliberately never maps an unusual DLL path by itself.
// A non-standard module location is not sufficient evidence of side-loading.
func MatchImagePath(path string) string {
	return ""
}

// MatchSystemBinaryProxyExecution maps only characteristic command-line
// patterns for Windows signed-binary proxy execution. Merely running a native
// utility is not enough to claim the ATT&CK sub-technique.
func MatchSystemBinaryProxyExecution(process ioc.ProcessIOC) string {
	name := strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(process.Name, "/", `\`))))
	command := strings.ToLower(strings.TrimSpace(process.Command))

	switch name {
	case "mshta.exe":
		if containsAny(command, "javascript:", "vbscript:", "script:", "http://", "https://") {
			return "T1218.005"
		}

	case "msiexec.exe":
		if strings.Contains(command, ".msi") &&
			containsAny(command, "http://", "https://", `\\`) {
			return "T1218.007"
		}

	case "regsvr32.exe":
		if containsAny(command, "http://", "https://") ||
			(strings.Contains(command, ".sct") && strings.Contains(command, "/i")) {
			return "T1218.010"
		}

	case "rundll32.exe":
		if containsAny(command, "javascript:", "http://", "https://") ||
			(strings.Contains(command, ".dll") && containsWritablePath(command)) {
			return "T1218.011"
		}

	case "installutil.exe":
		if (strings.Contains(command, ".exe") || strings.Contains(command, ".dll")) &&
			containsWritablePath(command) {
			return "T1218.004"
		}
	}

	return ""
}

func containsWritablePath(command string) bool {
	command = strings.ToLower(command)
	return containsAny(
		command,
		`\\users\\`,
		`\\appdata\\`,
		`\\windows\\temp\\`,
		`\\temp\\`,
		`\\programdata\\`,
	)
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

// MatchDLLSideLoading correlates the observable plant -> load pattern:
//  1. a DLL is created/modified in a user-writable location;
//  2. the same DLL is loaded;
//  3. the loader differs from the writer;
//  4. common script/runtime hosts are excluded.
func MatchDLLSideLoading(files []ioc.FileIOC, images []ioc.ImageIOC) (string, string) {
	type fileWrite struct {
		PID     uint64
		Process string
		Type    string
	}

	writes := make(map[string][]fileWrite)

	for _, file := range files {
		if file.PID == 0 || file.Path == "" {
			continue
		}

		typ := strings.ToLower(file.Type)
		if typ != "created" && typ != "modified" {
			continue
		}

		normalized := normalizeWindowsPath(file.Path)
		if !isDLL(normalized) || !isWritableDLLPath(normalized) {
			continue
		}

		writes[normalized] = append(writes[normalized], fileWrite{
			PID:     file.PID,
			Process: file.Process,
			Type:    typ,
		})
	}

	for _, image := range images {
		if image.PID == 0 || image.Path == "" {
			continue
		}

		normalized := normalizeWindowsPath(image.Path)
		if !isDLL(normalized) || !isWritableDLLPath(normalized) {
			continue
		}

		if isCommonRuntimeOrInterpreter(image.Process) {
			continue
		}

		for _, write := range writes[normalized] {
			if write.PID == image.PID {
				continue
			}

			return "T1574.002", buildDLLSideLoadingEvidence(
				image,
				write.PID,
				write.Process,
				write.Type,
			)
		}
	}

	return "", ""
}

func normalizeWindowsPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "/", `\`)))
	p = strings.TrimPrefix(p, `\??\`)

	if strings.HasPrefix(p, `\device\harddiskvolume`) {
		if idx := strings.Index(p, `\windows\`); idx >= 0 {
			p = p[idx:]
		} else if idx := strings.Index(p, `\users\`); idx >= 0 {
			p = p[idx:]
		} else if idx := strings.Index(p, `\programdata\`); idx >= 0 {
			p = p[idx:]
		}
	}

	if strings.HasPrefix(p, `\device\vmsmb\`) {
		if idx := strings.Index(p, `\os\`); idx >= 0 {
			p = p[idx+3:]
		}
	}

	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}

	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}

	return p
}

func isDLL(p string) bool {
	return strings.HasSuffix(p, `.dll`)
}

func isWritableDLLPath(p string) bool {
	for _, prefix := range []string{
		`\users\`,
		`\windows\temp\`,
		`\temp\`,
		`\appdata\`,
		`\programdata\`,
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func isCommonRuntimeOrInterpreter(process string) bool {
	name := strings.ToLower(strings.TrimSpace(path.Base(strings.ReplaceAll(process, "/", `\`))))
	switch name {
	case "powershell.exe", "pwsh.exe", "cmd.exe",
		"python.exe", "pythonw.exe",
		"wscript.exe", "cscript.exe", "mshta.exe":
		return true
	default:
		return false
	}
}

func buildDLLSideLoadingEvidence(
	image ioc.ImageIOC,
	writerPID uint64,
	writerProcess string,
	writeType string,
) string {
	return "Correlated DLL side-loading indicators: the DLL " +
		image.Path +
		" was " + writeType +
		" by " + writerProcess +
		" (PID=" + uint64String(writerPID) +
		") and loaded by " + image.Process +
		" (PID=" + uint64String(image.PID) +
		") from a user-writable location"
}

func uint64String(v uint64) string {
	if v == 0 {
		return "0"
	}

	const digits = "0123456789"
	var buf [20]byte
	i := len(buf)

	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}

	return string(buf[i:])
}
