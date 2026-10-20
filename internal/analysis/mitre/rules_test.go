package mitre

import (
	"testing"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func TestMatchProcessNameAcceptsShortNamesAndFullPaths(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"cmd.exe", "T1059.003"},
		{`C:\Windows\System32\cmd.exe`, "T1059.003"},
		{"C:/Windows/System32/cmd.exe", "T1059.003"},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe`, "T1059.001"},
		{"pwsh.exe", "T1059.001"},
		{`C:\Python312\python.exe`, "T1059.006"},
		{"sample.exe", ""},
		{`C:\ThreatBox\sample\sample.exe`, ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := MatchProcessName(tc.name); got != tc.want {
			t.Errorf("MatchProcessName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestProxyExecutionWritablePathDetection(t *testing.T) {
	cases := []struct {
		label string
		proc  ioc.ProcessIOC
		want  string
	}{
		{
			"rundll32 loading a DLL from a user temp dir",
			ioc.ProcessIOC{Name: `C:\Windows\System32\rundll32.exe`,
				Command: `rundll32.exe C:\Users\x\AppData\Local\Temp\a.dll,Run`},
			"T1218.011",
		},
		{
			"rundll32 with a normal system DLL is not flagged",
			ioc.ProcessIOC{Name: "rundll32.exe",
				Command: `rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL`},
			"",
		},
		{
			"installutil on an exe in ProgramData",
			ioc.ProcessIOC{Name: "installutil.exe",
				Command: `installutil.exe /U C:\ProgramData\x\tool.exe`},
			"T1218.004",
		},
		{
			"installutil on a system path is not flagged",
			ioc.ProcessIOC{Name: "installutil.exe",
				Command: `installutil.exe C:\Windows\Microsoft.NET\Framework\x.exe`},
			"",
		},
	}
	for _, tc := range cases {
		if got := MatchSystemBinaryProxyExecution(tc.proc); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.label, got, tc.want)
		}
	}
}
