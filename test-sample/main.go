package main

import (
	"os/exec"
)

func main() {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-Command",
		"Write-Output 'ThreatBox MITRE test'",
	)

	_ = cmd.Run()
}