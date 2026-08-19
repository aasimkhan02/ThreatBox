package analysis

import (
	"fmt"
	"os/exec"
)

func RunWithStrace(program string) (string, error) {
	cmd := exec.Command("strace", program)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("strace execution failed: %w", err)
	}

	return string(output), nil
}