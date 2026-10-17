package sandbox

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type mappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder"`
	ReadOnly      bool   `xml:"ReadOnly"`
}

type mappedFolders struct {
	Folders []mappedFolder `xml:"MappedFolder"`
}

type logonCommand struct {
	Command string `xml:"Command"`
}

type sandboxConfiguration struct {
	XMLName              xml.Name      `xml:"Configuration"`
	VGpu                 string        `xml:"VGpu"`
	Networking           string        `xml:"Networking"`
	ClipboardRedirection string        `xml:"ClipboardRedirection"`
	MemoryInMB           int           `xml:"MemoryInMB"`
	MappedFolders        mappedFolders `xml:"MappedFolders"`
	LogonCommand         logonCommand  `xml:"LogonCommand"`
}

func WriteConfig(
	configPath string,
	sampleHostDir string,
	outputHostDir string,
	toolsHostDir string,
	jobID string,
	sampleTimeout time.Duration,
) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}

	if sampleTimeout <= 0 {
		return fmt.Errorf("sample timeout must be positive")
	}

	sampleHostDir, err := absoluteExistingDirectory(sampleHostDir)
	if err != nil {
		return fmt.Errorf("sample directory: %w", err)
	}

	outputHostDir, err = absoluteExistingDirectory(outputHostDir)
	if err != nil {
		return fmt.Errorf("output directory: %w", err)
	}

	toolsHostDir, err = absoluteExistingDirectory(toolsHostDir)
	if err != nil {
		return fmt.Errorf("tools directory: %w", err)
	}

	timeoutSeconds := int(sampleTimeout / time.Second)
	if timeoutSeconds < 1 {
		timeoutSeconds = 1
	}

	command := fmt.Sprintf(
		`%s --job-id %s --timeout-seconds %s`,
		filepath.Join(GuestToolsDir, AgentExeName),
		jobID,
		strconv.Itoa(timeoutSeconds),
	)

	cfg := sandboxConfiguration{
		VGpu:                 "Disable",
		Networking:           "Disable",
		ClipboardRedirection: "Disable",
		MemoryInMB:           2048,
		MappedFolders: mappedFolders{
			Folders: []mappedFolder{
				{
					HostFolder:    sampleHostDir,
					SandboxFolder: GuestSampleDir,
					ReadOnly:      true,
				},
				{
					HostFolder:    outputHostDir,
					SandboxFolder: GuestOutputDir,
					ReadOnly:      false,
				},
				{
					HostFolder:    toolsHostDir,
					SandboxFolder: GuestToolsDir,
					ReadOnly:      true,
				},
			},
		},
		LogonCommand: logonCommand{
			Command: command,
		},
	}

	data, err := xml.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Sandbox configuration: %w", err)
	}

	data = append([]byte(xml.Header), data...)
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("write Sandbox configuration: %w", err)
	}

	return nil
}

func absoluteExistingDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", absolute)
	}

	return absolute, nil
}
