package sandbox

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteConfig(t *testing.T) {
	root := t.TempDir()

	sampleDir := filepath.Join(root, "sample")
	outputDir := filepath.Join(root, "output")
	toolsDir := filepath.Join(root, "tools")

	for _, dir := range []string{sampleDir, outputDir, toolsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	configPath := filepath.Join(root, "sandbox.wsb")

	err := WriteConfig(
		configPath,
		sampleDir,
		outputDir,
		toolsDir,
		"test-job-123",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		XMLName              xml.Name `xml:"Configuration"`
		VGpu                 string   `xml:"VGpu"`
		Networking           string   `xml:"Networking"`
		ClipboardRedirection string   `xml:"ClipboardRedirection"`
		MappedFolders        struct {
			Folders []struct {
				HostFolder    string `xml:"HostFolder"`
				SandboxFolder string `xml:"SandboxFolder"`
				ReadOnly      bool   `xml:"ReadOnly"`
			} `xml:"MappedFolder"`
		} `xml:"MappedFolders"`
		LogonCommand struct {
			Command string `xml:"Command"`
		} `xml:"LogonCommand"`
	}

	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("generated config is invalid XML: %v", err)
	}

	if decoded.XMLName.Local != "Configuration" {
		t.Fatalf("unexpected root element: %s", decoded.XMLName.Local)
	}
	if decoded.Networking != "Disable" {
		t.Fatalf("expected networking disabled, got %q", decoded.Networking)
	}
	if decoded.VGpu != "Disable" {
		t.Fatalf("expected vGPU disabled, got %q", decoded.VGpu)
	}
	if decoded.ClipboardRedirection != "Disable" {
		t.Fatalf("expected clipboard redirection disabled, got %q", decoded.ClipboardRedirection)
	}
	if len(decoded.MappedFolders.Folders) != 3 {
		t.Fatalf("expected 3 mapped folders, got %d", len(decoded.MappedFolders.Folders))
	}
	if !decoded.MappedFolders.Folders[0].ReadOnly {
		t.Fatal("sample folder must be read-only")
	}
	if decoded.MappedFolders.Folders[1].ReadOnly {
		t.Fatal("output folder must be writable")
	}
	if !decoded.MappedFolders.Folders[2].ReadOnly {
		t.Fatal("tools folder must be read-only")
	}
	if !strings.Contains(decoded.LogonCommand.Command, "sandbox-agent.exe") {
		t.Fatalf("LogonCommand does not launch the guest agent: %q", decoded.LogonCommand.Command)
	}
	if !strings.Contains(decoded.LogonCommand.Command, "--job-id test-job-123") {
		t.Fatalf("LogonCommand is missing the job ID: %q", decoded.LogonCommand.Command)
	}
}
