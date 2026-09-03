package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type ProcessEvent struct {
	Type    string `json:"type"`
	PID     uint64 `json:"pid"`
	PPID    uint64 `json:"ppid,omitempty"`
	Image   string `json:"image,omitempty"`
	Command string `json:"command,omitempty"`
}

type ProcessNode struct {
	PID      uint64
	PPID     uint64
	Image    string
	Command  string
	Children []*ProcessNode
}

func printProcessNode(node *ProcessNode, prefix string, last bool) {
	branch := "├── "
	nextPrefix := prefix + "│   "

	if last {
		branch = "└── "
		nextPrefix = prefix + "    "
	}

	fmt.Printf(
		"%s%s%s (PID=%d)\n",
		prefix,
		branch,
		node.Image,
		node.PID,
	)

	for i, child := range node.Children {
		printProcessNode(
			child,
			nextPrefix,
			i == len(node.Children)-1,
		)
	}
}

func analyzeEvents(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open telemetry: %w", err)
	}
	defer file.Close()

	processes := make(map[uint64]*ProcessNode)

	var sample *ProcessNode

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var event ProcessEvent

		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		if event.Type != "process_start" {
			continue
		}

		node := &ProcessNode{
			PID:     event.PID,
			PPID:    event.PPID,
			Image:   event.Image,
			Command: event.Command,
		}

		processes[event.PID] = node

		if event.Image == "sample.exe" {
			sample = node
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read telemetry: %w", err)
	}

	if sample == nil {
		fmt.Println("No sample.exe process found")
		return nil
	}

	// Build parent → child relationships.
	for _, node := range processes {
		if parent, ok := processes[node.PPID]; ok {
			parent.Children = append(parent.Children, node)
		}
	}

	// Walk upward from sample to find its ancestors.
	var chain []*ProcessNode

	current := sample

	for current != nil {
		chain = append(chain, current)

		parent, ok := processes[current.PPID]
		if !ok {
			break
		}

		current = parent
	}

	// Print from oldest ancestor down to sample.
	fmt.Println("PROCESS TREE")

	for i := len(chain) - 1; i >= 0; i-- {
		node := chain[i]

		if i == len(chain)-1 {
			fmt.Printf("%s (PID=%d)\n", node.Image, node.PID)
		} else {
			fmt.Printf("└── %s (PID=%d)\n", node.Image, node.PID)
		}
	}

	return nil
}

func main() {
	path := `C:\ThreatBox\runtime\output\events.jsonl`

	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	if err := analyzeEvents(path); err != nil {
		fmt.Println("Analyzer error:", err)
		os.Exit(1)
	}
}