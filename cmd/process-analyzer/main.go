package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
)

func addChild(parent, child *analysis.ProcessNode) {
	parent.Children = append(parent.Children, child)
	sort.Slice(parent.Children, func(i, j int) bool {
		return parent.Children[i].PID < parent.Children[j].PID
	})
}

func printNode(node *analysis.ProcessNode, prefix string, last bool) {
	branch := "├── "
	nextPrefix := prefix + "│   "
	if last {
		branch = "└── "
		nextPrefix = prefix + "    "
	}

	fmt.Printf("%s%s%s (PID=%d)\n", prefix, branch, node.Image, node.PID)

	for i, child := range node.Children {
		printNode(child, nextPrefix, i == len(node.Children)-1)
	}
}

func printProcessPath(chain []*analysis.ProcessNode) {
	if len(chain) == 0 {
		return
	}

	fmt.Printf("%s (PID=%d)\n", chain[0].Image, chain[0].PID)

	for i := 1; i < len(chain); i++ {
		prefix := strings.Repeat("    ", i-1)
		fmt.Printf("%s└── %s (PID=%d)\n", prefix, chain[i].Image, chain[i].PID)
	}

	sample := chain[len(chain)-1]
	prefix := strings.Repeat("    ", len(chain)-1)
	for i, child := range sample.Children {
		printNode(child, prefix, i == len(sample.Children)-1)
	}
}

func normalizeFileAction(eventType string) string {
	switch eventType {
	case "file_create", "file_create_init":
		return "CREATE"
	case "file_read":
		return "READ"
	case "file_write":
		return "WRITE"
	case "file_delete", "file_delete_information":
		return "DELETE"
	case "file_rename":
		return "RENAME"
	default:
		return ""
	}
}

func isInterestingPath(path string) bool {
	if path == "" {
		return false
	}

	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, "\\device\\harddisk") && strings.HasSuffix(lower, "\\dr0") {
		return false
	}

	return true
}

func resolveFilePath(event analysis.Event, names map[uint64]string) string {
	if isInterestingPath(event.FileName) {
		return event.FileName
	}

	if event.FileObject != 0 {
		if name := names[event.FileObject]; isInterestingPath(name) {
			return name
		}
	}

	if event.FileKey != 0 {
		if name := names[event.FileKey]; isInterestingPath(name) {
			return name
		}
	}

	return ""
}

func readEvents(path string) (
	map[uint64]*analysis.ProcessNode,
	[]*analysis.Event,
	*analysis.ProcessNode,
	uint64,
	map[uint64]uint64,
	map[uint64]string,
	error,
) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, 0, nil, nil, fmt.Errorf("open telemetry: %w", err)
	}
	defer file.Close()

	processes := make(map[uint64]*analysis.ProcessNode)
	var fileEvents []*analysis.Event
	var sample *analysis.ProcessNode
	var lostEvents uint64

	threadToProcess := make(map[uint64]uint64)
	fileNames := make(map[uint64]string)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		var event analysis.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		switch event.Type {
		case "process_start":
			node := &analysis.ProcessNode{
				PID:     event.PID,
				PPID:    event.PPID,
				Image:   event.Image,
				Command: event.Command,
				Time:    event.Time,
			}
			processes[event.PID] = node

			if strings.EqualFold(event.Image, "sample.exe") && sample == nil {
				sample = node
			}

		case "thread_start", "thread_dc_start":
			if event.ThreadID != 0 && event.PID != 0 {
				threadToProcess[event.ThreadID] = event.PID
			}

		case "etw_lost_events":
			if event.LostEvents > lostEvents {
				lostEvents = event.LostEvents
			}

		default:
			if isInterestingPath(event.FileName) {
				switch event.Type {
				case "file_name", "file_create", "file_rundown", "file_create_init":
					if event.FileObject != 0 {
						fileNames[event.FileObject] = event.FileName
					}
					if event.FileKey != 0 {
						fileNames[event.FileKey] = event.FileName
					}
				}
			}

			if normalizeFileAction(event.Type) != "" {
				copyEvent := event
				fileEvents = append(fileEvents, &copyEvent)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, nil, 0, nil, nil, fmt.Errorf("read telemetry: %w", err)
	}

	// Resolve thread-based attribution only after all thread/process events
	// have been read, so event ordering cannot make the mapping fail.
	for _, event := range fileEvents {
		// Preferred attribution: FileIo TTID -> Thread event -> ProcessId.
		if event.ThreadID != 0 {
			if pid, ok := threadToProcess[event.ThreadID]; ok {
				event.PID = pid
			}
		}

		// Fallback only when the FileIo header PID is a real process ID.
		// Classic FileIo commonly reports 0xffffffff, which must not be used.
		if event.PID == ^uint64(0) {
			event.PID = 0
		}

		if event.FileName == "" {
			if event.FileObject != 0 {
				event.FileName = fileNames[event.FileObject]
			}
			if event.FileName == "" && event.FileKey != 0 {
				event.FileName = fileNames[event.FileKey]
			}
		}
	}

	return processes, fileEvents, sample, lostEvents, threadToProcess, fileNames, nil
}

func buildProcessTree(processes map[uint64]*analysis.ProcessNode, sample *analysis.ProcessNode) []*analysis.ProcessNode {
	for _, node := range processes {
		node.Children = nil
	}

	for _, node := range processes {
		if parent, ok := processes[node.PPID]; ok && parent.PID != node.PID {
			addChild(parent, node)
		}
	}

	var chain []*analysis.ProcessNode
	for current := sample; current != nil; {
		chain = append(chain, current)
		parent, ok := processes[current.PPID]
		if !ok || parent.PID == current.PID {
			break
		}
		current = parent
	}

	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	return chain
}

func collectSampleFileActivity(
	fileEvents []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	fileNames map[uint64]string,
) []analysis.FileActivity {
	activities := make(map[string]*analysis.FileActivity)

	for _, event := range fileEvents {
		if !relevantPIDs[event.PID] {
			continue
		}

		action := normalizeFileAction(event.Type)
		if action == "" {
			continue
		}

		path := resolveFilePath(*event, fileNames)
		if path == "" {
			continue
		}

		image := "unknown"
		if process, ok := processes[event.PID]; ok {
			image = process.Image
		}

		key := fmt.Sprintf("%s\x00%s", action, path)
		activity, ok := activities[key]
		if !ok {
			activity = &analysis.FileActivity{
				Action: action,
				Path:   path,
				PID:    event.PID,
				Image:  image,
			}
			activities[key] = activity
		}

		activity.Count++
		if action == "WRITE" {
			activity.Bytes += event.IoSize
		}
	}

	result := make([]analysis.FileActivity, 0, len(activities))
	for _, activity := range activities {
		result = append(result, *activity)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Action != result[j].Action {
			return result[i].Action < result[j].Action
		}
		return result[i].Path < result[j].Path
	})

	return result
}

func markDescendants(root *analysis.ProcessNode, relevant map[uint64]bool) {
	relevant[root.PID] = true
	for _, child := range root.Children {
		markDescendants(child, relevant)
	}
}

func analyzeEvents(path string) error {
	processes, fileEvents, sample, lostEvents, _, fileNames, err := readEvents(path)
	if err != nil {
		return err
	}

	if sample == nil {
		fmt.Println("No sample.exe process found")
		return nil
	}

	chain := buildProcessTree(processes, sample)
	if len(chain) == 0 {
		fmt.Println("No process tree found")
		return nil
	}

	relevantPIDs := make(map[uint64]bool)
	markDescendants(sample, relevantPIDs)

	activities := collectSampleFileActivity(fileEvents, relevantPIDs, processes, fileNames)

	iocResult := ioc.Extract(activities, processes, relevantPIDs, sample)
	jsonData, _ := json.MarshalIndent(iocResult, "", "  ")
	fmt.Println(string(jsonData))

	fmt.Println("ANALYSIS")
	fmt.Printf("Target: %s (PID=%d)\n", sample.Image, sample.PID)

	fmt.Println("\nPROCESS TREE")
	printProcessPath(chain)

	fmt.Println("\nFILE ACTIVITY")
	if len(activities) == 0 {
		fmt.Println("No relevant file activity attributed to the sample process tree")
	} else {
		for _, activity := range activities {
			if activity.Action == "WRITE" && activity.Bytes > 0 {
				fmt.Printf("%s x%d | PID=%d | %s | %s | bytes=%d\n",
					activity.Action,
					activity.Count,
					activity.PID,
					activity.Image,
					activity.Path,
					activity.Bytes,
				)
			} else {
				fmt.Printf("%s x%d | PID=%d | %s | %s\n",
					activity.Action,
					activity.Count,
					activity.PID,
					activity.Image,
					activity.Path,
				)
			}
		}
	}

	fmt.Printf("\nTELEMETRY LOST: %d\n", lostEvents)
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
