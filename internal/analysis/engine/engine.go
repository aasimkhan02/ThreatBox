package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/scoring"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/stream"
)

// telemetry is everything extracted from one pass over the collector's
// JSONL output. Replaces the previous seven-value positional return
// from readEvents, which was about to grow past ten.
type telemetry struct {
	Processes map[uint64]*analysis.ProcessNode
	Sample    *analysis.ProcessNode

	FileEvents     []*analysis.Event
	NetworkEvents  []*analysis.Event
	RegistryEvents []*analysis.Event
	DNSEvents      []*analysis.Event
	ImageEvents    []*analysis.Event

	FileNames       map[uint64]string
	ThreadToProcess map[uint64]uint64
	LostEvents      uint64
}

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

func normalizeRegistryAction(eventType string) string {
	switch eventType {
	case "registry_create":
		return "CREATE"
	case "registry_open":
		return "OPEN"
	case "registry_delete":
		return "DELETE_KEY"
	case "registry_set_value":
		return "SET_VALUE"
	case "registry_delete_value":
		return "DELETE_VALUE"
	default:
		// Query/Enumerate/Flush/KCB/Rundown/Virtualize/Close are
		// bookkeeping noise for security analysis (the same subset
		// Sysmon surfaces by default) - skip them here.
		return ""
	}
}

func normalizeNetworkAction(eventType string) string {
	switch eventType {
	case "network_connect":
		return "TCP_CONNECT"
	case "network_accept":
		return "TCP_ACCEPT"
	case "network_udp_send":
		return "UDP_SEND"
	case "network_udp_receive":
		return "UDP_RECEIVE"
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

func readEvents(path string) (*telemetry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open telemetry: %w", err)
	}
	defer file.Close()

	t := &telemetry{
		Processes:       make(map[uint64]*analysis.ProcessNode),
		FileNames:       make(map[uint64]string),
		ThreadToProcess: make(map[uint64]uint64),
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		var event analysis.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		switch {
		case event.Type == "process_start":
			node := &analysis.ProcessNode{
				PID:     event.PID,
				PPID:    event.PPID,
				Image:   event.Image,
				Command: event.Command,
				Time:    event.Time,
			}
			t.Processes[event.PID] = node

			if strings.EqualFold(event.Image, "sample.exe") && t.Sample == nil {
				t.Sample = node
			}

		case event.Type == "thread_start" || event.Type == "thread_dc_start":
			if event.ThreadID != 0 && event.PID != 0 {
				t.ThreadToProcess[event.ThreadID] = event.PID
			}

		case event.Type == "etw_lost_events":
			if event.LostEvents > t.LostEvents {
				t.LostEvents = event.LostEvents
			}

		case strings.HasPrefix(event.Type, "network_"):
			copyEvent := event
			t.NetworkEvents = append(t.NetworkEvents, &copyEvent)

		case strings.HasPrefix(event.Type, "registry_"):
			copyEvent := event
			t.RegistryEvents = append(t.RegistryEvents, &copyEvent)

		case strings.HasPrefix(event.Type, "dns_"):
			copyEvent := event
			t.DNSEvents = append(t.DNSEvents, &copyEvent)

		case strings.HasPrefix(event.Type, "image_"):
			copyEvent := event
			t.ImageEvents = append(t.ImageEvents, &copyEvent)

		default:
			if isInterestingPath(event.FileName) {
				switch event.Type {
				case "file_name", "file_create", "file_rundown", "file_create_init":
					if event.FileObject != 0 {
						t.FileNames[event.FileObject] = event.FileName
					}
					if event.FileKey != 0 {
						t.FileNames[event.FileKey] = event.FileName
					}
				}
			}

			if normalizeFileAction(event.Type) != "" {
				copyEvent := event
				t.FileEvents = append(t.FileEvents, &copyEvent)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read telemetry: %w", err)
	}

	// Resolve thread-based attribution only after all thread/process events
	// have been read, so event ordering cannot make the mapping fail.
	for _, event := range t.FileEvents {
		// Preferred attribution: FileIo TTID -> Thread event -> ProcessId.
		if event.ThreadID != 0 {
			if pid, ok := t.ThreadToProcess[event.ThreadID]; ok {
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
				event.FileName = t.FileNames[event.FileObject]
			}
			if event.FileName == "" && event.FileKey != 0 {
				event.FileName = t.FileNames[event.FileKey]
			}
		}
	}

	return t, nil
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

func collectSampleNetworkActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
) []analysis.NetworkActivity {
	activities := make(map[string]*analysis.NetworkActivity)

	for _, event := range events {
		if !relevantPIDs[event.PID] {
			continue
		}

		action := normalizeNetworkAction(event.Type)
		if action == "" {
			continue
		}

		image := "unknown"
		if process, ok := processes[event.PID]; ok {
			image = process.Image
		}

		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", action, event.DestIP, event.DestPort, event.PID)
		activity, ok := activities[key]
		if !ok {
			activity = &analysis.NetworkActivity{
				Type:       action,
				Protocol:   event.Protocol,
				PID:        event.PID,
				Image:      image,
				SourceIP:   event.SourceIP,
				SourcePort: event.SourcePort,
				DestIP:     event.DestIP,
				DestPort:   event.DestPort,
			}
			activities[key] = activity
		}
		activity.Count++
	}

	result := make([]analysis.NetworkActivity, 0, len(activities))
	for _, activity := range activities {
		result = append(result, *activity)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		if result[i].DestIP != result[j].DestIP {
			return result[i].DestIP < result[j].DestIP
		}
		return result[i].DestPort < result[j].DestPort
	})

	return result
}

func collectSampleRegistryActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
) []analysis.RegistryActivity {
	activities := make(map[string]*analysis.RegistryActivity)

	for _, event := range events {
		if !relevantPIDs[event.PID] {
			continue
		}

		action := normalizeRegistryAction(event.Type)
		if action == "" || event.RegistryKey == "" {
			continue
		}

		image := "unknown"
		if process, ok := processes[event.PID]; ok {
			image = process.Image
		}

		key := fmt.Sprintf("%s\x00%s\x00%d", action, event.RegistryKey, event.PID)
		activity, ok := activities[key]
		if !ok {
			activity = &analysis.RegistryActivity{
				Action: action,
				Key:    event.RegistryKey,
				PID:    event.PID,
				Image:  image,
			}
			activities[key] = activity
		}
		activity.Count++
	}

	result := make([]analysis.RegistryActivity, 0, len(activities))
	for _, activity := range activities {
		result = append(result, *activity)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Action != result[j].Action {
			return result[i].Action < result[j].Action
		}
		return result[i].Key < result[j].Key
	})

	return result
}

func collectSampleDNSActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
) []analysis.DNSActivity {
	activities := make(map[string]*analysis.DNSActivity)

	for _, event := range events {
		if !relevantPIDs[event.PID] || event.DNSQueryName == "" {
			continue
		}

		image := "unknown"
		if process, ok := processes[event.PID]; ok {
			image = process.Image
		}

		key := fmt.Sprintf("%s\x00%d", event.DNSQueryName, event.PID)
		activity, ok := activities[key]
		if !ok {
			activity = &analysis.DNSActivity{
				QueryName: event.DNSQueryName,
				PID:       event.PID,
				Image:     image,
			}
			activities[key] = activity
		}
		activity.Count++

		for _, resolvedIP := range event.DNSResults {
			exists := false
			for _, existing := range activity.Results {
				if existing == resolvedIP {
					exists = true
					break
				}
			}
			if !exists {
				activity.Results = append(activity.Results, resolvedIP)
			}
		}
	}

	result := make([]analysis.DNSActivity, 0, len(activities))
	for _, activity := range activities {
		result = append(result, *activity)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].QueryName < result[j].QueryName
	})

	return result
}

func collectSampleImageActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
) []analysis.ImageActivity {
	activities := make(map[string]*analysis.ImageActivity)

	for _, event := range events {
		if !relevantPIDs[event.PID] || event.Image == "" {
			continue
		}

		// Skip the trace-start/trace-end rundown of every image already
		// loaded system-wide; that's not activity performed by the
		// sample, just Windows enumerating what's already resident.
		if event.Type == "image_dc_start" || event.Type == "image_dc_end" {
			continue
		}

		procImage := "unknown"
		if process, ok := processes[event.PID]; ok {
			procImage = process.Image
		}

		key := fmt.Sprintf("%s\x00%d", event.Image, event.PID)
		activity, ok := activities[key]
		if !ok {
			activity = &analysis.ImageActivity{
				Path:          event.Image,
				PID:           event.PID,
				Image:         procImage,
				ImageChecksum: event.ImageChecksum,
			}
			activities[key] = activity
		}
		activity.Count++
	}

	result := make([]analysis.ImageActivity, 0, len(activities))
	for _, activity := range activities {
		result = append(result, *activity)
	}

	sort.Slice(result, func(i, j int) bool {
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

func printFileActivity(activities []analysis.FileActivity) {
	if len(activities) == 0 {
		fmt.Println("No relevant file activity attributed to the sample process tree")
		return
	}

	for _, activity := range activities {
		if activity.Action == "WRITE" && activity.Bytes > 0 {
			fmt.Printf("%s x%d | PID=%d | %s | %s | bytes=%d\n",
				activity.Action, activity.Count, activity.PID, activity.Image, activity.Path, activity.Bytes)
		} else {
			fmt.Printf("%s x%d | PID=%d | %s | %s\n",
				activity.Action, activity.Count, activity.PID, activity.Image, activity.Path)
		}
	}
}

func printNetworkActivity(activities []analysis.NetworkActivity) {
	if len(activities) == 0 {
		fmt.Println("No relevant network activity attributed to the sample process tree")
		return
	}

	for _, activity := range activities {
		fmt.Printf("%s x%d | PID=%d | %s | %s:%d -> %s:%d\n",
			activity.Type, activity.Count, activity.PID, activity.Image,
			activity.SourceIP, activity.SourcePort, activity.DestIP, activity.DestPort)
	}
}

func printRegistryActivity(activities []analysis.RegistryActivity) {
	if len(activities) == 0 {
		fmt.Println("No relevant registry activity attributed to the sample process tree")
		return
	}

	for _, activity := range activities {
		fmt.Printf("%s x%d | PID=%d | %s | %s\n",
			activity.Action, activity.Count, activity.PID, activity.Image, activity.Key)
	}
}

func printDNSActivity(activities []analysis.DNSActivity) {
	if len(activities) == 0 {
		fmt.Println("No relevant DNS activity attributed to the sample process tree")
		return
	}

	for _, activity := range activities {
		results := "no response captured"
		if len(activity.Results) > 0 {
			results = strings.Join(activity.Results, ", ")
		}
		fmt.Printf("QUERY x%d | PID=%d | %s | %s -> %s\n",
			activity.Count, activity.PID, activity.Image, activity.QueryName, results)
	}
}

func printImageActivity(activities []analysis.ImageActivity) {
	if len(activities) == 0 {
		fmt.Println("No relevant image/DLL loads attributed to the sample process tree")
		return
	}

	for _, activity := range activities {
		fmt.Printf("LOAD x%d | PID=%d | %s | %s\n",
			activity.Count, activity.PID, activity.Image, activity.Path)
	}
}

func broadcast(server *stream.Server, event stream.Event) {
	if server != nil {
		server.Broadcast(event)
	}
}

func Analyze(path string, streamServer *stream.Server) (mitre.AnalysisOutput, error) {

	broadcast(streamServer, stream.Event{
		Type: "analysis_started",
		Data: map[string]interface{}{
			"message": "Analysis started",
		},
	})

	t, err := readEvents(path)
	if err != nil {
		return mitre.AnalysisOutput{}, err
	}

	if t.Sample == nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("no sample.exe process found")
	}

	chain := buildProcessTree(t.Processes, t.Sample)
	if len(chain) == 0 {
		return mitre.AnalysisOutput{}, fmt.Errorf("no process tree found")
	}

	relevantPIDs := make(map[uint64]bool)
	markDescendants(t.Sample, relevantPIDs)

	fileActivities := collectSampleFileActivity(t.FileEvents, relevantPIDs, t.Processes, t.FileNames)
	networkActivities := collectSampleNetworkActivity(t.NetworkEvents, relevantPIDs, t.Processes)
	registryActivities := collectSampleRegistryActivity(t.RegistryEvents, relevantPIDs, t.Processes)
	dnsActivities := collectSampleDNSActivity(t.DNSEvents, relevantPIDs, t.Processes)
	imageActivities := collectSampleImageActivity(t.ImageEvents, relevantPIDs, t.Processes)

	iocResult := ioc.Extract(ioc.Activities{
		Files:    fileActivities,
		Network:  networkActivities,
		Registry: registryActivities,
		DNS:      dnsActivities,
		Images:   imageActivities,
	}, t.Processes, relevantPIDs, t.Sample)

	mitreDB, err := mitre.LoadDatabase(`data\mitre-data\enterprise-attack.json`)
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("load MITRE database: %w", err)
	}

	techniques := mitre.Map(iocResult, mitreDB)

	for _, technique := range techniques {
		broadcast(streamServer, stream.Event{
			Type: "technique_detected",
			Data: technique,
		})
	}

	techniqueIDs := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		techniqueIDs = append(techniqueIDs, technique.TechniqueID)
	}

	threatScore := scoring.Calculate(techniqueIDs)

	broadcast(streamServer, stream.Event{
		Type: "score_updated",
		Data: threatScore,
	})

	broadcast(streamServer, stream.Event{Type: "network_activity", Data: networkActivities})
	broadcast(streamServer, stream.Event{Type: "registry_activity", Data: registryActivities})
	broadcast(streamServer, stream.Event{Type: "dns_activity", Data: dnsActivities})
	broadcast(streamServer, stream.Event{Type: "image_activity", Data: imageActivities})

	output := mitre.AnalysisOutput{
		Sample:      iocResult.Sample,
		Files:       iocResult.Files,
		Processes:   iocResult.Processes,
		Network:     iocResult.Network,
		Registry:    iocResult.Registry,
		DNS:         iocResult.DNS,
		Images:      iocResult.Images,
		Techniques:  techniques,
		ThreatScore: threatScore,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("marshal analysis result: %w", err)
	}

	broadcast(streamServer, stream.Event{
		Type: "analysis_completed",
		Data: output,
	})

	fmt.Println(string(jsonData))
	fmt.Println("ANALYSIS")
	fmt.Printf("Target: %s (PID=%d)\n", t.Sample.Image, t.Sample.PID)

	fmt.Println("\nPROCESS TREE")
	printProcessPath(chain)

	fmt.Println("\nFILE ACTIVITY")
	printFileActivity(fileActivities)

	fmt.Println("\nNETWORK ACTIVITY")
	printNetworkActivity(networkActivities)

	fmt.Println("\nREGISTRY ACTIVITY")
	printRegistryActivity(registryActivities)

	fmt.Println("\nDNS ACTIVITY")
	printDNSActivity(dnsActivities)

	fmt.Println("\nIMAGE LOAD ACTIVITY")
	printImageActivity(imageActivities)

	fmt.Printf("\nTELEMETRY LOST: %d\n", t.LostEvents)
	return output, nil
}
