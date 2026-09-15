package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/scoring"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/stream"
)

// telemetry is everything extracted from one pass over the collector's
// JSONL output. Replaces the previous seven-value positional return
// from readEvents, which was about to grow past ten.
type processInstance struct {
	PID     uint64
	PPID    uint64
	Image   string
	Command string
	Start   time.Time
	Stop    time.Time
	Node    *analysis.ProcessNode
}

type telemetry struct {
	Processes map[uint64]*analysis.ProcessNode
	Sample    *analysis.ProcessNode

	ProcessInstances []*processInstance
	SampleInstance   *processInstance

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

// fileCategory is a small semantic label used for reporting and prioritization.
// It is descriptive only; a category is not a malware verdict.
type fileCategory string

const (
	fileCategoryExecutable fileCategory = "EXECUTABLE"
	fileCategoryScript     fileCategory = "SCRIPT"
	fileCategoryConfig     fileCategory = "CONFIG"
	fileCategoryTemporary  fileCategory = "TEMPORARY"
	fileCategoryOther      fileCategory = "OTHER"
)

type fileRelevance int

const (
	fileRelevanceLow fileRelevance = iota
	fileRelevanceNormal
	fileRelevanceNotable
	fileRelevanceSuspicious
)

// FileBehaviorSummary is the high-level view of retained file telemetry.
// The detailed FileActivity records remain the source of IOC evidence.
type FileBehaviorSummary struct {
	Created                int                     `json:"created"`
	Modified               int                     `json:"modified"`
	Deleted                int                     `json:"deleted"`
	Renamed                int                     `json:"renamed"`
	InfrastructureCreated  int                     `json:"infrastructure_created"`
	InfrastructureModified int                     `json:"infrastructure_modified"`
	BehavioralCreated      int                     `json:"behavioral_created"`
	BehavioralModified     int                     `json:"behavioral_modified"`
	NotableReads           int                     `json:"notable_reads"`
	TotalActivities        int                     `json:"total_activities"`
	NormalActivities       int                     `json:"normal_activities"`
	NotableActivities      int                     `json:"notable_activities"`
	LowValueActivities     int                     `json:"low_value_activities"`
	SuppressedRawEvents    uint64                  `json:"suppressed_raw_events"`
	TotalBytesWritten      uint64                  `json:"total_bytes_written"`
	CategoryCounts         map[fileCategory]int    `json:"category_counts"`
	NotableFiles           []analysis.FileActivity `json:"notable_files"`
	Patterns               []string                `json:"patterns"`
}

func classifyFileCategory(path string) fileCategory {
	p := normalizeFilterPath(path)

	switch {
	case strings.HasSuffix(p, ".exe"),
		strings.HasSuffix(p, ".dll"),
		strings.HasSuffix(p, ".sys"),
		strings.HasSuffix(p, ".scr"),
		strings.HasSuffix(p, ".com"):
		return fileCategoryExecutable

	case strings.HasSuffix(p, ".ps1"),
		strings.HasSuffix(p, ".bat"),
		strings.HasSuffix(p, ".cmd"),
		strings.HasSuffix(p, ".vbs"),
		strings.HasSuffix(p, ".js"),
		strings.HasSuffix(p, ".jse"),
		strings.HasSuffix(p, ".wsf"),
		strings.HasSuffix(p, ".wsh"),
		strings.HasSuffix(p, ".hta"):
		return fileCategoryScript

	case strings.HasSuffix(p, ".ini"),
		strings.HasSuffix(p, ".cfg"),
		strings.HasSuffix(p, ".conf"),
		strings.HasSuffix(p, ".config"),
		strings.HasSuffix(p, ".json"),
		strings.HasSuffix(p, ".xml"),
		strings.HasSuffix(p, ".yaml"),
		strings.HasSuffix(p, ".yml"):
		return fileCategoryConfig

	case strings.HasSuffix(p, ".tmp"),
		strings.HasSuffix(p, ".temp"):
		return fileCategoryTemporary

	default:
		return fileCategoryOther
	}
}

func isUserWritablePath(path string) bool {
	p := normalizeFilterPath(path)

	for _, prefix := range []string{
		`\users\`,
		`\appdata\`,
		`\windows\temp\`,
		`\temp\`,
		`\programdata\`,
	} {
		if strings.Contains(p, prefix) {
			return true
		}
	}

	return false
}

func isSecuritySensitiveFilePath(path string) bool {
	p := normalizeFilterPath(path)

	for _, name := range []string{
		`\windows\system32\drivers\etc\hosts`,
		`\windows\system.ini`,
		`\windows\win.ini`,
	} {
		if strings.Contains(p, name) {
			return true
		}
	}

	for _, marker := range []string{
		`\startup\`,
		`\start menu\programs\startup\`,
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}

	return false
}

func isInfrastructureFilePath(path string) bool {
	p := normalizeFilterPath(path)

	infrastructurePrefixes := []string{
		`\windows\system32\`,
		`\windows\syswow64\`,
		`\windows\winsxs\`,
		`\windows\microsoft.net\`,
		`\windows\apppatch\`,
		`\windows\system32\windowspowershell\`,
		`\program files\windowspowershell\`,
		`\programdata\microsoft\windows defender\`,
		`\users\wdagutilityaccount\appdata\local\packages\microsoft.windows.search_`,
		`\users\wdagutilityaccount\appdata\local\microsoft\windows\powershell\`,
	}

	for _, prefix := range infrastructurePrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}

	// PowerShell's execution-policy probe is a short-lived runtime artifact,
	// not a payload drop.
	if strings.Contains(p, `\users\wdagutilityaccount\appdata\local\temp\__psscriptpolicytest_`) {
		return true
	}

	return false
}

func isExpectedRuntimeFileActivity(activity analysis.FileActivity) bool {
	if !isInfrastructureFilePath(activity.Path) {
		return false
	}

	process := strings.ToLower(strings.TrimSpace(activity.Image))
	switch process {
	case "powershell.exe", "pwsh.exe":
		return true
	default:
		return false
	}
}

func scoreFileRelevance(activity analysis.FileActivity) fileRelevance {
	category := classifyFileCategory(activity.Path)
	writable := isUserWritablePath(activity.Path)
	sensitive := isSecuritySensitiveFilePath(activity.Path)

	// PowerShell/.NET/Defender runtime activity in known infrastructure
	// locations is intentionally treated as low-value context. The same path
	// created by the submitted sample process remains visible and significant.
	if isExpectedRuntimeFileActivity(activity) && !sensitive {
		return fileRelevanceLow
	}

	score := 0

	// Mutations deserve more attention than ordinary reads.
	if activity.Action != "READ" {
		score++
	}

	if category == fileCategoryExecutable || category == fileCategoryScript {
		score += 2
	}

	if category == fileCategoryConfig {
		score++
	}

	if writable {
		score += 2
	}

	if sensitive {
		score += 3
	}

	// Repetition is useful context without making it a verdict.
	if activity.Count >= 25 {
		score++
	}

	if activity.Bytes >= 1024*1024 {
		score++
	}

	if sensitive || score >= 5 {
		return fileRelevanceSuspicious
	}

	if score >= 3 {
		return fileRelevanceNotable
	}

	if score >= 1 {
		return fileRelevanceNormal
	}

	return fileRelevanceLow
}

func fileActionPriority(action string) int {
	switch action {
	case "CREATE":
		return 5
	case "WRITE":
		return 4
	case "DELETE":
		return 3
	case "RENAME":
		return 2
	case "READ":
		return 1
	default:
		return 0
	}
}

func buildFileBehaviorSummary(
	activities []analysis.FileActivity,
	suppressed uint64,
) FileBehaviorSummary {
	summary := FileBehaviorSummary{
		TotalActivities:     len(activities),
		SuppressedRawEvents: suppressed,
		CategoryCounts:      make(map[fileCategory]int),
		NotableFiles:        make([]analysis.FileActivity, 0),
		Patterns:            make([]string, 0),
	}

	for _, activity := range activities {
		category := classifyFileCategory(activity.Path)
		summary.CategoryCounts[category]++

		infrastructure := isInfrastructureFilePath(activity.Path)
		switch activity.Action {
		case "CREATE":
			summary.Created++
			if infrastructure {
				summary.InfrastructureCreated++
			} else {
				summary.BehavioralCreated++
			}
		case "WRITE":
			summary.Modified++
			summary.TotalBytesWritten += activity.Bytes
			if infrastructure {
				summary.InfrastructureModified++
			} else {
				summary.BehavioralModified++
			}
		case "DELETE":
			summary.Deleted++
		case "RENAME":
			summary.Renamed++
		case "READ":
			// Counts retained READ records; only notable reads are surfaced
			// separately below.
		}

		switch scoreFileRelevance(activity) {
		case fileRelevanceLow:
			summary.LowValueActivities++
		case fileRelevanceNormal:
			summary.NormalActivities++
		case fileRelevanceNotable, fileRelevanceSuspicious:
			summary.NotableActivities++
			if activity.Action == "READ" {
				summary.NotableReads++
			}
		}
	}

	candidates := make([]analysis.FileActivity, 0)
	for _, activity := range activities {
		if scoreFileRelevance(activity) >= fileRelevanceNotable {
			candidates = append(candidates, activity)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		ri := scoreFileRelevance(candidates[i])
		rj := scoreFileRelevance(candidates[j])

		if ri != rj {
			return ri > rj
		}

		pi := fileActionPriority(candidates[i].Action)
		pj := fileActionPriority(candidates[j].Action)

		if pi != pj {
			return pi > pj
		}

		if candidates[i].Bytes != candidates[j].Bytes {
			return candidates[i].Bytes > candidates[j].Bytes
		}

		if candidates[i].Count != candidates[j].Count {
			return candidates[i].Count > candidates[j].Count
		}

		return candidates[i].Path < candidates[j].Path
	})

	const maxNotableFiles = 12
	if len(candidates) > maxNotableFiles {
		candidates = candidates[:maxNotableFiles]
	}

	summary.NotableFiles = append(summary.NotableFiles, candidates...)

	// Mass patterns describe behavioral paths, not Windows/.NET/Sandbox
	// infrastructure. This prevents PowerShell runtime activity from
	// masquerading as a payload drop burst.
	if summary.BehavioralCreated >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass behavioral file creation: %d distinct paths", summary.BehavioralCreated),
		)
	}

	if summary.BehavioralModified >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass behavioral file modification: %d distinct paths", summary.BehavioralModified),
		)
	}

	if summary.Deleted >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass file deletion: %d distinct paths", summary.Deleted),
		)
	}

	if summary.Renamed >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass file rename activity: %d distinct paths", summary.Renamed),
		)
	}

	if n := summary.CategoryCounts[fileCategoryExecutable]; n > 0 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Executable/library activity: %d distinct paths", n),
		)
	}

	if n := summary.CategoryCounts[fileCategoryScript]; n > 0 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Script activity: %d distinct paths", n),
		)
	}

	if n := summary.CategoryCounts[fileCategoryConfig]; n > 0 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Configuration activity: %d distinct paths", n),
		)
	}

	return summary
}

func hasTechnique(techniques []mitre.TechniqueMatch, id string) bool {
	for _, technique := range techniques {
		if technique.TechniqueID == id {
			return true
		}
	}
	return false
}

func hasExternalNetwork(activities []analysis.NetworkActivity) bool {
	for _, activity := range activities {
		if activity.DestIP == "" {
			continue
		}
		ip := net.ParseIP(activity.DestIP)
		if ip == nil {
			continue
		}
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func hasSuspiciousFileMutation(activities []analysis.FileActivity) bool {
	for _, activity := range activities {
		if activity.Action != "CREATE" && activity.Action != "WRITE" {
			continue
		}
		if isExpectedRuntimeFileActivity(activity) {
			continue
		}

		category := classifyFileCategory(activity.Path)
		if isSecuritySensitiveFilePath(activity.Path) ||
			(category == fileCategoryExecutable || category == fileCategoryScript) &&
				isUserWritablePath(activity.Path) {
			return true
		}
	}
	return false
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

// isRelevantProcess centralizes process-tree attribution for behavioral
// telemetry. A PID is relevant only when it belongs to the submitted sample
// or one of its descendants. PID 0 is never treated as sample activity.
func isRelevantProcess(pid uint64, relevantPIDs map[uint64]bool) bool {
	return pid != 0 && relevantPIDs[pid]
}

// harddiskVolumePrefix matches the NT-namespace volume prefix ETW commonly
// reports file paths in, e.g. "\device\harddiskvolume3\windows\...".
var harddiskVolumePrefix = regexp.MustCompile(`^\\device\\harddiskvolume\d+`)

// vsmbOsSharePrefix matches Windows Sandbox's virtual SMB share for the
// container's own OS volume, e.g.
// "\device\vmsmb\vsmb-{dcc079ae-60ba-4d07-847c-3493609c0870}\os\windows\...".
// This share re-exposes the sandbox's normal Windows directory over vmsmb, so
// once the share/GUID prefix is stripped the remainder is an ordinary Windows
// path and can be filtered with the same rules as any other Windows path.
//
// This intentionally does NOT match every \Device\vmsmb\... path - other
// VSMB paths (e.g. hash-named shares with no \os\ segment) are left
// untouched because it isn't yet known whether they represent sample-mounted
// data rather than sandbox OS infrastructure.
var vsmbOsSharePrefix = regexp.MustCompile(`^\\device\\vmsmb\\vsmb-\{[0-9a-f-]+\}\\os`)

// normalizeFilterPath collapses the different path representations ETW may
// report for the same file into one lowercase, backslash-separated form so
// prefix-based filtering matches regardless of how the path arrived:
//
//   - \Device\HarddiskVolume3\Windows\System32\kernel32.dll
//   - \??\C:\Windows\System32\kernel32.dll
//   - C:\Windows\System32\kernel32.dll
//   - \Device\vmsmb\VSMB-{guid}\os\Windows\System32\kernel32.dll
//
// all normalize to "\windows\system32\kernel32.dll". This is used only for
// filtering/comparison; callers keep the original, unnormalized path for
// display and evidence.
func normalizeFilterPath(path string) string {
	p := strings.ToLower(strings.ReplaceAll(path, "/", "\\"))

	// \??\C:\Windows\... (DOS-device path) -> C:\Windows\...
	p = strings.TrimPrefix(p, `\??\`)

	// \Device\HarddiskVolumeN\Windows\... -> \Windows\...
	// The specific volume number doesn't matter for filtering; only the
	// path beneath it does.
	p = harddiskVolumePrefix.ReplaceAllString(p, "")

	// \Device\vmsmb\VSMB-{guid}\os\Windows\... -> \Windows\...
	// Sandbox-OS share only; other vmsmb shares are left as-is.
	p = vsmbOsSharePrefix.ReplaceAllString(p, "")

	// C:\Windows\... -> \Windows\...
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}

	return p
}

// isHighValueFileRead filters low-value READ telemetry generated by normal
// Windows/Sandbox/runtime activity while retaining security-relevant reads.
func isHighValueFileRead(path string) bool {
	if path == "" {
		return false
	}

	p := normalizeFilterPath(path)

	// Security-sensitive files override the normal Windows noise rules.
	interestingNames := []string{
		`\windows\system32\drivers\etc\hosts`,
		`\windows\system.ini`,
		`\windows\win.ini`,
		`\sam`,
		`\security`,
		`\system`,
	}

	for _, name := range interestingNames {
		if strings.Contains(p, name) {
			return true
		}
	}

	// Normal OS/runtime reads are background noise for behavioral analysis.
	// This intentionally covers only known infrastructure, not arbitrary
	// user-writable locations.
	normalNoisePrefixes := []string{
		`\windows\system32\`,
		`\windows\syswow64\`,
		`\windows\winsxs\`,
		`\windows\microsoft.net\`,
		`\windows\apppatch\`,
		`\windows\system32\windowspowershell\`,
		`\program files\windowspowershell\`,
		`\programdata\microsoft\windows defender\`,
	}

	for _, prefix := range normalNoisePrefixes {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}

	// Windows Sandbox / session bootstrap artifacts that commonly appear as
	// descendants of cmd.exe / powershell.exe but are not sample behavior.
	if isKnownBackgroundFilePath(p) {
		return false
	}

	// Reads from user-writable or application-data locations remain visible.
	userWritablePrefixes := []string{
		`\users\`,
		`\windows\temp\`,
		`\temp\`,
		`\appdata\`,
		`\programdata\`,
		`\threatbox\runtime\`,
		`\threatbox\sample\`,
	}

	for _, prefix := range userWritablePrefixes {
		if strings.Contains(p, prefix) {
			return true
		}
	}

	// Executables, scripts, libraries and configuration files outside known
	// Windows runtime paths are useful evidence.
	highValueExtensions := []string{
		`.exe`,
		`.dll`,
		`.sys`,
		`.ps1`,
		`.bat`,
		`.cmd`,
		`.vbs`,
		`.js`,
		`.hta`,
		`.msi`,
		`.config`,
		`.ini`,
		`.json`,
	}

	for _, ext := range highValueExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}

	// Unknown non-system reads are retained rather than silently discarded.
	return true
}

// isKnownBackgroundFilePath identifies a small set of Windows Sandbox/session
// artifacts observed in our telemetry. These are suppressed for both reads
// and mutations because their repeated activity is known infrastructure noise.
// This is deliberately narrow; arbitrary files in Users/AppData/ProgramData
// remain visible.
func isKnownBackgroundFilePath(p string) bool {
	backgroundPrefixes := []string{
		`\users\wdagutilityaccount\appdata\local\packages\microsoft.windows.search_`,
		`\users\wdagutilityaccount\appdata\roaming\microsoft\windows\recent\automaticdestinations\`,
		`\users\wdagutilityaccount\appdata\roaming\microsoft\windows\recent\customdestinations\`,
		`\users\wdagutilityaccount\appdata\local\microsoft\windows\powershell\startupprofiledata`,
		`\windows\system32\microsoft\protect\s-1-5-18\preferred`,
		`\windows\apppatch\sysmain.sdb`,
		`\windows\system32\perfstringbackup.tmp`,
		`\programdata\microsoft\windows defender\`,
	}

	for _, prefix := range backgroundPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}

	return false
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

	openProcesses := make(map[uint64]*processInstance)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		var event analysis.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		switch {
		case event.Type == "process_start":
			startTime, err := parseEventTime(event.Time)
			if err != nil {
				continue
			}

			node := &analysis.ProcessNode{
				PID:     event.PID,
				PPID:    event.PPID,
				Image:   event.Image,
				Command: event.Command,
				Time:    event.Time,
			}

			instance := &processInstance{
				PID:     event.PID,
				PPID:    event.PPID,
				Image:   event.Image,
				Command: event.Command,
				Start:   startTime,
				Node:    node,
			}

			// A PID must not be considered the same process after reuse.
			// If a new start arrives without a stop for the old instance,
			// close the old lifetime at the new start timestamp.
			if previous := openProcesses[event.PID]; previous != nil && previous.Stop.IsZero() {
				previous.Stop = startTime
			}

			openProcesses[event.PID] = instance
			t.ProcessInstances = append(t.ProcessInstances, instance)

			// Keep the legacy PID-indexed map for existing output/IOC
			// compatibility. Behavioral attribution never relies on it.
			t.Processes[event.PID] = node

			if strings.EqualFold(event.Image, "sample.exe") && t.SampleInstance == nil {
				t.SampleInstance = instance
				t.Sample = node
			}

		case event.Type == "process_stop":
			stopTime, err := parseEventTime(event.Time)
			if err == nil {
				if instance := openProcesses[event.PID]; instance != nil {
					instance.Stop = stopTime
					delete(openProcesses, event.PID)
				}
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

func parseEventTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty event timestamp")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func buildProcessInstanceIndex(instances []*processInstance) map[uint64][]*processInstance {
	index := make(map[uint64][]*processInstance)
	for _, instance := range instances {
		index[instance.PID] = append(index[instance.PID], instance)
	}

	for pid := range index {
		sort.Slice(index[pid], func(i, j int) bool {
			return index[pid][i].Start.Before(index[pid][j].Start)
		})
	}

	return index
}

func processInstanceAt(pid uint64, eventTime time.Time, index map[uint64][]*processInstance) *processInstance {
	instances := index[pid]
	if len(instances) == 0 || eventTime.IsZero() {
		return nil
	}

	var candidate *processInstance
	for _, instance := range instances {
		if instance.Start.After(eventTime) {
			break
		}
		if instance.Stop.IsZero() || !eventTime.After(instance.Stop) {
			candidate = instance
		}
	}
	return candidate
}

func markRelevantProcessInstances(
	root *processInstance,
	instances []*processInstance,
	relevant map[*processInstance]bool,
) {
	if root == nil {
		return
	}

	relevant[root] = true

	// Resolve each child to the single parent process instance that was alive
	// when the child started. This prevents a reused PID from inheriting the
	// wrong ancestry.
	parentInstance := func(child *processInstance) *processInstance {
		var best *processInstance
		for _, candidate := range instances {
			if candidate.PID != child.PPID {
				continue
			}
			if candidate.Start.After(child.Start) {
				continue
			}
			if !candidate.Stop.IsZero() && candidate.Stop.Before(child.Start) {
				continue
			}
			if best == nil || candidate.Start.After(best.Start) {
				best = candidate
			}
		}
		return best
	}

	queue := []*processInstance{root}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]

		for _, child := range instances {
			if relevant[child] || child.PPID != parent.PID {
				continue
			}

			if p := parentInstance(child); p == parent {
				relevant[child] = true
				if child.Node != nil {
					parent.Node.Children = append(parent.Node.Children, child.Node)
				}
				queue = append(queue, child)
			}
		}
	}
}

func eventProcessInstance(
	event *analysis.Event,
	index map[uint64][]*processInstance,
) *processInstance {
	if event == nil {
		return nil
	}
	eventTime, err := parseEventTime(event.Time)
	if err != nil {
		return nil
	}
	return processInstanceAt(event.PID, eventTime, index)
}

func relevantEventProcess(
	event *analysis.Event,
	index map[uint64][]*processInstance,
	relevant map[*processInstance]bool,
) (*processInstance, bool) {
	instance := eventProcessInstance(event, index)
	if instance == nil || !relevant[instance] {
		return nil, false
	}
	return instance, true
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
	relevant map[*processInstance]bool,
	processIndex map[uint64][]*processInstance,
	fileNames map[uint64]string,
) ([]analysis.FileActivity, uint64) {
	activities := make(map[string]*analysis.FileActivity)
	var suppressedEvents uint64

	for _, event := range fileEvents {
		instance, ok := relevantEventProcess(event, processIndex, relevant)
		if !ok {
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

		filterPath := normalizeFilterPath(path)

		// Only READs from known Windows/Sandbox infrastructure are suppressed.
		// CREATE/WRITE/DELETE/RENAME are always retained because mutations can
		// represent payload drops, staging, persistence, or destructive behavior.
		if action == "READ" {
			if isKnownBackgroundFilePath(filterPath) || !isHighValueFileRead(path) {
				suppressedEvents++
				continue
			}
		}

		image := instance.Image

		// Preserve action/path/PID attribution in the evidence row while
		// deduplicating repeated low-level I/O.
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
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].PID < result[j].PID
	})

	return result, suppressedEvents
}

func collectSampleNetworkActivity(
	events []*analysis.Event,
	relevant map[*processInstance]bool,
	processIndex map[uint64][]*processInstance,
) []analysis.NetworkActivity {
	activities := make(map[string]*analysis.NetworkActivity)

	for _, event := range events {
		instance, ok := relevantEventProcess(event, processIndex, relevant)
		if !ok {
			continue
		}

		action := normalizeNetworkAction(event.Type)
		if action == "" {
			continue
		}

		image := instance.Image

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
	relevant map[*processInstance]bool,
	processIndex map[uint64][]*processInstance,
) []analysis.RegistryActivity {
	activities := make(map[string]*analysis.RegistryActivity)

	for _, event := range events {
		instance, ok := relevantEventProcess(event, processIndex, relevant)
		if !ok {
			continue
		}

		action := normalizeRegistryAction(event.Type)
		if action == "" || event.RegistryKey == "" {
			continue
		}

		image := instance.Image

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
	relevant map[*processInstance]bool,
	processIndex map[uint64][]*processInstance,
) []analysis.DNSActivity {
	activities := make(map[string]*analysis.DNSActivity)

	for _, event := range events {
		instance, ok := relevantEventProcess(event, processIndex, relevant)
		if !ok || event.DNSQueryName == "" {
			continue
		}

		image := instance.Image

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
	relevant map[*processInstance]bool,
	processIndex map[uint64][]*processInstance,
) []analysis.ImageActivity {
	activities := make(map[string]*analysis.ImageActivity)

	for _, event := range events {
		instance, ok := relevantEventProcess(event, processIndex, relevant)
		if !ok || event.Image == "" {
			continue
		}

		// Skip the trace-start/trace-end rundown of every image already
		// loaded system-wide; that's not activity performed by the
		// sample, just Windows enumerating what's already resident.
		if event.Type == "image_dc_start" || event.Type == "image_dc_end" {
			continue
		}

		procImage := instance.Image

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

	if t.SampleInstance == nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("sample.exe process instance not found")
	}

	processIndex := buildProcessInstanceIndex(t.ProcessInstances)
	relevantInstances := make(map[*processInstance]bool)
	markRelevantProcessInstances(t.SampleInstance, t.ProcessInstances, relevantInstances)

	if len(relevantInstances) == 0 {
		return mitre.AnalysisOutput{}, fmt.Errorf("no relevant process tree found")
	}

	relevantNodes := make(map[*analysis.ProcessNode]bool)
	relevantProcessList := make([]*analysis.ProcessNode, 0, len(relevantInstances))
	for instance := range relevantInstances {
		if instance.Node != nil {
			relevantNodes[instance.Node] = true
			relevantProcessList = append(relevantProcessList, instance.Node)
		}
	}
	sort.Slice(relevantProcessList, func(i, j int) bool {
		if relevantProcessList[i].PID != relevantProcessList[j].PID {
			return relevantProcessList[i].PID < relevantProcessList[j].PID
		}
		return relevantProcessList[i].Time < relevantProcessList[j].Time
	})

	fileActivities, suppressedFileEvents := collectSampleFileActivity(t.FileEvents, relevantInstances, processIndex, t.FileNames)
	fileSummary := buildFileBehaviorSummary(fileActivities, suppressedFileEvents)
	networkActivities := collectSampleNetworkActivity(t.NetworkEvents, relevantInstances, processIndex)
	registryActivities := collectSampleRegistryActivity(t.RegistryEvents, relevantInstances, processIndex)
	dnsActivities := collectSampleDNSActivity(t.DNSEvents, relevantInstances, processIndex)
	imageActivities := collectSampleImageActivity(t.ImageEvents, relevantInstances, processIndex)

	iocResult := ioc.ExtractRelevant(ioc.Activities{
		Files:    fileActivities,
		Network:  networkActivities,
		Registry: registryActivities,
		DNS:      dnsActivities,
		Images:   imageActivities,
	}, relevantProcessList, relevantNodes, t.Sample)

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

	threatScore := scoring.Calculate(techniqueIDs, scoring.Context{
		SuspiciousFileMutation:  hasSuspiciousFileMutation(fileActivities),
		MassFileCreation:        fileSummary.BehavioralCreated >= 25,
		MassFileModification:    fileSummary.BehavioralModified >= 25,
		ExternalNetworkActivity: len(networkActivities) > 0 && hasExternalNetwork(networkActivities),
		TelemetryLost:           t.LostEvents,
	})

	broadcast(streamServer, stream.Event{
		Type: "score_updated",
		Data: threatScore,
	})

	broadcast(streamServer, stream.Event{Type: "file_behavior_summary", Data: fileSummary})
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

	broadcast(streamServer, stream.Event{
		Type: "analysis_completed",
		Data: output,
	})

	fmt.Println()
	fmt.Println("========== THREATBOX ANALYSIS ==========")
	fmt.Printf("Sample   : %s\n", t.Sample.Image)
	fmt.Printf("PID      : %d\n", t.Sample.PID)
	fmt.Printf("Risk     : %s (%d/100)\n", threatScore.Severity, threatScore.Score)

	fmt.Println()
	fmt.Println("TECHNIQUES")

	if len(techniques) == 0 {
		fmt.Println("  None detected")
	} else {
		for _, technique := range techniques {
			fmt.Printf(
				"  • %s — %s\n",
				technique.TechniqueID,
				technique.Name,
			)
		}
	}

	fmt.Println()
	fmt.Println("FILE BEHAVIOR")
	fmt.Printf("  • Created: %d distinct paths\n", fileSummary.Created)
	fmt.Printf("    - Infrastructure/runtime: %d\n", fileSummary.InfrastructureCreated)
	fmt.Printf("    - Behavioral: %d\n", fileSummary.BehavioralCreated)
	fmt.Printf("  • Modified: %d distinct paths\n", fileSummary.Modified)
	fmt.Printf("    - Infrastructure/runtime: %d\n", fileSummary.InfrastructureModified)
	fmt.Printf("    - Behavioral: %d\n", fileSummary.BehavioralModified)
	fmt.Printf("  • Deleted: %d distinct paths\n", fileSummary.Deleted)
	fmt.Printf("  • Renamed: %d distinct paths\n", fileSummary.Renamed)
	if fileSummary.NotableReads > 0 {
		fmt.Printf("  • Notable reads: %d\n", fileSummary.NotableReads)
	}

	if len(fileSummary.NotableFiles) > 0 {
		fmt.Println()
		fmt.Println("NOTABLE FILES")
		for _, activity := range fileSummary.NotableFiles {
			if activity.Action == "WRITE" && activity.Bytes > 0 {
				fmt.Printf("  • %s x%d | %s | %s | bytes=%d\n",
					activity.Action,
					activity.Count,
					activity.Image,
					activity.Path,
					activity.Bytes,
				)
			} else {
				fmt.Printf("  • %s x%d | %s | %s\n",
					activity.Action,
					activity.Count,
					activity.Image,
					activity.Path,
				)
			}
		}
	}

	if len(fileSummary.Patterns) > 0 {
		fmt.Println()
		fmt.Println("FILE PATTERNS")
		for _, pattern := range fileSummary.Patterns {
			fmt.Printf("  • %s\n", pattern)
		}
	}

	if fileSummary.NormalActivities > 0 || fileSummary.LowValueActivities > 0 {
		fmt.Printf("\n  Additional file activity summarized: %d records\n",
			fileSummary.NormalActivities+fileSummary.LowValueActivities,
		)
	}

	if suppressedFileEvents > 0 {
		fmt.Printf("  Background file noise suppressed: %d raw events\n", suppressedFileEvents)
	}

	fmt.Println()
	fmt.Println("OTHER BEHAVIOR")
	if len(networkActivities) > 0 {
		fmt.Printf("  • Network activity: %d connections\n", len(networkActivities))
	}
	if len(dnsActivities) > 0 {
		fmt.Printf("  • DNS activity: %d queries\n", len(dnsActivities))
	}
	if len(imageActivities) > 0 {
		fmt.Printf("  • Image/DLL activity: %d modules\n", len(imageActivities))
	}

	fmt.Println("SCORE REASONS")

	if len(threatScore.Reasons) == 0 {
		fmt.Println("  None")
	} else {
		for _, reason := range threatScore.Reasons {
			fmt.Printf("  • %s\n", reason)
		}
	}

	fmt.Printf("\nTelemetry lost: %d\n", t.LostEvents)
	fmt.Println("========================================")

	return output, nil
}
