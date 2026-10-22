package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/ioc"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/mitre"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/sandbox"
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
	LostEvents      uint64
	ProcessSeq      map[*analysis.ProcessNode]int
	ThreadToProcess map[uint64]uint64 // retained for compatibility; never used for historical attribution
	Root            SampleRootInfo

	ProcessEvents     []*analysis.Event
	ThreadEvents      []*analysis.Event
	ProcessHistory    []*processLifetime
	ProcessByPID      map[uint64][]*processLifetime
	ThreadHistory     []*threadLifetime
	ThreadsByID       map[uint64][]*threadLifetime
	EventOwners       map[*analysis.Event]*processLifetime
	SampleInstance    *processLifetime
	RelevantInstances map[*processLifetime]bool
}

// processLifetime represents one observed instance of a PID. PID alone is not
// an identity: Windows may reuse it after a process exits. Rundown instances
// are known to have been present at capture startup, but their true creation
// time is not inferred from the rundown event's timestamp.
type processLifetime struct {
	PID      uint64
	PPID     uint64
	Node     *analysis.ProcessNode
	Start    time.Time
	Stop     time.Time
	HasStart bool
	HasStop  bool
	Rundown  bool
	Sequence int
	Parent   *processLifetime
	Children []*processLifetime
}

type threadLifetime struct {
	ThreadID uint64
	PID      uint64
	Start    time.Time
	Stop     time.Time
	HasStart bool
	HasStop  bool
	Process  *processLifetime
	Sequence int
}

type eventAttribution struct {
	owners   map[*analysis.Event]*processLifetime
	relevant map[*processLifetime]bool
}

type orderedEvent struct {
	event    *analysis.Event
	sequence int
	at       time.Time
	hasTime  bool
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
	Created             int                     `json:"created"`
	Modified            int                     `json:"modified"`
	Deleted             int                     `json:"deleted"`
	Renamed             int                     `json:"renamed"`
	NotableReads        int                     `json:"notable_reads"`
	TotalActivities     int                     `json:"total_activities"`
	NormalActivities    int                     `json:"normal_activities"`
	NotableActivities   int                     `json:"notable_activities"`
	LowValueActivities  int                     `json:"low_value_activities"`
	SuppressedRawEvents uint64                  `json:"suppressed_raw_events"`
	TotalBytesWritten   uint64                  `json:"total_bytes_written"`
	CategoryCounts      map[fileCategory]int    `json:"category_counts"`
	CategoryRecords     map[fileCategory]int    `json:"category_record_counts"`
	NotableFiles        []analysis.FileActivity `json:"notable_files"`
	Patterns            []string                `json:"patterns"`
	PathKeying          string                  `json:"path_keying"`
	CreatedMeaning      string                  `json:"created_meaning"`
	Accounting          FileEventAccounting     `json:"accounting"`
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

func scoreFileRelevance(activity analysis.FileActivity) fileRelevance {
	category := classifyFileCategory(activity.Path)
	writable := isUserWritablePath(activity.Path)
	sensitive := isSecuritySensitiveFilePath(activity.Path)

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
		CategoryRecords:     make(map[fileCategory]int),
		NotableFiles:        make([]analysis.FileActivity, 0),
		Patterns:            make([]string, 0),
		PathKeying:          pathKeyingDescription,
		CreatedMeaning:      createdMeaningDescription,
	}

	// Unique-path sets use a conservative normalized key, so repeated I/O and
	// case-only spelling differences cannot inflate "distinct path" counts.
	// Activity rows keep their original paths; only the counting key is folded.
	createdPaths := make(map[string]struct{})
	modifiedPaths := make(map[string]struct{})
	deletedPaths := make(map[string]struct{})
	renamedPaths := make(map[string]struct{})
	pathCategories := make(map[string]fileCategory)

	for _, activity := range activities {
		category := classifyFileCategory(activity.Path)
		summary.CategoryRecords[category]++

		key := pathCountKey(activity.Path)
		if _, seen := pathCategories[key]; !seen {
			pathCategories[key] = category
		}

		switch activity.Action {
		case "CREATE":
			createdPaths[key] = struct{}{}
		case "WRITE":
			modifiedPaths[key] = struct{}{}
			summary.TotalBytesWritten += activity.Bytes
		case "DELETE":
			deletedPaths[key] = struct{}{}
		case "RENAME":
			renamedPaths[key] = struct{}{}
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

	summary.Created = len(createdPaths)
	summary.Modified = len(modifiedPaths)
	summary.Deleted = len(deletedPaths)
	summary.Renamed = len(renamedPaths)

	for _, category := range pathCategories {
		summary.CategoryCounts[category]++
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

	// High-volume patterns are based on distinct retained paths, not raw
	// ETW event counts, so repeated I/O on one file does not create a
	// misleading "mass activity" finding.
	if summary.Created >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass file open/create activity: %d distinct paths", summary.Created),
		)
	}

	if summary.Modified >= 25 {
		summary.Patterns = append(
			summary.Patterns,
			fmt.Sprintf("Mass file modification: %d distinct paths", summary.Modified),
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

// normalizeETWPID treats the common 32-bit ETW invalid-PID sentinel and the
// all-bits-set 64-bit sentinel as unknown. The collector stores its 32-bit
// event-header PID in a uint64, so comparing only against ^uint64(0) is wrong.
func normalizeETWPID(pid uint64) uint64 {
	if pid == 0xffffffff || pid == ^uint64(0) {
		return 0
	}
	return pid
}

func parseEventTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func orderLifecycleEvents(events []*analysis.Event) []orderedEvent {
	ordered := make([]orderedEvent, 0, len(events))
	for i, event := range events {
		at, ok := parseEventTime(event.Time)
		ordered = append(ordered, orderedEvent{event: event, sequence: i, at: at, hasTime: ok})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.hasTime && b.hasTime && !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		if a.hasTime != b.hasTime {
			return a.hasTime // timed records must be ordered chronologically
		}
		return a.sequence < b.sequence
	})
	return ordered
}

func closeProcessLifetime(instance *processLifetime, at time.Time, hasTime bool) {
	if instance == nil {
		return
	}
	if hasTime {
		instance.Stop = at
		instance.HasStop = true
	}
}

// buildProcessHistory reconstructs process instances from start/stop and
// process-rundown records. It keeps the legacy PID->latest-node map for report
// compatibility, while retaining every instance for time-aware event lookup.
func buildProcessHistory(t *telemetry) {
	t.Processes = make(map[uint64]*analysis.ProcessNode)
	t.ProcessSeq = make(map[*analysis.ProcessNode]int)
	t.ProcessHistory = nil
	t.ProcessByPID = make(map[uint64][]*processLifetime)

	ordered := orderLifecycleEvents(t.ProcessEvents)
	active := make(map[uint64]*processLifetime)

	for _, item := range ordered {
		event := item.event
		pid := normalizeETWPID(event.PID)
		if pid == 0 {
			continue
		}

		switch event.Type {
		case "process_start", "process_rundown":
			// A rundown duplicates a process-start when the same process was
			// created just as capture began. Do not invent a second instance.
			if event.Type == "process_rundown" && active[pid] != nil {
				continue
			}
			if previous := active[pid]; previous != nil {
				closeProcessLifetime(previous, item.at, item.hasTime)
				delete(active, pid)
			}

			node := &analysis.ProcessNode{
				PID:     pid,
				PPID:    normalizeETWPID(event.PPID),
				Image:   event.Image,
				Command: event.Command,
				Time:    event.Time,
			}
			instance := &processLifetime{
				PID:      pid,
				PPID:     node.PPID,
				Node:     node,
				Start:    item.at,
				HasStart: item.hasTime,
				Rundown:  event.Type == "process_rundown",
				Sequence: len(t.ProcessHistory),
			}
			t.ProcessHistory = append(t.ProcessHistory, instance)
			t.ProcessByPID[pid] = append(t.ProcessByPID[pid], instance)
			active[pid] = instance
			t.Processes[pid] = node
			t.ProcessSeq[node] = instance.Sequence

		case "process_stop":
			if current := active[pid]; current != nil {
				closeProcessLifetime(current, item.at, item.hasTime)
				delete(active, pid)
			}
		// process_rundown_end is a trace-end snapshot, not an actual exit.
		case "process_rundown_end":
		}
	}
}

func hasProcessHistory(t *telemetry, pid uint64) bool {
	return pid != 0 && len(t.ProcessByPID[pid]) != 0
}

func processLifetimeAt(t *telemetry, pid uint64, at time.Time, hasTime bool) *processLifetime {
	pid = normalizeETWPID(pid)
	if pid == 0 {
		return nil
	}
	matches := t.ProcessByPID[pid]
	if len(matches) == 0 {
		return nil
	}
	if !hasTime {
		// Without event time, resolve only when one instance is possible.
		if len(matches) == 1 {
			return matches[0]
		}
		return nil
	}

	var best *processLifetime
	for _, instance := range matches {
		if !instance.HasStart && len(matches) > 1 {
			continue // an untimed instance is ambiguous when this PID was reused
		}
		if instance.HasStart && at.Before(instance.Start) {
			continue
		}
		if instance.HasStop && !at.Before(instance.Stop) {
			continue // stop time is an exclusive end boundary
		}
		if best == nil || (instance.HasStart && (!best.HasStart || instance.Start.After(best.Start))) {
			best = instance
		}
	}
	return best
}

func closeThreadLifetime(instance *threadLifetime, at time.Time, hasTime bool) {
	if instance == nil {
		return
	}
	if hasTime {
		instance.Stop = at
		instance.HasStop = true
	}
}

func buildThreadHistory(t *telemetry) {
	t.ThreadHistory = nil
	t.ThreadsByID = make(map[uint64][]*threadLifetime)
	t.ThreadToProcess = make(map[uint64]uint64) // compatibility snapshot; never consulted for event attribution
	ordered := orderLifecycleEvents(t.ThreadEvents)
	active := make(map[uint64]*threadLifetime)
	for _, item := range ordered {
		event := item.event
		tid := event.ThreadID
		if tid == 0 {
			continue
		}
		pid := normalizeETWPID(event.PID)
		switch event.Type {
		case "thread_start", "thread_dc_start":
			if pid != 0 {
				t.ThreadToProcess[tid] = pid
			}
			if event.Type == "thread_dc_start" && active[tid] != nil && active[tid].PID == pid {
				continue
			}
			if previous := active[tid]; previous != nil {
				closeThreadLifetime(previous, item.at, item.hasTime)
			}
			instance := &threadLifetime{
				ThreadID: tid,
				PID:      pid,
				Start:    item.at,
				HasStart: item.hasTime,
				Process:  processLifetimeAt(t, pid, item.at, item.hasTime),
				Sequence: len(t.ThreadHistory),
			}
			t.ThreadHistory = append(t.ThreadHistory, instance)
			t.ThreadsByID[tid] = append(t.ThreadsByID[tid], instance)
			active[tid] = instance
		case "thread_stop":
			if current := active[tid]; current != nil && (pid == 0 || current.PID == pid) {
				closeThreadLifetime(current, item.at, item.hasTime)
				delete(active, tid)
			}
		// thread_dc_stop is a trace rundown record, not necessarily thread exit.
		case "thread_dc_stop":
		}
	}
}

func threadLifetimeAt(t *telemetry, tid uint64, at time.Time, hasTime bool) *threadLifetime {
	if tid == 0 {
		return nil
	}
	matches := t.ThreadsByID[tid]
	if len(matches) == 0 {
		return nil
	}
	if !hasTime {
		if len(matches) == 1 {
			return matches[0]
		}
		return nil
	}
	var best *threadLifetime
	for _, instance := range matches {
		if !instance.HasStart && len(matches) > 1 {
			continue // an untimed instance is ambiguous when this TID was reused
		}
		if instance.HasStart && at.Before(instance.Start) {
			continue
		}
		if instance.HasStop && !at.Before(instance.Stop) {
			continue // stop time is an exclusive end boundary
		}
		if best == nil || (instance.HasStart && (!best.HasStart || instance.Start.After(best.Start))) {
			best = instance
		}
	}
	return best
}

func linkProcessInstances(t *telemetry) {
	for _, instance := range t.ProcessHistory {
		instance.Parent = nil
		instance.Children = nil
	}
	for _, child := range t.ProcessHistory {
		if child.PPID == 0 || child.PPID == child.PID {
			continue
		}
		parent := processLifetimeAt(t, child.PPID, child.Start, child.HasStart)
		if parent == nil && child.Rundown {
			// Rundown can enumerate a child immediately before its already-live
			// parent. Only use another observed rundown instance as this fallback.
			var closest *processLifetime
			var closestDelta time.Duration
			for _, candidate := range t.ProcessHistory {
				if candidate.PID != child.PPID || !candidate.Rundown {
					continue
				}
				delta := candidate.Start.Sub(child.Start)
				if delta < 0 {
					delta = -delta
				}
				if closest == nil || delta < closestDelta {
					closest, closestDelta = candidate, delta
				}
			}
			parent = closest
		}
		if parent == nil || parent == child {
			continue
		}
		child.Parent = parent
		parent.Children = append(parent.Children, child)
	}
	for _, instance := range t.ProcessHistory {
		sort.Slice(instance.Children, func(i, j int) bool {
			if instance.Children[i].PID != instance.Children[j].PID {
				return instance.Children[i].PID < instance.Children[j].PID
			}
			return instance.Children[i].Sequence < instance.Children[j].Sequence
		})
	}
}

func processInstancePath(sample *processLifetime) []*processLifetime {
	if sample == nil {
		return nil
	}

	var reverse []*processLifetime
	seen := make(map[*processLifetime]bool)

	for current := sample; current != nil; current = current.Parent {
		if seen[current] {
			break
		}
		seen[current] = true
		reverse = append(reverse, current)
	}

	chain := make([]*processLifetime, len(reverse))
	for i := range reverse {
		chain[len(reverse)-1-i] = reverse[i]
	}
	return chain
}

func printProcessInstanceNode(node *processLifetime, prefix string, last bool) {
	if node == nil || node.Node == nil {
		return
	}

	branch := "├── "
	nextPrefix := prefix + "│   "
	if last {
		branch = "└── "
		nextPrefix = prefix + "    "
	}

	fmt.Printf("%s%s%s (PID=%d)\n", prefix, branch, node.Node.Image, node.PID)

	for i, child := range node.Children {
		printProcessInstanceNode(child, nextPrefix, i == len(node.Children)-1)
	}
}

func printProcessInstancePath(chain []*processLifetime) {
	if len(chain) == 0 {
		return
	}

	root := chain[0]
	fmt.Printf("%s (PID=%d)\n", root.Node.Image, root.PID)

	for i := 1; i < len(chain); i++ {
		current := chain[i]
		prefix := strings.Repeat("    ", i-1)
		fmt.Printf("%s└── %s (PID=%d)\n", prefix, current.Node.Image, current.PID)
	}

	sample := chain[len(chain)-1]
	for i, child := range sample.Children {
		printProcessInstanceNode(child, strings.Repeat("    ", len(chain)-1), i == len(sample.Children)-1)
	}
}

func markRelevantInstances(root *processLifetime, relevant map[*processLifetime]bool) {
	if root == nil || relevant[root] {
		return
	}
	relevant[root] = true
	for _, child := range root.Children {
		markRelevantInstances(child, relevant)
	}
}

func (t *telemetry) chooseSampleInstance(expectedSampleNames []string, samplePID uint64) {
	if t.Sample == nil {
		return
	}
	for _, instance := range t.ProcessHistory {
		if instance.Node == t.Sample {
			t.SampleInstance = instance
			break
		}
	}

	// If a PID was reused and the PID map retained a later, unrelated process,
	// prefer the historical instance that actually matches the submitted sample.
	names := normalizeSampleNames(expectedSampleNames)
	var best *processLifetime
	bestScore := -1
	for _, instance := range t.ProcessHistory {
		if samplePID != 0 && instance.PID != samplePID {
			continue
		}
		score, _ := sampleSignalScore(instance.Node, names)
		if score < 0 {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && instance.Sequence < best.Sequence) {
			best, bestScore = instance, score
		}
	}
	currentScore := -1
	if t.SampleInstance != nil {
		currentScore, _ = sampleSignalScore(t.SampleInstance.Node, names)
	}
	if best != nil && (samplePID != 0 || t.SampleInstance == nil || bestScore > currentScore ||
		(bestScore == currentScore && best.Sequence < t.SampleInstance.Sequence)) {
		t.SampleInstance = best
		t.Sample = best.Node
		_, source := sampleSignalScore(best.Node, names)
		if samplePID != 0 {
			t.Root = SampleRootInfo{PID: best.PID, Image: best.Node.Image, Source: rootSourceAgentPID}
		} else {
			t.Root = SampleRootInfo{PID: best.PID, Image: best.Node.Image, Source: source}
		}
	}
}

// recentUniqueNetworkOwner is a conservative fallback for ETW network events
// whose provider supplies the invalid-PID sentinel and no thread ID. It only
// attributes an event when exactly one process instance started shortly before
// the event; otherwise the event remains unassigned. This is a heuristic, not
// a substitute for a real PID from the network provider.
func recentUniqueNetworkOwner(t *telemetry, at time.Time, hasTime bool) *processLifetime {
	if !hasTime {
		return nil
	}
	const window = 250 * time.Millisecond
	var candidate *processLifetime
	for _, instance := range t.ProcessHistory {
		if !instance.HasStart || instance.Start.After(at) || at.Sub(instance.Start) > window {
			continue
		}
		// More than one newly-started process makes temporal correlation ambiguous.
		if candidate != nil {
			return nil
		}
		candidate = instance
	}
	if candidate != nil && t.RelevantInstances[candidate] {
		return candidate
	}
	return nil
}

func resolveEventOwnership(t *telemetry) {
	t.EventOwners = make(map[*analysis.Event]*processLifetime)
	all := make([]*analysis.Event, 0,
		len(t.FileEvents)+len(t.NetworkEvents)+len(t.RegistryEvents)+len(t.DNSEvents)+len(t.ImageEvents))
	all = append(all, t.FileEvents...)
	all = append(all, t.NetworkEvents...)
	all = append(all, t.RegistryEvents...)
	all = append(all, t.DNSEvents...)
	all = append(all, t.ImageEvents...)
	for _, event := range all {
		rawPID := normalizeETWPID(event.PID)
		if rawPID == 0 {
			event.PID = 0
		}
		at, hasTime := parseEventTime(event.Time)

		owner := processLifetimeAt(t, rawPID, at, hasTime)
		if owner != nil {
			event.PID = owner.PID
			t.EventOwners[event] = owner
			continue
		}

		// A time-aware TID match can rescue a missing/sentinel PID. If the raw
		// PID has known history, only accept the TID fallback when it agrees with
		// the raw PID; this allows modest timestamp skew without crossing PID reuse.
		thread := threadLifetimeAt(t, event.ThreadID, at, hasTime)
		if thread != nil && thread.Process != nil &&
			(rawPID == 0 || rawPID == thread.Process.PID || !hasProcessHistory(t, rawPID)) {
			event.PID = thread.Process.PID
			t.EventOwners[event] = thread.Process
			continue
		}

		// Some network ETW records carry neither a usable PID nor TID. Use a
		// narrow, uniqueness-checked temporal fallback only for those records.
		// Never apply this to file/registry/DNS/image events, and never guess when
		// multiple processes started in the correlation window.
		if rawPID == 0 && strings.HasPrefix(event.Type, "network_") {
			if networkOwner := recentUniqueNetworkOwner(t, at, hasTime); networkOwner != nil {
				event.PID = networkOwner.PID
				t.EventOwners[event] = networkOwner
				continue
			}
		}

		// If this PID is known but no instance was alive at the event time, do
		// not let PID reuse make the event look like sample activity. Preserve it
		// as unassigned rather than guessing which instance produced the event.
		if rawPID != 0 && hasProcessHistory(t, rawPID) {
			event.PID = 0
			continue
		}

		// Keep an unknown nonzero PID for the report's unknown-process counter;
		// normalize only the sentinel values that cannot identify a process.
		event.PID = rawPID
	}
}

func eventIsRelevant(event *analysis.Event, relevantPIDs map[uint64]bool, attribution ...eventAttribution) bool {
	if len(attribution) > 0 && attribution[0].owners != nil {
		if owner, ok := attribution[0].owners[event]; ok {
			return attribution[0].relevant[owner]
		}
	}
	return isRelevantProcess(event.PID, relevantPIDs)
}

func eventImage(event *analysis.Event, processes map[uint64]*analysis.ProcessNode, attribution ...eventAttribution) string {
	if len(attribution) > 0 && attribution[0].owners != nil {
		if owner, ok := attribution[0].owners[event]; ok && owner.Node != nil && owner.Node.Image != "" {
			return owner.Node.Image
		}
	}
	if process, ok := processes[event.PID]; ok && process.Image != "" {
		return process.Image
	}
	return "unknown"
}

func accountFileEventsWithAttribution(
	fileEvents []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	fileNames map[uint64]string,
	suppressedReads uint64,
	attribution eventAttribution,
) FileEventAccounting {
	acc := FileEventAccounting{
		InTreeReadsSuppressed:  suppressedReads,
		RawEventCounts:         make(map[string]uint64),
		ExcludedRawEventCounts: make(map[string]uint64),
	}
	for _, event := range fileEvents {
		acc.TotalFileEvents++
		label := fileEventLabel(event)
		if eventIsRelevant(event, relevantPIDs, attribution) {
			acc.InTree++
			acc.RawEventCounts[label]++
			if resolveFilePath(*event, fileNames) == "" {
				acc.InTreeUnresolvedPath++
			}
			continue
		}
		acc.ExcludedRawEventCounts[label]++
		if event.PID == 0 {
			acc.ExcludedNoPID++
		} else if _, known := processes[event.PID]; known || (attribution.owners[event] != nil) {
			acc.ExcludedKnownProcess++
		} else {
			acc.ExcludedUnknownProcess++
		}
	}
	return acc
}

func readEvents(path string, expectedSampleNames ...string) (*telemetry, error) {
	return readEventsWithOptions(path, AnalyzeOptions{}, expectedSampleNames...)
}

func readEventsWithOptions(
	path string,
	opts AnalyzeOptions,
	expectedSampleNames ...string,
) (*telemetry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open telemetry: %w", err)
	}
	defer file.Close()

	t := &telemetry{
		Processes:       make(map[uint64]*analysis.ProcessNode),
		ProcessSeq:      make(map[*analysis.ProcessNode]int),
		FileNames:       make(map[uint64]string),
		ThreadToProcess: make(map[uint64]uint64),
		ProcessEvents:   make([]*analysis.Event, 0),
		ThreadEvents:    make([]*analysis.Event, 0),
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		var event analysis.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		switch {
		case event.Type == "process_start" || event.Type == "process_stop" ||
			event.Type == "process_rundown" || event.Type == "process_rundown_end":
			copyEvent := event
			t.ProcessEvents = append(t.ProcessEvents, &copyEvent)

		case event.Type == "thread_start" || event.Type == "thread_stop" ||
			event.Type == "thread_dc_start" || event.Type == "thread_dc_stop":
			copyEvent := event
			t.ThreadEvents = append(t.ThreadEvents, &copyEvent)

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

	// Reconstruct process and thread lifetimes after reading the entire stream.
	// The JSONL writer merges two ETW consumers, so arrival order is not a safe
	// substitute for the event timestamps when resolving ownership.
	buildProcessHistory(t)
	buildThreadHistory(t)
	linkProcessInstances(t)

	// Resolve the sample process only after the complete process table has been
	// collected. The sandbox normally presents the sample as sample.exe, but
	// frontend uploads may have any original filename. Prefer a process whose
	// command line points into the ThreatBox sample directory, then fall back to
	// the uploaded name and finally the legacy sample.exe name. This keeps the
	// analyzer independent of how the sandbox chooses to name the guest copy.
	t.Sample, t.Root = selectSampleRoot(
		t.Processes,
		t.ProcessSeq,
		opts.SamplePID,
		expectedSampleNames,
	)

	// Bind the exact sample process instance, mark its process-instance tree,
	// then resolve events using timestamps and historical thread ownership.
	t.chooseSampleInstance(expectedSampleNames, opts.SamplePID)
	t.RelevantInstances = make(map[*processLifetime]bool)
	if t.SampleInstance != nil {
		markRelevantInstances(t.SampleInstance, t.RelevantInstances)
	}
	resolveEventOwnership(t)

	return t, nil
}

func findSampleProcess(processes map[uint64]*analysis.ProcessNode, expectedSampleNames ...string) *analysis.ProcessNode {
	root, _ := selectSampleRoot(processes, nil, 0, expectedSampleNames)
	return root
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
	attribution ...eventAttribution,
) ([]analysis.FileActivity, uint64) {
	activities := make(map[string]*analysis.FileActivity)
	var suppressedEvents uint64

	for _, event := range fileEvents {
		if !eventIsRelevant(event, relevantPIDs, attribution...) {
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

		image := eventImage(event, processes, attribution...)

		// Deduplicate repeated low-level I/O only within the same process
		// instance. PID alone is not sufficient because Windows can reuse PIDs;
		// the historical owner sequence distinguishes separate lifetimes.
		instanceSequence := -1
		if len(attribution) > 0 && attribution[0].owners != nil {
			if owner, ok := attribution[0].owners[event]; ok && owner != nil {
				instanceSequence = owner.Sequence
			}
		}
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", action, path, event.PID, instanceSequence)
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
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	attribution ...eventAttribution,
) []analysis.NetworkActivity {
	activities := make(map[string]*analysis.NetworkActivity)

	for _, event := range events {
		if !eventIsRelevant(event, relevantPIDs, attribution...) {
			continue
		}

		action := normalizeNetworkAction(event.Type)
		if action == "" {
			continue
		}

		image := eventImage(event, processes, attribution...)

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
		if result[i].DestPort != result[j].DestPort {
			return result[i].DestPort < result[j].DestPort
		}
		if result[i].PID != result[j].PID {
			return result[i].PID < result[j].PID
		}
		if result[i].Protocol != result[j].Protocol {
			return result[i].Protocol < result[j].Protocol
		}
		if result[i].SourceIP != result[j].SourceIP {
			return result[i].SourceIP < result[j].SourceIP
		}
		return result[i].SourcePort < result[j].SourcePort
	})

	return result
}

func collectSampleRegistryActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	attribution ...eventAttribution,
) []analysis.RegistryActivity {
	activities := make(map[string]*analysis.RegistryActivity)

	for _, event := range events {
		if !eventIsRelevant(event, relevantPIDs, attribution...) {
			continue
		}

		action := normalizeRegistryAction(event.Type)
		if action == "" || event.RegistryKey == "" {
			continue
		}

		image := eventImage(event, processes, attribution...)

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
		if result[i].Key != result[j].Key {
			return result[i].Key < result[j].Key
		}
		return result[i].PID < result[j].PID
	})

	return result
}

func collectSampleDNSActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	attribution ...eventAttribution,
) []analysis.DNSActivity {
	activities := make(map[string]*analysis.DNSActivity)

	for _, event := range events {
		if !eventIsRelevant(event, relevantPIDs, attribution...) || event.DNSQueryName == "" {
			continue
		}

		image := eventImage(event, processes, attribution...)

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
		if result[i].QueryName != result[j].QueryName {
			return result[i].QueryName < result[j].QueryName
		}
		return result[i].PID < result[j].PID
	})

	return result
}

func collectSampleImageActivity(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	attribution ...eventAttribution,
) []analysis.ImageActivity {
	activities := make(map[string]*analysis.ImageActivity)

	for _, event := range events {
		if !eventIsRelevant(event, relevantPIDs, attribution...) || event.Image == "" {
			continue
		}

		// Skip the trace-start/trace-end rundown of every image already
		// loaded system-wide; that's not activity performed by the
		// sample, just Windows enumerating what's already resident.
		if event.Type == "image_dc_start" || event.Type == "image_dc_end" {
			continue
		}

		procImage := eventImage(event, processes, attribution...)

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
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].PID < result[j].PID
	})

	return result
}

func markDescendants(root *analysis.ProcessNode, relevant map[uint64]bool) {
	if root == nil || root.PID == 0 || relevant[root.PID] {
		return
	}

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

// Analyze analyzes one collector output file. When the guest agent's
// status.json sits beside the events file, its sample_pid anchors the sample
// root; otherwise root selection falls back to command-line and name matching.
func Analyze(path string, streamServer *stream.Server, expectedSampleNames ...string) (mitre.AnalysisOutput, error) {
	opts := AnalyzeOptions{}
	if status, err := sandbox.ReadAgentStatus(filepath.Dir(path)); err == nil && status.SamplePID > 0 {
		opts.SamplePID = uint64(status.SamplePID)
	}

	return AnalyzeWithOptions(path, streamServer, opts, expectedSampleNames...)
}

// AnalyzeWithOptions is Analyze with caller-supplied ground truth.
func AnalyzeWithOptions(
	path string,
	streamServer *stream.Server,
	opts AnalyzeOptions,
	expectedSampleNames ...string,
) (mitre.AnalysisOutput, error) {

	broadcast(streamServer, stream.Event{
		Type: "analysis_started",
		Data: map[string]interface{}{
			"message": "Analysis started",
		},
	})

	t, err := readEventsWithOptions(path, opts, expectedSampleNames...)
	if err != nil {
		return mitre.AnalysisOutput{}, err
	}

	if t.Sample == nil {
		return mitre.AnalysisOutput{}, fmt.Errorf("no sample process found (expected upload names: %s)", strings.Join(expectedSampleNames, ", "))
	}

	// Preserve the legacy PID map for report APIs, but use historical
	// process instances for the sample's actual process tree.
	analysisProcesses := make(map[uint64]*analysis.ProcessNode, len(t.Processes))
	for pid, node := range t.Processes {
		analysisProcesses[pid] = node
	}

	relevantPIDs := make(map[uint64]bool)
	for _, instance := range t.ProcessHistory {
		if t.RelevantInstances[instance] {
			relevantPIDs[instance.PID] = true
			analysisProcesses[instance.PID] = instance.Node
		}
	}

	if len(relevantPIDs) == 0 {
		markDescendants(t.Sample, relevantPIDs)
	}

	chain := processInstancePath(t.SampleInstance)
	if len(chain) == 0 {
		return mitre.AnalysisOutput{}, fmt.Errorf("no process tree found")
	}
	attr := eventAttribution{owners: t.EventOwners, relevant: t.RelevantInstances}

	fileActivities, suppressedFileEvents := collectSampleFileActivity(t.FileEvents, relevantPIDs, analysisProcesses, t.FileNames, attr)
	fileSummary := buildFileBehaviorSummary(fileActivities, suppressedFileEvents)
	fileSummary.Accounting = accountFileEventsWithAttribution(
		t.FileEvents,
		relevantPIDs,
		analysisProcesses,
		t.FileNames,
		suppressedFileEvents,
		attr,
	)
	networkActivities := collectSampleNetworkActivity(t.NetworkEvents, relevantPIDs, analysisProcesses, attr)
	registryActivities := collectSampleRegistryActivity(t.RegistryEvents, relevantPIDs, analysisProcesses, attr)
	dnsActivities := collectSampleDNSActivity(t.DNSEvents, relevantPIDs, analysisProcesses, attr)
	imageActivities := collectSampleImageActivity(t.ImageEvents, relevantPIDs, analysisProcesses, attr)
	imageEventsForSample := make([]*analysis.Event, 0, len(t.ImageEvents))
	for _, event := range t.ImageEvents {
		if eventIsRelevant(event, relevantPIDs, attr) {
			imageEventsForSample = append(imageEventsForSample, event)
		}
	}
	moduleMetrics := collectModuleMetrics(imageEventsForSample, relevantPIDs, len(imageActivities))

	iocResult := ioc.Extract(ioc.Activities{
		Files:    fileActivities,
		Network:  networkActivities,
		Registry: registryActivities,
		DNS:      dnsActivities,
		Images:   imageActivities,
	}, analysisProcesses, relevantPIDs, t.Sample)

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
		Metrics: AnalysisMetrics{
			SampleRoot: t.Root,
			Files:      fileSummary.Accounting,
			Modules:    moduleMetrics,
		},
	}

	broadcast(streamServer, stream.Event{
		Type: "analysis_completed",
		Data: output,
	})

	fmt.Println()
	fmt.Println("========== THREATBOX ANALYSIS ==========")
	fmt.Printf("Sample   : %s\n", t.Sample.Image)
	fmt.Printf("PID      : %d\n", t.Sample.PID)
	fmt.Printf("Root     : %s\n", describeSampleRoot(t.Root))
	fmt.Printf("Risk     : %s (%d/100)\n", threatScore.Severity, threatScore.Score)

	fmt.Println()
	fmt.Println("PROCESS TREE")
	printProcessInstancePath(chain)

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
	fmt.Printf("  • Opened or created: %d distinct paths\n", fileSummary.Created)
	fmt.Printf("  • Modified: %d distinct paths\n", fileSummary.Modified)
	fmt.Printf("  • Deleted: %d distinct paths\n", fileSummary.Deleted)
	fmt.Printf("  • Renamed: %d distinct paths\n", fileSummary.Renamed)
	if line := formatEventCounts(fileSummary.Accounting.RawEventCounts, "file_create/"); line != "" {
		fmt.Printf("  • file_create events by ID (raw, sample tree): %s\n", line)
	}
	if fileSummary.NotableReads > 0 {
		fmt.Printf("  • Notable reads: %d\n", fileSummary.NotableReads)
	}

	if len(fileSummary.NotableFiles) > 0 {
		fmt.Println()
		fmt.Println("NOTABLE FILES")
		for _, activity := range fileSummary.NotableFiles {
			if activity.Action == "WRITE" && activity.Bytes > 0 {
				fmt.Printf("  • %s x%d | %s (PID=%d) | %s | bytes=%d\n",
					activity.Action,
					activity.Count,
					activity.Image,
					activity.PID,
					activity.Path,
					activity.Bytes,
				)
			} else {
				fmt.Printf("  • %s x%d | %s (PID=%d) | %s\n",
					activity.Action,
					activity.Count,
					activity.Image,
					activity.PID,
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
		fmt.Printf("  Low-value READ events suppressed (sample tree only): %d raw events\n", suppressedFileEvents)
	}

	accounting := fileSummary.Accounting
	fmt.Printf(
		"  Excluded from sample attribution: %d of %d file events "+
			"(%d from known processes outside the sample tree, "+
			"%d from PIDs absent from the process table, %d with no PID)\n",
		accounting.ExcludedKnownProcess+accounting.ExcludedUnknownProcess+accounting.ExcludedNoPID,
		accounting.TotalFileEvents,
		accounting.ExcludedKnownProcess,
		accounting.ExcludedUnknownProcess,
		accounting.ExcludedNoPID,
	)

	fmt.Println()
	fmt.Println("OTHER BEHAVIOR")
	if len(networkActivities) > 0 {
		fmt.Printf("  • Network activity: %d connections\n", len(networkActivities))
	}
	if len(dnsActivities) > 0 {
		fmt.Printf("  • DNS activity: %d queries\n", len(dnsActivities))
	}
	if moduleMetrics.LoadEvents > 0 || moduleMetrics.UnloadEvents > 0 {
		fmt.Printf(
			"  • Image events (sample tree): %d loads, %d unloads; "+
				"%d distinct modules loaded; %d (module, process) pairs\n",
			moduleMetrics.LoadEvents,
			moduleMetrics.UnloadEvents,
			moduleMetrics.DistinctModulesLoaded,
			moduleMetrics.DistinctModuleProcessPairs,
		)
	} else if len(imageActivities) > 0 {
		fmt.Printf("  • Image/DLL activity: %d (module, process) records\n", len(imageActivities))
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
