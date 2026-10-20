package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
)

const (
	rootSourceAgentPID   = "agent-reported sample_pid (status.json)"
	rootSourceSampleDir  = "command line under \\ThreatBox\\sample\\"
	rootSourceUploadName = "uploaded filename"
	rootSourceLegacyName = "legacy sample.exe name"
	rootSourceNone       = "none"
)

const (
	pathKeyingDescription     = "case-folded, slash-normalized; \\Device\\HarddiskVolumeN and drive-letter forms are not merged"
	createdMeaningDescription = "distinct paths with a file_create event (Kernel-File event IDs 12 and/or 30); includes opens of existing files and directories; see accounting.raw_event_counts"
)

// AnalyzeOptions carries optional ground truth supplied by the caller.
// SamplePID is the PID the guest agent recorded for the sample process
// (status.json sample_pid); zero means unknown.
type AnalyzeOptions struct {
	SamplePID uint64
}

// SampleRootInfo records how the sample process was identified, so the report
// can state whether the root came from the guest agent's own record or from
// command-line and name matching.
type SampleRootInfo struct {
	PID    uint64 `json:"pid"`
	Image  string `json:"image"`
	Source string `json:"source"`
	Note   string `json:"note,omitempty"`
}

// FileEventAccounting states what happened to every retained file event, so the
// report shows how much telemetry was attributed to the sample tree and how much
// was excluded, instead of silently dropping the remainder. All values are raw
// event counts, not unique paths. Keys of the raw count maps are
// "<type>/<provider event ID>", for example "file_create/12". The report does
// not interpret what each event ID means.
type FileEventAccounting struct {
	TotalFileEvents        uint64            `json:"total_file_events"`
	InTree                 uint64            `json:"in_tree"`
	InTreeUnresolvedPath   uint64            `json:"in_tree_unresolved_path"`
	InTreeReadsSuppressed  uint64            `json:"in_tree_reads_suppressed"`
	ExcludedKnownProcess   uint64            `json:"excluded_known_process_outside_tree"`
	ExcludedUnknownProcess uint64            `json:"excluded_pid_not_in_process_table"`
	ExcludedNoPID          uint64            `json:"excluded_no_pid"`
	RawEventCounts         map[string]uint64 `json:"raw_event_counts"`
	ExcludedRawEventCounts map[string]uint64 `json:"excluded_raw_event_counts"`
}

// ModuleMetrics separates image load events, unload events and rundown events,
// and distinguishes distinct module paths from distinct (module, process) pairs.
// LegacyActivityRecords is the number the report previously labelled "modules".
type ModuleMetrics struct {
	LoadEvents                 uint64 `json:"load_events"`
	UnloadEvents               uint64 `json:"unload_events"`
	RundownEventsIgnored       uint64 `json:"rundown_events_ignored"`
	DistinctModulesLoaded      int    `json:"distinct_modules_loaded"`
	DistinctModulesUnloaded    int    `json:"distinct_modules_unloaded"`
	DistinctModuleProcessPairs int    `json:"distinct_module_process_pairs_loaded"`
	LegacyActivityRecords      int    `json:"legacy_activity_records"`
}

// AnalysisMetrics is additive report metadata carried in AnalysisOutput.Metrics.
type AnalysisMetrics struct {
	SampleRoot SampleRootInfo      `json:"sample_root"`
	Files      FileEventAccounting `json:"file_accounting"`
	Modules    ModuleMetrics       `json:"modules"`
}

// windowsBaseName returns the final element of a Windows or slash path. It does
// not depend on the host OS, unlike filepath.Base.
func windowsBaseName(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), `\/`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

func normalizeSampleNames(names []string) map[string]bool {
	normalized := make(map[string]bool, len(names))
	for _, name := range names {
		base := strings.ToLower(windowsBaseName(name))
		if base != "" {
			normalized[base] = true
		}
	}
	return normalized
}

// sampleSignalScore ranks how strongly a process looks like the submitted
// sample: 100 for a command line under the guest sample directory, 80 for the
// uploaded filename, 60 for the legacy sample.exe name, and -1 for no signal.
func sampleSignalScore(
	process *analysis.ProcessNode,
	names map[string]bool,
) (int, string) {
	imageName := strings.ToLower(windowsBaseName(process.Image))
	if imageName == "" {
		return -1, ""
	}

	score := -1
	source := ""
	command := strings.ToLower(strings.ReplaceAll(process.Command, "/", `\`))

	if strings.Contains(command, `\threatbox\sample\`) {
		score, source = 100, rootSourceSampleDir
	}
	if names[imageName] && score < 80 {
		score, source = 80, rootSourceUploadName
	}
	if imageName == "sample.exe" && score < 60 {
		score, source = 60, rootSourceLegacyName
	}

	return score, source
}

// selectSampleRoot identifies the submitted sample process.
//
// When samplePID is known and that process matches at least one sample
// identity signal, it is used. Otherwise candidates are ranked by signal
// strength, and ties go to the process whose process_start event appeared
// first in the telemetry (or the lowest PID when no ordering is supplied), so
// the result never depends on map iteration order.
func selectSampleRoot(
	processes map[uint64]*analysis.ProcessNode,
	seq map[*analysis.ProcessNode]int,
	samplePID uint64,
	expectedSampleNames []string,
) (*analysis.ProcessNode, SampleRootInfo) {
	names := normalizeSampleNames(expectedSampleNames)
	info := SampleRootInfo{Source: rootSourceNone}

	if samplePID != 0 {
		node, ok := processes[samplePID]
		switch {
		case !ok || node == nil:
			info.Note = fmt.Sprintf(
				"agent-reported sample_pid %d has no process_start event; "+
					"used command-line and name matching",
				samplePID,
			)
		default:
			if score, _ := sampleSignalScore(node, names); score < 0 {
				info.Note = fmt.Sprintf(
					"agent-reported sample_pid %d is %q, which matches no sample "+
						"identity signal; used command-line and name matching",
					samplePID,
					node.Image,
				)
			} else {
				info.PID = node.PID
				info.Image = node.Image
				info.Source = rootSourceAgentPID
				return node, info
			}
		}
	}

	rank := func(node *analysis.ProcessNode) int {
		if order, ok := seq[node]; ok {
			return order
		}
		return int(^uint(0) >> 1)
	}

	ordered := make([]*analysis.ProcessNode, 0, len(processes))
	for _, node := range processes {
		if node != nil {
			ordered = append(ordered, node)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		ri, rj := rank(ordered[i]), rank(ordered[j])
		if ri != rj {
			return ri < rj
		}
		return ordered[i].PID < ordered[j].PID
	})

	var best *analysis.ProcessNode
	bestScore := -1
	bestSource := rootSourceNone

	for _, node := range ordered {
		score, source := sampleSignalScore(node, names)
		if score > bestScore {
			best, bestScore, bestSource = node, score, source
		}
	}

	if best != nil {
		info.PID = best.PID
		info.Image = best.Image
		info.Source = bestSource
	}

	return best, info
}

// pathCountKey returns a conservative key for counting distinct paths. It only
// folds case, unifies separators, collapses repeated separators (keeping a
// leading UNC prefix) and drops a trailing separator. It deliberately does not
// map \Device\HarddiskVolumeN\ paths to drive letters, because that mapping is
// not verified for this telemetry. The original path is never altered; callers
// keep it for display and evidence.
func pathCountKey(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "/", `\`))

	prefix := ""
	if strings.HasPrefix(p, `\\`) {
		prefix = `\\`
		p = strings.TrimLeft(p, `\`)
	}

	for strings.Contains(p, `\\`) {
		p = strings.ReplaceAll(p, `\\`, `\`)
	}

	if len(p) > 1 && strings.HasSuffix(p, `\`) && !(len(p) == 3 && p[1] == ':') {
		p = strings.TrimSuffix(p, `\`)
	}

	return prefix + strings.ToLower(p)
}

func fileEventLabel(event *analysis.Event) string {
	return fmt.Sprintf("%s/%d", event.Type, event.EventID)
}

// accountFileEvents classifies every retained file event as inside the sample
// tree or excluded, using the same PID the engine attributes events to.
func accountFileEvents(
	fileEvents []*analysis.Event,
	relevantPIDs map[uint64]bool,
	processes map[uint64]*analysis.ProcessNode,
	fileNames map[uint64]string,
	suppressedReads uint64,
) FileEventAccounting {
	acc := FileEventAccounting{
		InTreeReadsSuppressed:  suppressedReads,
		RawEventCounts:         make(map[string]uint64),
		ExcludedRawEventCounts: make(map[string]uint64),
	}

	for _, event := range fileEvents {
		acc.TotalFileEvents++
		label := fileEventLabel(event)

		if isRelevantProcess(event.PID, relevantPIDs) {
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
			continue
		}
		if _, known := processes[event.PID]; known {
			acc.ExcludedKnownProcess++
		} else {
			acc.ExcludedUnknownProcess++
		}
	}

	return acc
}

// collectModuleMetrics counts image events attributed to the sample tree.
func collectModuleMetrics(
	events []*analysis.Event,
	relevantPIDs map[uint64]bool,
	legacyRecords int,
) ModuleMetrics {
	metrics := ModuleMetrics{LegacyActivityRecords: legacyRecords}

	loaded := make(map[string]struct{})
	unloaded := make(map[string]struct{})
	pairs := make(map[string]struct{})

	for _, event := range events {
		if !isRelevantProcess(event.PID, relevantPIDs) || event.Image == "" {
			continue
		}

		key := pathCountKey(event.Image)

		switch event.Type {
		case "image_load":
			metrics.LoadEvents++
			loaded[key] = struct{}{}
			pairs[fmt.Sprintf("%s\x00%d", key, event.PID)] = struct{}{}
		case "image_unload":
			metrics.UnloadEvents++
			unloaded[key] = struct{}{}
		case "image_dc_start", "image_dc_end":
			metrics.RundownEventsIgnored++
		}
	}

	metrics.DistinctModulesLoaded = len(loaded)
	metrics.DistinctModulesUnloaded = len(unloaded)
	metrics.DistinctModuleProcessPairs = len(pairs)

	return metrics
}

func describeSampleRoot(info SampleRootInfo) string {
	if info.Note != "" {
		return info.Source + " (" + info.Note + ")"
	}
	return info.Source
}

// formatEventCounts renders the counts whose key starts with prefix as
// "<id>=<count>" pairs sorted by key, for example "12=1868, 30=14".
func formatEventCounts(counts map[string]uint64, prefix string) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.TrimPrefix(key, prefix), counts[key]))
	}

	return strings.Join(parts, ", ")
}
