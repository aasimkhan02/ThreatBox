package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
)

func p1Node(pid uint64, image, command string) *analysis.ProcessNode {
	return &analysis.ProcessNode{PID: pid, Image: image, Command: command}
}

func TestP1PathCountKey(t *testing.T) {
	same := [][2]string{
		{`C:\Windows\System32\X.dll`, `c:\windows\system32\x.dll`},
		{`C:/Temp//a.txt`, `c:\temp\a.txt`},
		{`C:\Temp\`, `c:\temp`},
		{`\\Server\Share\A`, `\\server\share\a`},
	}
	for _, pair := range same {
		a, b := pathCountKey(pair[0]), pathCountKey(pair[1])
		if a != b {
			t.Errorf("pathCountKey(%q)=%q and pathCountKey(%q)=%q, want equal", pair[0], a, pair[1], b)
		}
	}

	different := [][2]string{
		// Device and drive-letter forms are deliberately not merged.
		{`\Device\HarddiskVolume2\Windows\x.dll`, `C:\Windows\x.dll`},
		// A UNC path is not the same path as a rooted local path.
		{`\\server\share\a`, `\server\share\a`},
		{`C:\Temp\a.txt`, `C:\Temp\b.txt`},
	}
	for _, pair := range different {
		a, b := pathCountKey(pair[0]), pathCountKey(pair[1])
		if a == b {
			t.Errorf("pathCountKey(%q) and pathCountKey(%q) are both %q, want different", pair[0], pair[1], a)
		}
	}

	if got := pathCountKey(`C:\`); got != `c:\` {
		t.Errorf("pathCountKey(`C:\\`) = %q, want %q", got, `c:\`)
	}
}

func TestP1FileSummaryCountsUniquePaths(t *testing.T) {
	activities := []analysis.FileActivity{
		{Action: "CREATE", Path: `C:\Temp\A.txt`, PID: 10, Count: 1},
		{Action: "CREATE", Path: `c:\temp\a.txt`, PID: 11, Count: 1},
		{Action: "CREATE", Path: `C:\Temp\lib.DLL`, PID: 10, Count: 1},
		{Action: "WRITE", Path: `C:\Temp\lib.DLL`, PID: 10, Count: 1, Bytes: 100},
		{Action: "WRITE", Path: `\Device\HarddiskVolume2\Temp\lib.dll`, PID: 10, Count: 1},
	}

	summary := buildFileBehaviorSummary(activities, 7)

	// a.txt (two spellings) and lib.dll are two distinct created paths.
	if summary.Created != 2 {
		t.Errorf("Created = %d, want 2", summary.Created)
	}
	// lib.dll and the device-path form are not merged, so two modified paths.
	if summary.Modified != 2 {
		t.Errorf("Modified = %d, want 2", summary.Modified)
	}
	if summary.Deleted != 0 || summary.Renamed != 0 {
		t.Errorf("Deleted/Renamed = %d/%d, want 0/0", summary.Deleted, summary.Renamed)
	}
	if summary.TotalActivities != 5 || summary.SuppressedRawEvents != 7 {
		t.Errorf("TotalActivities/SuppressedRawEvents = %d/%d, want 5/7",
			summary.TotalActivities, summary.SuppressedRawEvents)
	}
	if summary.TotalBytesWritten != 100 {
		t.Errorf("TotalBytesWritten = %d, want 100", summary.TotalBytesWritten)
	}

	// Category totals count unique paths; the old per-record totals stay
	// available under CategoryRecords.
	if got := summary.CategoryCounts[fileCategoryExecutable]; got != 2 {
		t.Errorf("CategoryCounts[EXECUTABLE] = %d, want 2", got)
	}
	if got := summary.CategoryCounts[fileCategoryOther]; got != 1 {
		t.Errorf("CategoryCounts[OTHER] = %d, want 1", got)
	}
	if got := summary.CategoryRecords[fileCategoryExecutable]; got != 3 {
		t.Errorf("CategoryRecords[EXECUTABLE] = %d, want 3", got)
	}
	if got := summary.CategoryRecords[fileCategoryOther]; got != 2 {
		t.Errorf("CategoryRecords[OTHER] = %d, want 2", got)
	}

	foundExecutable := false
	for _, pattern := range summary.Patterns {
		if pattern == "Executable/library activity: 2 distinct paths" {
			foundExecutable = true
		}
		if strings.HasPrefix(pattern, "Mass file creation") {
			t.Errorf("unexpected pattern %q", pattern)
		}
	}
	if !foundExecutable {
		t.Errorf("patterns %v do not contain the unique-path executable count", summary.Patterns)
	}

	// Original paths are preserved in the evidence rows, not rewritten.
	if activities[1].Path != `c:\temp\a.txt` {
		t.Errorf("input activity path was modified: %q", activities[1].Path)
	}
}

func TestP1MassCreatePatternUsesOpenCreateWording(t *testing.T) {
	activities := make([]analysis.FileActivity, 0, 30)
	for i := 0; i < 30; i++ {
		activities = append(activities, analysis.FileActivity{
			Action: "CREATE",
			Path:   `C:\Temp\file` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `.txt`,
			PID:    10,
			Count:  1,
		})
	}

	summary := buildFileBehaviorSummary(activities, 0)
	if summary.Created != 30 {
		t.Fatalf("Created = %d, want 30", summary.Created)
	}

	want := "Mass file open/create activity: 30 distinct paths"
	for _, pattern := range summary.Patterns {
		if pattern == want {
			return
		}
	}
	t.Errorf("patterns %v do not contain %q", summary.Patterns, want)
}

func TestP1FileSummaryJSONKeepsLegacyKeys(t *testing.T) {
	summary := buildFileBehaviorSummary(nil, 0)
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	legacy := []string{
		"created", "modified", "deleted", "renamed", "notable_reads",
		"total_activities", "normal_activities", "notable_activities",
		"low_value_activities", "suppressed_raw_events", "total_bytes_written",
		"category_counts", "notable_files", "patterns",
	}
	for _, key := range legacy {
		if _, ok := decoded[key]; !ok {
			t.Errorf("legacy JSON key %q is missing", key)
		}
	}

	additive := []string{
		"category_record_counts", "path_keying", "created_meaning", "accounting",
	}
	for _, key := range additive {
		if _, ok := decoded[key]; !ok {
			t.Errorf("additive JSON key %q is missing", key)
		}
	}
}

func TestP1AccountFileEvents(t *testing.T) {
	processes := map[uint64]*analysis.ProcessNode{
		100: p1Node(100, "sample.exe", ""),
		200: p1Node(200, "other.exe", ""),
	}
	relevant := map[uint64]bool{100: true}

	events := []*analysis.Event{
		{Type: "file_create", EventID: 12, PID: 100, FileName: `C:\a`},
		{Type: "file_create", EventID: 30, PID: 100, FileName: `C:\b`},
		{Type: "file_create", EventID: 12, PID: 100},
		{Type: "file_write", EventID: 16, PID: 200, FileName: `C:\c`},
		{Type: "file_read", EventID: 15, PID: 300, FileName: `C:\d`},
		{Type: "file_create", EventID: 12, PID: 0, FileName: `C:\e`},
	}

	got := accountFileEvents(events, relevant, processes, nil, 9)

	want := FileEventAccounting{
		TotalFileEvents:        6,
		InTree:                 3,
		InTreeUnresolvedPath:   1,
		InTreeReadsSuppressed:  9,
		ExcludedKnownProcess:   1,
		ExcludedUnknownProcess: 1,
		ExcludedNoPID:          1,
		RawEventCounts: map[string]uint64{
			"file_create/12": 2,
			"file_create/30": 1,
		},
		ExcludedRawEventCounts: map[string]uint64{
			"file_write/16":  1,
			"file_read/15":   1,
			"file_create/12": 1,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("accountFileEvents mismatch\n got: %+v\nwant: %+v", got, want)
	}

	if line := formatEventCounts(got.RawEventCounts, "file_create/"); line != "12=2, 30=1" {
		t.Errorf("formatEventCounts = %q, want %q", line, "12=2, 30=1")
	}
}

func TestP1ModuleMetricsSeparateLoadsUnloadsAndDistinctModules(t *testing.T) {
	relevant := map[uint64]bool{100: true, 101: true}

	events := []*analysis.Event{
		{Type: "image_load", PID: 100, Image: `C:\Windows\a.dll`},
		{Type: "image_load", PID: 100, Image: `C:\Windows\a.dll`},
		{Type: "image_load", PID: 100, Image: `C:\WINDOWS\A.DLL`},
		{Type: "image_load", PID: 100, Image: `C:\Windows\b.dll`},
		{Type: "image_load", PID: 101, Image: `C:\Windows\a.dll`},
		{Type: "image_unload", PID: 100, Image: `C:\Windows\a.dll`},
		{Type: "image_unload", PID: 100, Image: `C:\Windows\c.dll`},
		{Type: "image_dc_start", PID: 100, Image: `C:\Windows\z.dll`},
		{Type: "image_load", PID: 999, Image: `C:\Windows\q.dll`},
		{Type: "image_load", PID: 100, Image: ""},
	}

	got := collectModuleMetrics(events, relevant, 7)

	want := ModuleMetrics{
		LoadEvents:                 5,
		UnloadEvents:               2,
		RundownEventsIgnored:       1,
		DistinctModulesLoaded:      2,
		DistinctModulesUnloaded:    2,
		DistinctModuleProcessPairs: 3,
		LegacyActivityRecords:      7,
	}

	if got != want {
		t.Errorf("collectModuleMetrics mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestP1SelectSampleRoot(t *testing.T) {
	parent := p1Node(10, "sample.exe", `C:\ThreatBox\sample\sample.exe`)
	child := p1Node(20, "sample.exe", `C:\ThreatBox\sample\sample.exe --child`)
	shell := p1Node(30, "cmd.exe", `cmd.exe /c ver`)

	processes := map[uint64]*analysis.ProcessNode{10: parent, 20: child, 30: shell}
	seq := map[*analysis.ProcessNode]int{parent: 0, child: 1, shell: 2}
	names := []string{"upload.exe", "sample.exe"}

	cases := []struct {
		name       string
		samplePID  uint64
		wantPID    uint64
		wantSource string
		wantNote   string
	}{
		{"agent PID selects the exact process", 20, 20, rootSourceAgentPID, ""},
		{"tie without agent PID goes to the first process_start", 0, 10, rootSourceSampleDir, ""},
		{"agent PID missing from the process table falls back", 999, 10, rootSourceSampleDir, "999"},
		{"agent PID with no sample signal falls back", 30, 10, rootSourceSampleDir, "cmd.exe"},
	}

	for _, tc := range cases {
		root, info := selectSampleRoot(processes, seq, tc.samplePID, names)
		if root == nil || root.PID != tc.wantPID {
			t.Errorf("%s: root = %+v, want PID %d", tc.name, root, tc.wantPID)
			continue
		}
		if info.Source != tc.wantSource || info.PID != tc.wantPID {
			t.Errorf("%s: info = %+v, want source %q PID %d", tc.name, info, tc.wantSource, tc.wantPID)
		}
		if tc.wantNote == "" && info.Note != "" {
			t.Errorf("%s: unexpected note %q", tc.name, info.Note)
		}
		if tc.wantNote != "" && !strings.Contains(info.Note, tc.wantNote) {
			t.Errorf("%s: note %q does not mention %q", tc.name, info.Note, tc.wantNote)
		}
	}
}

func TestP1SampleDirectorySignalMatchesRealCommandLine(t *testing.T) {
	// The image name is neither sample.exe nor an expected upload name, so only
	// the command-line signal can identify it.
	odd := p1Node(5, "renamed.exe", `C:\ThreatBox\sample\sample.exe`)
	processes := map[uint64]*analysis.ProcessNode{
		5: odd,
		6: p1Node(6, "cmd.exe", "cmd.exe"),
	}

	root, info := selectSampleRoot(processes, nil, 0, nil)
	if root != odd {
		t.Fatalf("root = %+v, want the process launched from the sample directory", root)
	}
	if info.Source != rootSourceSampleDir {
		t.Errorf("source = %q, want %q", info.Source, rootSourceSampleDir)
	}
}

func TestP1SelectSampleRootIsDeterministic(t *testing.T) {
	processes := make(map[uint64]*analysis.ProcessNode)
	seq := make(map[*analysis.ProcessNode]int)

	// Scrambled PIDs: the process with seq 0 has PID 100.
	for i := 0; i < 12; i++ {
		pid := uint64(100 + (i*7)%12)
		node := p1Node(pid, "sample.exe", `C:\ThreatBox\sample\sample.exe`)
		processes[pid] = node
		seq[node] = i
	}

	for run := 0; run < 200; run++ {
		root, _ := selectSampleRoot(processes, seq, 0, nil)
		if root == nil || root.PID != 100 {
			t.Fatalf("run %d: root = %+v, want PID 100", run, root)
		}
	}

	// Without ordering information the lowest PID wins, still deterministically.
	for run := 0; run < 200; run++ {
		if root := findSampleProcess(processes, "sample.exe"); root == nil || root.PID != 100 {
			t.Fatalf("run %d: findSampleProcess = %+v, want PID 100", run, root)
		}
	}
}

func TestP1ReadEventsUsesAgentPIDAndKeepsEventID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")

	lines := []string{
		`{"type":"process_start","pid":10,"ppid":1,"image":"sample.exe","command":"C:\\ThreatBox\\sample\\sample.exe"}`,
		`{"type":"process_start","pid":20,"ppid":10,"image":"sample.exe","command":"C:\\ThreatBox\\sample\\sample.exe --child"}`,
		`{"type":"file_create","event_id":30,"pid":20,"file_name":"C:\\Temp\\x.txt"}`,
		`{"type":"file_create","event_id":12,"pid":10,"file_name":"C:\\Temp\\y.txt"}`,
		`{not json`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	withPID, err := readEventsWithOptions(path, AnalyzeOptions{SamplePID: 20}, "sample.exe")
	if err != nil {
		t.Fatal(err)
	}
	if withPID.Sample == nil || withPID.Sample.PID != 20 {
		t.Fatalf("sample = %+v, want PID 20", withPID.Sample)
	}
	if withPID.Root.Source != rootSourceAgentPID {
		t.Errorf("root source = %q, want %q", withPID.Root.Source, rootSourceAgentPID)
	}

	if len(withPID.FileEvents) != 2 {
		t.Fatalf("file events = %d, want 2", len(withPID.FileEvents))
	}
	if withPID.FileEvents[0].EventID != 30 || withPID.FileEvents[1].EventID != 12 {
		t.Errorf("event IDs = %d, %d, want 30, 12",
			withPID.FileEvents[0].EventID, withPID.FileEvents[1].EventID)
	}

	withoutPID, err := readEvents(path, "sample.exe")
	if err != nil {
		t.Fatal(err)
	}
	if withoutPID.Sample == nil || withoutPID.Sample.PID != 10 {
		t.Errorf("without agent PID, sample = %+v, want the first process_start (PID 10)", withoutPID.Sample)
	}
}

func TestP1CollectorsOrderTiesByPID(t *testing.T) {
	relevant := map[uint64]bool{3: true, 5: true, 9: true}
	processes := map[uint64]*analysis.ProcessNode{
		3: p1Node(3, "a.exe", ""),
		5: p1Node(5, "b.exe", ""),
		9: p1Node(9, "c.exe", ""),
	}
	want := []uint64{3, 5, 9}

	for _, order := range [][]uint64{{3, 5, 9}, {9, 5, 3}, {5, 9, 3}} {
		var images, dns, network []*analysis.Event
		for _, pid := range order {
			images = append(images, &analysis.Event{Type: "image_load", PID: pid, Image: `C:\Users\x\same.dll`})
			dns = append(dns, &analysis.Event{Type: "dns_query", PID: pid, DNSQueryName: "same.example"})
			network = append(network, &analysis.Event{Type: "network_connect", PID: pid, DestIP: "127.0.0.1", DestPort: 80})
		}

		var gotImages, gotDNS, gotNetwork []uint64
		for _, activity := range collectSampleImageActivity(images, relevant, processes) {
			gotImages = append(gotImages, activity.PID)
		}
		for _, activity := range collectSampleDNSActivity(dns, relevant, processes) {
			gotDNS = append(gotDNS, activity.PID)
		}
		for _, activity := range collectSampleNetworkActivity(network, relevant, processes) {
			gotNetwork = append(gotNetwork, activity.PID)
		}

		if !reflect.DeepEqual(gotImages, want) {
			t.Errorf("input order %v: image PIDs = %v, want %v", order, gotImages, want)
		}
		if !reflect.DeepEqual(gotDNS, want) {
			t.Errorf("input order %v: DNS PIDs = %v, want %v", order, gotDNS, want)
		}
		if !reflect.DeepEqual(gotNetwork, want) {
			t.Errorf("input order %v: network PIDs = %v, want %v", order, gotNetwork, want)
		}
	}
}
