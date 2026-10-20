package ioc

import (
	"reflect"
	"testing"

	"github.com/aasimkhan02/ThreatBox/internal/analysis"
)

func TestP1ExtractProcessesAreInPIDOrder(t *testing.T) {
	processes := make(map[uint64]*analysis.ProcessNode)
	relevant := make(map[uint64]bool)

	for _, pid := range []uint64{40, 7, 23, 91, 3, 58, 12, 77} {
		processes[pid] = &analysis.ProcessNode{PID: pid, Image: "p.exe"}
		relevant[pid] = true
	}
	// Present in the process table but not part of the sample tree.
	processes[500] = &analysis.ProcessNode{PID: 500, Image: "outside.exe"}

	want := []uint64{3, 7, 12, 23, 40, 58, 77, 91}

	for run := 0; run < 100; run++ {
		result := Extract(Activities{}, processes, relevant, nil)

		got := make([]uint64, 0, len(result.Processes))
		for _, process := range result.Processes {
			got = append(got, process.PID)
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: process PIDs = %v, want %v", run, got, want)
		}
	}
}
