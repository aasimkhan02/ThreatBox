package main

import (
	"fmt"
	"log"
	"time"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/sandbox"
)

func main() {
	sb := &sandbox.WindowsSandbox{
		ConfigPath: `C:\ThreatBox\sandbox.wsb`,
		OutputPath: `C:\ThreatBox\runtime\output`,
	}

	sample := `C:\ThreatBox\runtime\sample\sample.exe`

	if err := sb.CopySample(sample); err != nil {
		log.Fatal(err)
	}

	if err := sb.Create(); err != nil {
		log.Fatal(err)
	}

	defer sb.Destroy()

	if err := sb.Execute(); err != nil {
		log.Fatal(err)
	}

	// Give Sandbox time to boot and execute the sample.
	time.Sleep(5 * time.Second)

	result, err := sb.Collect()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)
}