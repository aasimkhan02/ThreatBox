package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/engine"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/stream"
)

func main() {
	path := `C:\ThreatBox\output\events.jsonl`

	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	streamServer := stream.NewServer()

	http.HandleFunc("/ws", streamServer.HandleWebSocket)

	go func() {
		if err := http.ListenAndServe(":8081", nil); err != nil {
			fmt.Println("WebSocket server error:", err)
		}
	}()

	fmt.Println("WebSocket server running on ws://localhost:8081/ws")
	fmt.Println("Press ENTER to start analysis...")

	fmt.Scanln()

	output, err := engine.Analyze(path, streamServer)
	if err != nil {
		fmt.Println("Analyzer error:", err)
		os.Exit(1)
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Println("Analyzer output error:", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))

	select {}
}
