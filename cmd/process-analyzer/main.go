package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/aasimkhan02/ThreatBox/internal/analysis/engine"
	"github.com/aasimkhan02/ThreatBox/internal/analysis/stream"
)

func main() {
	path := `C:\ThreatBox\runtime\output\events.jsonl`

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

	if _, err := engine.Analyze(path, streamServer); err != nil {
		fmt.Println("Analyzer error:", err)
		os.Exit(1)
	}

	select {}
}