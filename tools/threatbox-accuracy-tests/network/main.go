// network is a benign ThreatBox accuracy fixture.
// Parent listens on loopback; a child process connects and sends a short marker.
// Build on the Windows host, then upload/run only through the normal Sandbox flow.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type groundTruth struct {
	Role    string `json:"role"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	Action  string `json:"action"`
	Address string `json:"address,omitempty"`
	Port    int    `json:"port,omitempty"`
	Payload string `json:"payload,omitempty"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func emit(v groundTruth) {
	b, _ := json.Marshal(v)
	fmt.Printf("GROUND_TRUTH %s\n", b)
}

func main() {
	childMode := flag.Bool("child", false, "run as the child connector")
	address := flag.String("address", "", "parent loopback listener address")
	flag.Parse()
	if *childMode {
		runChild(*address)
		return
	}
	runParent()
}

func runParent() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "listen", Success: false, Error: err.Error()})
		os.Exit(1)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(12 * time.Second))
	addr := listener.Addr().String()
	_, portText, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portText)

	cmd := exec.Command(os.Args[0], "--child", "--address", addr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "start_child", Address: addr, Port: port, Success: false, Error: err.Error()})
		os.Exit(1)
	}

	conn, acceptErr := listener.Accept()
	if acceptErr != nil {
		_ = cmd.Wait()
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "accept", Address: addr, Port: port, Success: false, Error: acceptErr.Error()})
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "receive", Address: addr, Port: port, Success: false, Error: readErr.Error()})
	} else {
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "accept_receive", Address: addr, Port: port, Payload: string(buf[:n]), Success: true})
	}
	if waitErr := cmd.Wait(); waitErr != nil {
		emit(groundTruth{Role: "parent", PID: os.Getpid(), Action: "wait_child", Success: false, Error: waitErr.Error()})
		os.Exit(1)
	}
}

func runChild(address string) {
	pid, ppid := os.Getpid(), os.Getppid()
	conn, err := net.DialTimeout("tcp4", address, 4*time.Second)
	if err != nil {
		emit(groundTruth{Role: "child", PID: pid, PPID: ppid, Action: "tcp_connect", Address: address, Success: false, Error: err.Error()})
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := "THREATBOX_NETWORK_FIXTURE"
	if _, err := conn.Write([]byte(payload)); err != nil {
		emit(groundTruth{Role: "child", PID: pid, PPID: ppid, Action: "tcp_connect_write", Address: address, Payload: payload, Success: false, Error: err.Error()})
		os.Exit(1)
	}
	host, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)
	emit(groundTruth{Role: "child", PID: pid, PPID: ppid, Action: "tcp_connect_write", Address: host, Port: port, Payload: payload, Success: true})
}
