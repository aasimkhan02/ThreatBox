package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/tekert/goetw/etw"
)

func StartETW() error {
	flags := etw.GetKernelProviderFlags("Process")

	session := etw.NewKernelRealTimeSession(flags)
	defer session.Stop()

	if err := session.Start(); err != nil {
		return fmt.Errorf("start kernel ETW session: %w", err)
	}

	fmt.Println("ETW kernel session started")

	consumer := etw.NewConsumer(context.Background())
	defer consumer.Stop()

	consumer.FromSessions(session)

	// EventPreparedCallback runs after goetw has prepared
	// the event's property metadata.
	consumer.EventPreparedCallback = func(
		h *etw.EventRecordHelper,
	) error {

		switch h.EventID() {

		case 1: // Process Start
			fmt.Println("\nPROCESS START")

			processID, err := h.GetPropertyUint("ProcessId")
			if err != nil {
				fmt.Printf("  ProcessId: %v\n", err)
			} else {
				fmt.Printf("  PID: %d\n", processID)
			}

			parentID, err := h.GetPropertyUint("ParentId")
			if err != nil {
				fmt.Printf("  ParentId: %v\n", err)
			} else {
				fmt.Printf("  PPID: %d\n", parentID)
			}

			sessionID, err := h.GetPropertyUint("SessionId")
			if err != nil {
				fmt.Printf("  SessionId: %v\n", err)
			} else {
				fmt.Printf("  Session ID: %d\n", sessionID)
			}

			imageName, err := h.GetPropertyString("ImageFileName")
			if err != nil {
				fmt.Printf("  ImageFileName: %v\n", err)
			} else {
				fmt.Printf("  Image: %s\n", imageName)
			}

			commandLine, err := h.GetPropertyString("CommandLine")
			if err == nil && commandLine != "" {
				fmt.Printf("  Command: %s\n", commandLine)
			}

		case 2: // Process Stop
			fmt.Println("\nPROCESS STOP")

			processID, err := h.GetPropertyUint("ProcessId")
			if err != nil {
				fmt.Printf("  ProcessId: %v\n", err)
			} else {
				fmt.Printf("  PID: %d\n", processID)
			}

			exitStatus, err := h.GetPropertyInt("ExitStatus")
			if err != nil {
				fmt.Printf("  ExitStatus: %v\n", err)
			} else {
				fmt.Printf("  Exit Code: %d\n", exitStatus)
			}

			imageName, err := h.GetPropertyString("ImageFileName")
			if err != nil {
				fmt.Printf("  ImageFileName: %v\n", err)
			} else {
				fmt.Printf("  Image: %s\n", imageName)
			}
		}

		return nil
	}

	if err := consumer.Start(); err != nil {
		return fmt.Errorf("start ETW consumer: %w", err)
	}

	time.Sleep(30 * time.Second)

	return nil
}