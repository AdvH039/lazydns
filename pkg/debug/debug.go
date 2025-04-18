package debug

import (
	"bufio"
	"log"
	"os"
	"time"
)

const (
	path = "/sys/kernel/debug/tracing/trace_pipe"
)

type DebugDaemon struct {
	tracePipe *os.File
}

func CreateDaemon() (*DebugDaemon, error) {
	tracePipe, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	dbgDaemon := &DebugDaemon{
		tracePipe: tracePipe,
	}
	return dbgDaemon, nil

}

// How to add concurrent errors?
func (dbgDaemon *DebugDaemon) Log() {
	scanner := bufio.NewScanner(dbgDaemon.tracePipe)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			for scanner.Scan() {
				log.Println(scanner.Text())
			}

			if err := scanner.Err(); err != nil {
				log.Printf("Error reading trace_pipe: %v", err)
				//return err
			}
		}
	}()

}
