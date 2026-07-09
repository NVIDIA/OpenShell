package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const signalPath = "/tmp/signal/ready"

var ready atomic.Bool

func main() {
	go pollSignalFile()

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
		}
	})

	log.Println("readiness sidecar listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func pollSignalFile() {
	for {
		if _, err := os.Stat(signalPath); err == nil {
			if !ready.Load() {
				ready.Store(true)
				log.Println("signal file detected, transitioning to ready")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
