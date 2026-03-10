package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"message":  "hello from erlkoenig",
			"path":     r.URL.Path,
			"method":   r.Method,
			"host":     r.Host,
			"remote":   r.RemoteAddr,
			"time":     time.Now().Format(time.RFC3339),
			"hostname": hostname(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	fmt.Printf("echo-server listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
