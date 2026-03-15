package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

const ledgerPath = "/tmp/archive.jsonl"

var mu sync.Mutex

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: archive <port>")
	}
	port := os.Args[1]

	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			handlePost(w, r)
		case "GET":
			handleGet(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	log.Printf("archive listening on :%s, ledger at %s", port, ledgerPath)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile(ledgerPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Write JSON line (strip trailing newline if present, then add one)
	line := body
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]\n"))
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Write(data)
}
