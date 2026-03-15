package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type signRequest struct {
	Document string `json:"document"`
	Signer   string `json:"signer"`
}

type signResponse struct {
	ID        string `json:"id"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
	Timestamp string `json:"timestamp"`
	Seq       int64  `json:"seq"`
	Archived  bool   `json:"archived"`
}

var (
	seq   int64
	seqMu sync.Mutex
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: signer <port> <archive-url>")
	}
	port := os.Args[1]
	archiveURL := os.Args[2]

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	log.Printf("ed25519 key generated")

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var req signRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Document == "" || req.Signer == "" {
			http.Error(w, "document and signer required", http.StatusBadRequest)
			return
		}

		hash := sha256.Sum256([]byte(req.Document))
		hashHex := hex.EncodeToString(hash[:])
		sig := ed25519.Sign(privKey, hash[:])
		sigHex := hex.EncodeToString(sig)
		now := time.Now().UTC().Format(time.RFC3339)

		seqMu.Lock()
		seq++
		curSeq := seq
		seqMu.Unlock()

		id := fmt.Sprintf("sig-%s-%d", hashHex[:8], curSeq)

		resp := signResponse{
			ID:        id,
			Hash:      hashHex,
			Signature: sigHex,
			Signer:    req.Signer,
			Timestamp: now,
			Seq:       curSeq,
		}

		// Forward to archive
		entry, _ := json.Marshal(resp)
		archResp, err := http.Post(archiveURL+"/log", "application/json", bytes.NewReader(entry))
		if err == nil {
			archResp.Body.Close()
			resp.Archived = archResp.StatusCode == http.StatusOK
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	log.Printf("signer listening on :%s, archive at %s", port, archiveURL)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
