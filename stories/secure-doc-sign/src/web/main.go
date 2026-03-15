package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: web <port> <backend-url>")
	}
	port := os.Args[1]
	backend := os.Args[2]

	proxy := func(method, path string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			url := backend + path
			req, err := http.NewRequestWithContext(r.Context(), method, url, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}
	}

	http.HandleFunc("/sign", proxy("POST", "/sign"))
	http.HandleFunc("/archive", proxy("GET", "/log"))

	log.Printf("web proxy listening on :%s -> %s", port, backend)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
