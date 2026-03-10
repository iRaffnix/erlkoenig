package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: reverse-proxy <listen-addr> <backend-url> [<backend-url>...]\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  reverse-proxy :80 http://10.0.0.20:8080\n")
		fmt.Fprintf(os.Stderr, "  reverse-proxy :443 http://10.0.0.20:8080 http://10.0.0.21:8080\n")
		os.Exit(1)
	}

	listenAddr := os.Args[1]
	backends := os.Args[2:]

	targets := make([]*url.URL, len(backends))
	for i, b := range backends {
		u, err := url.Parse(b)
		if err != nil {
			log.Fatalf("invalid backend URL %q: %v", b, err)
		}
		targets[i] = u
	}

	var handler http.Handler
	if len(targets) == 1 {
		handler = httputil.NewSingleHostReverseProxy(targets[0])
	} else {
		handler = roundRobin(targets)
	}

	// Wrap with access logging
	logged := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s -> %s", r.RemoteAddr, r.Method, r.URL.Path, strings.Join(backends, ","))
		handler.ServeHTTP(w, r)
	})

	log.Printf("reverse-proxy listening on %s -> %s", listenAddr, strings.Join(backends, ", "))
	if err := http.ListenAndServe(listenAddr, logged); err != nil {
		log.Fatalf("error: %v", err)
	}
}

// roundRobin distributes requests across multiple backends
func roundRobin(targets []*url.URL) http.Handler {
	proxies := make([]*httputil.ReverseProxy, len(targets))
	for i, t := range targets {
		proxies[i] = httputil.NewSingleHostReverseProxy(t)
	}

	var counter uint64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := counter % uint64(len(proxies))
		counter++
		proxies[idx].ServeHTTP(w, r)
	})
}
