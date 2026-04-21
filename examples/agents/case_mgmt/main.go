// case_mgmt — reference task-tracker workload (showcase).
//
// Static-linked Go binary that runs inside an erlkoenig container
// and exposes an HTTP API for task management. Reads two service
// capabilities from its environment:
//
//   PGHOST              — directory containing .s.PGSQL.5432 (postgres.local)
//   JOURNAL_LOCAL_SOCK  — Unix socket of journal.local
//
// The DSL `requires :"postgres.local"` and `requires :"journal.local"`
// declarations bind-mount /run/erlkoenig/ into the container and
// inject these env vars. No other config inside the container.
//
// Endpoints (all writes also append a journal entry):
//
//   GET  /healthz                       liveness probe
//
//   GET  /users
//   POST /users               {name, email?, hourly_rate_cents?}
//
//   GET  /tasks               [?q=substring]
//   POST /tasks               {title, description, assignee_id?}
//   GET  /tasks/:id                     full timeline (notes, deadlines,
//                                       time entries, effort summary)
//   POST /tasks/:id/close
//
//   POST /tasks/:id/notes     {body}
//   POST /tasks/:id/deadlines {due_at, description, category}
//   POST /deadlines/:id/done
//   GET  /deadlines/upcoming  [?days=14]   used by the worker
//   POST /tasks/:id/time      {user_id, occurred_on, minutes,
//                              description}
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed ui.html
var uiHTML []byte

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")

	pgHost := os.Getenv("PGHOST")
	if pgHost == "" {
		fatal("PGHOST not set — is `requires :\"postgres.local\"` declared?")
	}
	pgUser := envOr("PGUSER", "case_mgmt")
	pgDB := envOr("PGDATABASE", "cases")
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s port=5432", pgHost, pgUser, pgDB)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fatal("pgxpool.New: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fatal("postgres ping failed (PGHOST=%q): %v", pgHost, err)
	}

	jrnl := newJournal(os.Getenv("JOURNAL_LOCAL_SOCK"))
	defer jrnl.close()

	app := &app{pool: pool, jrnl: jrnl}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.healthz)

	uiHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(uiHTML)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		uiHandler(w, r)
	})
	mux.HandleFunc("/ui", uiHandler)

	mux.HandleFunc("/users", app.usersRoot)                 // GET, POST
	mux.HandleFunc("/tasks", app.tasksRoot)                 // GET, POST
	mux.HandleFunc("/tasks/", app.taskSubresource)          // /:id, /:id/notes, ...
	mux.HandleFunc("/deadlines/upcoming", app.deadlinesUpcoming)
	mux.HandleFunc("/deadlines/", app.deadlineByID)         // /:id/done

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	fmt.Fprintf(os.Stderr, "case_mgmt listening on %s (PGHOST=%s)\n", addr, pgHost)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("server: %v", err)
	}
}

func envOr(k, dflt string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dflt
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "case_mgmt: "+format+"\n", args...)
	os.Exit(1)
}
