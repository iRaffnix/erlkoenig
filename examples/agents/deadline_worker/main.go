// deadline_worker — second container in the showcase pod.
//
// Polls case_mgmt's /deadlines/upcoming endpoint at a fixed
// interval and writes one consolidated journal.local entry per
// scan when there are upcoming deadlines. Operators can wire
// alerts on the AMQP topic `events.case_mgmt-...` to surface
// these in their on-call channel.
//
// Why a separate container? Mostly to demonstrate pod orchestration
// (one_for_one strategy: if the worker crashes, case_mgmt keeps
// serving). In production the worker would also dedup warnings
// (don't spam the same deadline daily); here every scan logs.
//
// Env:
//   CASE_MGMT_URL       (default http://case_mgmt-0-agent.erlkoenig:8080)
//   JOURNAL_LOCAL_SOCK  (provided by `requires :"journal.local"`)
//   SCAN_INTERVAL_SEC   (default 30)
//   DAYS_AHEAD          (default 14)

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	url := envOr("CASE_MGMT_URL", "http://case_mgmt-0-agent.erlkoenig:8080")
	interval := time.Duration(envInt("SCAN_INTERVAL_SEC", 30)) * time.Second
	daysAhead := envInt("DAYS_AHEAD", 14)

	jrnl := newJournal(os.Getenv("JOURNAL_LOCAL_SOCK"))
	defer jrnl.close()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr,
		"deadline_worker started: url=%s interval=%s days=%d\n",
		url, interval, daysAhead)
	jrnl.log("deadline_worker_started", "scheduler", map[string]any{
		"url": url, "interval_sec": int(interval.Seconds()), "days": daysAhead,
	})

	// Tick once immediately, then on the interval.
	tick := time.NewTicker(interval)
	defer tick.Stop()
	scan(ctx, url, daysAhead, jrnl)
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "deadline_worker stopping")
			jrnl.log("deadline_worker_stopped", "scheduler", nil)
			return
		case <-tick.C:
			scan(ctx, url, daysAhead, jrnl)
		}
	}
}

// scan fetches upcoming deadlines and emits one journal entry
// summarising them. On HTTP failure, log a 'scan_failed' entry —
// silence would hide the worker being broken.
func scan(ctx context.Context, url string, daysAhead int, jrnl *journal) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/deadlines/upcoming?days=%d", url, daysAhead), nil)
	if err != nil {
		jrnl.log("deadline_scan_failed", "scheduler", map[string]any{"err": err.Error()})
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		jrnl.log("deadline_scan_failed", "scheduler", map[string]any{"err": err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		jrnl.log("deadline_scan_failed", "scheduler", map[string]any{
			"status": resp.StatusCode, "body": string(body),
		})
		return
	}

	var deadlines []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&deadlines); err != nil {
		jrnl.log("deadline_scan_failed", "scheduler", map[string]any{"decode": err.Error()})
		return
	}

	if len(deadlines) == 0 {
		// Quiet: don't spam audit chain when there's nothing to report.
		fmt.Fprintln(os.Stderr, "deadline_worker: 0 upcoming")
		return
	}

	// Build a compact summary: just IDs + days_left so the audit
	// entry stays readable. Detail lives in case_mgmt's DB.
	summary := make([]map[string]any, 0, len(deadlines))
	urgentCount := 0
	for _, d := range deadlines {
		days := 0
		if v, ok := d["days_left"].(float64); ok {
			days = int(v)
		}
		if days <= 7 {
			urgentCount++
		}
		summary = append(summary, map[string]any{
			"id":          d["id"],
			"task_id":     d["task_id"],
			"title":       d["title"],
			"due_at":      d["due_at"],
			"days_left":   days,
			"deadline_id": d["id"],
		})
	}

	jrnl.log("deadline_warning", "scheduler", map[string]any{
		"count":         len(deadlines),
		"urgent_count":  urgentCount,
		"days_ahead":    daysAhead,
		"deadlines":     summary,
	})
	fmt.Fprintf(os.Stderr,
		"deadline_worker: %d upcoming, %d urgent (≤7 days)\n",
		len(deadlines), urgentCount)
}

// ── helpers ─────────────────────────────────────────────────

func envOr(k, dflt string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dflt
}

func envInt(k string, dflt int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return dflt
}

// ── journal writer (same shape as case_mgmt) ────────────────

type journal struct {
	path string
	mu   sync.Mutex
	conn net.Conn
}

func newJournal(path string) *journal {
	if path == "" {
		fmt.Fprintln(os.Stderr,
			"deadline_worker: JOURNAL_LOCAL_SOCK not set, audit hook disabled")
	}
	return &journal{path: path}
}

func (j *journal) log(eventType, subject string, fields map[string]any) {
	if j == nil || j.path == "" {
		return
	}
	entry := map[string]any{
		"subject": subject,
		"level":   "info",
		"msg":     eventType,
		"fields":  fields,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.conn == nil {
		c, err := net.DialTimeout("unix", j.path, 2*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "deadline_worker: journal dial: %v\n", err)
			return
		}
		j.conn = c
	}
	_ = j.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := j.conn.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "deadline_worker: journal write: %v\n", err)
		_ = j.conn.Close()
		j.conn = nil
	}
}

func (j *journal) close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.conn != nil {
		_ = j.conn.Close()
		j.conn = nil
	}
}
