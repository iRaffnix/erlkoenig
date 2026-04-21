// journal.go — best-effort writer to journal.local.
//
// Connects lazily on the first call, retries on write failure.
// If the socket isn't there or write fails, we log to stderr but
// don't break the request — the workload is still useful without
// the audit hook (the operator sees logs in their stack and can
// investigate why audit is silent).

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type journal struct {
	path string
	mu   sync.Mutex
	conn net.Conn
}

func newJournal(path string) *journal {
	if path == "" {
		fmt.Fprintln(os.Stderr,
			"case_mgmt: JOURNAL_LOCAL_SOCK not set, audit hook disabled")
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
			fmt.Fprintf(os.Stderr, "case_mgmt: journal dial: %v\n", err)
			return
		}
		j.conn = c
	}
	_ = j.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := j.conn.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "case_mgmt: journal write: %v\n", err)
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
