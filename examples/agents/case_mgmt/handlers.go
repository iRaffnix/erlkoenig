// handlers.go — HTTP handlers for the task-tracker API.
//
// Resource hierarchy:
//   /users
//   /tasks, /tasks/:id, /tasks/:id/{notes,deadlines,time,close}
//   /deadlines/:id/done, /deadlines/upcoming
//
// Every mutation logs to journal.local with a stable event_type;
// reads stay quiet so the chain isn't drowned in /healthz noise.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type app struct {
	pool *pgxpool.Pool
	jrnl *journal
}

// ── healthz ─────────────────────────────────────────────────

func (a *app) healthz(w http.ResponseWriter, r *http.Request) {
	if err := a.pool.Ping(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// ── /users ──────────────────────────────────────────────────

type user struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email,omitempty"`
	HourlyRateCents int    `json:"hourly_rate_cents"`
}

func (a *app) usersRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.pool.Query(r.Context(),
			`SELECT id, name, COALESCE(email,''), hourly_rate_cents
			   FROM users ORDER BY name`)
		if err != nil {
			httpErr(w, err, http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var out []user
		for rows.Next() {
			var u user
			if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.HourlyRateCents); err == nil {
				out = append(out, u)
			}
		}
		respondJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var in user
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		err := a.pool.QueryRow(r.Context(),
			`INSERT INTO users (name, email, hourly_rate_cents)
			 VALUES ($1, NULLIF($2,''), $3) RETURNING id`,
			in.Name, in.Email, in.HourlyRateCents).Scan(&in.ID)
		if err != nil {
			httpErr(w, err, http.StatusInternalServerError)
			return
		}
		a.jrnl.log("user_created", in.Name, map[string]any{
			"id": in.ID, "rate_cents": in.HourlyRateCents,
		})
		respondJSON(w, http.StatusCreated, in)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── /tasks ──────────────────────────────────────────────────

type taskRec struct {
	ID          int64   `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Status      string  `json:"status"`
	AssigneeID  *int64  `json:"assignee_id,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	ClosedAt    *string `json:"closed_at,omitempty"`
}

func (a *app) tasksRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("q")
		var rows pgx.Rows
		var err error
		if q == "" {
			rows, err = a.pool.Query(r.Context(),
				`SELECT id, title, description, status, assignee_id,
				        created_at, updated_at, closed_at
				   FROM tasks ORDER BY id DESC LIMIT 100`)
		} else {
			rows, err = a.pool.Query(r.Context(),
				`SELECT id, title, description, status, assignee_id,
				        created_at, updated_at, closed_at
				   FROM tasks WHERE title ILIKE '%' || $1 || '%'
				  ORDER BY id DESC LIMIT 100`, q)
		}
		if err != nil {
			httpErr(w, err, http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []taskRec{}
		for rows.Next() {
			t, _ := scanTask(rows)
			out = append(out, t)
		}
		respondJSON(w, http.StatusOK, out)

	case http.MethodPost:
		var in struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			AssigneeID  *int64 `json:"assignee_id,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if in.Title == "" || in.Description == "" {
			http.Error(w, "title + description required", http.StatusBadRequest)
			return
		}
		var id int64
		err := a.pool.QueryRow(r.Context(),
			`INSERT INTO tasks (title, description, assignee_id)
			 VALUES ($1, $2, $3) RETURNING id`,
			in.Title, in.Description, in.AssigneeID).Scan(&id)
		if err != nil {
			httpErr(w, err, http.StatusInternalServerError)
			return
		}
		a.jrnl.log("task_created", in.Title, map[string]any{
			"id": id, "description_len": len(in.Description), "assignee_id": in.AssigneeID,
		})
		respondJSON(w, http.StatusCreated, map[string]any{
			"id": id, "title": in.Title, "description": in.Description,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── /tasks/:id and subresources ─────────────────────────────

func (a *app) taskSubresource(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/tasks/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}

	if len(parts) == 1 || parts[1] == "" {
		if r.Method == http.MethodGet {
			a.getTaskTimeline(w, r, id)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	switch {
	case parts[1] == "notes" && r.Method == http.MethodPost:
		a.addNote(w, r, id)
	case parts[1] == "deadlines" && r.Method == http.MethodPost:
		a.addDeadline(w, r, id)
	case parts[1] == "time" && r.Method == http.MethodPost:
		a.addTime(w, r, id)
	case parts[1] == "close" && r.Method == http.MethodPost:
		a.closeTask(w, r, id)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// getTaskTimeline returns task + notes + deadlines + time entries +
// effort summary in one call. Heavy but it's the showcase view.
func (a *app) getTaskTimeline(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()

	var t taskRec
	err := a.pool.QueryRow(ctx,
		`SELECT id, title, description, status, assignee_id,
		        created_at, updated_at, closed_at
		   FROM tasks WHERE id = $1`, id).Scan(
		&t.ID, &t.Title, &t.Description, &t.Status, &t.AssigneeID,
		scanTime(&t.CreatedAt), scanTime(&t.UpdatedAt), scanTimePtr(&t.ClosedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}

	notes := loadNotes(ctx, a.pool, id)
	deadlines := loadDeadlines(ctx, a.pool, id)
	timeEntries, totalCents := loadTime(ctx, a.pool, id)

	respondJSON(w, http.StatusOK, map[string]any{
		"task":         t,
		"notes":        notes,
		"deadlines":    deadlines,
		"time_entries": timeEntries,
		"effort": map[string]any{
			"total_cents": totalCents,
			"total_eur":   fmt.Sprintf("%.2f", float64(totalCents)/100.0),
			"entry_count": len(timeEntries),
		},
	})
}

// ── notes ────────────────────────────────────────────────────

func (a *app) addNote(w http.ResponseWriter, r *http.Request, id int64) {
	var in struct{ Body string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if in.Body == "" {
		http.Error(w, "body required", http.StatusBadRequest)
		return
	}
	var noteID int64
	err := a.pool.QueryRow(r.Context(),
		`INSERT INTO task_notes (task_id, body) VALUES ($1, $2) RETURNING id`,
		id, in.Body).Scan(&noteID)
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	a.jrnl.log("task_note_added", fmt.Sprintf("task#%d", id), map[string]any{
		"task_id": id, "note_id": noteID, "body_len": len(in.Body),
	})
	respondJSON(w, http.StatusCreated, map[string]any{"id": noteID})
}

// ── deadlines ────────────────────────────────────────────────

type deadline struct {
	ID          int64   `json:"id"`
	TaskID      int64   `json:"task_id"`
	DueAt       string  `json:"due_at"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Status      string  `json:"status"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

func (a *app) addDeadline(w http.ResponseWriter, r *http.Request, taskID int64) {
	var in struct {
		DueAt       string `json:"due_at"`
		Description string `json:"description"`
		Category    string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if in.DueAt == "" || in.Description == "" || in.Category == "" {
		http.Error(w, "due_at + description + category required", http.StatusBadRequest)
		return
	}
	due, err := time.Parse(time.RFC3339, in.DueAt)
	if err != nil {
		http.Error(w, "due_at must be RFC3339", http.StatusBadRequest)
		return
	}
	var id int64
	err = a.pool.QueryRow(r.Context(),
		`INSERT INTO deadlines (task_id, due_at, description, category)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		taskID, due, in.Description, in.Category).Scan(&id)
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	a.jrnl.log("deadline_set", fmt.Sprintf("task#%d", taskID), map[string]any{
		"task_id": taskID, "deadline_id": id,
		"due_at": due.Format(time.RFC3339), "category": in.Category,
	})
	respondJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *app) deadlineByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/deadlines/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid deadline id", http.StatusBadRequest)
		return
	}
	if len(parts) != 2 || parts[1] != "done" || r.Method != http.MethodPost {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var taskID int64
	err = a.pool.QueryRow(r.Context(),
		`UPDATE deadlines SET status = 'done', completed_at = NOW()
		  WHERE id = $1 RETURNING task_id`, id).Scan(&taskID)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	a.jrnl.log("deadline_done", fmt.Sprintf("task#%d", taskID), map[string]any{
		"task_id": taskID, "deadline_id": id,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) deadlinesUpcoming(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	days := 14
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	rows, err := a.pool.Query(r.Context(),
		`SELECT d.id, d.task_id, d.due_at, d.description, d.category,
		        d.status, t.title
		   FROM deadlines d
		   JOIN tasks t ON t.id = d.task_id
		  WHERE d.status = 'open'
		    AND d.due_at <= NOW() + ($1 || ' days')::INTERVAL
		  ORDER BY d.due_at`, fmt.Sprintf("%d", days))
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var d deadline
		var title string
		var due time.Time
		if err := rows.Scan(&d.ID, &d.TaskID, &due, &d.Description,
			&d.Category, &d.Status, &title); err == nil {
			d.DueAt = due.Format(time.RFC3339)
			out = append(out, map[string]any{
				"id":          d.ID,
				"task_id":     d.TaskID,
				"due_at":      d.DueAt,
				"description": d.Description,
				"category":    d.Category,
				"title":       title,
				"days_left":   int(time.Until(due).Hours() / 24),
			})
		}
	}
	respondJSON(w, http.StatusOK, out)
}

// ── time entries ─────────────────────────────────────────────

func (a *app) addTime(w http.ResponseWriter, r *http.Request, taskID int64) {
	var in struct {
		UserID      int64  `json:"user_id"`
		OccurredOn  string `json:"occurred_on"`
		Minutes     int    `json:"minutes"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if in.UserID == 0 || in.OccurredOn == "" || in.Minutes <= 0 {
		http.Error(w, "user_id + occurred_on + minutes>0 required", http.StatusBadRequest)
		return
	}
	occurred, err := time.Parse("2006-01-02", in.OccurredOn)
	if err != nil {
		http.Error(w, "occurred_on must be YYYY-MM-DD", http.StatusBadRequest)
		return
	}
	// Snapshot the user's current rate.
	var rate int
	err = a.pool.QueryRow(r.Context(),
		`SELECT hourly_rate_cents FROM users WHERE id = $1`, in.UserID).
		Scan(&rate)
	if err != nil {
		httpErr(w, err, http.StatusBadRequest)
		return
	}
	var id int64
	err = a.pool.QueryRow(r.Context(),
		`INSERT INTO time_entries
		   (task_id, user_id, occurred_on, minutes, description, rate_cents)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		taskID, in.UserID, occurred, in.Minutes, in.Description, rate).Scan(&id)
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	a.jrnl.log("time_logged", fmt.Sprintf("task#%d", taskID), map[string]any{
		"task_id": taskID, "user_id": in.UserID,
		"minutes": in.Minutes, "rate_cents": rate,
		"amount_cents": (in.Minutes * rate) / 60,
	})
	respondJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// ── close task ───────────────────────────────────────────────

func (a *app) closeTask(w http.ResponseWriter, r *http.Request, id int64) {
	var title string
	err := a.pool.QueryRow(r.Context(),
		`UPDATE tasks SET status = 'closed', closed_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND status = 'open' RETURNING title`, id).Scan(&title)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "not found or already closed", http.StatusBadRequest)
		return
	}
	if err != nil {
		httpErr(w, err, http.StatusInternalServerError)
		return
	}
	a.jrnl.log("task_closed", title, map[string]any{"task_id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────

func httpErr(w http.ResponseWriter, err error, code int) {
	http.Error(w, err.Error(), code)
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// scanTime returns a destination that converts a TIMESTAMPTZ row
// value into RFC3339 string. Use with QueryRow().Scan().
func scanTime(s *string) any {
	return &timeScanner{out: s}
}
func scanTimePtr(s **string) any {
	return &timePtrScanner{out: s}
}

type timeScanner struct{ out *string }

func (t *timeScanner) Scan(v any) error {
	if v == nil {
		*t.out = ""
		return nil
	}
	if tv, ok := v.(time.Time); ok {
		*t.out = tv.Format(time.RFC3339)
		return nil
	}
	return fmt.Errorf("not a time: %T", v)
}

type timePtrScanner struct{ out **string }

func (t *timePtrScanner) Scan(v any) error {
	if v == nil {
		*t.out = nil
		return nil
	}
	if tv, ok := v.(time.Time); ok {
		s := tv.Format(time.RFC3339)
		*t.out = &s
		return nil
	}
	return fmt.Errorf("not a time: %T", v)
}

func scanTask(rows pgx.Rows) (taskRec, error) {
	var t taskRec
	err := rows.Scan(
		&t.ID, &t.Title, &t.Description, &t.Status, &t.AssigneeID,
		scanTime(&t.CreatedAt), scanTime(&t.UpdatedAt), scanTimePtr(&t.ClosedAt))
	return t, err
}
