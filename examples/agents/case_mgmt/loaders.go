// loaders.go — read paths used by the timeline view.
// Kept separate from handlers.go so that file stays focused on
// HTTP routing.

package main

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func loadNotes(ctx context.Context, pool *pgxpool.Pool, taskID int64) []map[string]any {
	out := []map[string]any{}
	rows, err := pool.Query(ctx,
		`SELECT id, body, created_at FROM task_notes
		  WHERE task_id = $1 ORDER BY id`, taskID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var body string
		var ts time.Time
		if err := rows.Scan(&id, &body, &ts); err == nil {
			out = append(out, map[string]any{
				"id":         id,
				"body":       body,
				"created_at": ts.Format(time.RFC3339),
			})
		}
	}
	return out
}

func loadDeadlines(ctx context.Context, pool *pgxpool.Pool, taskID int64) []deadline {
	out := []deadline{}
	rows, err := pool.Query(ctx,
		`SELECT id, due_at, description, category, status, completed_at
		   FROM deadlines WHERE task_id = $1 ORDER BY due_at`, taskID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d deadline
		var due time.Time
		var completed *time.Time
		if err := rows.Scan(&d.ID, &due, &d.Description, &d.Category,
			&d.Status, &completed); err == nil {
			d.TaskID = taskID
			d.DueAt = due.Format(time.RFC3339)
			if completed != nil {
				s := completed.Format(time.RFC3339)
				d.CompletedAt = &s
			}
			out = append(out, d)
		}
	}
	return out
}

// loadTime returns the entries plus the total billable amount in cents.
func loadTime(ctx context.Context, pool *pgxpool.Pool, taskID int64) ([]map[string]any, int64) {
	out := []map[string]any{}
	var total int64
	rows, err := pool.Query(ctx,
		`SELECT t.id, t.user_id, u.name, t.occurred_on, t.minutes,
		        t.description, t.rate_cents
		   FROM time_entries t
		   JOIN users u ON u.id = t.user_id
		  WHERE t.task_id = $1
		  ORDER BY t.occurred_on, t.id`, taskID)
	if err != nil {
		return out, 0
	}
	defer rows.Close()
	for rows.Next() {
		var id, userID int64
		var userName, description string
		var occurred time.Time
		var minutes, rate int
		if err := rows.Scan(&id, &userID, &userName, &occurred,
			&minutes, &description, &rate); err == nil {
			amount := int64(minutes) * int64(rate) / 60
			total += amount
			out = append(out, map[string]any{
				"id":           id,
				"user_id":      userID,
				"user_name":    userName,
				"occurred_on":  occurred.Format("2006-01-02"),
				"minutes":      minutes,
				"description":  description,
				"rate_cents":   rate,
				"amount_cents": amount,
			})
		}
	}
	return out, total
}
