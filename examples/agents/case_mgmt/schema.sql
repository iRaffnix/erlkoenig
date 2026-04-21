-- Reference workload schema — generic task/issue tracking.
--
-- Drop + recreate idempotent. The showcase target wipes and
-- re-seeds from this file every `make showcase` so the demo is
-- always reproducible.

DROP TABLE IF EXISTS time_entries CASCADE;
DROP TABLE IF EXISTS deadlines CASCADE;
DROP TABLE IF EXISTS parties CASCADE;           -- legacy, dropped
DROP TABLE IF EXISTS case_notes CASCADE;        -- legacy, renamed below
DROP TABLE IF EXISTS task_notes CASCADE;
DROP TABLE IF EXISTS cases CASCADE;             -- legacy, renamed below
DROP TABLE IF EXISTS tasks CASCADE;
DROP TABLE IF EXISTS lawyers CASCADE;           -- legacy, renamed below
DROP TABLE IF EXISTS users CASCADE;

-- ── users ────────────────────────────────────────────────────
-- Who's on the hook for tasks — engineers, operators, reviewers.
-- hourly_rate_cents is a snapshot source for time_entries billing
-- (most workloads won't use it; present for the full-stack demo).
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    hourly_rate_cents INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── tasks ────────────────────────────────────────────────────
-- The tracked work item. assignee_id = who owns it.
CREATE TABLE tasks (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'closed', 'archived')),
    assignee_id BIGINT REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ
);

CREATE INDEX tasks_title_idx ON tasks (title);
CREATE INDEX tasks_status_idx ON tasks (status);

-- ── task_notes ───────────────────────────────────────────────
-- Freeform comments per task.
CREATE TABLE task_notes (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX task_notes_task_idx ON task_notes (task_id);

-- ── deadlines ────────────────────────────────────────────────
-- Due dates with categories. deadline_worker pollt upcoming +
-- warnt bei < 7 Tagen.
CREATE TABLE deadlines (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    due_at TIMESTAMPTZ NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,                  -- 'review', 'response', 'meeting', etc.
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'done', 'missed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX deadlines_open_due_idx ON deadlines (due_at)
    WHERE status = 'open';
CREATE INDEX deadlines_task_idx ON deadlines (task_id);

-- ── time_entries ─────────────────────────────────────────────
-- Effort tracking. rate_cents = snapshot at entry time.
CREATE TABLE time_entries (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id),
    occurred_on DATE NOT NULL,
    minutes INTEGER NOT NULL CHECK (minutes > 0),
    description TEXT NOT NULL,
    rate_cents INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX time_entries_task_idx ON time_entries (task_id);
CREATE INDEX time_entries_user_idx ON time_entries (user_id);

-- ── grants ───────────────────────────────────────────────────
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO case_mgmt;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO case_mgmt;
