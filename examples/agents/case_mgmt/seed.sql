-- Reference workload seed — generic task tracker.
--
-- 3 users, 5 tasks across the typical workflow shapes:
--   1. Bug fix in production (high urgency)
--   2. Feature work (steady state)
--   3. Incident response (time-critical)
--   4. Migration / schema work
--   5. Closed task with completed deadline (history sample)
--
-- After `make showcase` this is what an operator sees in the UI.

-- ── users ────────────────────────────────────────────────────
INSERT INTO users (name, email, hourly_rate_cents) VALUES
    ('Alex Carter',  'alex@example.com',  15000),   -- senior
    ('Jamie Reyes',  'jamie@example.com', 10000),   -- mid
    ('Sam Okafor',   'sam@example.com',   12000);   -- senior

-- ── tasks ────────────────────────────────────────────────────
INSERT INTO tasks (title, description, status, assignee_id) VALUES
    ('Fix nightly export job',
     'Cron-driven export crashes on large batches; OOM in worker. Reproduces on staging with > 50k rows.',
     'open', 1),
    ('Add bulk-edit to dashboard',
     'Operators want multi-select + bulk status change. Behind feature flag bulk_edit_v1.',
     'open', 2),
    ('PROD-2113: API 5xx spike',
     'Sustained 5xx on /v2/orders since 09:14 UTC. Tracing rollout suspect — see incident channel #inc-2113.',
     'open', 1),
    ('Migrate sessions to new schema',
     'Drop legacy sessions_v1 table after the dual-write window closes. Backfill verified.',
     'open', 3),
    ('Retire old admin UI bundle',
     'Old /admin-classic served by nginx is unused; pull from build pipeline + remove route.',
     'closed', 3);

-- ── task_notes ───────────────────────────────────────────────
INSERT INTO task_notes (task_id, body) VALUES
    (1, 'Repro: ./scripts/export.sh --since=2026-04-01 --batch=50000 → killed by OOM at ~3.2 GB RSS.'),
    (1, 'Heap dump points at unbounded buffer in formatter. Streaming rewrite drafted in branch fix/export-stream.'),
    (2, 'UX review with operator team done — they want undo within 30s. Toast pattern OK.'),
    (2, 'Backend bulk endpoint shipped behind flag last week; UI is the remaining piece.'),
    (3, 'Rolled back tracing config at 09:38 UTC, error rate dropping. Monitoring; postmortem owner: Alex.'),
    (3, 'Filed PROD-2113 in incident tracker, sev-2. Expected closeout once 5xx stays under 0.1% for 1h.'),
    (4, 'Dual-write window opened 2026-04-01. Read-from-new since 2026-04-08, no parity gaps for 12 days.'),
    (5, 'Verified zero requests to /admin-classic for 30d in access logs. Safe to remove.');

-- ── deadlines ────────────────────────────────────────────────
-- Mix of open + completed. Open deadlines fall 2-30 days out so
-- the deadline_worker has something to warn about on first scan.
INSERT INTO deadlines (task_id, due_at, description, category, status) VALUES
    (1, NOW() + INTERVAL '5 days',
        'Ship export fix to production',                 'release', 'open'),
    (1, NOW() + INTERVAL '21 days',
        'Postmortem write-up due',                       'review',  'open'),
    (2, NOW() + INTERVAL '12 days',
        'Bulk-edit feature flag rollout to 25%',         'release', 'open'),
    (3, NOW() + INTERVAL '3 days',
        'Incident postmortem PROD-2113',                 'review',  'open'),
    (3, NOW() + INTERVAL '28 days',
        'Follow-up review with platform team',           'meeting', 'open'),
    (4, NOW() + INTERVAL '14 days',
        'Drop legacy sessions_v1 table',                 'release', 'open');

-- One completed deadline on the closed task.
INSERT INTO deadlines (task_id, due_at, description, category, status, completed_at) VALUES
    (5, NOW() - INTERVAL '60 days',
        'Confirm zero traffic on /admin-classic',        'review',  'done',
        NOW() - INTERVAL '62 days');

-- ── time_entries ─────────────────────────────────────────────
-- Several entries per task spread over the last month so the
-- billing/effort summary isn't empty.
INSERT INTO time_entries (task_id, user_id, occurred_on, minutes, description, rate_cents) VALUES
    (1, 1, CURRENT_DATE - 14, 90,  'Repro export OOM, capture heap dump',           15000),
    (1, 1, CURRENT_DATE - 12, 180, 'Trace allocator, isolate buffer growth',        15000),
    (1, 2, CURRENT_DATE - 10, 120, 'Draft streaming-formatter rewrite',             10000),
    (1, 1, CURRENT_DATE - 5,  60,  'Code review with Jamie',                        15000),

    (2, 2, CURRENT_DATE - 21, 60,  'Spec bulk-edit endpoint contract',              10000),
    (2, 2, CURRENT_DATE - 18, 240, 'Implement backend handler + tests',             10000),
    (2, 2, CURRENT_DATE - 12, 90,  'Wire UI multi-select component',                10000),

    (3, 1, CURRENT_DATE - 25, 120, 'Triage 5xx spike, page on-call',                15000),
    (3, 1, CURRENT_DATE - 22, 180, 'Root-cause tracing config regression',          15000),
    (3, 2, CURRENT_DATE - 20, 60,  'Roll back tracing config + verify recovery',    10000),

    (4, 3, CURRENT_DATE - 8,  90,  'Verify dual-write parity over 7d window',       12000),
    (4, 3, CURRENT_DATE - 5,  60,  'Plan cutover steps + rollback',                 12000),

    (5, 3, CURRENT_DATE - 75, 240, 'Audit access logs for /admin-classic usage',    12000),
    (5, 3, CURRENT_DATE - 65, 180, 'Remove route from nginx + build pipeline',      12000),
    (5, 3, CURRENT_DATE - 62, 90,  'Confirm cleanup, close ticket',                 12000);
