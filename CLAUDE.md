# CLAUDE.md — LSS Backup Management Server Project Notebook

This file is my working notebook for this project. It captures what's built, how it works,
why decisions were made, and what's next. Keep it up to date as the project evolves.

---

## What This Project Is

A web-based management server for LSS Backup CLI nodes. It receives encrypted heartbeats
and post-run reports from CLI nodes, provides a dashboard for operators, and enables remote
terminal access to nodes through reverse SSH tunnels over WebSocket.

**Version:** v1.29.3
**Paired CLI:** v2.13.5
**Module:** `github.com/lssolutions-ie/lss-backup-server`
**Go version:** 1.25.0

---

## Architecture

### Directory Layout

```
├── cmd/server/main.go              Entry point, HTTP mux, version var
├── internal/
│   ├── api/status.go               Node heartbeat/report endpoint (POST /api/v1/status)
│   ├── config/config.go            TOML config loader (incl. terminal.sessions_dir)
│   ├── crypto/                     AES-256-GCM decrypt, PSK encrypt/decrypt
│   ├── db/
│   │   ├── db.go                   MySQL connection, migrations
│   │   ├── queries.go              All DB queries, tunnel authorized_keys writer
│   │   └── audit.go                audit_log queries + node-event ingest + ack reconcile
│   ├── logx/logx.go                Structured logging (slog) — auto-init, request IDs, redaction
│   ├── models/models.go            Node, User, Session, JobSnapshot, NodeStatus, AuditEvent…
│   ├── notify/                     Notifier interface (NoOp; full stack DEFERRED to last)
│   ├── recorder/recorder.go        Asciinema v2 .cast writer for terminal session recording
│   ├── web/
│   │   ├── auth.go                 Login/logout/setup handlers
│   │   ├── dashboard.go            Main dashboard page
│   │   ├── middleware.go           Session auth, RBAC, template rendering
│   │   ├── logging.go              Request-ID/access-log middleware + s.Fail() helper
│   │   ├── audit.go                auditServer / auditServerFor helpers
│   │   ├── audit_page.go           /audit + per-node /nodes/{id}/audit handlers
│   │   ├── replay.go               /audit/session/{file} terminal replay handler
│   │   ├── nodes.go                Node CRUD, PSK regeneration, anomaly counts endpoint
│   │   ├── groups.go               Client group CRUD
│   │   ├── users.go                User CRUD
│   │   ├── settings.go             Password change, SMTP config
│   │   ├── tuning.go               /settings/tuning page (all knobs)
│   │   ├── anomalies.go            /anomalies + archive + ack/bulk-ack/anomaly-counts
│   │   ├── terminal.go             Dashboard terminal (WebSocket → SSH proxy + recording tee)
│   │   └── ssh_tunnel.go           Node reverse tunnel endpoint (WebSocket → sshd)
│   └── worker/
│       ├── worker.go               Background offline-node checker
│       └── retention.go            Hourly: prune reports, audit_log, .cast recordings
├── migrations/                     SQL migration files (001-032)
├── templates/                      Go HTML templates (Tabler UI)
├── static/                         CSS/JS assets
└── install/install.sh              Server installer (systemd, nginx, MySQL, sshd config)
```

### Network Topology

```
CLI Node → HTTPS → HAProxy (OPNsense, SSL termination)
         → HTTP  → nginx (:80, WebSocket pass-through for /ws/)
         → HTTP  → Go server (127.0.0.1:8080)
```

### Key Endpoints

| Path | Auth | Purpose |
|------|------|---------|
| `POST /api/v1/status` | PSK/AES-256-GCM encrypted payload | Node heartbeat + post-run reports + v3 audit_events ingest |
| `GET /ws/ssh-tunnel` | HMAC-SHA256 in HTTP headers | Node reverse tunnel (WebSocket → sshd) |
| `GET /ws/terminal` | Dashboard session cookie | Operator terminal (WebSocket → SSH, recorded when enabled) |
| `GET /nodes/{id}/terminal` | Dashboard session cookie | Terminal page with credential form + recording banner |
| `GET /nodes/{id}/anomaly-counts` | Dashboard session cookie | JSON map of unack'd anomaly counts per job (used by node-detail shield refresh) |
| `GET /audit` | Manager+ | Global audit log (server + node sources) |
| `GET /nodes/{id}/audit` | Node-view permission | Per-node audit tab |
| `GET /audit/session/{file}` | Superadmin | asciinema v2 replay viewer + raw .cast download |
| `POST /anomalies/bulk-ack` | Dashboard session cookie | Bulk ack/unack with `ids=` and `action=ack\|unack` |

---

## SSH Tunnel System

### How It Works

1. **CLI node** connects to `wss://<server>/ws/ssh-tunnel` with HMAC-SHA256 auth headers
2. **Server** authenticates via PSK, upgrades to WebSocket, proxies bytes to local sshd (127.0.0.1:22)
3. **CLI** performs SSH handshake over the WebSocket as user `lss-tunnel`
4. **CLI** requests reverse port forward (`-R <port>:localhost:22`)
5. **sshd** opens a listening port on `127.0.0.1:<port>`
6. **Dashboard terminal** connects to `127.0.0.1:<port>` to reach the node

### HMAC Authentication (ssh_tunnel.go)

- Message: `"ssh-tunnel:<uid>:<unix_timestamp>"` (colon-separated, matching CLI v2.1.135+)
- Algorithm: HMAC-SHA256 with node's PSK as key
- Headers: `X-LSS-UID`, `X-LSS-TS`, `X-LSS-HMAC`
- Replay protection: ±2 minute timestamp skew window
- Constant-time comparison via `subtle.ConstantTimeCompare`

### lss-tunnel User (sshd config)

Configured in `/etc/ssh/sshd_config.d/lss-tunnel.conf`:
- `PubkeyAuthentication yes`
- `PasswordAuthentication no`
- `AllowTcpForwarding yes` (needed for reverse forwards)
- `GatewayPorts no` (tunnels bind to localhost only)
- `ForceCommand /usr/bin/sleep infinity` (keeps session alive, prevents shell)
- `PermitTTY no`, `X11Forwarding no`, `AllowAgentForwarding no`, `PermitTunnel no`
- `AuthorizedKeysCommand /usr/local/bin/lss-tunnel-authkeys.sh` (reads from managed file)
- Shell: `/usr/sbin/nologin`

### Authorized Keys Management

- Keys stored in DB column `nodes.tunnel_public_key`
- Written atomically to `/var/lib/lss-backup-server/tunnel_authorized_keys` (tempfile + rename)
- sshd reads via `AuthorizedKeysCommand` script (not from `~/.ssh/authorized_keys`)
- Regenerated on startup and whenever a node's key changes via heartbeat

### Heartbeat Key Registration

- When a heartbeat includes `tunnel.public_key`, the server stores it and writes authorized_keys
- Response includes `tunnel_key_registered: true` so the CLI knows it's safe to start the tunnel
- Prevents auth race on first daemon start (CLI waits for confirmation before SSH attempt)

---

## Dashboard Terminal (terminal.go)

### Security Model

- **Credentials are NEVER stored** — operator enters SSH username/password each time
- Password is sent in the first WebSocket message, used to create `ssh.ClientConfig`, then zeroed
- Password is never logged (only username, host, port, and mode are logged)
- Requires `CanWrite()` permission (not available to read-only viewers)

### Connection Flow

1. Browser opens `/nodes/{id}/terminal` — renders credential form
2. If node has active tunnel: hides host/port fields, shows "Reverse tunnel active" info
3. If no tunnel: shows host/port fields for direct SSH
4. Browser upgrades to WebSocket at `/ws/terminal`
5. First message: `{type: "auth", node_id, host, port, username, password, cols, rows}`
6. Server resolves target: tunnel → `127.0.0.1:<tunnel_port>`, or direct → `host:port`
7. Server dials SSH, opens PTY, proxies stdin/stdout/stderr bidirectionally
8. Browser uses xterm.js for terminal rendering

---

## Node Heartbeat API (status.go)

### Request Flow

1. Node sends `POST /api/v1/status` with `{v, uid, data}` where `data` is AES-256-GCM encrypted
2. Server decrypts with node's PSK, parses `NodeStatus` payload
3. Validates freshness (±10 min age, ±2 min future skew)
4. Upserts job snapshots, inserts node report, updates `last_seen_at`
5. If tunnel info present: updates tunnel port/connected/public_key, regenerates authorized_keys if key changed
6. Sends failure notifications for failed jobs
7. Response: `{"ok": true, "tunnel_key_registered": true}` (latter only when tunnel key is present)

### Report Types

- `heartbeat` — periodic 5-minute tick from daemon
- `post_run` — sent after each backup job completes

---

## Logging (v1.11.6+)

Structured JSON via Go `log/slog`, written to stderr (captured by systemd journal). Every line is parseable by `jq`. Level controlled by `LSS_LOG_LEVEL=debug|info|warn|error` env var (default `info`).

Sample line:
```json
{"time":"2026-04-15T20:47:49.31Z","level":"INFO","msg":"open","service":"lss-backup-server","component":"tunnel","node_id":9,"uid":"lss-linux-vm-01","peer":"127.0.0.1:35158"}
```

### Conventions
- **Component tag** on every line via `logx.Component("name")` — values: `api`, `auth`, `audit`, `db`, `db.audit`, `http`, `permissions`, `recorder`, `repo`, `silences`, `terminal`, `tunnel`, `web`, `worker`.
- **Request IDs** flow through `r.Context()` — handlers use `logx.FromContext(r.Context())` so every line for one HTTP request shares `req_id`. Stitch a request with `jq 'select(.req_id=="abc123")'`.
- **Access log middleware** (`web.RequestLog`) emits one line per mutating route (POST/PUT/DELETE/PATCH) with method, path, status, duration, user, remote IP. Skips `/api/v1/status` and `/ws/*` (high-volume + already detailed).
- **`s.Fail(w, r, status, err, clientMsg)`** — log + http.Error in one call. Used everywhere a 500 might otherwise be silent.
- **Heartbeat noise demoted to DEBUG** — per-heartbeat ingest line only fires at `LSS_LOG_LEVEL=debug`. Default INFO is signal-only.
- **Redaction** — `logx.Redact(secret)` returns `***(N)`. Used for PSKs, passwords, raw cookies. Do NOT log secrets directly.
- **logx auto-init** — package `init()` in `internal/logx` runs before any importer's var declarations so package-level `var lg = logx.Component("foo")` captures the JSON handler, not the pre-init default. Critical: without this, captures get double-wrapped after `log.SetOutput` redirect.
- **Hijacker passthrough** — `statusCapturingWriter` (access-log wrapper) implements `http.Hijacker` and `http.Flusher`. Without those, gorilla/websocket's Upgrade fails on every `/ws/*` connection.

---

## Database

MySQL with 42 migrations:

| Migration | Purpose |
|-----------|---------|
| 001 | Base schema: nodes, client_groups, users, sessions |
| 002 | Job snapshots table |
| 003 | Node reports table |
| 004 | User-group access control |
| 005 | Node reports: report_type column |
| 006 | Nodes: tunnel_port, tunnel_connected, tunnel_public_key columns |
| 007 | Node hardware info columns (OS, arch, CPUs, RAM, storage, IPs) |
| 008 | SSH host keys table (TOFU) |
| 009 | User TOTP 2FA columns |
| 010 | User force_setup flag |
| 011 | Session idle tracking (last_active_at) |
| 012 | User email column |
| 013 | SMTP config table |
| 014 | Tags table + node_tags junction |
| 015 | User-tag permissions table (user_tags) |
| 016 | Tag text_color column |
| 017 | Roles renamed: user→manager, viewer→user; added manager, guest |
| 018 | client_groups.rank ENUM (bronze, silver, gold, diamond) |
| 019 | User tags split: user_tag_catalog + user_tag_links (dropped old user_tags) |
| 020 | Permission scaffolding: tag_permissions, user_groups, user_group_members, user_group_tags, user_node_overrides |
| 021 | Unified permission_rules (priority, effect, access, polymorphic subject+target); migrates + drops tag_permissions/user_node_overrides |
| 022 | node_tag allowed as subject type (later removed from UI; enum kept) |
| 023 | permission_rules.enabled flag |
| 024 | Job status extensions: VARCHAR last_status, bytes/files/snapshot_id/repo_size + per-job override |
| 025 | server_tuning single-row table (reconcile interval, retention, offline thresholds, etc.) |
| 026 | job_daily_stats aggregation table (retention rollup) |
| 027 | job_silences (timed mute per node+job) |
| 028 | job_tag_catalog + job_tag_links (priority labels) |
| 029 | snapshot_count column + job_anomalies audit table + anomaly threshold settings |
| 030 | server_tuning.anomaly_ack_retention_days (default 30) — moves old acked anomalies to /anomalies/archive |
| 031 | audit_log table (UNIQUE source_node_id+source_seq), nodes.audit_ack_seq, server_tuning.audit_retention_days |
| 032 | server_tuning.terminal_recording_enabled + terminal_recording_retention_days |
| 033 | server_tuning.silent_alert_threshold_minutes (default 7) — aggressive missed-heartbeat alarm |
| 034 | job_anomalies.resolution_note — free-text note captured at ack time |
| 035 | audit_log.source ENUM extended with 'host' + host_audit_state table for journalctl cursor |
| 036 | job_snapshots.snapshot_ids JSON + job_anomalies.prev_snapshot_id/curr_snapshot_id — forensics |
| 037 | nodes.audit_chain_head — HMAC chain verification for audit tamper evidence |
| 038 | dr_config table (S3 creds encrypted at rest) + 8 DR columns on nodes — server-controlled disaster recovery |
| 039 | cli_version + cli_update_pending on nodes, latest_cli_version on server_tuning — remote CLI update |
| 040 | update_check_interval_minutes + latest_server_version on server_tuning — configurable version checking |
| 041 | node_install_tokens table — one-command node deployment + recovery tokens |
| 042 | deletion_phase + secrets_export_enc + deletion_retain_data on nodes — graceful node deletion |
| 043 | server_backup_enabled/interval/status columns on server_tuning — server auto-backup |
| 044 | DR config split: separate server/node restic passwords + retention (keep_last/keep_daily) |
| 045 | latest_server_release_notes on server_tuning — GitHub release notes display |
| 046 | latest_cli_release_notes on server_tuning — CLI release notes display |

---

## RBAC

| Feature | superadmin | manager | user | guest |
|---------|-----------|---------|------|-------|
| Dashboard | All nodes | All nodes | Scoped to groups | Scoped to groups |
| Register/Edit/Delete Node | Yes | Yes | No | No |
| Regenerate PSK | Yes | Yes | No | No |
| Terminal (SSH) | Yes | Yes | No | No |
| Browse Repos & Download | Yes | Yes | Yes | No |
| Manage Users | Yes | Yes | No | No |
| Manage Client Groups | Yes | Yes | No | No |
| Manage Tags | Yes | Yes | No | No |
| SMTP/Server Settings | Yes | No | No | No |
| View Jobs & Check-ins | Yes | Yes | Yes | Yes |

---

## Job Reporting Protocol (v1.9.0+, paired with CLI v2.2.x)

Extended `NodeStatus.Jobs[]` schema. Fields are optional/omitempty — server tolerates any subset.

### Status enum (widened)
`success | warning | failure | "" (never run) | skipped | cancelled | paused`

Stored as VARCHAR(32) on `job_snapshots.last_status` to avoid future enum migrations.

### `result` object (on post_run)
```jsonc
"result": {
  "bytes_total":    12345678,    // total dataset size after run
  "bytes_new":       4567890,    // new bytes added this run
  "files_total":       12000,
  "files_new":           300,
  "snapshot_id":   "a1b2c3d4",   // restic short-id (rsync omits)
  "snapshot_count":         9    // restic-only: total snapshots in repo (post-prune)
}
```

### `repo_size_bytes` (on heartbeat, on demand)
- Server emits `reconcile_repo_stats: ["job-x", ...]` in heartbeat response when stats are stale
- CLI runs `restic stats` only for listed jobs, sends `repo_size_bytes` on next outgoing report
- Server overwrites `repo_size_observed` and resets `repo_size_estimated`
- Between reconciles: server adds `bytes_new` to running estimate
- UI shows "1.2 TB (verified 3 days ago)"

### Server-side error classifier
- `internal/classify` — regex rules over raw `last_error`
- Categories: network / auth / disk_full / permission / repo_corrupt / timeout / config / cancelled / other
- Stored on `job_snapshots.error_category`

---

## Anomaly Detection (v1.10.0)

Three security-relevant detectors compare each post_run against the previous job_snapshots state:

| Detector | Trigger | Catches |
|----------|---------|---------|
| `snapshot_drop` | `prev.snapshot_count − curr > threshold` | Repo tampering — `restic forget` attack |
| `files_drop` | `prev.files_total − curr ≥ N AND ≥ pct%` | Source wipe / ransomware / mass deletion |
| `bytes_drop` | `prev.bytes_total − curr ≥ N MB AND ≥ pct%` | Same |

### Tunable thresholds (per-server, in `/settings/tuning`)
Defaults: snapshot drop > 1, files drop ≥5% AND ≥10 files, bytes drop ≥10% AND ≥100 MB.

### Audit log
- `job_anomalies` table records each fire with prev/curr/delta/percentage + `snapshot_id` for forensics
- 24h dedup on insert: same `(node_id, job_id, anomaly_type)` won't re-fire while an unack'd row exists
- Visible via Security button on node detail → `/nodes/{id}/anomalies`
- Acknowledge button captures who+when reviewed

### Detection logic
- `internal/api/status.go` calls `detectAnomalies()` after every post_run upsert
- Reads `prev` via `db.GetJobSnapshotPrev` *before* the upsert, then compares
- Inserts via `db.InsertJobAnomaly` (which dedupes)

---

## Job History (v1.10.0)

- Per-job History button on node detail jobs row → inline expander
- Reads from `node_reports.payload_json`, parses each report, extracts the matching job state
- Deduplicated by `last_run_at` so 1 row per actual run (not per heartbeat re-report)
- Sortable columns (Reported / Last Run / Status / Dur. / Bytes New / Files / Error)
- Filters: Status, From, To (Flatpickr), Limit (10/25/50/100)
- Snapshot column hidden for rsync jobs
- Error column merges `error_category` badge + truncated `last_error` (full on hover)

---

## Permissions System (v1.8.0)

Firewall-style **rule engine** that determines what each non-superadmin user can see/do on each node.

### Tables

- `permission_rules (id, priority, enabled, effect, access, subject_type, subject_id, target_type, target_id, locked_by_superadmin, created_by, created_at)`
- `user_groups (id, name, client_group_id)` + `user_group_members (is_lead)` + `user_group_tags`
- User tags stored separately: `user_tag_catalog` + `user_tag_links` (migration 019)

### Rule shape

- **Priority** (int, default 1000) — higher wins (z-index semantics)
- **Enabled** (bool) — disabled rules skipped during evaluation
- **Effect**: `allow` | `deny`
- **Access**: `view` | `manage` (UI label: "Edit")
- **Subject**: `user` | `user_group` | `user_tag` + ID
- **Target**: `node` | `node_tag` + ID
- **Locked by superadmin**: if true, managers cannot modify or delete

### Evaluation (for user U needing access A on node N)

1. Superadmin → `manage` (bypass)
2. Client scope: if U's client ≠ N's client → `none`
3. Collect applicable rules (subject matches U, target matches N, enabled)
4. Walk rules in priority DESC order:
   - `allow` with access ≥ A → granted
   - `deny` with access ≤ A → denied
   - else skip
5. No decision → default deny
6. Cap by role: user/guest max = view

### Subject → User matching

A rule matches a user if:
- `subject_type=user` AND `subject_id=userID`
- `subject_type=user_group` AND user is a member
- `subject_type=user_tag` AND user has that tag directly OR via group inheritance

### Implementation

- `internal/db/queries.go`: `ListPermissionRules`, `CreatePermissionRule`, `UpdatePermissionRule`, `DeletePermissionRule`, `SetPermissionRuleEnabled`, `ListVisibleNodeIDsForUser` (eval engine)
- `internal/web/permissions.go`: page + AJAX endpoints (`POST /permissions/rule`, `/permissions/rule/{id}/toggle`, `/permissions/rule/{id}/delete`)
- `internal/web/user_groups.go`: `/user-groups` CRUD
- `internal/web/user_tags.go`: `/user-tags` CRUD
- `internal/web/middleware.go`: `EffectiveNodeAccess`, `EnforceNodeView`, `EnforceNodeManage`
- `templates/permissions.html`: editor + firewall-table UI with multi-select target picker

### Enforcement points

- **Dashboard**: non-superadmin sees only nodes in `ListVisibleNodeIDsForUser`
- **Node detail**: `EnforceNodeView` gates access; write buttons gated on `.NodeAccess == "manage"`
- **Edit/Delete/RegenPSK/ManageTags/Terminal**: `EnforceNodeManage`
- **Repo browse**: `EnforceBrowseRepo` (role) + `EnforceNodeView` (per-node)

---

## Client Ranks (v1.7.0)

Each client (previously "client group") has a rank: **bronze | silver | gold | diamond**.
Visible and editable by superadmin only. Shown as a colored badge on:
- Dashboard client cards (top-right of card title)
- Clients list page
- Client create/edit form (dropdown)

Colors are hardcoded in `ClientGroup.RankColor()`: bronze #cd7f32, silver #c0c0c0, gold #ffd700, diamond #b9f2ff.

---

## User Tags (v1.7.0)

Users can be tagged using the same `tags` table as nodes (reuses `user_tags` junction table
from migration 015). Superadmin only — set on user create/edit form, visible as badges on
the Users list.

Semantics: identity/affiliation ("David is from CUS"), not access control.

Queries: `GetUserTags`, `SetUserTags`, `GetAllUserTags` in `internal/db/queries.go`.

---

## Dashboard Features (v1.7.0)

### Stats cards (5 across top)
- Total nodes
- Online (last 10 min)
- With failures
- With warnings (new: counts nodes with at least one 'warning' job status)
- Never seen

### Client cards (3 per row)
Each card shows:
- Client name (2em) + rank badge (superadmin only)
- `X nodes · X jobs`
- `X success · X warn · X failed · X pending` (color-coded)
- SVG donut chart of success rate (only shown when TotalJobs > 0)
- Click card to filter nodes table by client

### Nodes table filters
Dropdown filters with removable badge labels: **Tag, Status, Online, Client**. All filters
stack (AND logic). Combine with free-text search.

### Job status values
- `success` — last run completed OK
- `warning` — completed with warnings (partial/recoverable issues)
- `failure` — last run failed
- `` (empty) — never run

Worst-status roll-up priority: failure > warning > success > never_run > empty.

---

## Color Picker UX (v1.7.0)

Every color picker in the app has a paired hex text input below/beside it, synced both ways:
- Pick a color → hex updates
- Type a valid `#RRGGBB` → picker updates

Applied on: tag edit, tags list (create), node detail modal, node new form.

---

## Build & Deploy

### Build

```bash
# Dev
go build ./cmd/server

# Production (with version)
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=v1.10.2" -o lss-backup-server ./cmd/server
```

Version is set via `-ldflags "-X main.Version=vX.Y.Z"` — defaults to `"dev"` if not set.

### Deploy to Test Server

```bash
# 1. Build
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=vX.Y.Z" -o /tmp/lss-backup-server ./cmd/server

# 2. Stop, copy, start (must stop first — can't overwrite running binary)
ssh root@10.0.0.123 'systemctl stop lss-backup-server'
scp /tmp/lss-backup-server root@10.0.0.123:/usr/local/bin/lss-backup-server
ssh root@10.0.0.123 'systemctl start lss-backup-server'
```

**Important:** The binary is `/usr/local/bin/lss-backup-server` (NOT `lss-backup-server`).

---

## Nginx WebSocket Configuration

`/etc/nginx/sites-enabled/lss-backup-server` has two location blocks:

```nginx
location /ws/ {
    proxy_pass         http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header   Upgrade           $http_upgrade;
    proxy_set_header   Connection        "Upgrade";
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    # ... standard proxy headers
}

location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_read_timeout 30s;
    proxy_send_timeout 30s;
    # ... standard proxy headers
}
```

The `/ws/` block is critical — without the Upgrade/Connection headers, WebSocket connections fail.

---

## HAProxy (OPNsense)

The lssbackup backend has these in the tuning pass-through:

```
option http-server-close
timeout tunnel 24h
```

Without these, HAProxy kills idle WebSocket connections after its default timeout.

---

## Things To Watch Out For

- **Binary filename:** systemd runs `lss-backup-server`, not `lss-backup-server`. Deploy to the right path.
- **nginx /ws/ block:** Without WebSocket header pass-through, ALL tunnel connections fail with "upgrade token not found in Connection header". This was the #1 issue during initial tunnel debugging.
- **ForceCommand:** Must be `/usr/bin/sleep infinity`, not `/bin/false`. False exits immediately, killing SSH sessions and their reverse port forwards.
- **HAProxy timeout tunnel:** Without this, HAProxy kills WebSocket connections after ~30 seconds of "idle" (no HTTP-level activity).
- **Authorized keys race:** On first-ever key registration, the CLI should wait for `tunnel_key_registered: true` in the heartbeat response before attempting the SSH tunnel.
- **Credentials:** The terminal never stores SSH passwords. They're sent once over WebSocket, used in-memory, and zeroed immediately.
- **cmd/server is in .gitignore** — use `git add -f cmd/server/main.go` when committing changes to it.

---

## Global Anomalies Page (v1.10.3 – v1.10.10)

`/anomalies` aggregates every anomaly across every node into one forensic table.

- Top nav link with shield-x icon; dashboard has a clickable "Anomalies" stat card (red when > 0).
- **Filter button group** (top-right): Show All / Acknowledged / Unacknowledged — backed by `?filter=all|ack|unack` (was a boolean `?unacked=1` pre-v1.10.3).
- **Sortable columns** (Detected / Client / Node / Job / What happened / Change / Status) — click header to toggle asc/desc; blue ▲/▼ on active column, faded ⇅ on inactive.
- **Per-column filter row** under the header — free-text for Detected/Job, dropdowns for Client, Node, What happened, Status (populated by Go template helpers `uniqueClients` / `uniqueNodes` in `middleware.go`).
- **Global search box** — matches across all visible data + human labels (e.g. "snapshots deleted", "acknowledged", numeric values, node UID). Registered in the haystack list in `anomalies_global.html`.
- All data is embedded in a `<script id="anom-data" type="application/json">` block; tbody is rendered client-side so sort/filter/search stay snappy without server round-trips.
- Columns:
  - **Detected** — date on line 1, time on line 2.
  - **Client** — link to `/groups/{id}/edit`.
  - **Node** — link to `/nodes/{id}`; shows `UID: lss-xxx` in muted below.
  - **Job** — link to `/nodes/{id}#job-<jobID>` using job name when available, else job ID; program below in muted.
  - **What happened** — colored badge (Snapshots deleted / Files removed / Data shrunk).
  - **Change** — `prev → curr` with unit (snapshots / files / bytes) and red delta+pct below.
  - **Status** — `Ack'd` (grey) or `Unreviewed` (red).
  - **Action** — Acknowledge (green) or Unacknowledge (outline-warning) POST form.

Server-side wiring:
- `db.ListEnrichedAnomalies(filter, limit)` joins `job_anomalies` with nodes + clients + `job_snapshots.job_name/job_program` for display labels.
- `HandleAnomalies` (web/anomalies.go) uses `filter` string instead of bool.
- `HandleAnomalyAck` handles both `/anomalies/{id}/ack` and `/anomalies/{id}/unack`.

### Anomaly dedup
`db.InsertJobAnomaly` skips inserting when an unacknowledged row with the same `(node_id, job_id, anomaly_type)` was inserted in the last 24 hours. Stops spam when the CLI re-reports post-wipe state via heartbeats.

### UPSERT "overwrite real zeros" fix (v1.10.2)
`UpsertJobSnapshotWithCategory` used to preserve old `bytes_total` / `files_total` / `snapshot_count` when CLI sent 0 (via `IF(VALUES > 0, VALUES, prev)`). That masked legitimate wipes — prev never advanced, and every re-report re-fired the same anomaly. Now: always overwrite. Pair it with the 24h dedup above.

---

## Audit System (v1.11.0–v1.11.11, paired with CLI v2.3.0–v2.3.2)

Unified `audit_log` table records both server-originated user actions AND node-originated events. Same UI for both, same forensics path.

### Schema (migration 031)
`audit_log (id, ts, source ENUM('server','node'), source_node_id, source_seq, user_id, username, ip, category, severity ENUM('info','warn','critical'), actor, action, entity_type, entity_id, message, details_json)`. UNIQUE on `(source_node_id, source_seq)` for dedup. Indexed on ts, source, category. Ack pointer per node lives on `nodes.audit_ack_seq`. Retention via `server_tuning.audit_retention_days` (0 = forever, default 0).

### Server-side hook points (33 in v1.11.3)
Every mutating handler calls `s.auditServer(r, category, severity, action, entityType, entityID, message, details)` after the successful DB mutation:
auth (login/logout/2fa/setup), users/nodes/groups/tags/user-tags/job-tags/user-groups/permissions CRUD, PSK regen, node-tag edits, tuning save, settings password + SMTP save/test, silences, anomaly ack/unack/bulk, terminal open/close/replay, repo downloads. Helper is `internal/web/audit.go`.

### Node-side ingest (CLI v2.3.0+ → /api/v1/status payload_version=3)
`NodeStatus.AuditEvents []AuditEvent` arrives encrypted in the heartbeat. Each event: `{seq, ts, category, severity, actor, message, details}`. Server inserts via `db.InsertNodeAuditEvents(nodeID, prevAck, events)` with INSERT IGNORE on the UNIQUE constraint. Response carries `audit_ack_seq = highest contiguous seq stored`. CLI trims its local `audit.jsonl` to events past that ack.

### Two-layer self-healing (v1.11.11)
1. **Contiguous reconcile** — after every batch insert, `computeContiguousAck` walks `source_seq` ASC starting at `prevAck+1`, advances through whatever contiguous run exists in the DB. Handles in-order delivery + CLI-side reships from migrations + arbitrary ordering uniformly.
2. **Stale-gap sweeper** — if reconcile didn't move the pointer but events past prevAck exist AND `MIN(detected_at) > 1 hour old`, the gap is presumed permanently lost (event dropped client-side). Server logs WARN and advances past the gap, then re-runs reconcile. Trade-off: lose forensic continuity on that gap, but a frozen pipeline forever is worse.

### Pages
- `/audit` (manager+) — sort/filter/multi-select/global-search/paginate, same UX as `/anomalies`. All-sources/Server/Nodes toggle.
- `/nodes/{id}/audit` (node-view) — per-node scope.
- Details column shows `<code>key=value</code>` pills, EXCEPT `terminal_opened` / `terminal_closed` rows where it shows just the **▶ Replay** button (see Terminal Recording).

---

## Terminal Session Recording (v1.11.4, asciinema v2)

Every dashboard SSH session via `/ws/terminal` is teed into a `.cast` file when `server_tuning.terminal_recording_enabled = true` (default ON). Migration 032 added the toggle + `terminal_recording_retention_days` (default 30).

### How
- `internal/recorder/recorder.go` writes asciinema v2 format: header line + `[delta_seconds, "o"|"i"|"r", data]` frames per event.
- Storage: `cfg.Terminal.SessionsDir` (default `/var/lib/lss-backup-server/sessions/`), one `.cast` per session named `<unix_nano>-<username>-<node_id>.cast`.
- The websocket pump in `terminal.go` calls `rec.WriteOutput(b)` on SSH→browser bytes, `rec.WriteInput(b)` on browser→SSH, and `rec.Resize(cols, rows)` on resize messages. Recorder is `nil` when disabled — calls are zero-cost no-ops.
- Audit row `terminal_opened` carries `session_id` + `session_file` in details. Replay button on the audit page links to `/audit/session/{filename}`.
- `/audit/session/{filename}` (superadmin only) renders an in-browser asciinema-player viewer (CDN). `/audit/session/{filename}.raw` serves the raw `.cast` for download. Loading the replay page itself emits a `session_replay` audit row (severity warn).
- Red banner on the terminal page when recording is enabled — "anything typed or printed is captured".
- Retention: `worker.RetentionWorker` runs `recorder.PruneOlderThan(dir, days)` hourly.

---

## Global Anomalies Page (v1.10.3 – v1.10.15)

`/anomalies` aggregates every anomaly across every node into one forensic table.

- Top nav link with shield-x icon; dashboard has a clickable "Anomalies" stat card (red when > 0).
- **Filter button group** (top-right): Show All / Acknowledged / Unacknowledged — backed by `?filter=all|ack|unack`. On `/anomalies/archive` the Unacknowledged option is hidden (archive is acked-only).
- **Filter dropdown + multi-select** (v1.10.14): pick a field (Client/Node/Job/What happened) → searchable multi-select of values → Apply / Reset. Active filters render as removable pills below the bar.
- **Sortable columns**, **global search** across all fields + human labels + numeric values.
- **Bulk select**: master checkbox (selects current page only), bulk ACK/UNACK buttons in card header. ≥2 selected prompts confirm().
- Per-row **ACK / UNACK** button (short labels, full text in tooltip).
- "Ack'd" badge tooltip shows `Acknowledged by <user> at <timestamp>`.
- All in-place via fetch (no full reload). Dashboard shield + per-node shield refresh via `/nodes/{id}/anomaly-counts`.
- Footer: pagination + "Showing X–Y of Z" + Rows-per-page selector (default 25).
- **Archive** (`/anomalies/archive`) shows ONLY ack'd rows past the retention window (`server_tuning.anomaly_ack_retention_days`, default 30, settable in /settings/tuning under "Anomaly Tuning").

### Anomaly dedup
`db.InsertJobAnomaly` skips inserting when an unacknowledged row with the same `(node_id, job_id, anomaly_type)` was inserted in the last 24 hours. Stops spam when the CLI re-reports post-wipe state via heartbeats.

### UPSERT "overwrite real zeros" fix (v1.10.2)
`UpsertJobSnapshotWithCategory` used to preserve old `bytes_total` / `files_total` / `snapshot_count` when CLI sent 0 (via `IF(VALUES > 0, VALUES, prev)`). That masked legitimate wipes — prev never advanced, and every re-report re-fired the same anomaly. Now: always overwrite. Pair it with the 24h dedup above.

---

## Backup & Restore (v1.13.1)

`/settings/backup` (superadmin only):
- **Download Backup Now** — streams a zip: `dump.sql` (full mysqldump), `secret.key`, `config.toml`, `metadata.json`, all `.cast` session recordings.
- **Restore** — upload zip, reimport SQL, restore secret key + recordings, wipe sessions, force superadmin password + 2FA reset. Audited as `system_restored/critical`.

---

## HMAC Chain for Audit (v1.14.0–v1.14.4, paired with CLI v2.5.0)

Per-event `hmac = HMAC-SHA256(psk, prev_hmac_hex_string || canonical_json(event_minus_hmac))`. RFC 8785 JCS canonical JSON. Chain-break → CRITICAL audit row + ack frozen. TOFU on first event, prev as raw hex string bytes. Reset via `POST /nodes/{id}/reset-audit-chain` (superadmin).

---

## "What Was Deleted" Forensics (v1.14.5)

`files_drop`/`bytes_drop` anomaly rows with snapshot IDs show **"Show deleted"** button. Prompts for SSH creds, runs `lss-backup-cli repo-diff --json` over the tunnel, renders removed/added/changed files inline.

---

## Disaster Recovery (v1.15.0, paired with CLI v2.7.1)

Server-controlled node config backup to S3 via restic. Every node's CLI configuration is automatically backed up at a configurable interval.

### Architecture
- **One S3 repo per deployment**, bucket per client. Nodes get folders: `s3://{bucket}/{node-uid}/`.
- **Per-client restic password** (not per-node). Stored encrypted at rest in `dr_config` table using AppKey.
- **Server pushes config** via heartbeat response (`dr_config` object with S3 creds + restic password + interval + force_run). CLI caches encrypted locally, runs restic backup on schedule.
- **CLI reports status** via heartbeat payload (`dr_status` object). Server updates per-node DR columns.

### Settings page
`/settings/node-disaster-recovery` (superadmin) — S3 endpoint, bucket, region, access key, secret key, restic password, default interval (hours). Secrets encrypted before DB storage.

### Shield states (on node detail + node list)
- **Grey** `ti-shield-off` — DR not enabled. Click to enable (requires global S3 config first).
- **Green** `ti-shield-check` — last backup within interval AND status=success.
- **Red** `ti-shield-x` — enabled but failed / overdue / never ran.

### Actions (superadmin)
- **Enable DR** — `POST /nodes/{id}/dr/enable`
- **Disable DR** — `POST /nodes/{id}/dr/disable`
- **Run Now** — `POST /nodes/{id}/dr/run-now` (sets `force_run=true` in next heartbeat response)

### Wire format (additive, no payload_version bump)
- Response: `dr_config {version, enabled, s3_*, restic_password, node_folder, interval_hours, force_run}`
- Payload: `dr_status {configured, config_version, last_backup_at, status, error, snapshot_count}`

---

## Remote CLI Update (v1.16.0–v1.19.2)

Dashboard "Version" column shows each node's CLI version. Auto-update sends `update_cli: true` + `update_cli_url` (direct GitHub release binary URL) on every heartbeat when a node is behind the latest version. Manual "Update" button triggers immediate update via SSH. Version checker polls GitHub tags every N minutes (configurable in Server Tuning).

---

## One-Command Node Deployment (v1.18.0)

`/nodes/new` → "Server-Assisted Install" card generates a one-liner with embedded credentials. Operator pastes on target machine → CLI auto-installs, configures, starts daemon → node appears on dashboard.

- Token: one-time use, 24h expiry, SHA-256 hash stored in `node_install_tokens` table
- Endpoint: `GET /api/v1/install/{token}` (unauthenticated — token IS the auth)
- Script embeds `LSS_SERVER_URL`, `LSS_NODE_UID`, `LSS_PSK_KEY` as env vars
- Pending nodes visible at `/settings/pending-nodes`, hidden from dashboard until first heartbeat

---

## Graceful Node Deletion (v1.20.0)

Multi-step deletion flow with secret export:
1. "Delete Node" → `export_pending` → CLI sends `secrets_export` (job creds, DR creds, SSH creds)
2. Server stores encrypted, generates human-readable `.txt` credential report
3. Operator downloads report, confirms "I have saved credentials", chooses retain/destroy data
4. `uninstall_pending` → CLI stops daemon, removes binary/config, optionally destroys backup data

---

## One-Command Node Recovery (v1.21.0)

"Recover" button on node detail generates a one-liner that reinstalls CLI on a replacement machine, restores job configs + secrets from DR backup, resumes operations with the original UID + PSK.

- Endpoint: `GET /api/v1/recover/{token}` — reuses install token table
- Script adds `LSS_RECOVERY_MODE=true` → CLI runs `--setup-recover` instead of `--setup-auto`
- Recovery flow: install binary → heartbeat → get DR config → restic restore → selective copy (jobs + secrets) → new SSH creds → start daemon

---

## Server Auto-Backup (v1.26.0)

Background worker backs up the server itself to S3 via restic every 24h (configurable). Includes mysqldump, secret.key, config.toml, and .cast session recordings. Stored at `s3://{bucket}/lss-backup-server/`.

Separate restic passwords and retention settings for server vs node backups. DR settings page split into 3 cards: Global S3, Server Backup, Node Backup.

### Restore from Snapshot
"Restore From Snapshot" button on DR settings page lists all server snapshots from S3. Selecting one restores the database, encryption key, and recordings. Sessions wiped, 2FA cleared, superadmin forced to re-setup. Audit entry injected post-restore.

---

## Server Self-Update (v1.26.5)

One-click "Update Server Now" on Software Updates page. Downloads latest release binary from GitHub, stages to `/var/lib/lss-backup-server/update-staging`, calls sudo helper script which uses `systemd-run` to create a transient unit (survives service restart under ProtectSystem).

Requires:
- `/usr/local/bin/lss-apply-update.sh` (helper script)
- `/etc/sudoers.d/lss-update` (NOPASSWD rule for the helper)
- `NoNewPrivileges=false` in systemd unit

Auto-reload: after clicking update, page polls every 2s and reloads when server comes back.

---

## Node DR Restore (v1.26.6, paired with CLI v2.12.0)

"Restore from Snapshot" in node Actions dropdown. Lists node's DR snapshots from S3 (server-side, no SSH needed for listing). SSH credentials required for the actual restore — runs `lss-backup-cli --dr-restore --snapshot {id}` via tunnel with `nohup` so it survives the tunnel drop when the daemon restarts.

---

## Release Notes Display (v1.27.1)

Version checker uses GitHub releases API (not tags) for both CLI and server. Release notes stored in `server_tuning` and displayed on Software Updates page when update is available.

---

## Roadmap

Most features shipped. Remaining:

1. Run `install.sh` on a fresh Ubuntu 24.04 VM (code-reviewed, never executed).
2. Fix host audit journalctl worker — SSH unit name varies by Ubuntu version.
3. **(LAST EVER)** Notification stack — SMTP, webhook, escalation.

---

_Last updated: 2026-04-18 (v1.29.3)_
