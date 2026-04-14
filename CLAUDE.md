# CLAUDE.md — LSS Backup Management Server Project Notebook

This file is my working notebook for this project. It captures what's built, how it works,
why decisions were made, and what's next. Keep it up to date as the project evolves.

---

## What This Project Is

A web-based management server for LSS Backup CLI nodes. It receives encrypted heartbeats
and post-run reports from CLI nodes, provides a dashboard for operators, and enables remote
terminal access to nodes through reverse SSH tunnels over WebSocket.

**Version:** v1.10.10
**Module:** `github.com/lssolutions-ie/lss-management-server`
**Go version:** 1.25.0

---

## Architecture

### Directory Layout

```
├── cmd/server/main.go              Entry point, HTTP mux, version var
├── internal/
│   ├── api/status.go               Node heartbeat/report endpoint (POST /api/v1/status)
│   ├── config/config.go            TOML config loader
│   ├── crypto/                     AES-256-GCM decrypt, PSK encrypt/decrypt
│   ├── db/
│   │   ├── db.go                   MySQL connection, migrations
│   │   └── queries.go              All DB queries, tunnel authorized_keys writer
│   ├── models/models.go            Node, User, Session, JobSnapshot, NodeStatus structs
│   ├── notify/                     Notifier interface (NoOp for now)
│   ├── web/
│   │   ├── auth.go                 Login/logout/setup handlers
│   │   ├── dashboard.go            Main dashboard page
│   │   ├── middleware.go           Session auth, RBAC, template rendering
│   │   ├── nodes.go                Node CRUD, PSK regeneration
│   │   ├── groups.go               Client group CRUD
│   │   ├── users.go                User CRUD
│   │   ├── settings.go             Password change
│   │   ├── terminal.go             Dashboard terminal (WebSocket → SSH proxy)
│   │   └── ssh_tunnel.go           Node reverse tunnel endpoint (WebSocket → sshd)
│   └── worker/worker.go            Background offline-node checker
├── migrations/                     SQL migration files (001-029)
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
| `POST /api/v1/status` | PSK/AES-256-GCM encrypted payload | Node heartbeat and post-run reports |
| `GET /ws/ssh-tunnel` | HMAC-SHA256 in HTTP headers | Node reverse tunnel (WebSocket → sshd) |
| `GET /ws/terminal` | Dashboard session cookie | Operator terminal (WebSocket → SSH) |
| `GET /nodes/{id}/terminal` | Dashboard session cookie | Terminal page with credential form |

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
- Written atomically to `/var/lib/lss-management/tunnel_authorized_keys` (tempfile + rename)
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

## Logging

All log lines use the `lss-mgmt:` prefix. Key log points:

| Area | What's logged |
|------|--------------|
| **Startup** | `starting server version=X listen=X tunnel_authkeys=X` |
| **Heartbeat** | `api: <type> from node=N uid=X jobs=N` |
| **Tunnel open** | `ssh-tunnel: open node=N uid=X peer=X` |
| **Tunnel close** | `ssh-tunnel: closed node=N uid=X` |
| **Tunnel auth fail** | `ssh-tunnel: hmac mismatch node=N uid=X` |
| **Tunnel key change** | `api: tunnel key changed for node=N; authorized_keys regenerated` |
| **Terminal open** | `terminal: user=X opening ssh via-tunnel=X@X:N` |
| **Terminal close** | `terminal: user=X closed ssh via-tunnel=X@X:N duration=Xs` |
| **Login success** | `auth: login ok user="X" role=X ip=X` |
| **Login failure** | `auth: login failed user="X" ip=X` |
| **Node offline** | `worker: node "X" (uid=X) is offline, last seen: X` |

---

## Database

MySQL with 18 migrations:

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
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=v1.10.2" -o lss-management-server ./cmd/server
```

Version is set via `-ldflags "-X main.Version=vX.Y.Z"` — defaults to `"dev"` if not set.

### Deploy to Test Server

```bash
# 1. Build
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=vX.Y.Z" -o /tmp/lss-management ./cmd/server

# 2. Stop, copy, start (must stop first — can't overwrite running binary)
ssh root@10.0.0.123 'systemctl stop lss-management'
scp /tmp/lss-management root@10.0.0.123:/usr/local/bin/lss-management-server
ssh root@10.0.0.123 'systemctl start lss-management'
```

**Important:** The binary is `/usr/local/bin/lss-management-server` (NOT `lss-management`).

---

## Nginx WebSocket Configuration

`/etc/nginx/sites-enabled/lss-management` has two location blocks:

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

- **Binary filename:** systemd runs `lss-management-server`, not `lss-management`. Deploy to the right path.
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

## Roadmap

Live list: `ROADMAP.md` at repo root. Top of backlog:

1. **SMTP notifier wiring** (critical) — anomalies sit silently today.
2. **"What was deleted" forensics** (high) — run `restic diff prev curr` over the repo-viewer tunnel, lazy-load deleted-file list in an expander on each anomaly row. Biggest client-satisfaction win. Discussed 2026-04-14.
3. **Snapshot ID set tracking** (high) — count-only comparisons miss `restic forget` of one snapshot within retention; also feeds item 2 for snapshot-drop events.
4. Anomalies UI workflow: mute-future-fires on ack, bulk acknowledge, resolution note field, auto-archive acked rows older than N days.

---

_Last updated: 2026-04-14 (v1.10.10)_
