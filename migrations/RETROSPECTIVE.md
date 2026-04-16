# Migration Retrospective

One-line "why this exists" for every migration. Captures decision context that's otherwise scattered across commit messages and CLAUDE.md sections — useful when something later breaks and you need to remember whether a column was load-bearing or vestigial.

Pair this file with `README.md` (convention) and `CLAUDE.md` § Database (the table view).

## v0.x — base schema and core entities

| # | File | Why |
|---|------|-----|
| 001 | `001_initial.sql` | Bootstraps everything: nodes, users, sessions, client_groups, schema_migrations tracking. |
| 002 | `002_sessions.sql` | Refines the sessions table after first auth pass — adds expiration handling. |
| 003 | `003_viewer_role.sql` | Original RBAC: introduces the read-only viewer role distinct from full users. Later renamed/restructured by 017. |
| 004 | `004_report_type.sql` | Lets `node_reports` distinguish heartbeat from post_run. Required for retention to age out cheap heartbeats faster than expensive post-run snapshots. |
| 005 | `005_job_config.sql` | First version of per-job config storage (`job_snapshots.config_json`). Schemas were unstable so we went JSON-blob rather than relational. Still serves us well. |
| 006 | `006_node_tunnel.sql` | Adds `tunnel_port`, `tunnel_connected`, `tunnel_public_key` to nodes — the bare minimum to support the reverse SSH tunnel feature. |
| 007 | `007_node_hardware.sql` | OS, arch, CPUs, RAM, storage, IPs reported in heartbeat hardware block. Powers the node-detail "Hardware" card. |
| 008 | `008_ssh_host_keys.sql` | TOFU host-key verification for the dashboard terminal. First time a node is contacted via SSH the key is recorded; subsequent connections fail loudly on mismatch. |

## v1.5–1.7 — auth, RBAC, and tagging

| # | File | Why |
|---|------|-----|
| 009 | `009_totp.sql` | Adds 2FA columns to users (`totp_secret`, `totp_enabled`). |
| 010 | `010_force_setup.sql` | `force_setup` flag forces newly-created users to set their own password before their first session is honored. |
| 011 | `011_session_idle.sql` | `last_active_at` so middleware can enforce a 30-minute idle timeout on top of the existing absolute 2-hour cap. |
| 012 | `012_user_email.sql` | Email column for the eventual SMTP notifier (deferred forever, but the column is harmless). |
| 013 | `013_smtp_config.sql` | Single-row `smtp_config` table for server-wide outbound mail settings. Configurable today; not actually wired to anomaly/failure notifications yet — that work is the LAST item on the roadmap. |
| 014 | `014_tags.sql` | Generic `tags` table + `node_tags` junction. Used for cross-cutting node organization that doesn't fit the client_group hierarchy. |
| 015 | `015_user_tags.sql` | First attempt at user tagging — re-used the `tags` table via a new junction. Superseded by 019. |
| 016 | `016_tag_text_color.sql` | Adds `text_color` to tags so high-contrast pairings (yellow tag with white text) became fixable. |
| 017 | `017_roles_update.sql` | Role overhaul: `user→manager`, `viewer→user`, added `manager` and `guest` as distinct roles. Schema rename only — the rebalance was done in app code. |
| 018 | `018_client_rank.sql` | `client_groups.rank` ENUM (bronze/silver/gold/diamond). Visual-only — no permission impact, just dashboard signaling. |
| 019 | `019_split_user_tags.sql` | Reversal of 015's design choice. Splits user tags from node tags into `user_tag_catalog` + `user_tag_links`, drops the old `user_tags` junction. The shared-table approach made the permissions UI confusing. |

## v1.8 — permissions rule engine

| # | File | Why |
|---|------|-----|
| 020 | `020_permissions.sql` | Scaffolding tables for the new permission engine: `tag_permissions`, `user_groups`, `user_group_members`, `user_group_tags`, `user_node_overrides`. Initially designed as multiple narrow tables. |
| 021 | `021_permission_rules.sql` | Unified those tables into a single `permission_rules` table with priority/effect/access/polymorphic subject+target. Migrates the existing rows out of `tag_permissions`/`user_node_overrides`, then drops them. The single-table design is what the firewall-style UI maps to. |
| 022 | `022_subject_nodetag.sql` | Allowed `node_tag` as a subject type. Removed from the UI later but the enum value stayed because dropping it would break old rules. |
| 023 | `023_rule_enabled.sql` | `enabled` flag on permission_rules — lets ops disable a rule without deleting it (reversible debugging). |

## v1.9–v1.10 — job reporting + anomaly detection

| # | File | Why |
|---|------|-----|
| 024 | `024_job_status_ext.sql` | Widens `last_status` from ENUM to VARCHAR(32), adds bytes/files/snapshot_id/repo_size columns, and a per-job `repo_stats_interval_seconds` override. The VARCHAR is intentional — saves a future ALTER every time CLI invents a new status. |
| 025 | `025_server_tuning.sql` | Single-row `server_tuning` table — central knobs for retention windows, offline thresholds, repo-stats cadence, default silence duration. Better than scattering env vars or hardcoded constants. |
| 026 | `026_job_daily_stats.sql` | Aggregation table for the retention worker. Old raw `node_reports` get rolled into one row per (job, day) with min/max/count/avg. Keeps long-term forensic value at a fraction of the storage. |
| 027 | `027_job_silences.sql` | Timed mute per (node, job). Scheduled-maintenance windows wouldn't drown out real alerts otherwise. Reused by the v1.11.x mute-on-ack flow. |
| 028 | `028_job_tags.sql` | `job_tag_catalog` + `job_tag_links` for priority labels on jobs (e.g. "P0", "production"). Job-level tagging is independent of node-level tagging. |
| 029 | `029_anomaly_detection.sql` | The big one for the security stack: `snapshot_count` on job_snapshots (CLI v2.2.6+ ships this), `job_anomalies` audit table, and 5 threshold columns on `server_tuning`. Introduces the three detectors: snapshot_drop, files_drop, bytes_drop. |

## v1.10.x – v1.11.x — security workflow

| # | File | Why |
|---|------|-----|
| 030 | `030_anomaly_archive.sql` | `anomaly_ack_retention_days` (default 30) splits live `/anomalies` from `/anomalies/archive`. Acked rows past the retention move to the archive page so the live view stays focused on what's unreviewed. |
| 031 | `031_audit_log.sql` | Unified `audit_log` table — server-side user actions and node-side ingested events under one roof. `UNIQUE(source_node_id, source_seq)` is the dedup key for the heartbeat-piggybacked audit ingest. `nodes.audit_ack_seq` tracks the per-node ack pointer. `audit_retention_days` knob added (default 0 = forever). Paired with CLI v2.3.0 protocol v3. |
| 032 | `032_terminal_recording.sql` | Toggle (`terminal_recording_enabled`, default ON) and retention (`terminal_recording_retention_days`, default 30) for asciinema v2 session recording. The actual `.cast` files live on disk under `cfg.Terminal.SessionsDir`, not in the database. |
| 033 | `033_silent_node_alarm.sql` | `silent_alert_threshold_minutes` (default 7). Aggressive companion to the existing 10-minute offline check — fires within 1-2 missed heartbeats so an attacker who stops the daemon doesn't get a clean window. |
| 034 | `034_anomaly_resolution_note.sql` | `resolution_note` on `job_anomalies`. Captured at ack time, surfaced as a tooltip on the Ack'd badge — closes the "why was this acked?" forensics question. Free text up to 500 chars. |
| 035 | `035_host_audit.sql` | Extends `audit_log.source` ENUM with `'host'` and adds `host_audit_state` for the journalctl cursor. Powers the host-audit worker that captures sshd logins, sudo invocations, and lss-management.service lifecycle into the unified audit feed. |

## v1.15.x — disaster recovery

| # | File | Why |
|---|------|-----|
| 038 | `038_disaster_recovery.sql` | Server-controlled node config backup to S3. `dr_config` single-row table holds S3 endpoint, bucket, region, access key, secret key, restic password (secrets encrypted with AppKey) + default interval + config version. 8 new columns on `nodes` for per-node DR state (enabled, interval, last_backup_at, last_status, last_error, snapshot_count, force_run, config_version). Server pushes credentials to CLI via heartbeat response; CLI backs up, reports status via heartbeat payload. |

## Maintaining this file

- Add a row when you write a new `NNN_x.sql` migration. Keep it to one line.
- If a migration is later effectively undone or superseded, leave the original row and add a note in the related rows. Don't delete history here.
- The `.down.sql` neighbor is mandatory for new migrations (see `README.md`).
