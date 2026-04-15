# Roadmap

Items committed for future work but not blocking today's release. Ordered by priority.

---

## Security & Anomaly Detection (post v1.10.x)

The current 3-detector engine catches obvious attacks (full repo wipes, ransomware, mass deletions). To make it production-grade against sophisticated threats, the following are queued:

### Deferred — do LAST (user decision 2026-04-15)

- **All notification work is deferred to the very end of the project.** This includes SMTP wiring to anomalies/failures, webhook notifier (Slack/PagerDuty/JSON POST), and mandatory-ack-escalation. Do not start on any of these until everything else on this roadmap is done. The UI + detection + forensics stack must be complete first.

### High

- **"What was deleted" forensics on anomalies.** Clients will always ask "which files/snapshots did they take?" Two tracks:
  - *Files-drop / bytes-drop:* when the snapshots involved still exist, run `restic diff <prev_snapshot> <curr_snapshot>` (piggyback on the existing repo-viewer tunnel plumbing) to list exact removed paths. Store `prev_snapshot_id` + `curr_snapshot_id` on the anomaly row; render a lazy-loaded "Show deleted files" expander. ~2-3 hrs. Highest client-satisfaction win.
  - *Snapshot-drop:* requires the Snapshot ID set tracking below — tells you *which* snapshots disappeared (by ID + date), but the file contents are gone with them unless we separately cached a manifest.
  - *Rsync:* no cheap diff — CLI would have to maintain its own file manifest. Backlog.
- **Snapshot ID set tracking** — currently we only count snapshots, so an attacker who deletes one snapshot within a `keep-last N` retention window goes invisible (next backup creates one, count stays at N). Need to track which snapshot IDs exist over time and flag specific disappearances. Also feeds the forensics feature above.
- **Restic `--append-only` mode recommendation** in install docs — server-side detection is best paired with append-only repos so a compromised host can't delete its own backups.

### Medium

- **Append-only / off-server anomaly log** (syslog, file mirror, or external write-once store) so a compromised management server can't `DELETE FROM job_anomalies` to erase forensics.
- **Cross-node correlation** — surface "5 anomalies across 3 nodes in 10 min" as a meta-alert (campaign view).
- **Slow-drift detection** — current per-run delta thresholds miss attackers who delete a few files daily forever, never crossing the threshold. Need rolling-window absolute-count tracking.

### Anomalies UI workflow

- ✅ **Bulk acknowledge** — shipped v1.10.13.
- ✅ **Auto-archive acked rows older than N days** — shipped v1.10.14 (`anomaly_ack_retention_days`, /anomalies/archive page).
- **"Mute future fires" option when acknowledging** — checkbox in the ack flow that also creates a silence on the related (node, job) for a chosen duration so you're not re-alerted while investigating.
- **Resolution note field** — text input on the Acknowledge action; stored alongside `acknowledged_by` / `acknowledged_at`. Renders as a tooltip / detail row. Useful for forensics ("acked because dataset rotation, not an attack").

### Audit + observability (mostly shipped)

- ✅ **Server audit log** — unified `audit_log` table, /audit page, 33 hook points (v1.11.0–v1.11.3).
- ✅ **Node audit** — CLI v2.3.0 ships `audit_events[]` on heartbeat v3, server ingests with self-healing ack.
- ✅ **Terminal session recording** — asciinema v2 .cast files, in-browser replay, retention knob (v1.11.4).
- ✅ **Structured JSON logging via slog** — request IDs, access log, s.Fail() helper (v1.11.6, v1.11.9).
- **Host audit** — small worker polls journalctl for sshd / sudo / lss-management.service, parses, inserts into `audit_log` with `source='host'` (new enum value, migration 033). ~150 LOC + tiny migration.
- **Off-server audit mirror** — once host audit lands, add a syslog emitter so `audit_log` rows also flow to syslog `LOG_AUTH`. One-line per emit site. Defends against compromised server `DELETE FROM audit_log`.

### Low

- **Per-job auto-baseline / FP reduction** — learn typical churn per job to tune sensitivity automatically.
- **Silence policy controls** — max silence duration, audit log of who muted what (stop fatigued admins from over-silencing).
- **First-run baseline gap** — attacker who hits a brand-new node before any backup ever ran has no `prev` to compare against. Need a "first observation" floor or admin-set initial baseline.
- **Pointer types in `JobResult`** — currently CLI omitempty + Go zero-value collide on real-zero wipes. Use `*uint64` so server can distinguish "absent" from "true zero". Server has workarounds today; pointer fix is the proper protocol.
- **Server-side `bytes_total` / `files_total` delta visualization in Job History** — currently only `bytes_new` shown as additions; would be nice to see the running total trend graph.

---

## Other backlog (from earlier work)

- **Test 7 — permission_denied attack scenario**: requires non-root daemon path on macOS/Windows.
- **Test 9 — `warning` status emission**: CLI doesn't emit it yet (only success/failure). Code change needed CLI side before the protocol value is meaningful.
- **Repo viewer auto-navigate** to source path: currently disabled because of CLI `--path` filtering edge cases at deep paths.
- **Per-job override UI for `repo_stats_interval`**: tucked under "advanced" on the job edit page.
- **Production deployment** on a fresh server via `install.sh`.
