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
- ✅ **Mute future fires on ack** — shipped v1.12.0 (modal with duration picker, creates job_silences row).
- ✅ **Resolution note field** — shipped v1.12.0 (migration 034, tooltip on Ack'd badge).

### Audit + observability (mostly shipped)

- ✅ **Server audit log** — unified `audit_log` table, /audit page, 33 hook points (v1.11.0–v1.11.3).
- ✅ **Node audit** — CLI v2.3.0 ships `audit_events[]` on heartbeat v3, server ingests with self-healing ack.
- ✅ **Terminal session recording** — asciinema v2 .cast files, in-browser replay, retention knob (v1.11.4).
- ✅ **Structured JSON logging via slog** — request IDs, access log, s.Fail() helper (v1.11.6, v1.11.9).
- ✅ **Host audit** — shipped v1.12.0 (migration 035, journalctl polling for sshd/sudo/lss-backup.service). Known issue: SSH unit name varies by Ubuntu version, causing "exit status 1" spam on some installs.
- **Off-server audit mirror** — syslog emitter so `audit_log` rows also flow to syslog. Low priority now that HMAC chain provides tamper evidence.

### Shipped since original roadmap

- ✅ **HMAC chain for audit** — shipped v1.14.0–v1.14.4 + CLI v2.5.0. Tamper evidence on every audit event. See `docs/HMAC_CHAIN_SPEC.md`.
- ✅ **"What was deleted" forensics** — shipped v1.14.5. `restic diff` over SSH tunnel, renders inline on anomaly rows.
- ✅ **Snapshot ID set tracking** — shipped v1.13.0 (migration 036). Server diffs prev vs curr set, fires specific disappeared IDs.
- ✅ **Backup & Restore** — shipped v1.13.1. Full server backup/restore from `/settings/backup`.
- ✅ **Disaster Recovery** — shipped v1.15.0 + CLI v2.7.1. Server-controlled node config backup to S3 via restic. Three-state shield (grey/green/red), per-client encryption, "Run Now" button.
- ✅ **Tunnel rate-limiting** — shipped v1.12.0. Per-UID exponential backoff.
- ✅ **Silent-node alarm** — shipped v1.12.0 (migration 033). Fires within 7min of missed heartbeat.
- ✅ **GitHub Actions CI** — shipped v1.12.0. Build + vet + test on push.
- ✅ **Structured JSON logging** — shipped v1.11.6–v1.11.9. slog with request IDs, access log, s.Fail().

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
