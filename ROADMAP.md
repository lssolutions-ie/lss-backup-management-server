# Roadmap

Items committed for future work but not blocking today's release. Ordered by priority.

---

## Security & Anomaly Detection (post v1.10.x)

The current 3-detector engine catches obvious attacks (full repo wipes, ransomware, mass deletions). To make it production-grade against sophisticated threats, the following are queued:

### Critical

- **SMTP notifier wired to anomalies + failures.** Right now anomalies sit silently in the UI — an attack at 03:00 emails nobody. SMTP is configured but the notifier is still NoOp. Highest-impact remaining work.

### High

- **"What was deleted" forensics on anomalies.** Clients will always ask "which files/snapshots did they take?" Two tracks:
  - *Files-drop / bytes-drop:* when the snapshots involved still exist, run `restic diff <prev_snapshot> <curr_snapshot>` (piggyback on the existing repo-viewer tunnel plumbing) to list exact removed paths. Store `prev_snapshot_id` + `curr_snapshot_id` on the anomaly row; render a lazy-loaded "Show deleted files" expander. ~2-3 hrs. Highest client-satisfaction win.
  - *Snapshot-drop:* requires the Snapshot ID set tracking below — tells you *which* snapshots disappeared (by ID + date), but the file contents are gone with them unless we separately cached a manifest.
  - *Rsync:* no cheap diff — CLI would have to maintain its own file manifest. Backlog.
- **Snapshot ID set tracking** — currently we only count snapshots, so an attacker who deletes one snapshot within a `keep-last N` retention window goes invisible (next backup creates one, count stays at N). Need to track which snapshot IDs exist over time and flag specific disappearances. Also feeds the forensics feature above.
- **Restic `--append-only` mode recommendation** in install docs — server-side detection is best paired with append-only repos so a compromised host can't delete its own backups.

### Medium

- **Append-only / off-server anomaly log** (syslog, file mirror, or external write-once store) so a compromised management server can't `DELETE FROM job_anomalies` to erase forensics.
- **Webhook notifier** alongside SMTP — Slack, PagerDuty, generic JSON POST.
- **Cross-node correlation** — surface "5 anomalies across 3 nodes in 10 min" as a meta-alert (campaign view).
- **Slow-drift detection** — current per-run delta thresholds miss attackers who delete a few files daily forever, never crossing the threshold. Need rolling-window absolute-count tracking.

### Anomalies UI workflow (tomorrow)

- **"Mute future fires" option when acknowledging** — checkbox in the ack flow that also creates a silence on the related (node, job) for a chosen duration so you're not re-alerted while investigating.
- **Bulk acknowledge** — checkbox per row + "Acknowledge selected" button (mirrors the bulk delete UX on the tags pages).
- **Resolution note field** — text input on the Acknowledge action; stored alongside `acknowledged_by` / `acknowledged_at`. Renders as a tooltip / detail row. Useful for forensics ("acked because dataset rotation, not an attack").
- **Auto-archive acked rows older than N days** — moves to a separate `job_anomalies_archive` table (or just hides from the default view) with a configurable retention. Keeps the live page clean while preserving forensics indefinitely.

### Low

- **Per-job auto-baseline / FP reduction** — learn typical churn per job to tune sensitivity automatically.
- **Mandatory ack within N hours, else escalate** to higher-priority alert channel.
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
