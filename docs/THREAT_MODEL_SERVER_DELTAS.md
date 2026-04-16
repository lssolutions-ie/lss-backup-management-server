# Threat Model — Server-Side Deltas

Additions for the shared `THREAT_MODEL.md` maintained in the CLI repo. These cover attack surfaces and mitigations that are purely or primarily server-side. Merge into the shared doc and delete this file.

---

## PSK Leak Attack Tree

**What the attacker gets with a leaked PSK:**

1. **Forge heartbeats** — send fake `NodeStatus` payloads that look like real reports. Server trusts them (AES-256-GCM decrypts cleanly). Can inject false job states, mark jobs as success when they're failing.
2. **Forge audit events** — inject arbitrary audit rows with any `actor`, including `user:admin`. `/audit` page shows them as legitimate. **Mitigation (planned, not shipped):** HMAC chain (see `docs/HMAC_CHAIN_SPEC.md`). Until shipped, audit is tamper-evident only relative to a trusted CLI.
3. **Open reverse tunnels** — connect to `/ws/ssh-tunnel`, HMAC auth succeeds. Attacker gets a reverse TCP forward on the server's loopback. From there: attempt SSH to the tunnel user (but needs the node's SSH private key, which is NOT the PSK). **Mitigation (shipped v1.12.0):** per-UID exponential backoff rate limiter on `/ws/ssh-tunnel`. A leaked PSK still lets the attacker connect once, but brute-forcing SSH keys over the tunnel is rate-capped (1s → 10min backoff).
4. **Replay old heartbeats** — resend a captured payload. **Mitigation (shipped v1.0):** ±10 min freshness window on `reported_at`. Replays older than 10 min are rejected.

**What the attacker does NOT get:**
- Database access (PSK is node-specific; doesn't authenticate to MySQL or the web UI).
- Web session (PSK is used only on `/api/v1/status` and `/ws/ssh-tunnel`; the dashboard uses session cookies + bcrypt passwords).
- Other nodes' data (each node has its own PSK; compromising one doesn't affect others).
- Server-side secret key (`secret.key` encrypts PSKs at rest in MySQL; the PSK itself is the decrypted form. Knowing a PSK doesn't reveal the server key).

**Mitigation chain:**
- PSK rotation via `HandleNodeRegeneratePSK` (manual, audited).
- No scheduled auto-rotation (acceptable for single-tenant; flag when multi-tenant).
- When rotated: old PSK immediately invalidated in DB. All future heartbeats with the old PSK fail decryption → 400.

---

## Compromised Management Server Scenarios

**Scenario 1: Attacker has root on the management server.**

| Asset | Status |
|-------|--------|
| MySQL data (audit_log, anomalies, nodes, sessions) | Fully exposed. Attacker can read, modify, delete. |
| secret.key (encrypts PSKs at rest) | Exposed → attacker can decrypt all node PSKs from MySQL. |
| `.cast` session recordings | Exposed. Every recorded SSH session is readable. |
| Web sessions | Attacker can forge session cookies or read them from MySQL. |
| Node trust | Attacker can impersonate any node (has all PSKs). |
| Off-host backups | Safe IF `LSS_BACKUP_REMOTE` in `/etc/default/lss-mgmt-backup` ships to a separate machine the attacker doesn't control. |

**Mitigation posture:** We do NOT defend against this today. The management server is a single point of trust. Realistic hardening path:
- Off-host syslog mirror of audit_log (so attacker can't `DELETE FROM audit_log` without the syslog copy surviving).
- HMAC chain makes audit-event forgery detectable after the fact (chain will break when the attacker tries to insert or modify events).
- HSM for secret.key storage (eliminates PSK decryption even with root).
- All three are roadmap items, none are shipped.

**Scenario 2: Attacker has web UI access (stolen superadmin session).**

| Action | Possible? | Audited? |
|--------|-----------|----------|
| View all nodes, jobs, anomalies | Yes | No (read-only, not audited) |
| Ack/unack anomalies | Yes | Yes (anomaly_acknowledged) |
| Create/delete users | Yes | Yes (user_created, user_deleted) |
| Regenerate PSK (lock out a node) | Yes | Yes (node_psk_regenerated) |
| Open terminal to any node | Yes | Yes (terminal_opened + session recording) |
| Modify permissions | Yes | Yes (permission_rule_created, etc.) |
| Change tuning thresholds | Yes | Yes (tuning_saved) — attacker could raise anomaly thresholds to suppress detection |
| Delete nodes | Yes | Yes (node_deleted) |

**Key risk:** attacker raises anomaly thresholds to max → no anomalies fire → wipes go undetected. **Mitigation (not shipped):** alert on tuning_saved with threshold fields in details; flag large-magnitude changes. SMTP notifier (deferred LAST) would make this visible.

---

## Defensive Posture Table (server-side, v1.12.0)

| Control | Status | Reference |
|---------|--------|-----------|
| Per-heartbeat AES-256-GCM encryption | ✅ Shipped v1.0 | `internal/crypto/` |
| ±10 min freshness / replay protection | ✅ Shipped v1.0 | `api/status.go:87-102` |
| HMAC-SHA256 tunnel auth | ✅ Shipped v1.0 | `web/ssh_tunnel.go` |
| Tunnel rate-limit (exponential backoff) | ✅ Shipped v1.12.0 | `web/tunnel_ratelimit.go` |
| Silent-node alarm (1-2 missed heartbeats) | ✅ Shipped v1.12.0 | `worker/silent.go`, migration 033 |
| 3-vector anomaly detection (snapshot/files/bytes drop) | ✅ Shipped v1.10.0 | `api/status.go:detectAnomalies` |
| Snapshot ID set tracking | ✅ Server-side ready v1.12.x | `api/status.go:snapshotSetDiff`. Awaits CLI `snapshot_ids` field |
| 24h anomaly dedup | ✅ Shipped v1.10.2 | `db/queries.go:InsertJobAnomaly` |
| Audit log (33 server hooks + node ingest + host journal) | ✅ Shipped v1.11.x–v1.12.0 | `web/audit.go`, `db/audit.go`, `worker/hostaudit.go` |
| Contiguous-ack reconcile + 1hr gap sweeper | ✅ Shipped v1.11.11 | `db/audit.go:InsertNodeAuditEvents` |
| Terminal session recording (asciinema v2) | ✅ Shipped v1.11.4 | `internal/recorder/`, `web/terminal.go` |
| Structured JSON logging with request IDs | ✅ Shipped v1.11.6 | `internal/logx/` |
| s.Fail() — no silent 500s | ✅ Shipped v1.11.6 | `web/logging.go` |
| HMAC chain for audit (tamper evidence) | ⏳ Spec drafted | `docs/HMAC_CHAIN_SPEC.md` |
| Off-server audit/syslog mirror | ⏳ Planned | ROADMAP |
| SMTP alerting for anomalies | ⏳ Deferred LAST | ROADMAP |
| Multi-tenant PSK isolation | ❌ Not planned | Single-tenant assumption |
| HSM for secret.key | ❌ Not planned | Acceptable risk for current scale |

---

## To CLI session

Merge these sections into `v2/docs/THREAT_MODEL.md` wherever they fit. Specifically:
- PSK leak attack tree → under "Trust Boundaries" or new "Attack Trees" section.
- Compromised server scenarios → new section or under "Explicit Non-Goals" with the detail.
- Defensive posture table → merge rows into the existing table, marking server-side ones.
- Update any rows that reference v1.12.0 hardening items (tunnel rate-limit, silent alarm) from "pending" to ✅.
