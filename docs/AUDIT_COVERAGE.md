# Audit Log Coverage — Complete Reference

Every mutating action, state transition, and security-relevant event is recorded in the `audit_log` table. This document is the authoritative list. **73/73 event types audited (100%).**

Last verified: 2026-04-17 (v1.21.9)

---

## Sources

| Source | Description |
|--------|-------------|
| `server` | User actions on the management dashboard |
| `node` | Events shipped by CLI nodes via heartbeat (audit_events protocol v3) |
| `host` | Events from the management server's own systemd journal (sshd, sudo, service lifecycle) |

---

## Auth Events

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `auth_login` | info | Successful login | `auth.go:completeLogin()` |
| `auth_login_failed` | warn | Wrong username/password | `auth.go:HandleLogin()` |
| `auth_2fa_failed` | warn | Wrong TOTP code | `auth.go:HandleTOTPVerify()` |
| `auth_2fa_enabled` | info | User enables 2FA | `auth.go:HandleTOTPSetup()` |
| `auth_2fa_disabled` | warn | User disables 2FA | `auth.go:HandleTOTPDisable()` |
| `auth_logout` | info | User logs out | `auth.go:HandleLogout()` |
| `user_password_changed` | warn | Password changed (self or forced) | `settings.go:HandleSettings/ForcePassword()` |

## Node Lifecycle

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `node_created` | info | Manual node registration | `nodes.go:HandleNodeNew()` |
| `node_updated` | info | Node details edited | `nodes.go:HandleNodeEdit()` |
| `node_deleted` | critical | Direct node deletion | `nodes.go:HandleNodeDelete()` |
| `node_psk_regenerated` | warn | PSK rotated | `nodes.go:HandleNodeRegeneratePSK()` |
| `node_tags_updated` | info | Node tags changed | `nodes.go:HandleNodeTags()` |
| `node_silent` | warn | Node missed heartbeat (7min) | `worker/silent.go` via `db.FireSilentNodeAlerts()` |
| `node_offline` | critical | Node confirmed offline (10min) | `worker/worker.go` via `db.FireNodeOfflineAudit()` |
| `node_online` | info | Node back online after being offline | `api/status.go:HandleStatus()` |
| `node_recovered` | critical | First heartbeat after disaster recovery | `api/status.go:HandleStatus()` (detects recovery token) |

## Node Deployment & Recovery

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `install_token_created` | info | Operator generates install command | `node_install.go:HandleGenerateInstallToken()` |
| `install_token_redeemed` | critical | Install script fetched (PSK served) | `api/install.go:HandleInstall()` |
| `recovery_token_created` | critical | Operator generates recovery command | `node_install.go:HandleGenerateRecoveryToken()` |
| `recovery_token_redeemed` | critical | Recovery script fetched (PSK served) | `api/install.go:HandleRecover()` |
| `pending_node_deleted` | info | Abandoned pending node removed | `pending_nodes.go:HandleDeletePendingNode()` |

## Graceful Node Deletion

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `node_deletion_initiated` | critical | "Delete Node" clicked, export requested | `node_deletion.go:HandleInitiateNodeDeletion()` |
| `secrets_exported` | critical | Credential report downloaded | `node_deletion.go:HandleDownloadCredentialReport()` |
| `node_deletion_confirmed` | critical | Operator confirmed, uninstall pending | `node_deletion.go:HandleConfirmNodeDeletion()` |
| `node_deletion_cancelled` | info | Deletion aborted | `node_deletion.go:HandleCancelNodeDeletion()` |

## Disaster Recovery

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `dr_config_saved` | warn | S3/restic config changed | `dr_settings.go:HandleDRSettings()` |
| `dr_node` | warn | DR enabled/disabled per node | `dr_settings.go:HandleDRNodeAction()` |
| `dr_run_now` | info | Instant DR backup via SSH | `dr_settings.go:HandleDRRunNow()` |
| `dr_node` (force_run) | warn | DR force-run via heartbeat | `dr_settings.go:HandleDRRunNow()` (fallback) |

## CLI Updates

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `cli_update_executed` | info | Instant CLI update via SSH | `cli_update.go:HandleScheduleCLIUpdate()` |
| `version_check` | info | Manual "Check Now" for CLI or server | `update_settings.go:HandleCheckCLI/ServerVersion()` |

## Anomaly Management

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `anomaly_acknowledged` | info | Single or bulk ack | `anomalies.go:HandleAnomalyAck/BulkAck()` |
| `anomaly_unacknowledged` | warn | Single or bulk unack | `anomalies.go:HandleAnomalyAck/BulkAck()` |

## Users

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `user_created` | info/critical | User created (critical for initial superadmin) | `users.go/auth.go` |
| `user_updated` | info | User details edited | `users.go:HandleUserEdit()` |
| `user_deleted` | critical | User removed | `users.go:HandleUserDelete()` |

## Client Groups

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `group_created` | info | Client group created | `groups.go` |
| `group_updated` | info | Client group edited | `groups.go` |
| `group_deleted` | warn | Client group removed | `groups.go` |

## Tags (Node / User / Job)

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `tag_created` | info | Node tag created | `tags.go` |
| `tag_updated` | info | Node tag edited | `tags.go` |
| `tag_deleted` | warn | Node tag removed | `tags.go` |
| `tag_bulk_deleted` | warn | Multiple node tags removed | `tags.go` |
| `user_tag_created` | info | User tag created | `user_tags.go` |
| `user_tag_updated` | info | User tag edited | `user_tags.go` |
| `user_tag_deleted` | warn | User tag removed | `user_tags.go` |
| `user_tag_bulk_deleted` | warn | Multiple user tags removed | `user_tags.go` |
| `job_tag_created` | info | Job tag created | `job_tags.go` |
| `job_tag_updated` | info | Job tag edited | `job_tags.go` |
| `job_tag_deleted` | warn | Job tag removed | `job_tags.go` |

## User Groups

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `user_group_created` | info | User group created | `user_groups.go` |
| `user_group_updated` | info | User group edited | `user_groups.go` |
| `user_group_deleted` | warn | User group removed | `user_groups.go` |

## Permissions

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `permission_rule_created` | info | New firewall rule | `permissions.go` |
| `permission_rule_updated` | info | Rule modified | `permissions.go` |
| `permission_rule_toggled` | info/warn | Rule enabled/disabled | `permissions.go` |
| `permission_rule_deleted` | warn | Rule removed | `permissions.go` |

## Settings

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `tuning_saved` | warn | Server tuning changed | `tuning.go` |
| `smtp_config_saved` | warn | SMTP settings changed | `settings.go` |
| `smtp_test` | info/warn | SMTP test email (success/fail) | `settings.go` |

## Terminal

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `terminal_opened` | warn | SSH session started from dashboard | `terminal.go` |
| `terminal_closed` | info | SSH session ended | `terminal.go` |
| `session_replay` | warn | Terminal recording replayed | `replay.go` |

## Repository

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `repo_download` | info | File downloaded (rsync/restic, single/zip) | `repository.go` (4 handlers) |

## Backup & Restore

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `backup_created` | warn | Server backup downloaded | `backup.go` |
| `system_restored` | critical | Server restored from backup | `backup.go` |

## Silences

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `silence_created` | warn | Job muted | `silences.go` |
| `silence_cleared` | info | Job unmuted | `silences.go` |

## Security / HMAC Chain

| Category | Severity | Trigger | Handler |
|----------|----------|---------|---------|
| `audit_chain_break` | critical | HMAC chain tamper detected | `api/status.go` (max 1/node/hour) |
| `audit_chain_reset` | critical | Chain manually reset | `anomalies.go:HandleResetAuditChain()` |

## Host Audit (from systemd journal)

| Category | Severity | Trigger | Source |
|----------|----------|---------|--------|
| `host_ssh_login` | info | SSH login success | journalctl SYSLOG_IDENTIFIER=sshd |
| `host_ssh_login_failed` | warn | SSH login failure | journalctl SYSLOG_IDENTIFIER=sshd |
| `host_sudo` | warn | sudo command executed | journalctl SYSLOG_IDENTIFIER=sudo |
| `host_service_started` | info | lss-management.service started | journalctl _SYSTEMD_UNIT |
| `host_service_stopped` | warn | lss-management.service stopped | journalctl _SYSTEMD_UNIT |
| `host_service_failed` | critical | lss-management.service crashed | journalctl _SYSTEMD_UNIT |

---

## Intentionally NOT Audited

| Action | Reason |
|--------|--------|
| GET/read-only page views | Too noisy — every page load would flood the audit log. Access log middleware covers POST/PUT/DELETE. |
| Heartbeat receipt (per-node) | Demoted to DEBUG slog. ~900 events/day for 4 nodes. Would drown real signal. |
| Version check worker ticks | Background polling, not user action. Logged to slog at DEBUG. |
| Retention worker prunes | Routine cleanup. Logged to slog at INFO when rows are actually deleted. |
| Template parse/render errors | Logged to slog. Not a user action — operational issue. |

---

## Severity Guide

| Level | When to use |
|-------|-------------|
| `info` | Normal successful operations (login, create, edit, mute) |
| `warn` | Destructive or security-sensitive (delete, disable, PSK regen, failed auth, sudo) |
| `critical` | Irreversible or high-impact (user/node deletion, system restore, DR recovery, credential export, chain tampering, service crash) |
