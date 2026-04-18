# LSS Backup Server

Enterprise backup management platform for MSP and IT operations teams. Centralized monitoring, disaster recovery, encrypted credential vault, anomaly detection, and remote node management — all from a single dashboard.

Manages cross-platform backup nodes (Linux, macOS, Windows) with AES-256-GCM encrypted communications, HMAC-chained audit logs, and one-click deploy/update/recover workflows.

## Features

- Real-time dashboard with node monitoring, job status, anomaly detection
- Password vault with credential tamper detection
- Disaster recovery: automatic server + node backup to S3
- One-click server self-update from the dashboard
- Terminal session recording with replay
- HMAC-chained audit logs (73+ event types)
- One-command node deploy, recover, and delete
- Firewall-style RBAC permission engine

## Requirements

- Ubuntu 22.04 LTS or 24.04 LTS
- A domain name with an A record pointing to this server's public IP
- Ports 80 and 443 open
- Root or sudo access

## Installation

### One-Line Install (recommended)

```bash
export LSS_DOMAIN=your-domain.com
curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-backup-server/main/install/install-remote.sh | bash
```

This downloads the latest release binary from GitHub and installs everything:
MySQL, nginx, systemd service, SSH tunnel user, server self-update helper,
and daily backup cron. No git clone or Go compiler needed.

### Developer Install (from source)

```bash
git clone https://github.com/lssolutions-ie/lss-backup-server.git
cd lss-backup-server
sudo bash install/install.sh
```

This clones the repo, installs Go, and builds from source. The script will
prompt for your domain name.

## SSL Certificate

If connecting directly (no reverse proxy):

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

If behind a reverse proxy (HAProxy / OPNsense), add these to the backend:

```
option http-server-close
timeout tunnel 24h
```

## First Login

Visit `https://your-domain.com/setup` to create your superadmin account.
This page is only available once — it disappears after the first account is
created.

## Registering Nodes

### Server-Assisted Install (recommended)

1. Log in to the dashboard
2. Go to **Nodes** → **Register Node**
3. Select a client group and click **Generate Install Command**
4. Copy the one-liner and paste it on the target machine
5. The node installs, configures, and appears on the dashboard automatically

### Manual Registration

1. Go to **Nodes** → **Register Node**
2. Fill in Node ID, Hostname, Client Group
3. Copy the PSK key shown
4. On the node, open LSS Backup CLI → **Settings** → **Configure Management Console**
5. Enter the Server URL, Node ID, and PSK Key

## Upgrading

### From the Dashboard (recommended)

Go to **Settings** → **Software Updates** → **Check Now** → **Update Server Now**.
The server downloads the latest release, replaces the binary, and restarts.

### Manual Upgrade (one-line install)

Re-run the install command — it's idempotent:

```bash
export LSS_DOMAIN=your-domain.com
curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-backup-server/main/install/install-remote.sh | bash
```

### Manual Upgrade (developer install)

```bash
cd lss-backup-server
git pull
sudo bash install/install.sh
```

## Service Management

```bash
systemctl status lss-backup     # Status
journalctl -u lss-backup -f     # Live logs
systemctl restart lss-backup    # Restart
systemctl stop lss-backup       # Stop
```

## Backup & Restore

### Automatic (recommended)

The server automatically backs up to S3 every 24 hours when Disaster Recovery
is configured (**Settings** → **Disaster Recovery**). Includes database,
encryption key, config, and terminal recordings.

Restore from **Settings** → **Disaster Recovery** → **Restore From Snapshot**.

### Manual

Download a backup zip from **Settings** → **Backup & Restore** → **Download Backup Now**.
Restore by uploading the zip on a fresh install via the same page.

### Critical Files

| File | Impact if lost |
|------|----------------|
| `/etc/lss-backup/secret.key` | All PSK keys unreadable — every node must be re-registered |
| `/etc/lss-backup/config.toml` | Recoverable — recreate or restore from backup |
| MySQL `lss_backup` database | All history lost without a backup |

## Troubleshooting

**Service won't start:**
```bash
journalctl -u lss-backup -n 100
```

**Node not appearing in dashboard:**
- Check the node's CLI activity log for HTTP errors
- Verify nginx: `systemctl status nginx`
- Check server log: `journalctl -u lss-backup -n 50`

**Forgot superadmin password:**
```bash
mysql lss_backup -e "UPDATE users SET force_setup = 1, totp_secret = '', totp_enabled = 0 WHERE role = 'superadmin';"
mysql lss_backup -e "DELETE FROM sessions;"
```
Then log in with `lssbackuppassword` and you'll be prompted to set a new password + 2FA.

## License

Copyright 2026 LS Solutions. All rights reserved.
