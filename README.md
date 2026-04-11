# LSS Management Server

A self-hosted management server for LSS Backup CLI v2 deployments. Client nodes
(macOS, Linux, Windows) POST AES-256-GCM encrypted status reports to this
server; an MSP operator monitors every node and backup job through a single
web dashboard.

## Requirements

- Ubuntu 22.04 LTS or 24.04 LTS
- A domain name with an A record pointing to this server's public IP
- Ports 80 and 443 open (ufw: `sudo ufw allow 80 && sudo ufw allow 443`)
- Root or sudo access

## Installation

The complete installation is three commands:

```bash
git clone https://github.com/lssolutions-ie/lss-backup-management-server.git
cd lss-backup-management-server
sudo bash install/install.sh
```

The script installs all dependencies (MySQL, nginx, Go), configures the
database, builds the binary, sets up the systemd service, and configures
nginx. It will prompt for your domain name.

## SSL Certificate (required after install)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

## First Login

Visit `https://your-domain.com/setup` to create your superadmin account.
This page is only available once — it disappears after the first account is
created.

## Registering a Node

1. Log in to the dashboard
2. Go to **Client Groups** → create a group for the client (e.g. "Acme Ltd")
3. Go to **Register Node**
4. Enter the node name and UID, assign to the client group
5. Copy the PSK key shown — **it will not be shown again**
6. On the node machine, open LSS Backup CLI → **Settings** → **Configure
   Management Console**
7. Enter: server URL, user ID, node name, and paste the PSK key
8. The node will check in within 5 minutes

## Upgrading

```bash
cd lss-backup-management-server
git pull
sudo bash install/install.sh
```

The script is idempotent — it rebuilds the binary and restarts the service.
It never overwrites your config, secret key, or database.

## Service Management

```bash
# Status
systemctl status lss-management

# Logs (live)
journalctl -u lss-management -f

# Restart
systemctl restart lss-management

# Stop
systemctl stop lss-management
```

## Backup

Back up these files regularly — losing them is unrecoverable:

| File | What it contains | Impact if lost |
|------|------------------|----------------|
| `/etc/lss-management/secret.key` | App encryption key | All PSK keys become unreadable; every node must be re-registered |
| `/etc/lss-management/db.password` | MySQL credentials | Recoverable — reset MySQL password and update `config.toml` |
| `/etc/lss-management/config.toml` | Server config | Recoverable — recreate from scratch |
| MySQL `lss_management` database | All node history | Unrecoverable without a backup |

Recommended backup command (run as root, add to cron):

```bash
mysqldump lss_management | gzip > /var/backups/lss-management-$(date +%F).sql.gz
cp /etc/lss-management/secret.key /var/backups/lss-management-secret.key
```

## Troubleshooting

**Service won't start:**

```bash
journalctl -u lss-management -n 100
```

**"secret key file not found" error:**
The `/etc/lss-management/secret.key` file is missing. If this is a fresh
install, re-run `install.sh`. If the file was lost, all nodes must be
re-registered.

**Node not appearing in dashboard:**
- Verify the node's server URL, user ID, and PSK key in the CLI settings
- Check the node's LSS Backup CLI activity log for HTTP errors
- Verify nginx is running: `systemctl status nginx`
- Check the server log: `journalctl -u lss-management -n 50`

**Forgot superadmin password:**

```bash
# Reset via MySQL
mysql lss_management -e "UPDATE users SET password_hash='<new-bcrypt-hash>' WHERE role='superadmin';"
```

Generate a bcrypt hash with:

```bash
htpasswd -bnBC 12 "" newpassword | tr -d ':\n'
```
