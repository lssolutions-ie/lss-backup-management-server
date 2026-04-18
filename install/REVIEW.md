# install.sh — review notes

Read of `install.sh` against a fresh Ubuntu 24.04 mental model. Captures the gaps applied as fixes (in this commit) and the gaps left as known limitations.

## Fixes applied in this commit

- **Sessions dir was missing.** Terminal recording writes to `/var/lib/lss-management/sessions/`. install.sh didn't create it → first SSH session would log `recorder init failed`. Now created with `750` perms in step 3.
- **`terminal.sessions_dir`** was missing from the generated `config.toml`. Added in step 8.
- **Step counter said `11`** but we now have 12 steps. Fixed.
- **MySQL backup script** wasn't installed. Now copies `lss-mgmt-backup.sh` to `/usr/local/bin/`, writes `/etc/default/lss-mgmt-backup` with the DB password (mode 600), and registers a daily cron entry.
- **First-run wait too short.** Was `sleep 3` — first start applies 35 migrations, can easily take >3s. Now polls `systemctl is-active` for up to 30 s.
- **`Include /etc/ssh/sshd_config.d/*.conf` check.** Default on Ubuntu 22.04+ but absent on hardened images. Now warns if missing.
- **Error trap added.** `trap 'error "Install failed at line $LINENO"; exit 1' ERR` so failures point at the line, not just `set -e` exit.
- **Reload-failure warning.** The previous `|| true` swallowed sshd-reload failures silently. Now warns explicitly.
- **Summary section** now lists firewall ports to open and the backup directory.

## Known gaps (NOT fixed — operator responsibility, documented)

- **No `mysql_secure_installation` equivalent.** Default MySQL on Ubuntu has no anonymous users / test DB to remove these days, but operators on older bases should run it. Not part of install.sh.
- **No firewall (ufw / iptables) rules applied.** install.sh refuses to make assumptions about an operator's network. Summary lists the required ports.
- **No SSL certificate.** install.sh prints the certbot command but doesn't run it — the DNS A record needs to exist first.
- **No HAProxy / OPNsense detection.** install.sh prints the required HAProxy backend tuning (`option http-server-close`, `timeout tunnel 24h`) in the summary but can't apply it.
- **Domain prompt is interactive.** No env override yet (e.g. `LSS_INSTALL_DOMAIN=foo`). Blocks unattended installs. Acceptable for now.
- **Default password is `lssbackuppassword`** — forced-change on first login but still a known string. Acceptable for the setup window; harden when shipping to real customers.

## How to actually verify on a fresh box

```bash
# Spin a clean Ubuntu 24.04 VM (multipass is fine):
multipass launch 24.04 --name lss-fresh --memory 2G --disk 10G
multipass shell lss-fresh

# Inside the VM:
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/lssolutions-ie/lss-backup-server.git
cd lss-backup-management-server
sudo bash install/install.sh
```

Watch for:
- All 12 steps print `→` lines, no `⚠` lines except the documented "back up your secret key" prompt.
- `systemctl status lss-management` shows `active (running)`.
- `journalctl -u lss-management -n 30 --no-pager -o cat` shows the JSON `starting server` line followed by migration logs ending around `applied migration 035_host_audit.sql`.
- `curl -sI http://127.0.0.1:8080/login` returns `HTTP/1.1 200 OK`.
- `ls -la /var/lib/lss-management/sessions/` exists with `lss-management:lss-management` ownership.
- `crontab -u root -l | grep lss-mgmt-backup` shows the daily entry.

## Things to validate end-to-end after install

- Node registration: register a CLI node, watch a heartbeat land in `journalctl -u lss-management -f`.
- Audit log: log into the dashboard, ack an anomaly (or just log out / log back in), see the row appear at `/audit`.
- Terminal recording: if you have a node, open a terminal, type a few commands, log out, replay from `/audit`.
- Backup: run `sudo /usr/local/bin/lss-mgmt-backup.sh` and confirm a `.sql.gz` lands in `/var/backups/lss-mgmt/`.

## Pre-flight: what install.sh DOESN'T do

- Does not run on non-Ubuntu (rejected at step 1).
- Does not configure DNS.
- Does not provision the operator's machine — assumes you SSH'd in.
- Does not migrate from a prior non-install.sh deployment. If you've been hand-deploying (like 10.0.0.123), some paths might not match — review before re-running.
