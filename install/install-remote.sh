#!/usr/bin/env bash
#
# LSS Management Server — remote installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/lssolutions-ie/lss-backup-management-server/main/install/install-remote.sh | sudo bash
#
# Downloads the latest release binary from GitHub. No git clone, no Go compiler needed.
# Idempotent — safe to re-run for upgrades.

set -euo pipefail

# ─── Colour helpers ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'
    C_RESET=$'\033[0m'
else
    C_RED= C_GREEN= C_YELLOW= C_BLUE= C_RESET=
fi

step()  { echo; echo "${C_BLUE}[STEP $1/12]${C_RESET} $2"; }
info()  { echo "  ${C_GREEN}→${C_RESET} $*"; }
warn()  { echo "  ${C_YELLOW}⚠${C_RESET} $*"; }
error() { echo "${C_RED}✗ $*${C_RESET}" >&2; }
die()   { error "$*"; exit 1; }

GITHUB_REPO="lssolutions-ie/lss-backup-management-server"

# ─── Constants ───────────────────────────────────────────────────────────────
SERVICE_USER="lss-management"
CONFIG_DIR="/etc/lss-management"
STATE_DIR="/var/lib/lss-management"
LOG_DIR="/var/log/lss-management"
SECRET_KEY_FILE="$CONFIG_DIR/secret.key"
DB_PASSWORD_FILE="$CONFIG_DIR/db.password"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BINARY_PATH="/usr/local/bin/lss-management-server"
SYSTEMD_UNIT="/etc/systemd/system/lss-management.service"
NGINX_AVAILABLE="/etc/nginx/sites-available/lss-management"
NGINX_ENABLED="/etc/nginx/sites-enabled/lss-management"
TUNNEL_USER="lss-tunnel"
TUNNEL_AUTHKEYS_FILE="$STATE_DIR/tunnel_authorized_keys"
TUNNEL_AUTHKEYS_SCRIPT="/usr/local/bin/lss-tunnel-authkeys.sh"
SSHD_DROPIN="/etc/ssh/sshd_config.d/lss-tunnel.conf"
SESSIONS_DIR="$STATE_DIR/sessions"
UPDATE_SCRIPT="/usr/local/bin/lss-apply-update.sh"

trap 'error "Install failed at line $LINENO"; exit 1' ERR

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — Check prerequisites
# ═════════════════════════════════════════════════════════════════════════════
step 1 "Checking prerequisites"

if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Try: curl ... | sudo bash"
fi

if [[ ! -f /etc/os-release ]]; then
    die "Cannot detect operating system (missing /etc/os-release)."
fi

source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
    die "This installer supports Ubuntu only (detected: ${ID:-unknown})."
fi
info "Detected Ubuntu ${VERSION_ID:-unknown} (${VERSION_CODENAME:-unknown})"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 2 — Install system dependencies
# ═════════════════════════════════════════════════════════════════════════════
step 2 "Installing system dependencies"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y mysql-server nginx openssl curl ca-certificates cron restic
info "Installed mysql-server, nginx, openssl, curl, cron, restic"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 3 — Create service user and directories
# ═════════════════════════════════════════════════════════════════════════════
step 3 "Creating service user and directories"

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created user: $SERVICE_USER"
else
    info "User $SERVICE_USER already exists"
fi

if getent group systemd-journal &>/dev/null; then
    usermod -aG systemd-journal "$SERVICE_USER" 2>/dev/null || true
    info "Added $SERVICE_USER to systemd-journal group"
fi

for dir in "$CONFIG_DIR" "$LOG_DIR" "$STATE_DIR" "$SESSIONS_DIR"; do
    mkdir -p "$dir"
    chown "$SERVICE_USER:$SERVICE_USER" "$dir"
done
chmod 750 "$CONFIG_DIR" "$LOG_DIR" "$SESSIONS_DIR"
chmod 755 "$STATE_DIR"

info "Directories created"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4 — Configure MySQL
# ═════════════════════════════════════════════════════════════════════════════
step 4 "Configuring MySQL"

systemctl start mysql
systemctl enable mysql --quiet
info "MySQL service started and enabled"

user_exists="$(mysql -N -B -e \
    "SELECT COUNT(*) FROM mysql.user WHERE user='lss_mgmt' AND host='localhost';")"

if [[ "$user_exists" == "0" ]]; then
    info "Creating MySQL user lss_mgmt and database lss_management"
    DB_PASSWORD="$(openssl rand -base64 24)"

    mysql <<SQL
CREATE USER IF NOT EXISTS 'lss_mgmt'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
CREATE DATABASE IF NOT EXISTS lss_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON lss_management.* TO 'lss_mgmt'@'localhost';
FLUSH PRIVILEGES;
SQL

    umask 077
    printf '%s' "$DB_PASSWORD" > "$DB_PASSWORD_FILE"
    umask 022
    chown "$SERVICE_USER:$SERVICE_USER" "$DB_PASSWORD_FILE"
    chmod 600 "$DB_PASSWORD_FILE"
    info "MySQL configured. Credentials saved to $DB_PASSWORD_FILE"
else
    info "MySQL user lss_mgmt already exists — skipping"
    if [[ ! -f "$DB_PASSWORD_FILE" ]]; then
        die "lss_mgmt exists but $DB_PASSWORD_FILE is missing."
    fi
    DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
    mysql -e "CREATE DATABASE IF NOT EXISTS lss_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5 — Generate secret key
# ═════════════════════════════════════════════════════════════════════════════
step 5 "Generating secret key"

if [[ ! -f "$SECRET_KEY_FILE" ]]; then
    umask 077
    openssl rand -hex 32 > "$SECRET_KEY_FILE"
    umask 022
    chown "$SERVICE_USER:$SERVICE_USER" "$SECRET_KEY_FILE"
    chmod 600 "$SECRET_KEY_FILE"
    info "Secret key generated at $SECRET_KEY_FILE"
    warn "BACK THIS UP — losing it means re-registering all nodes"
else
    info "Secret key already exists — skipping"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6 — Provision reverse-tunnel SSH user
# ═════════════════════════════════════════════════════════════════════════════
step 6 "Provisioning reverse-tunnel SSH user"

if ! id "$TUNNEL_USER" &>/dev/null; then
    useradd --system --create-home --shell /usr/sbin/nologin "$TUNNEL_USER"
    info "Created user: $TUNNEL_USER"
else
    info "User $TUNNEL_USER already exists"
fi

TUNNEL_HOME="$(getent passwd "$TUNNEL_USER" | cut -d: -f6)"
mkdir -p "$TUNNEL_HOME/.ssh"
chown "$TUNNEL_USER:$TUNNEL_USER" "$TUNNEL_HOME/.ssh"
chmod 700 "$TUNNEL_HOME/.ssh"
: > "$TUNNEL_HOME/.ssh/authorized_keys"
chown "$TUNNEL_USER:$TUNNEL_USER" "$TUNNEL_HOME/.ssh/authorized_keys"
chmod 600 "$TUNNEL_HOME/.ssh/authorized_keys"

touch "$TUNNEL_AUTHKEYS_FILE"
chown "$SERVICE_USER:$SERVICE_USER" "$TUNNEL_AUTHKEYS_FILE"
chmod 644 "$TUNNEL_AUTHKEYS_FILE"

cat > "$TUNNEL_AUTHKEYS_SCRIPT" <<'SCRIPT'
#!/bin/bash
if [[ "$1" != "lss-tunnel" ]]; then
    exit 0
fi
cat /var/lib/lss-management/tunnel_authorized_keys 2>/dev/null
SCRIPT
chown root:root "$TUNNEL_AUTHKEYS_SCRIPT"
chmod 0755 "$TUNNEL_AUTHKEYS_SCRIPT"

cat > "$SSHD_DROPIN" <<EOF
Match User $TUNNEL_USER
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding yes
    GatewayPorts no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    PermitTunnel no
    ForceCommand /usr/bin/sleep infinity
    AuthorizedKeysCommand $TUNNEL_AUTHKEYS_SCRIPT
    AuthorizedKeysCommandUser nobody
EOF
chown root:root "$SSHD_DROPIN"
chmod 0644 "$SSHD_DROPIN"

if sshd -t 2>/dev/null; then
    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
        info "sshd reloaded"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 7 — Download latest release binary
# ═════════════════════════════════════════════════════════════════════════════
step 7 "Downloading latest release binary"

RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest")"
VERSION="$(echo "$RELEASE_JSON" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
DOWNLOAD_URL="$(echo "$RELEASE_JSON" | grep -m1 '"browser_download_url"' | cut -d'"' -f4)"

if [[ -z "$VERSION" || -z "$DOWNLOAD_URL" ]]; then
    die "Could not fetch latest release from GitHub"
fi

info "Latest version: $VERSION"
info "Downloading binary..."
curl -fsSL -o "$BINARY_PATH" "$DOWNLOAD_URL"
chown root:root "$BINARY_PATH"
chmod 755 "$BINARY_PATH"
info "Binary installed at $BINARY_PATH"

# Download runtime assets (templates, migrations, static) from the repo
info "Downloading runtime assets..."
ASSETS_URL="https://github.com/$GITHUB_REPO/archive/refs/tags/$VERSION.tar.gz"
TMPDIR="$(mktemp -d)"
curl -fsSL "$ASSETS_URL" | tar -xz -C "$TMPDIR" --strip-components=1

for asset in templates migrations static; do
    if [[ -d "$TMPDIR/$asset" ]]; then
        rm -rf "$CONFIG_DIR/$asset"
        cp -r "$TMPDIR/$asset" "$CONFIG_DIR/$asset"
        chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/$asset"
        find "$CONFIG_DIR/$asset" -type d -exec chmod 755 {} \;
        find "$CONFIG_DIR/$asset" -type f -exec chmod 644 {} \;
    fi
done
rm -rf "$TMPDIR"
info "Templates, migrations, and static assets installed"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 8 — Write config file
# ═════════════════════════════════════════════════════════════════════════════
step 8 "Writing config file"

if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<EOF
[server]
listen_addr = "127.0.0.1:8080"

[database]
dsn = "lss_mgmt:${DB_PASSWORD}@tcp(localhost:3306)/lss_management?parseTime=true&loc=Local"

[security]
secret_key_file = "$SECRET_KEY_FILE"

[session]
cookie_name   = "lss_session"
max_age_hours = 24

[terminal]
sessions_dir = "$SESSIONS_DIR"
EOF
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    info "Config written: $CONFIG_FILE"
else
    info "Config already exists — skipping (upgrade-safe)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 9 — Install systemd unit
# ═════════════════════════════════════════════════════════════════════════════
step 9 "Installing systemd unit"

cat > "$SYSTEMD_UNIT" <<'EOF'
[Unit]
Description=LSS Management Server
After=network.target mysql.service
Requires=mysql.service

[Service]
Type=simple
User=lss-management
Group=lss-management
ExecStart=/usr/local/bin/lss-management-server
WorkingDirectory=/etc/lss-management
Environment=LSS_ENV=production
Environment=LSS_CONFIG=/etc/lss-management/config.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lss-management

# Hardening
NoNewPrivileges=false
PrivateTmp=true
ReadWritePaths=/etc/lss-management /var/log/lss-management /var/lib/lss-management

[Install]
WantedBy=multi-user.target
EOF
chown root:root "$SYSTEMD_UNIT"
chmod 644 "$SYSTEMD_UNIT"

systemctl daemon-reload
systemctl enable lss-management --quiet
info "systemd unit installed and enabled"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 10 — Configure nginx
# ═════════════════════════════════════════════════════════════════════════════
step 10 "Configuring nginx"

if [[ ! -f "$NGINX_AVAILABLE" ]]; then
    read -rp "Enter the domain name for this server (e.g. backup.example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        die "Domain name cannot be empty."
    fi

    cat > "$NGINX_AVAILABLE" <<NGINX
server {
    listen 80;
    server_name ${DOMAIN};

    location /ws/ {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           \$http_upgrade;
        proxy_set_header   Connection        "Upgrade";
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 1m;
    }

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        client_max_body_size 500m;
    }
}
NGINX
    chown root:root "$NGINX_AVAILABLE"
    chmod 644 "$NGINX_AVAILABLE"
    info "Wrote $NGINX_AVAILABLE"

    ln -sf "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    rm -f /etc/nginx/sites-enabled/default

    if ! nginx -t 2>/dev/null; then
        nginx -t || true
        die "nginx configuration test failed"
    fi

    systemctl reload nginx
    info "nginx reloaded"
else
    info "nginx config already exists — skipping"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 11 — Start/restart the service
# ═════════════════════════════════════════════════════════════════════════════
step 11 "Starting lss-management service"

if systemctl is-active --quiet lss-management; then
    systemctl restart lss-management
    info "Service restarted"
else
    systemctl start lss-management
    info "Service started"
fi

for i in {1..30}; do
    if systemctl is-active --quiet lss-management; then
        break
    fi
    sleep 1
done

if systemctl is-active --quiet lss-management; then
    info "${C_GREEN}Service is running${C_RESET}"
else
    error "Service failed to start. Run: journalctl -u lss-management -n 50"
    die "Installation incomplete"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 12 — Install update helper + backup cron
# ═════════════════════════════════════════════════════════════════════════════
step 12 "Installing update helper and backup cron"

# Server self-update helper (called via sudo from the dashboard)
cat > "$UPDATE_SCRIPT" <<'UPDATESCRIPT'
#!/bin/bash
STAGED="/var/lib/lss-management/update-staging"
TARGET="/usr/local/bin/lss-management-server"
if [ ! -f "$STAGED" ]; then
  echo "No staged update found"
  exit 1
fi
systemd-run --unit=lss-update --description="LSS server update" bash -c '
  sleep 1
  systemctl stop lss-management
  cp /var/lib/lss-management/update-staging /usr/local/bin/lss-management-server
  chmod 755 /usr/local/bin/lss-management-server
  rm -f /var/lib/lss-management/update-staging
  systemctl start lss-management
  echo "Update applied at $(date)" >> /var/log/lss-management/update.log
'
UPDATESCRIPT
chown root:root "$UPDATE_SCRIPT"
chmod 755 "$UPDATE_SCRIPT"

# Sudoers rule for the update helper
echo "$SERVICE_USER ALL=(root) NOPASSWD: $UPDATE_SCRIPT" > /etc/sudoers.d/lss-update
chmod 440 /etc/sudoers.d/lss-update
info "Update helper installed"

# Daily MySQL backup cron
cat > /usr/local/bin/lss-mgmt-backup.sh <<'BACKUPSCRIPT'
#!/bin/bash
set -euo pipefail
if [[ -f /etc/default/lss-mgmt-backup ]]; then
    . /etc/default/lss-mgmt-backup
fi
BACKUP_DIR="${LSS_BACKUP_DIR:-/var/backups/lss-mgmt}"
DB_NAME="${LSS_BACKUP_DB:-lss_management}"
DB_USER="${LSS_BACKUP_USER:-lss_mgmt}"
DB_PASS="${LSS_BACKUP_PASS:-}"
KEEP="${LSS_BACKUP_KEEP:-14}"
if [[ -z "$DB_PASS" ]]; then
    echo "[$(date -Is)] ERROR: LSS_BACKUP_PASS not set" >&2
    exit 1
fi
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/lss_management-$STAMP.sql.gz"
mysqldump --user="$DB_USER" --password="$DB_PASS" --single-transaction --routines --triggers --hex-blob --default-character-set=utf8mb4 "$DB_NAME" | gzip -9 > "$OUT"
chmod 600 "$OUT"
ls -1t "$BACKUP_DIR"/lss_management-*.sql.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f --
echo "[$(date -Is)] backup ok ($(stat -c %s "$OUT") bytes)"
BACKUPSCRIPT
chown root:root /usr/local/bin/lss-mgmt-backup.sh
chmod 750 /usr/local/bin/lss-mgmt-backup.sh

if [[ ! -f /etc/default/lss-mgmt-backup ]]; then
    umask 077
    cat > /etc/default/lss-mgmt-backup <<EOF
LSS_BACKUP_PASS="$DB_PASSWORD"
EOF
    umask 022
    chmod 600 /etc/default/lss-mgmt-backup
fi

CRONLINE='30 3 * * * /usr/local/bin/lss-mgmt-backup.sh >> /var/log/lss-mgmt-backup.log 2>&1'
if ! (crontab -u root -l 2>/dev/null || true) | grep -qF "lss-mgmt-backup.sh"; then
    ( (crontab -u root -l 2>/dev/null || true); echo "$CRONLINE" ) | crontab -u root -
    info "Backup cron installed (03:30 daily)"
else
    info "Backup cron already present"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Completion summary
# ═════════════════════════════════════════════════════════════════════════════
DISPLAY_DOMAIN="(not configured)"
if [[ -f "$NGINX_AVAILABLE" ]]; then
    extracted="$(grep -m1 -E '^\s*server_name' "$NGINX_AVAILABLE" | awk '{print $2}' | sed 's/;$//')"
    if [[ -n "$extracted" ]]; then
        DISPLAY_DOMAIN="$extracted"
    fi
fi

cat <<SUMMARY

============================================================
 LSS Management Server — Installation Complete
============================================================
 Version:    $VERSION
 Service:    lss-management (systemd, enabled)
 Binary:     $BINARY_PATH
 Config:     $CONFIG_FILE
 Logs:       journalctl -u lss-management -f

 Next steps:
   1. Visit https://$DISPLAY_DOMAIN/setup to create your superadmin account.
   2. If behind a reverse proxy (HAProxy / OPNsense), add:
        option http-server-close
        timeout tunnel 24h

 Important — back these up:
   $SECRET_KEY_FILE   (losing this = re-register all nodes)
============================================================
SUMMARY
