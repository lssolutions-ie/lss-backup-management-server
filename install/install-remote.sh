#!/usr/bin/env bash
#
# LSS Backup Server — remote installation script
#
# Usage:
#   Behind a reverse proxy (HAProxy/OPNsense):
#     export LSS_DOMAIN=backup.example.com
#     curl -fsSL https://raw.githubusercontent.com/.../install-remote.sh | bash -s -- --proxy
#
#   Direct VPS (public-facing, full hardening + SSL):
#     export LSS_DOMAIN=backup.example.com
#     curl -fsSL https://raw.githubusercontent.com/.../install-remote.sh | bash -s -- --vps
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

info()  { echo "  ${C_GREEN}→${C_RESET} $*"; }
warn()  { echo "  ${C_YELLOW}⚠${C_RESET} $*"; }
error() { echo "${C_RED}✗ $*${C_RESET}" >&2; }
die()   { error "$*"; exit 1; }

GITHUB_REPO="lssolutions-ie/lss-backup-server"

# ─── Parse arguments ────────────────────────────────────────────────────────
MODE=""
DOMAIN="${LSS_DOMAIN:-}"
SSH_PUBKEY="${LSS_SSH_PUBKEY:-}"

for arg in "$@"; do
    case "$arg" in
        --proxy) MODE="proxy" ;;
        --vps)   MODE="vps" ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$arg"
            fi
            ;;
    esac
done

if [[ -z "$MODE" ]]; then
    die "Please specify --proxy or --vps

  --proxy  Behind a reverse proxy (HAProxy/OPNsense). Skips SSL and VPS hardening.
  --vps    Direct public-facing VPS. Full hardening: SSL, fail2ban, SSH key-only, firewall.

  Example:
    export LSS_DOMAIN=backup.example.com
    curl -fsSL https://raw.githubusercontent.com/.../install-remote.sh | bash -s -- --vps"
fi

if [[ "$MODE" == "proxy" ]]; then
    TOTAL_STEPS=13
else
    TOTAL_STEPS=15
fi

step() { echo; echo "${C_BLUE}[STEP $1/$TOTAL_STEPS]${C_RESET} $2"; }

info "Install mode: ${C_YELLOW}${MODE}${C_RESET}"

# ─── Constants ───────────────────────────────────────────────────────────────
SERVICE_USER="lss-backup-server"
CONFIG_DIR="/etc/lss-backup-server"
STATE_DIR="/var/lib/lss-backup-server"
LOG_DIR="/var/log/lss-backup-server"
SECRET_KEY_FILE="$CONFIG_DIR/secret.key"
DB_PASSWORD_FILE="$CONFIG_DIR/db.password"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BINARY_PATH="/usr/local/bin/lss-backup-server"
SYSTEMD_UNIT="/etc/systemd/system/lss-backup-server.service"
NGINX_AVAILABLE="/etc/nginx/sites-available/lss-backup-server"
NGINX_ENABLED="/etc/nginx/sites-enabled/lss-backup-server"
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
    die "This script must be run as root."
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
PACKAGES="mysql-server nginx openssl curl ca-certificates cron restic"
if [[ "$MODE" == "vps" ]]; then
    PACKAGES="$PACKAGES fail2ban ufw"
fi
apt-get install -y $PACKAGES
info "System dependencies installed"

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
    "SELECT COUNT(*) FROM mysql.user WHERE user='lss_backup_server' AND host='localhost';")"

if [[ "$user_exists" == "0" ]]; then
    DB_PASSWORD="$(openssl rand -base64 24)"
    mysql <<SQL
CREATE USER IF NOT EXISTS 'lss_backup_server'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
CREATE DATABASE IF NOT EXISTS lss_backup_server CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON lss_backup_server.* TO 'lss_backup_server'@'localhost';
FLUSH PRIVILEGES;
SQL
    umask 077
    printf '%s' "$DB_PASSWORD" > "$DB_PASSWORD_FILE"
    umask 022
    chown "$SERVICE_USER:$SERVICE_USER" "$DB_PASSWORD_FILE"
    chmod 600 "$DB_PASSWORD_FILE"
    info "MySQL configured"
else
    info "MySQL user already exists — skipping"
    if [[ ! -f "$DB_PASSWORD_FILE" ]]; then
        die "lss_backup_server exists but $DB_PASSWORD_FILE is missing."
    fi
    DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
    mysql -e "CREATE DATABASE IF NOT EXISTS lss_backup_server CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
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
cat /var/lib/lss-backup-server/tunnel_authorized_keys 2>/dev/null
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
curl -fsSL -o "$BINARY_PATH" "$DOWNLOAD_URL"
chown root:root "$BINARY_PATH"
chmod 755 "$BINARY_PATH"
info "Binary installed at $BINARY_PATH"

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
info "Runtime assets installed"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 8 — Write config file
# ═════════════════════════════════════════════════════════════════════════════
step 8 "Writing config file"

if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<EOF
[server]
listen_addr = "127.0.0.1:8080"

[database]
dsn = "lss_backup_server:${DB_PASSWORD}@tcp(localhost:3306)/lss_backup_server?parseTime=true&loc=Local"

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
    info "Config written"
else
    info "Config already exists — skipping"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 9 — Install systemd unit
# ═════════════════════════════════════════════════════════════════════════════
step 9 "Installing systemd unit"

cat > "$SYSTEMD_UNIT" <<'EOF'
[Unit]
Description=LSS Backup Server
After=network.target mysql.service
Requires=mysql.service

[Service]
Type=simple
User=lss-backup-server
Group=lss-backup-server
ExecStart=/usr/local/bin/lss-backup-server
WorkingDirectory=/etc/lss-backup-server
Environment=LSS_ENV=production
Environment=LSS_CONFIG=/etc/lss-backup-server/config.toml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lss-backup-server

# Hardening
NoNewPrivileges=false
PrivateTmp=true
ReadWritePaths=/etc/lss-backup-server /var/log/lss-backup-server /var/lib/lss-backup-server

[Install]
WantedBy=multi-user.target
EOF
chown root:root "$SYSTEMD_UNIT"
chmod 644 "$SYSTEMD_UNIT"
systemctl daemon-reload
systemctl enable lss-backup-server --quiet
info "systemd unit installed"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 10 — Configure nginx
# ═════════════════════════════════════════════════════════════════════════════
step 10 "Configuring nginx"

if [[ ! -f "$NGINX_AVAILABLE" ]]; then
    if [[ -z "$DOMAIN" ]]; then
        read -rp "Enter the domain name for this server (e.g. backup.example.com): " DOMAIN < /dev/tty || true
    fi
    if [[ -z "$DOMAIN" ]]; then
        die "Domain name required. Set LSS_DOMAIN env var."
    fi
    info "Configuring nginx for: $DOMAIN"

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
    ln -sf "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    rm -f /etc/nginx/sites-enabled/default
    nginx -t 2>/dev/null || die "nginx config test failed"
    systemctl reload nginx
    info "nginx configured"
else
    info "nginx config already exists — skipping"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 11 — Start/restart service
# ═════════════════════════════════════════════════════════════════════════════
step 11 "Starting lss-backup-server service"

if systemctl is-active --quiet lss-backup-server; then
    systemctl restart lss-backup-server
    info "Service restarted"
else
    systemctl start lss-backup-server
    info "Service started"
fi

for i in {1..30}; do
    systemctl is-active --quiet lss-backup-server && break
    sleep 1
done

if systemctl is-active --quiet lss-backup-server; then
    info "${C_GREEN}Service is running${C_RESET}"
else
    die "Service failed to start. Run: journalctl -u lss-backup-server -n 50"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 12 — Install update helper + backup cron
# ═════════════════════════════════════════════════════════════════════════════
step 12 "Installing update helper and backup cron"

cat > "$UPDATE_SCRIPT" <<'UPDATESCRIPT'
#!/bin/bash
STAGED="/var/lib/lss-backup-server/update-staging"
TARGET="/usr/local/bin/lss-backup-server"
if [ ! -f "$STAGED" ]; then
  echo "No staged update found"
  exit 1
fi
systemd-run --unit=lss-update --description="LSS server update" bash -c '
  sleep 1
  systemctl stop lss-backup-server
  cp /var/lib/lss-backup-server/update-staging /usr/local/bin/lss-backup-server
  chmod 755 /usr/local/bin/lss-backup-server
  rm -f /var/lib/lss-backup-server/update-staging
  systemctl start lss-backup-server
  echo "Update applied at $(date)" >> /var/log/lss-backup-server/update.log
'
UPDATESCRIPT
chown root:root "$UPDATE_SCRIPT"
chmod 755 "$UPDATE_SCRIPT"
echo "$SERVICE_USER ALL=(root) NOPASSWD: $UPDATE_SCRIPT" > /etc/sudoers.d/lss-update
chmod 440 /etc/sudoers.d/lss-update
info "Update helper installed"

cat > /usr/local/bin/lss-backup-server-db.sh <<'BACKUPSCRIPT'
#!/bin/bash
set -euo pipefail
[[ -f /etc/default/lss-backup-server-db ]] && . /etc/default/lss-backup-server-db
BACKUP_DIR="${LSS_BACKUP_DIR:-/var/backups/lss-backup-server-db}"
DB_NAME="${LSS_BACKUP_DB:-lss_backup_server}"
DB_USER="${LSS_BACKUP_USER:-lss_backup_server}"
DB_PASS="${LSS_BACKUP_PASS:-}"
KEEP="${LSS_BACKUP_KEEP:-14}"
[[ -z "$DB_PASS" ]] && { echo "[$(date -Is)] ERROR: LSS_BACKUP_PASS not set" >&2; exit 1; }
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/lss_backup_server-$STAMP.sql.gz"
mysqldump --user="$DB_USER" --password="$DB_PASS" --single-transaction --routines --triggers --hex-blob --default-character-set=utf8mb4 "$DB_NAME" | gzip -9 > "$OUT"
chmod 600 "$OUT"
ls -1t "$BACKUP_DIR"/lss_backup_server-*.sql.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f --
echo "[$(date -Is)] backup ok ($(stat -c %s "$OUT") bytes)"
BACKUPSCRIPT
chown root:root /usr/local/bin/lss-backup-server-db.sh
chmod 750 /usr/local/bin/lss-backup-server-db.sh

if [[ ! -f /etc/default/lss-backup-server-db ]]; then
    umask 077
    printf 'LSS_BACKUP_PASS="%s"\n' "$DB_PASSWORD" > /etc/default/lss-backup-server-db
    umask 022
    chmod 600 /etc/default/lss-backup-server-db
fi

CRONLINE='30 3 * * * /usr/local/bin/lss-backup-server-db.sh >> /var/log/lss-backup-server-db.log 2>&1'
if ! (crontab -u root -l 2>/dev/null || true) | grep -qF "lss-backup-server-db.sh"; then
    ( (crontab -u root -l 2>/dev/null || true); echo "$CRONLINE" ) | crontab -u root -
    info "Backup cron installed (03:30 daily)"
else
    info "Backup cron already present"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 13 — Install fail2ban (both modes)
# ═════════════════════════════════════════════════════════════════════════════
step 13 "Configuring fail2ban"

if command -v fail2ban-client &>/dev/null; then
    cat > /etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled  = true
port     = ssh
maxretry = 3

[nginx-http-auth]
enabled = true
port    = http,https

[nginx-botsearch]
enabled = true
port    = http,https
JAIL
    systemctl enable fail2ban --quiet
    systemctl restart fail2ban
    info "fail2ban configured (3 jails)"
else
    apt-get install -y fail2ban 2>&1 | tail -1
    # Re-run this step
    cat > /etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled  = true
port     = ssh
maxretry = 3

[nginx-http-auth]
enabled = true
port    = http,https

[nginx-botsearch]
enabled = true
port    = http,https
JAIL
    systemctl enable fail2ban --quiet
    systemctl restart fail2ban
    info "fail2ban installed and configured"
fi

# ═════════════════════════════════════════════════════════════════════════════
# VPS-ONLY STEPS (14-15)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "vps" ]]; then

# ═════════════════════════════════════════════════════════════════════════════
# STEP 14 — VPS hardening (SSH, nginx headers, kernel, firewall)
# ═════════════════════════════════════════════════════════════════════════════
step 14 "Hardening server (VPS mode)"

# ── SSH key setup ──
mkdir -p /root/.ssh
chmod 700 /root/.ssh

if [[ -n "$SSH_PUBKEY" ]]; then
    echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
    info "SSH public key added from LSS_SSH_PUBKEY"
elif [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    info "SSH authorized_keys already has keys"
else
    warn "No SSH key found. Add your public key to /root/.ssh/authorized_keys BEFORE logging out!"
    warn "  echo 'ssh-ed25519 AAAA...' >> /root/.ssh/authorized_keys"
fi

if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    chmod 600 /root/.ssh/authorized_keys

    # Harden SSH — disable password auth
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
    info "SSH hardened: key-only, root prohibit-password, max 3 attempts"
else
    warn "SSH password auth LEFT ENABLED — no authorized_keys found"
    warn "Add your key and re-run, or manually disable PasswordAuthentication"
fi

# ── Nginx security headers ──
cat > /etc/nginx/conf.d/security-headers.conf <<'HEADERS'
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=()" always;
HEADERS
sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf 2>/dev/null
sed -i 's/server_tokens on;/server_tokens off;/' /etc/nginx/nginx.conf 2>/dev/null
nginx -t 2>/dev/null && systemctl reload nginx
info "Nginx: server tokens hidden, security headers added"

# ── Kernel hardening ──
cat > /etc/sysctl.d/99-lss-hardening.conf <<'SYSCTL'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-lss-hardening.conf >/dev/null 2>&1
info "Kernel hardened: SYN flood protection, ICMP hardened"

# ── Firewall ──
ufw allow 22/tcp >/dev/null 2>&1
ufw allow 80/tcp >/dev/null 2>&1
ufw allow 443/tcp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
info "Firewall: SSH + HTTP + HTTPS only"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 15 — SSL certificate (VPS mode)
# ═════════════════════════════════════════════════════════════════════════════
step 15 "Installing SSL certificate"

if [[ -n "$DOMAIN" ]]; then
    apt-get install -y certbot python3-certbot-nginx 2>&1 | tail -1
    if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>&1; then
        info "SSL certificate installed for $DOMAIN"
    else
        warn "Certbot failed — check DNS points to this server's IP"
        warn "Run manually: certbot --nginx -d $DOMAIN"
    fi
else
    warn "No domain set — skipping SSL. Run: certbot --nginx -d yourdomain.com"
fi

fi # end VPS-only steps

# ═════════════════════════════════════════════════════════════════════════════
# Completion summary
# ═════════════════════════════════════════════════════════════════════════════
DISPLAY_DOMAIN="${DOMAIN:-(not configured)}"

if [[ "$MODE" == "vps" ]]; then
    PROTOCOL="https"
else
    PROTOCOL="http"
fi

cat <<SUMMARY

============================================================
 LSS Backup Server — Installation Complete ($MODE mode)
============================================================
 Version:    $VERSION
 Mode:       $MODE
 Service:    lss-backup-server (systemd, enabled)
 Binary:     $BINARY_PATH
 Config:     $CONFIG_FILE
 Logs:       journalctl -u lss-backup-server -f

 Next steps:
   1. Visit ${PROTOCOL}://$DISPLAY_DOMAIN/setup to create your superadmin account.
SUMMARY

if [[ "$MODE" == "proxy" ]]; then
    cat <<PROXY
   2. Configure your reverse proxy to forward to this server on port 80.
      HAProxy backend settings:
        option http-server-close
        timeout tunnel 24h
PROXY
fi

cat <<FINAL

 Important — back these up:
   $SECRET_KEY_FILE   (losing this = re-register all nodes)
============================================================
FINAL
