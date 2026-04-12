#!/usr/bin/env bash
#
# LSS Management Server — installation script
# Usage: sudo bash install/install.sh
#
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

step()  { echo; echo "${C_BLUE}[STEP $1/11]${C_RESET} $2"; }
info()  { echo "  ${C_GREEN}→${C_RESET} $*"; }
warn()  { echo "  ${C_YELLOW}⚠${C_RESET} $*"; }
error() { echo "${C_RED}✗ $*${C_RESET}" >&2; }
die()   { error "$*"; exit 1; }

# ─── Resolve repo root ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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
GO_MIN_VERSION="1.22"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 1 — Check prerequisites
# ═════════════════════════════════════════════════════════════════════════════
step 1 "Checking prerequisites"

if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Try: sudo bash install/install.sh"
fi

if [[ ! -f /etc/os-release ]]; then
    die "Cannot detect operating system (missing /etc/os-release)."
fi

# shellcheck disable=SC1091
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
apt-get install -y mysql-server nginx git openssl curl ca-certificates
info "Installed mysql-server, nginx, git, openssl, curl"

# Go check / install
install_go() {
    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       die "Unsupported architecture: $(uname -m)" ;;
    esac

    info "Fetching latest Go release info"
    local version
    version="$(curl -fsSL https://go.dev/VERSION?m=text | head -n1)"
    if [[ -z "$version" ]]; then
        die "Could not fetch latest Go version from go.dev"
    fi

    local tarball="${version}.linux-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    info "Downloading ${url}"
    curl -fsSL -o "/tmp/${tarball}" "$url"

    info "Installing Go to /usr/local/go"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
}

version_ge() {
    # returns 0 if $1 >= $2 (semver-ish)
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

GO_BIN="$(command -v go || true)"
NEED_GO_INSTALL=0
if [[ -z "$GO_BIN" ]]; then
    NEED_GO_INSTALL=1
else
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
    if ! version_ge "$current" "$GO_MIN_VERSION"; then
        info "Existing Go $current is older than $GO_MIN_VERSION"
        NEED_GO_INSTALL=1
    else
        info "Go $current already installed"
    fi
fi

if [[ $NEED_GO_INSTALL -eq 1 ]]; then
    install_go
fi
export PATH="/usr/local/go/bin:$PATH"
info "Using $(go version)"

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

mkdir -p "$CONFIG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

mkdir -p "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
chmod 750 "$LOG_DIR"

mkdir -p "$STATE_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
chmod 755 "$STATE_DIR"

info "Config dir: $CONFIG_DIR"
info "Log dir:    $LOG_DIR"
info "State dir:  $STATE_DIR"

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
        die "lss_mgmt exists but $DB_PASSWORD_FILE is missing. Cannot recover password automatically. Reset with: ALTER USER 'lss_mgmt'@'localhost' IDENTIFIED BY 'new-password';"
    fi
    DB_PASSWORD="$(cat "$DB_PASSWORD_FILE")"
    # Ensure the database exists (idempotent)
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

    cat <<BANNER

============================================================
 IMPORTANT — SECRET KEY GENERATED
============================================================
 A secret key has been saved to:
   $SECRET_KEY_FILE

 This key encrypts all node PSK keys in the database.
 If this file is lost, every node must be re-registered.

 Back this file up to a secure location NOW.
 Press Enter to continue...
============================================================
BANNER
    read -r _
else
    info "Secret key already exists — skipping generation"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6 — Provision the reverse-tunnel SSH user
# ═════════════════════════════════════════════════════════════════════════════
step 6 "Provisioning reverse-tunnel SSH user"

# Restricted user that nodes use to hold persistent reverse tunnels.
# Cannot get a shell, cannot open PTYs, can only establish TCP port forwards.
if ! id "$TUNNEL_USER" &>/dev/null; then
    useradd --system --create-home --shell /usr/sbin/nologin "$TUNNEL_USER"
    info "Created user: $TUNNEL_USER"
else
    info "User $TUNNEL_USER already exists"
fi

# Ensure ~lss-tunnel/.ssh exists with correct perms even though we rely on
# AuthorizedKeysCommand instead of a literal authorized_keys file — some
# OpenSSH versions still probe the home dir.
TUNNEL_HOME="$(getent passwd "$TUNNEL_USER" | cut -d: -f6)"
mkdir -p "$TUNNEL_HOME/.ssh"
chown "$TUNNEL_USER:$TUNNEL_USER" "$TUNNEL_HOME/.ssh"
chmod 700 "$TUNNEL_HOME/.ssh"
: > "$TUNNEL_HOME/.ssh/authorized_keys"
chown "$TUNNEL_USER:$TUNNEL_USER" "$TUNNEL_HOME/.ssh/authorized_keys"
chmod 600 "$TUNNEL_HOME/.ssh/authorized_keys"

# authorized_keys file maintained by lss-management.
touch "$TUNNEL_AUTHKEYS_FILE"
chown "$SERVICE_USER:$SERVICE_USER" "$TUNNEL_AUTHKEYS_FILE"
chmod 644 "$TUNNEL_AUTHKEYS_FILE"

# Helper script sshd invokes via AuthorizedKeysCommand. It just cats the file.
cat > "$TUNNEL_AUTHKEYS_SCRIPT" <<'SCRIPT'
#!/bin/bash
# Invoked by sshd for the lss-tunnel user. Emits the current authorized_keys
# contents from the file maintained by the lss-management service.
if [[ "$1" != "lss-tunnel" ]]; then
    exit 0
fi
cat /var/lib/lss-management/tunnel_authorized_keys 2>/dev/null
SCRIPT
chown root:root "$TUNNEL_AUTHKEYS_SCRIPT"
chmod 0755 "$TUNNEL_AUTHKEYS_SCRIPT"

# sshd drop-in that only applies to the lss-tunnel user.
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
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    info "sshd reloaded with drop-in $SSHD_DROPIN"
else
    warn "sshd config test failed — tunnel drop-in not applied; run 'sshd -t' to inspect"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 7 — Build the binary
# ═════════════════════════════════════════════════════════════════════════════
step 7 "Building the binary"

cd "$REPO_ROOT"
GIT_VERSION="$(cd "$REPO_ROOT" && git describe --tags --abbrev=0 2>/dev/null || echo 'dev')"
info "Running: go build -ldflags \"-X main.Version=$GIT_VERSION\" -o $BINARY_PATH ./cmd/server"
LSS_ENV=production go build -ldflags "-X main.Version=$GIT_VERSION" -o "$BINARY_PATH" ./cmd/server
chown root:root "$BINARY_PATH"
chmod 755 "$BINARY_PATH"
info "Binary installed at $BINARY_PATH"

# Install runtime assets (templates, migrations, static) into the working dir.
# The Go server reads these relative to its WorkingDirectory (/etc/lss-management).
info "Installing runtime assets to $CONFIG_DIR"
for asset in templates migrations static; do
    if [[ -d "$REPO_ROOT/$asset" ]]; then
        rm -rf "$CONFIG_DIR/$asset"
        cp -r "$REPO_ROOT/$asset" "$CONFIG_DIR/$asset"
        chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/$asset"
        find "$CONFIG_DIR/$asset" -type d -exec chmod 755 {} \;
        find "$CONFIG_DIR/$asset" -type f -exec chmod 644 {} \;
    fi
done

# ═════════════════════════════════════════════════════════════════════════════
# STEP 7 — Write config file
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
EOF
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    info "Config written: $CONFIG_FILE"
else
    info "Config already exists — skipping (upgrade-safe)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 8 — Install systemd unit
# ═════════════════════════════════════════════════════════════════════════════
step 9 "Installing systemd unit"

cp "$REPO_ROOT/install/lss-management.service" "$SYSTEMD_UNIT"
chown root:root "$SYSTEMD_UNIT"
chmod 644 "$SYSTEMD_UNIT"

systemctl daemon-reload
systemctl enable lss-management --quiet
info "systemd unit installed and enabled"

# ═════════════════════════════════════════════════════════════════════════════
# STEP 9 — Configure nginx
# ═════════════════════════════════════════════════════════════════════════════
step 10 "Configuring nginx"

if [[ ! -f "$NGINX_AVAILABLE" ]]; then
    read -rp "Enter the domain name for this server (e.g. backup.example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        die "Domain name cannot be empty."
    fi

    sed "s/<DOMAIN>/${DOMAIN}/g" \
        "$REPO_ROOT/install/nginx-example.conf" > "$NGINX_AVAILABLE"
    chown root:root "$NGINX_AVAILABLE"
    chmod 644 "$NGINX_AVAILABLE"
    info "Wrote $NGINX_AVAILABLE"

    ln -sf "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    rm -f /etc/nginx/sites-enabled/default

    if ! nginx -t 2>/dev/null; then
        error "nginx -t failed. Running again with output:"
        nginx -t || true
        die "nginx configuration test failed — aborting"
    fi

    systemctl reload nginx
    info "nginx reloaded"
else
    info "nginx config already exists — skipping"
fi

# ═════════════════════════════════════════════════════════════════════════════
# STEP 10 — Start/restart the service
# ═════════════════════════════════════════════════════════════════════════════
step 11 "Starting lss-management service"

if systemctl is-active --quiet lss-management; then
    systemctl restart lss-management
    info "Service restarted"
else
    systemctl start lss-management
    info "Service started"
fi

sleep 3

if systemctl is-active --quiet lss-management; then
    info "${C_GREEN}Service is running${C_RESET}"
else
    error "Service failed to start. Run:"
    error "    journalctl -u lss-management -n 50"
    die "Installation incomplete"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Completion summary
# ═════════════════════════════════════════════════════════════════════════════
VERSION="$(cd "$REPO_ROOT" && git describe --tags --always 2>/dev/null || echo 'unknown')"
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
   1. Ensure DNS A record for $DISPLAY_DOMAIN points to this server.
   2. Obtain SSL certificate:
        sudo apt install certbot python3-certbot-nginx
        sudo certbot --nginx -d $DISPLAY_DOMAIN
        sudo systemctl reload nginx
   3. Visit https://$DISPLAY_DOMAIN/setup to create your superadmin account.
      Default password: lssbackuppassword (must be changed on first login).

 If behind a reverse proxy (e.g. HAProxy / OPNsense):
   Add these to the backend configuration for this server:
     option http-server-close
     timeout tunnel 24h
   Without these, WebSocket connections (SSH tunnels, terminal)
   will be killed after the proxy's default idle timeout.

 Important files to back up:
   $SECRET_KEY_FILE   (losing this = re-register all nodes)
   $DB_PASSWORD_FILE  (MySQL credentials)
   MySQL database dump
============================================================
SUMMARY
