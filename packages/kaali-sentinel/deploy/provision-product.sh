#!/usr/bin/env bash
# Kaali — per-product isolation provisioner. RUN THIS ON YOUR VPS as a sudoer.
#
# The lesson of the pakchoi compromise: the box was FLAT — one root, every app
# under /root, every .env harvestable in one place. One foothold owned all 13
# projects. This script provisions ONE product into its own locked, sandboxed
# lane so a compromise of one app cannot read another's files, secrets, or DB.
#
# Idempotent: safe to re-run. It never deletes data.
#
#   sudo bash provision-product.sh vyrel --port 4321 --db --run "node server.js"
#   sudo bash provision-product.sh bodh  --port 4900 --db --repo https://github.com/starvoxlabs89-design/bodh.git --run "npm start"
#   sudo bash provision-product.sh trst  --port 4700 --db --dry-run     # preview, write nothing
#
# What ONE product gets:
#   • a locked system user  <product>  (no login shell, home = /srv/<product>, 700)
#   • /srv/<product>/{app,data}  owned <product>:<product>, 700  (siblings can't read it)
#   • an ISOLATED Postgres role + database <product> with its own password;
#     PUBLIC can't connect to it, and the role can't reach other products' DBs
#   • a HARDENED systemd unit (User=<product> + full sandbox: ProtectSystem=strict,
#     ProtectHome, PrivateTmp, NoNewPrivileges, empty CapabilityBoundingSet,
#     ReadWritePaths=/srv/<product> only) — the app is jailed to its own directory
#   • a .env at /srv/<product>/.env, chmod 600, owned by the product user

set -euo pipefail

# --- 0. Args -----------------------------------------------------------------
PRODUCT="${1:-}"; shift || true
PORT=""; REPO=""; RUN_CMD=""; WANT_DB=0; DRY_RUN=0; TAKE_BASELINE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     PORT="$2"; shift 2 ;;
    --repo)     REPO="$2"; shift 2 ;;
    --run)      RUN_CMD="$2"; shift 2 ;;
    --db)       WANT_DB=1; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    --baseline) TAKE_BASELINE=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

step() { printf "\n\033[1;36m➤ %s\033[0m\n" "$*"; }
info() { printf "  %s\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
die()  { printf "\033[1;31m✗ %s\033[0m\n" "$*" >&2; exit 1; }

# --- 1. Validate -------------------------------------------------------------
[[ -n "$PRODUCT" ]] || die "usage: provision-product.sh <product> [--port N] [--db] [--repo URL] [--run \"cmd\"] [--dry-run]"
[[ "$PRODUCT" =~ ^[a-z][a-z0-9_-]{1,30}$ ]] || die "product name must be lower-case [a-z0-9_-], starting with a letter"
case "$PRODUCT" in
  root|postgres|daemon|bin|sys|nobody|www-data|sshd|systemd*|kaali)
    die "'$PRODUCT' is a reserved/system name — pick another" ;;
esac
if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then die "run as root (sudo)"; fi

HOME_DIR="/srv/$PRODUCT"
APP_DIR="$HOME_DIR/app"
DATA_DIR="$HOME_DIR/data"
ENV_FILE="$HOME_DIR/.env"
UNIT="/etc/systemd/system/$PRODUCT.service"
DB_NAME="$PRODUCT"; DB_USER="$PRODUCT"

run() { if [[ $DRY_RUN -eq 1 ]]; then printf "  [dry-run] %s\n" "$*"; else eval "$@"; fi; }

step "Provisioning isolated lane for '$PRODUCT'${DRY_RUN:+ }$([[ $DRY_RUN -eq 1 ]] && echo '(DRY RUN — nothing will be written)')"

# --- 2. Locked system user ---------------------------------------------------
step "System user + locked home"
if id -u "$PRODUCT" >/dev/null 2>&1; then
  info "user '$PRODUCT' already exists — leaving it"
else
  run "useradd --system --no-create-home --home-dir '$HOME_DIR' --shell /usr/sbin/nologin '$PRODUCT'"
  info "created locked system user '$PRODUCT' (nologin shell, no password)"
fi
run "mkdir -p '$APP_DIR' '$DATA_DIR'"
run "chown -R '$PRODUCT:$PRODUCT' '$HOME_DIR'"
run "chmod 700 '$HOME_DIR' '$APP_DIR' '$DATA_DIR'"   # siblings + other service users cannot traverse in
info "home $HOME_DIR is 700, owned by $PRODUCT — no other product user can read it"

# --- 3. Code (optional) ------------------------------------------------------
if [[ -n "$REPO" ]]; then
  step "Fetching code from $REPO"
  if [[ -d "$APP_DIR/.git" ]]; then
    run "sudo -u '$PRODUCT' git -C '$APP_DIR' pull --ff-only"
  else
    run "sudo -u '$PRODUCT' git clone '$REPO' '$APP_DIR'"
  fi
fi

# --- 4. Isolated Postgres role + database ------------------------------------
DB_URL=""
if [[ $WANT_DB -eq 1 ]]; then
  step "Isolated Postgres role + database '$DB_NAME'"
  have psql || info "note: postgres client not found — install 'postgresql' first if the DB step fails"
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] CREATE USER $DB_USER WITH PASSWORD '<random>';"
    info "[dry-run] CREATE DATABASE $DB_NAME OWNER $DB_USER;"
    info "[dry-run] REVOKE CONNECT ON DATABASE $DB_NAME FROM PUBLIC; GRANT CONNECT ... TO $DB_USER;"
    DB_URL="postgres://$DB_USER:<random>@127.0.0.1:5432/$DB_NAME"
  else
    if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
      info "role '$DB_USER' exists — reusing (password unchanged)"
      DB_PASS="$(grep -s '^DB_PASS=' "$HOME_DIR/.db_credentials" | cut -d= -f2- || true)"
      [[ -n "$DB_PASS" ]] || info "  (no stored password found; DATABASE_URL will need a manual password)"
    else
      DB_PASS="$(openssl rand -hex 24)"
      sudo -u postgres psql -qc "CREATE USER \"$DB_USER\" WITH PASSWORD '$DB_PASS';"
      printf 'DB_PASS=%s\n' "$DB_PASS" > "$HOME_DIR/.db_credentials"
      chown "$PRODUCT:$PRODUCT" "$HOME_DIR/.db_credentials"; chmod 600 "$HOME_DIR/.db_credentials"
      info "generated DB password → $HOME_DIR/.db_credentials (600)"
    fi
    sudo -u postgres psql -lqt | cut -d\| -f1 | grep -qw "$DB_NAME" \
      || sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
    # Lock the database: only this role may connect; PUBLIC cannot.
    sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "$DB_NAME" >/dev/null <<SQL
REVOKE CONNECT ON DATABASE "$DB_NAME" FROM PUBLIC;
GRANT  CONNECT ON DATABASE "$DB_NAME" TO "$DB_USER";
GRANT  ALL ON SCHEMA public TO "$DB_USER";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
    info "database '$DB_NAME' locked: PUBLIC connect revoked, only role '$DB_USER' may connect"
    [[ -n "${DB_PASS:-}" ]] && DB_URL="postgres://$DB_USER:$DB_PASS@127.0.0.1:5432/$DB_NAME"
  fi
fi

# --- 5. .env (secrets, 600) --------------------------------------------------
step ".env (locked to the product user)"
if [[ -f "$ENV_FILE" ]]; then
  info "$ENV_FILE exists — leaving it (not overwriting secrets)"
else
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] would write $ENV_FILE (600, owner $PRODUCT) with PORT/SESSION_SECRET${DB_URL:+/DATABASE_URL}"
  else
    { echo "# $PRODUCT — provisioned $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      [[ -n "$PORT" ]]   && echo "PORT=$PORT"
      [[ -n "$DB_URL" ]] && echo "DATABASE_URL=$DB_URL"
      echo "SESSION_SECRET=$(openssl rand -hex 32)"
      echo "DATA_DIR=$DATA_DIR"
    } > "$ENV_FILE"
    chown "$PRODUCT:$PRODUCT" "$ENV_FILE"; chmod 600 "$ENV_FILE"
    info "wrote $ENV_FILE (600, owner $PRODUCT) — fill in provider keys, then restart"
  fi
fi

# --- 6. Hardened systemd unit ------------------------------------------------
step "Hardened systemd unit → $UNIT"
UNIT_CONTENT="$(cat <<UNITEOF
[Unit]
Description=$PRODUCT (Kaali-isolated)
After=network.target postgresql.service

[Service]
Type=simple
User=$PRODUCT
Group=$PRODUCT
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=${RUN_CMD:-/bin/false  # set with --run \"node server.js\"}
Restart=on-failure
RestartSec=3

# ---- blast-radius containment (this is the point) ----
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$HOME_DIR
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
# MemoryDenyWriteExecute=yes   # strongest, but breaks some Node/V8 + native addons — enable + test per app

[Install]
WantedBy=multi-user.target
UNITEOF
)"

if [[ $DRY_RUN -eq 1 ]]; then
  echo "  ---- would write $UNIT ----"
  echo "$UNIT_CONTENT" | sed 's/^/  /'
  echo "  ---------------------------"
else
  echo "$UNIT_CONTENT" > "$UNIT"
  systemctl daemon-reload
  systemctl enable "$PRODUCT" >/dev/null 2>&1 || true
  if [[ -n "$RUN_CMD" ]]; then
    systemctl restart "$PRODUCT"
    sleep 2
    if systemctl is-active --quiet "$PRODUCT"; then
      info "✓ $PRODUCT is running as user '$PRODUCT'${PORT:+ on 127.0.0.1:$PORT}"
    else
      info "✗ $PRODUCT failed to start — check: journalctl -u $PRODUCT -n 50"
    fi
  else
    info "unit installed but not started (no --run given). Set ExecStart in $UNIT, then: systemctl start $PRODUCT"
  fi
fi

# --- 7. Postgres exposure sanity check ---------------------------------------
if [[ $WANT_DB -eq 1 && $DRY_RUN -eq 0 ]]; then
  step "Postgres exposure check"
  if have ss && ss -tlnH 2>/dev/null | grep -q ':5432' && ! ss -tlnH 2>/dev/null | grep ':5432' | grep -qE '127\.0\.0\.1|::1'; then
    info "⚠ Postgres appears to listen on a non-localhost address. Set listen_addresses='localhost' in postgresql.conf and reload."
  else
    info "✓ Postgres not exposed beyond localhost"
  fi
fi

# --- 8. Optional Kaali Sentinel baseline -------------------------------------
if [[ $TAKE_BASELINE -eq 1 && $DRY_RUN -eq 0 ]]; then
  step "Recording a Kaali Sentinel baseline (post-provision known-good state)"
  SENTINEL="$(dirname "$0")/../host-scan.js"
  [[ -f "$SENTINEL" ]] && node "$SENTINEL" --save-baseline >/dev/null 2>&1 \
    && info "baseline saved to /var/lib/kaali/baseline.json" \
    || info "sentinel not found next to this script — run host-scan.js --save-baseline manually"
fi

# --- 9. Summary --------------------------------------------------------------
cat <<EOF

$([[ $DRY_RUN -eq 1 ]] && echo "✅ Dry run complete — nothing was written." || echo "✅ '$PRODUCT' is provisioned and isolated.")

Isolation guarantees:
  • runs as locked user '$PRODUCT' — cannot log in, cannot read other products' homes
  • jailed to $HOME_DIR (ProtectSystem=strict + ReadWritePaths); the rest of the FS is read-only
  • no capabilities, no new privileges, private /tmp — a foothold here can't pivot to the host$([[ $WANT_DB -eq 1 ]] && echo "
  • its own Postgres DB '$DB_NAME' with a unique password; PUBLIC connect revoked — a leaked
    credential for another product cannot reach this database, and vice-versa")

Next:
  1. $([[ -n "$RUN_CMD" ]] && echo "verify: systemctl status $PRODUCT" || echo "set ExecStart in $UNIT (or re-run with --run \"...\"), then: systemctl start $PRODUCT")
  2. fill provider keys in $ENV_FILE (chmod 600), then: systemctl restart $PRODUCT
  3. front it with nginx on 127.0.0.1:${PORT:-<port>} and issue a TLS cert
  4. after all products are provisioned, take a fresh baseline:  host-scan.js --save-baseline
EOF
