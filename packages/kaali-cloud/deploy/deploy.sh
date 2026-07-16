#!/usr/bin/env bash
# Kaali Cloud one-shot deploy — RUN THIS ON YOUR VPS as a sudoer.
# Idempotent: safe to re-run.
#
#   curl -fsSL https://raw.githubusercontent.com/starvoxlabs89-design/kaali/main/packages/kaali-cloud/deploy/deploy.sh | sudo bash
# or after `git clone` on the VPS:
#   cd kaali/packages/kaali-cloud && sudo bash deploy/deploy.sh

set -euo pipefail

# --- 0. Config ---------------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/starvoxlabs89-design/kaali.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/kaali}"
SVC_USER="${SVC_USER:-kaali}"
PRIMARY_HOST="${PRIMARY_HOST:-kaali.io}"          # apex — landing + app + OAuth base
API_HOST="${API_HOST:-api.kaali.io}"
APP_HOST="${APP_HOST:-app.kaali.io}"
DB_NAME="${DB_NAME:-kaali}"
DB_USER="${DB_USER:-kaali}"
# All four hosts share one cert; kaali.io FIRST so the lineage is /live/kaali.io/.
CERT_HOSTS=(-d "$PRIMARY_HOST" -d "www.$PRIMARY_HOST" -d "$APP_HOST" -d "$API_HOST")
CERT_DIR="/etc/letsencrypt/live/$PRIMARY_HOST"

step() { printf "\n\033[1;36m➤ %s\033[0m\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. Packages -------------------------------------------------------------
step "Installing packages (nodejs 20, postgres, nginx, certbot)"
if ! have node || [[ "$(node -v)" != v20.* && "$(node -v)" != v21.* && "$(node -v)" != v22.* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
apt-get install -y postgresql nginx certbot python3-certbot-nginx git

# --- 2. User + code ----------------------------------------------------------
step "Creating service user + fetching code"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd -r -m -d "$INSTALL_DIR" -s /bin/bash "$SVC_USER"
mkdir -p "$INSTALL_DIR"
if [[ ! -d "$INSTALL_DIR/kaali/.git" ]]; then
  sudo -u "$SVC_USER" git clone "$REPO_URL" "$INSTALL_DIR/kaali"
else
  sudo -u "$SVC_USER" git -C "$INSTALL_DIR/kaali" pull --ff-only
fi

APP_DIR="$INSTALL_DIR/kaali/packages/kaali-cloud"
sudo -u "$SVC_USER" bash -lc "cd '$APP_DIR' && npm install --omit=dev --silent"

# --- 3. Postgres -------------------------------------------------------------
step "Configuring Postgres role + database"
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
  DB_PASS=$(openssl rand -hex 24)
  sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
  echo "DB_PASS=$DB_PASS" > "$APP_DIR/.db_credentials"
  chown "$SVC_USER:$SVC_USER" "$APP_DIR/.db_credentials"
  chmod 600 "$APP_DIR/.db_credentials"
  echo "  → generated DB password saved to $APP_DIR/.db_credentials"
fi
if ! sudo -u postgres psql -lqt | cut -d\| -f1 | grep -qw "$DB_NAME"; then
  sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
fi

step "Applying migrations"
# Pipe SQL via stdin so the `postgres` OS user doesn't need to traverse the
# kaali user's home dir (which is 750). Migrations are idempotent
# (CREATE TABLE IF NOT EXISTS + ALTER … DROP NOT NULL is safe on re-run).
for f in "$APP_DIR"/migrations/*.sql; do
  echo "  applying $(basename "$f")"
  cat "$f" | sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null
done

# Migrations run as the `postgres` superuser, which means tables/sequences are
# owned by postgres by default and the app-role has no privileges. Grant them
# explicitly, and set default privileges so future migrations inherit access.
step "Granting privileges to $DB_USER"
sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null <<SQL
GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;
SQL

# --- 4. .env -----------------------------------------------------------------
step "Ensuring .env"
if [[ ! -f "$APP_DIR/.env" ]]; then
  DB_PASS_LINE=$(cat "$APP_DIR/.db_credentials" 2>/dev/null || echo "DB_PASS=CHANGE_ME")
  DB_PASS_VAL=${DB_PASS_LINE#DB_PASS=}
  cat > "$APP_DIR/.env" <<EOF
PORT=4842
PUBLIC_URL=https://$PRIMARY_HOST
DASHBOARD_URL=https://$PRIMARY_HOST
DATABASE_URL=postgres://$DB_USER:$DB_PASS_VAL@127.0.0.1:5432/$DB_NAME
SESSION_SECRET=$(openssl rand -hex 32)
CSRF_SECRET=$(openssl rand -hex 32)
COOKIE_SECURE=1

# Fill these before restart:
# Seeds the first admin account on boot (use your email):
KAALI_BOOTSTRAP_ADMIN_EMAIL=
RESEND_API_KEY=
EMAIL_FROM=Kaali <noreply@$PRIMARY_HOST>
# OAuth redirect URI to register: https://$PRIMARY_HOST/auth/google/callback
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
# OAuth redirect URI to register: https://$PRIMARY_HOST/auth/meta/callback
META_APP_ID=
META_APP_SECRET=
EOF
  chown "$SVC_USER:$SVC_USER" "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"
  echo "  → generated $APP_DIR/.env — edit RESEND_API_KEY + OAuth keys, then re-run OR restart service."
else
  echo "  → $APP_DIR/.env exists, leaving alone"
fi

# --- 5. systemd --------------------------------------------------------------
step "Installing systemd unit"
sed "s|/opt/kaali/kaali-cloud|$APP_DIR|g" "$APP_DIR/deploy/kaali-cloud.service" > /etc/systemd/system/kaali-cloud.service
systemctl daemon-reload
systemctl enable kaali-cloud >/dev/null

# --- 6. TLS certificate (MUST exist before the SSL nginx site can load) ------
# The nginx site is SSL-only and references $CERT_DIR; if that cert is missing,
# `nginx -t` fails. So obtain the cert FIRST (certonly, via the already-running
# nginx — e.g. the box's existing vhost — to answer the ACME challenge).
step "Obtaining TLS certificate for $PRIMARY_HOST (+ www/app/api)"
if [[ -f "$CERT_DIR/fullchain.pem" ]]; then
  echo "  → cert already present at $CERT_DIR"
elif getent hosts "$PRIMARY_HOST" >/dev/null 2>&1; then
  certbot certonly --nginx --non-interactive --agree-tos -m "hello@$PRIMARY_HOST" \
    "${CERT_HOSTS[@]}" \
    || echo "  ⚠ certbot failed — check DNS + port 80, then re-run this script."
else
  echo "  → DNS for $PRIMARY_HOST not resolving from this box yet; skipping cert."
  echo "    Point DNS at this server, then re-run: sudo bash deploy/deploy.sh"
fi

# --- 7. nginx site -----------------------------------------------------------
step "Installing nginx site"
cp "$APP_DIR/deploy/nginx.conf" /etc/nginx/sites-available/kaali.conf
ln -sfn /etc/nginx/sites-available/kaali.conf /etc/nginx/sites-enabled/kaali.conf
if nginx -t 2>/dev/null; then
  systemctl reload nginx
  echo "  ✓ nginx reloaded — https://$PRIMARY_HOST is served"
else
  echo "  ⚠ nginx -t failed (usually: the TLS cert isn't present yet)."
  echo "    Fix the cert (step 6), then: sudo nginx -t && sudo systemctl reload nginx"
fi

# --- 8. Start ----------------------------------------------------------------
step "Starting kaali-cloud"
systemctl restart kaali-cloud
sleep 2
if systemctl is-active --quiet kaali-cloud; then
  echo "  ✓ kaali-cloud is running on 127.0.0.1:4842"
else
  echo "  ✗ kaali-cloud failed to start — check: journalctl -u kaali-cloud -n 50"
  exit 1
fi

# --- 9. Done -----------------------------------------------------------------
cat <<EOF

✅ Deploy complete. The landing is live now at https://$PRIMARY_HOST

To finish enabling sign-in (full Kaali Cloud), edit $APP_DIR/.env:
  KAALI_BOOTSTRAP_ADMIN_EMAIL=you@domain.com     # seeds your admin account
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET         # redirect: https://$PRIMARY_HOST/auth/google/callback
  RESEND_API_KEY + EMAIL_FROM                      # for password signup / verification emails
  (META_APP_ID / META_APP_SECRET optional)         # redirect: https://$PRIMARY_HOST/auth/meta/callback
then:  sudo systemctl restart kaali-cloud

Verify:
  curl -sI https://$PRIMARY_HOST | head -1                 # expect 200
  curl -s  https://$PRIMARY_HOST/auth/providers            # expect {"providers":[...]}
  sudo journalctl -u kaali-cloud -f                        # watch logs
EOF
