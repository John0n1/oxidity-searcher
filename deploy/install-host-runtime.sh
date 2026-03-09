#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install-host-runtime.sh" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

timestamp="$(date +%Y%m%d%H%M%S)"
wallet_files=(
  "oxidity-wallet-debug.apk"
  "oxidity-wallet-release.apk"
  "oxidity-wallet-extension.zip"
)

backup_if_exists() {
  local path="$1"
  if [[ -e "${path}" ]]; then
    cp -a "${path}" "${path}.bak.${timestamp}"
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "Missing required file: ${path}" >&2
    exit 1
  fi
}

require_file "${REPO_ROOT}/.env"
require_file "${REPO_ROOT}/target/release/oxidity-searcher"
require_file "${REPO_ROOT}/target/release/oxidity_wallet_backend"

install -d -m 0755 /opt/oxidity/bin /opt/oxidity/data /etc/oxidity /var/lib/oxidity

backup_if_exists /etc/oxidity/searcher.env
backup_if_exists /etc/oxidity/wallet-backend.env
backup_if_exists /etc/systemd/system/oxidity-searcher.service
backup_if_exists /etc/systemd/system/oxidity-wallet-backend.service
backup_if_exists /etc/nginx/sites-available/oxidity.io
backup_if_exists /etc/nginx/sites-available/wallet.oxidity.io

install -m 0755 "${REPO_ROOT}/target/release/oxidity-searcher" /opt/oxidity/bin/oxidity-searcher
install -m 0755 "${REPO_ROOT}/target/release/oxidity_wallet_backend" /opt/oxidity/bin/oxidity_wallet_backend
rsync -a --delete "${REPO_ROOT}/data/" /opt/oxidity/data/
chown -R john:john /opt/oxidity

cp "${REPO_ROOT}/.env" /etc/oxidity/searcher.env
cat >> /etc/oxidity/searcher.env <<'EOF'

DATA_DIR=/opt/oxidity/data
DATABASE_URL=sqlite:///var/lib/oxidity/oxidity_searcher.db
EOF

cp "${REPO_ROOT}/.env" /etc/oxidity/wallet-backend.env
cat >> /etc/oxidity/wallet-backend.env <<'EOF'

DATA_DIR=/opt/oxidity/data
OXIDITY_WALLET_BACKEND_BIND=127.0.0.1
OXIDITY_WALLET_BACKEND_PORT=9555
OXIDITY_WALLET_BACKEND_DB=sqlite:///var/lib/oxidity/oxidity_wallet_backend.db
EOF

chmod 0600 /etc/oxidity/searcher.env /etc/oxidity/wallet-backend.env

systemctl stop oxidity-wallet-backend.service || true
sqlite3 "${REPO_ROOT}/oxidity_wallet_backend.db" ".backup '/var/lib/oxidity/oxidity_wallet_backend.db'"

systemctl stop oxidity-searcher.service || true
sqlite3 "${REPO_ROOT}/oxidity_searcher.db" ".backup '/var/lib/oxidity/oxidity_searcher.db'"

chown john:john /var/lib/oxidity/oxidity_searcher.db /var/lib/oxidity/oxidity_wallet_backend.db
chmod 0640 /var/lib/oxidity/oxidity_searcher.db /var/lib/oxidity/oxidity_wallet_backend.db

install -m 0644 "${REPO_ROOT}/deploy/systemd/oxidity-searcher.service" /etc/systemd/system/oxidity-searcher.service
install -m 0644 "${REPO_ROOT}/deploy/systemd/oxidity-wallet-backend.service" /etc/systemd/system/oxidity-wallet-backend.service

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

"${REPO_ROOT}/deploy/nginx/render.sh" "${tmpdir}/oxidity.io" 80 127.0.0.1:9000 127.0.0.1:9545
"${REPO_ROOT}/deploy/nginx/render-wallet.sh" "${tmpdir}/wallet.oxidity.io" 80 127.0.0.1:9555

install -m 0644 "${tmpdir}/oxidity.io" /etc/nginx/sites-available/oxidity.io
install -m 0644 "${tmpdir}/wallet.oxidity.io" /etc/nginx/sites-available/wallet.oxidity.io

/usr/sbin/nginx -t

rsync -a --delete --exclude 'downloads/' "${REPO_ROOT}/apps/site/dist/" /var/www/oxidity.io/
install -d -m 0775 /var/www/oxidity.io/downloads
rsync -a "${REPO_ROOT}/artifacts/downloads/" /var/www/oxidity.io/downloads/
rsync -a --delete "${REPO_ROOT}/apps/wallet/dist/" /var/www/wallet.oxidity.io/

for file in "${wallet_files[@]}"; do
  rm -f "/var/www/wallet.oxidity.io/${file}"
  rm -f "/var/www/wallet.oxidity.io/downloads/${file}"
done

chown -R john:john /var/www/oxidity.io /var/www/wallet.oxidity.io

systemctl daemon-reload
systemctl start oxidity-wallet-backend.service
systemctl start oxidity-searcher.service
systemctl reload nginx

rm -f /etc/systemd/system/wallet-service.service
systemctl daemon-reload

systemctl is-active oxidity-wallet-backend.service oxidity-searcher.service
curl -fsS http://127.0.0.1:9555/api/bootstrap >/dev/null
curl -I -fsS https://oxidity.io/downloads/oxidity-wallet-extension.zip >/dev/null

echo "Host runtime cutover complete."
