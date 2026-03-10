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

searcher_env_patterns=(
  "CHAINS"
  "DATA_DIR"
  "GLOBAL_PATHS_PATH"
  "GLOBAL_DATA_PATH"
  "TOKENLIST_PATH"
  "ADDRESS_REGISTRY_PATH"
  "PAIRS_PATH"
  "CHAINLINK_FEEDS_PATH"
  "DATABASE_URL"
  "HTTP_PROVIDER_*"
  "WEBSOCKET_PROVIDER_*"
  "IPC_PROVIDER_*"
  "PROVIDER_JWT_SECRET_PATH"
  "PROVIDER_JWT_SECRET_PATH_*"
  "FLASHBOTS_*"
  "MEV_*"
  "ETHERSCAN_API_KEY"
  "BINANCE_API_KEY"
  "COINMARKETCAP_API_KEY"
  "COINGECKO_API_KEY"
  "CRYPTOCOMPARE_API_KEY"
  "MASSIVE_API_KEY"
  "MASIVE_API_KEY"
  "OXIDITY_WALLET_PRIVATE_KEY"
  "OXIDITY_BUNDLE_PRIVATE_KEY"
  "OXIDITY_WALLET_ADDRESS"
  "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS"
  "OXIDITY_LOG_LEVEL"
  "METRICS_*"
  "PUBLIC_RPC_INGRESS_*"
  "STRATEGY_*"
  "DEBUG"
  "SANDWICH_*"
  "FLASHLOAN_*"
  "ALLOW_*"
  "FORCE_*"
  "ROUTER_*"
  "TOXIC_*"
  "BALANCE_*"
  "AUTO_SLIPPAGE_*"
  "PROFIT_*"
  "GAS_*"
  "BUNDLE_*"
  "CHAINLINK_*"
  "RPC_CAPABILITY_STRICT*"
  "SKIP_LOG_EVERY"
  "RECEIPT_*"
  "SPONSORSHIP_*"
  "LIQUIDITY_*"
  "SELL_MIN_NATIVE_OUT_WEI"
  "NO_COLOR"
  "TERM"
  "LOG_TABLE_MAX_WIDTH"
)

wallet_backend_env_patterns=(
  "DATA_DIR"
  "GLOBAL_PATHS_PATH"
  "GLOBAL_DATA_PATH"
  "TOKENLIST_PATH"
  "ADDRESS_REGISTRY_PATH"
  "PAIRS_PATH"
  "CHAINLINK_FEEDS_PATH"
  "HTTP_PROVIDER_*"
  "WEBSOCKET_PROVIDER_*"
  "IPC_PROVIDER_*"
  "PROVIDER_JWT_SECRET_PATH"
  "PROVIDER_JWT_SECRET_PATH_*"
  "FLASHBOTS_RELAY_URL"
  "MEV_SHARE_RELAY_URL"
  "ETHERSCAN_API_KEY"
  "BINANCE_API_KEY"
  "COINMARKETCAP_API_KEY"
  "COINGECKO_API_KEY"
  "CRYPTOCOMPARE_API_KEY"
  "MASSIVE_API_KEY"
  "MASIVE_API_KEY"
  "OXIDITY_WALLET_PRIVATE_KEY"
  "OXIDITY_WALLET_ADDRESS"
  "OXIDITY_FLASHLOAN_CONTRACT_ADDRESS"
  "OXIDITY_BUNDLE_PRIVATE_KEY"
  "BUNDLE_*"
  "CHAINLINK_*"
  "RPC_CAPABILITY_STRICT*"
  "RECEIPT_*"
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

append_env_matches() {
  local source_path="$1"
  local destination_path="$2"
  shift 2

  while IFS= read -r line; do
    [[ "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    local key="${line%%=*}"
    for pattern in "$@"; do
      if [[ "${key}" == ${pattern} ]]; then
        printf '%s\n' "${line}" >> "${destination_path}"
        break
      fi
    done
  done < "${source_path}"
}

write_env_subset() {
  local destination_path="$1"
  shift
  : > "${destination_path}"
  append_env_matches "${REPO_ROOT}/.env" "${destination_path}" "$@"
}

backup_live_db() {
  local source_path="$1"
  if [[ -f "${source_path}" ]]; then
    sqlite3 "${source_path}" ".backup '${source_path}.bak.${timestamp}'"
  fi
}

seed_db_if_missing() {
  local repo_path="$1"
  local live_path="$2"
  if [[ -f "${live_path}" ]]; then
    return
  fi
  if [[ -f "${repo_path}" ]]; then
    sqlite3 "${repo_path}" ".backup '${live_path}'"
  fi
}

require_file "${REPO_ROOT}/.env"
require_file "${REPO_ROOT}/target/release/oxidity-searcher"
require_file "${REPO_ROOT}/target/release/oxidity_wallet_backend"

install -d -m 0755 /opt/oxidity/bin /opt/oxidity/data /etc/oxidity /var/lib/oxidity
chown john:john /var/lib/oxidity

backup_if_exists /etc/oxidity/searcher.env
backup_if_exists /etc/oxidity/wallet-backend.env
backup_if_exists /etc/systemd/system/oxidity-searcher.service
backup_if_exists /etc/systemd/system/oxidity-wallet-backend.service
backup_if_exists /etc/nginx/sites-available/oxidity.io
backup_if_exists /etc/nginx/sites-available/wallet.oxidity.io

install -m 0755 "${REPO_ROOT}/target/release/oxidity-searcher" /opt/oxidity/bin/oxidity-searcher
install -m 0755 "${REPO_ROOT}/target/release/oxidity_wallet_backend" /opt/oxidity/bin/oxidity_wallet_backend
rsync -a --delete "${REPO_ROOT}/data/" /opt/oxidity/data/
rsync -a --delete "${REPO_ROOT}/migrations/" /opt/oxidity/bin/migrations/
chown -R john:john /opt/oxidity

write_env_subset /etc/oxidity/searcher.env "${searcher_env_patterns[@]}"
cat >> /etc/oxidity/searcher.env <<'EOF'

DATA_DIR=/opt/oxidity/data
DATABASE_URL=sqlite:///var/lib/oxidity/oxidity_searcher.db
EOF

write_env_subset /etc/oxidity/wallet-backend.env "${wallet_backend_env_patterns[@]}"
cat >> /etc/oxidity/wallet-backend.env <<'EOF'

DATA_DIR=/opt/oxidity/data
OXIDITY_WALLET_BACKEND_BIND=127.0.0.1
OXIDITY_WALLET_BACKEND_PORT=9555
OXIDITY_WALLET_BACKEND_DB=sqlite:///var/lib/oxidity/oxidity_wallet_backend.db
EOF

chmod 0600 /etc/oxidity/searcher.env /etc/oxidity/wallet-backend.env

systemctl stop oxidity-wallet-backend.service || true
backup_live_db /var/lib/oxidity/oxidity_wallet_backend.db
seed_db_if_missing "${REPO_ROOT}/oxidity_wallet_backend.db" /var/lib/oxidity/oxidity_wallet_backend.db

systemctl stop oxidity-searcher.service || true
backup_live_db /var/lib/oxidity/oxidity_searcher.db
seed_db_if_missing "${REPO_ROOT}/oxidity_searcher.db" /var/lib/oxidity/oxidity_searcher.db

for db_path in /var/lib/oxidity/oxidity_searcher.db /var/lib/oxidity/oxidity_wallet_backend.db; do
  if [[ -f "${db_path}" ]]; then
    chown john:john "${db_path}"
    chmod 0640 "${db_path}"
  fi
done

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
