#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <output> <listen_port> <wallet_api_upstream>" >&2
  exit 1
fi

output="$1"
listen_port="$2"
wallet_api_upstream="$3"

mkdir -p "$(dirname "$output")"

sed \
  -e "s/__WALLET_HTTP_PORT__/${listen_port}/g" \
  -e "s#__WALLET_API_UPSTREAM__#${wallet_api_upstream}#g" \
  deploy/nginx/wallet.oxidity.io.conf.template > "$output"
