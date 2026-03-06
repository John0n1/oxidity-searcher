#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <output> <listen_port> <metrics_upstream> <rpc_upstream>" >&2
  exit 1
fi

output="$1"
listen_port="$2"
metrics_upstream="$3"
rpc_upstream="$4"

mkdir -p "$(dirname "$output")"

sed \
  -e "s/__MITANDER_HTTP_PORT__/${listen_port}/g" \
  -e "s#__PUBLIC_METRICS_UPSTREAM__#${metrics_upstream}#g" \
  -e "s#__RPC_UPSTREAM__#${rpc_upstream}#g" \
  deploy/nginx/mitander.dev.conf.template > "$output"
