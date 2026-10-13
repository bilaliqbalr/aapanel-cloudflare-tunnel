#!/bin/bash
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"
rm -f "$OUT/cftunnel.zip"
(
  cd "$ROOT"
  zip -r "$OUT/cftunnel.zip" \
    info.json \
    cftunnel_main.py \
    cf_common.py \
    dns_manager.py \
    tunnel_manager.py \
    ingress_manager.py \
    index.html \
    icon.png \
    install.sh \
    uninstall.sh \
    static
)
echo "$OUT/cftunnel.zip"
