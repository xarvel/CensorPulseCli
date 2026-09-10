#!/bin/sh
# Fetch the GeoLite2 CSV tables the client uses to record the scanning
# network's ASN and country offline (report field "network").
#
# Source: the "release" branch of github.com/Loyalsoldier/geoip, which
# republishes MaxMind GeoLite2 under its own licence terms. Nothing here is
# sent anywhere; the tables are read locally by `cpprobe scan`.
#
# Usage: sh scripts/geoip-update.sh [DIR]     (default: ~/.cpprobe/geoip, or $CPPROBE_GEOIP_DIR)
set -eu

dir="${1:-${CPPROBE_GEOIP_DIR:-$HOME/.cpprobe/geoip}}"
base="https://raw.githubusercontent.com/Loyalsoldier/geoip/release"
files="GeoLite2-ASN-Blocks-IPv4.csv GeoLite2-ASN-Blocks-IPv6.csv GeoLite2-Country-Blocks-IPv4.csv GeoLite2-Country-Blocks-IPv6.csv GeoLite2-Country-Locations-en.csv"

mkdir -p "$dir"
for f in $files; do
  tmp="$dir/.$f.part"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$tmp" "$base/$f"
  else
    wget -q -O "$tmp" "$base/$f"
  fi
  # a table must have a header and at least one row
  if [ "$(wc -l <"$tmp")" -lt 2 ]; then
    echo "geoip-update: $f looks empty, keeping the previous copy" >&2
    rm -f "$tmp"
    continue
  fi
  mv -f "$tmp" "$dir/$f"
  echo "geoip-update: $f ($(wc -l <"$dir/$f") lines)"
done
echo "geoip-update: tables in $dir"
