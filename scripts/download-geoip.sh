#!/usr/bin/env bash
# Download the DB-IP IP-to-Country Lite database (free, CC BY 4.0, no account).
# Same .mmdb format as MaxMind GeoLite2-Country, readable by the geoip2 library.
#
# Usage: download-geoip.sh [DEST_PATH]
set -euo pipefail

DEST="${1:-/geoip/dbip-country-lite.mmdb}"
mkdir -p "$(dirname "$DEST")"

# Current month, then previous month as a fallback (early in the month the
# newest file may not be published yet). Support both GNU and BSD `date`.
prev_month() {
  date -d 'last month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m
}

for ym in "$(date +%Y-%m)" "$(prev_month)"; do
  url="https://download.db-ip.com/free/dbip-country-lite-${ym}.mmdb.gz"
  echo "Trying ${url}"
  if curl -fsSL "${url}" -o /tmp/geoip.mmdb.gz; then
    gunzip -c /tmp/geoip.mmdb.gz > "${DEST}"
    rm -f /tmp/geoip.mmdb.gz
    echo "Saved ${DEST}"
    exit 0
  fi
done

echo "Failed to download GeoIP database" >&2
exit 1
