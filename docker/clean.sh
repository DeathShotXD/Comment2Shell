#!/usr/bin/env bash
#
# Purge Comment2Shell payload comments and orphaned shells from the lab.
# Run this between exploit attempts to keep only the newest payload on the
# page. The exploit still works with older payloads present (the tool
# detects the first live one), this just keeps the lab tidy.
#
# Usage: bash docker/clean.sh [db_container] [wp_container]

set -euo pipefail

DB_CONTAINER="${1:-comment2shell-db}"
WP_CONTAINER="${2:-comment2shell-lab}"

echo "[*] Removing XSS payload comments..."
docker exec "$DB_CONTAINER" mysql -uwp -pwppass wordpress -e \
    "DELETE FROM wp_comments WHERE comment_content LIKE '%onfocus%' AND comment_content LIKE '%autofocus%';" \
    2>/dev/null || true

echo "[*] Removing orphaned single-file plugins..."
docker exec "$WP_CONTAINER" sh -c '
for d in /var/www/html/wp-content/plugins/*/; do
    b=$(basename "$d")
    if [ "${#b}" = 6 ] && [ -f "$d$b.php" ]; then
        rm -rf "$d"
    fi
done' 2>/dev/null || true

echo "[+] Lab cleaned"
