#!/usr/bin/env bash
#
# Comment2Shell lab setup / repair.
#
# The wordpress:7.1.0 lab image ships with $wp_db_version stored as the
# string "7.1.0". wp-admin casts the db_version option to int and compares
# it to $wp_db_version, so the two never match and every wp-admin request
# is redirected to upgrade.php. That redirect breaks the plugin-upload
# nonce fetch the exploit relies on, and the webshell is never written.
#
# This script makes the guard pass and points the site at localhost so a
# logged-in admin session and the tool talk to the same origin.
#
# Usage: bash docker/setup.sh [wordpress_container] [db_container]

set -euo pipefail

WP_CONTAINER="${1:-comment2shell-lab}"
DB_CONTAINER="${2:-comment2shell-db}"

echo "[*] Waiting for WordPress to come up..."
for _ in $(seq 1 30); do
    if docker exec "$WP_CONTAINER" test -f /var/www/html/wp-includes/version.php 2>/dev/null; then
        break
    fi
    sleep 2
done

echo "[*] Patching db_version guard in wp-includes/version.php..."
docker exec "$WP_CONTAINER" sed -i \
    "s/^\$wp_db_version = .*/\$wp_db_version = 7;/" \
    /var/www/html/wp-includes/version.php

echo "[*] Pointing siteurl/home at http://localhost..."
docker exec "$DB_CONTAINER" mysql -uwp -pwppass wordpress -e \
    "UPDATE wp_options SET option_value='http://localhost' WHERE option_name IN ('siteurl','home');" \
    2>/dev/null || echo "    (db not ready yet, set siteurl manually)"

echo
echo "[+] Lab ready: http://localhost"
echo "    Admin: admin / Password123!"
echo "    Test:  python3 comment2shell.py -t http://localhost -c \"id\""
