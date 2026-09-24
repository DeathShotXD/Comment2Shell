#!/usr/bin/env bash
# Comment2Shell IOC Checker - CVE-2026-93485
# Run on the WordPress server to check for exploitation signs.
#
# Usage: bash check_ioc.sh /var/www/html
# Requirements: grep, find (standard Linux)

set -euo pipefail

WP_ROOT="${1:-/var/www/html}"
FOUND=0

echo "=========================================================="
echo "  Comment2Shell IOC Checker - CVE-2026-93485"
echo "  WordPress Pre-Auth Stored XSS -> RCE"
echo "=========================================================="
echo
echo "[*] Scanning: $WP_ROOT"
echo

# -- IOC 1: Suspicious single-file plugins ------------------------------------
echo "[1/5] Checking for suspicious plugin directories..."
while IFS= read -r -d '' dir; do
    dirname=$(basename "$dir")
    # Skip known plugins
    case "$dirname" in
        akismet|hello.php|hello-dolly|index.php|wp-cache|jetpack|woocommerce|wordfence|yoast-seo)
            continue ;;
    esac
    # Flag short directory names (4-8 chars, alphanumeric) containing single PHP file
    if [[ "$dirname" =~ ^[a-z0-9]{4,8}$ ]]; then
        php_files=$(find "$dir" -maxdepth 1 -name "*.php" 2>/dev/null | wc -l)
        if [[ "$php_files" -le 2 ]]; then
            echo "  [!] SUSPICIOUS: $dir/ ($php_files PHP file(s))"
            echo "      Files:"
            find "$dir" -name "*.php" -exec ls -la {} \; 2>/dev/null | sed 's/^/        /'
            # Check for system/exec calls
            if grep -rl 'system\|exec\|passthru\|shell_exec\|popen' "$dir"/*.php 2>/dev/null; then
                echo "  [!!] ACTIVE WEBSHELL DETECTED in $dir/"
                FOUND=1
            fi
        fi
    fi
done < <(find "$WP_ROOT/wp-content/plugins/" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

# -- IOC 2: Recently modified PHP files in plugins/themes ---------------------
echo "[2/5] Checking recently modified PHP files (last 7 days)..."
find "$WP_ROOT/wp-content/plugins/" "$WP_ROOT/wp-content/themes/" \
    -name "*.php" -mtime -7 -not -path "*/akismet/*" \
    -not -path "*/hello*" -not -name "index.php" 2>/dev/null | while read -r f; do
    echo "  [!] Recently modified: $f ($(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null))"
    FOUND=1
done

# -- IOC 3: WordPress comment database check ----------------------------------
echo "[3/5] Checking wp_comments table for XSS payloads..."
WP_CONFIG="$WP_ROOT/wp-config.php"
if [[ -f "$WP_CONFIG" ]]; then
    DB_NAME=$(grep "DB_NAME" "$WP_CONFIG" | head -1 | sed "s/.*'\\(.*\\)'.*/\\1/" || echo "")
    DB_USER=$(grep "DB_USER" "$WP_CONFIG" | head -1 | sed "s/.*'\\(.*\\)'.*/\\1/" || echo "")
    DB_PASS=$(grep "DB_PASSWORD" "$WP_CONFIG" | head -1 | sed "s/.*'\\(.*\\)'.*/\\1/" || echo "")
    DB_HOST=$(grep "DB_HOST" "$WP_CONFIG" | head -1 | sed "s/.*'\\(.*\\)'.*/\\1/" || echo "localhost")

    if command -v mysql &>/dev/null && [[ -n "$DB_NAME" ]]; then
        MYSQL_CMD="mysql -h$DB_HOST -u$DB_USER"
        [[ -n "$DB_PASS" ]] && MYSQL_CMD="$MYSQL_CMD -p$DB_PASS"

        SUSPECT=$($MYSQL_CMD -N -e \
            "SELECT comment_ID, comment_author, LEFT(comment_content, 300)
             FROM \`${DB_NAME}\`.wp_comments
             WHERE comment_content LIKE '%blockquote%cite%onfocus%'
                OR comment_content LIKE '%blockquote%cite%autofocus%'
                OR (comment_content LIKE '%blockquote%' AND comment_content LIKE '%&#10;%')
             ORDER BY comment_date DESC LIMIT 20;" 2>/dev/null || echo "")

        if [[ -n "$SUSPECT" ]]; then
            echo "  [!!] SUSPICIOUS COMMENTS FOUND:"
            echo "$SUSPECT" | while IFS=$'\t' read -r id author content; do
                echo "      ID=$id Author=$author"
                echo "      Content: ${content:0:200}..."
            done
            FOUND=1
        else
            echo "  [OK] No suspicious comments found"
        fi
    else
        echo "  [SKIP] mysql client not available or DB config not found"
    fi
else
    echo "  [SKIP] wp-config.php not found"
fi

# -- IOC 4: wpautop() patch verification --------------------------------------
echo "[4/5] Checking wpautop() patch status..."
FORMAT_FILE="$WP_ROOT/wp-includes/formatting.php"
if [[ -f "$FORMAT_FILE" ]]; then
    if grep -q 'blockquote(\[^>\]\*)' "$FORMAT_FILE" 2>/dev/null || \
       grep -qF '|<p><blockquote([^>]*)>|' "$FORMAT_FILE" 2>/dev/null; then
        echo "  [!!] VULNERABLE: wpautop() regex not patched (pre-7.1.1)"
        FOUND=1
    elif grep -qF 'blockquote((?:[^>"'\'']' "$FORMAT_FILE" 2>/dev/null || \
         grep -q 'blockquote((?:\[' "$FORMAT_FILE" 2>/dev/null; then
        echo "  [OK] Patched: wpautop() regex uses quote-aware subpattern (7.1.1+)"
    else
        echo "  [?] Could not determine patch status"
    fi
else
    echo "  [SKIP] formatting.php not found"
fi

# -- IOC 5: Recent plugin upload events ---------------------------------------
echo "[5/5] Checking for recent plugin uploads..."
if [[ -f "$WP_ROOT/wp-content/debug.log" ]]; then
    grep -i "upload-plugin\|plugin_upload\|Plugin uploaded" \
        "$WP_ROOT/wp-content/debug.log" 2>/dev/null | tail -5 | while read -r line; do
        echo "  [!] $line"
        FOUND=1
    done
fi

# Check access logs for upload-plugin POST requests
for LOG in /var/log/apache2/access.log /var/log/nginx/access.log \
           /var/log/httpd/access_log "$WP_ROOT"/../access.log; do
    if [[ -f "$LOG" ]]; then
        RECENT_UPLOADS=$(grep "update.php?action=upload-plugin" "$LOG" 2>/dev/null | tail -10 || true)
        if [[ -n "$RECENT_UPLOADS" ]]; then
            echo "  [!] Plugin upload requests in $LOG:"
            echo "$RECENT_UPLOADS" | tail -5 | sed 's/^/      /'
            FOUND=1
        fi
        # Check for comment posts with blockquote payloads
        XSS_COMMENTS=$(grep "wp-comments-post.php" "$LOG" 2>/dev/null | \
            grep -i "blockquote" | grep -i "onfocus\|autofocus\|cite" | tail -10 || true)
        if [[ -n "$XSS_COMMENTS" ]]; then
            echo "  [!!] Potential XSS comment submissions in $LOG:"
            echo "$XSS_COMMENTS" | sed 's/^/      /'
            FOUND=1
        fi
    fi
done

echo
echo "=========================================================="
if [[ $FOUND -eq 1 ]]; then
    echo "[!!] INDICATORS OF COMPROMISE DETECTED"
    echo "     Investigate immediately. Recommend:"
    echo "     1. Update WordPress to 7.1.1+"
    echo "     2. Remove suspicious plugins/files"
    echo "     3. Review admin accounts and application passwords"
    echo "     4. Check wp-config.php for modifications"
    echo "     5. Restore from pre-exposure backup if possible"
else
    echo "[OK] No indicators of Comment2Shell exploitation detected"
fi
echo "=========================================================="
exit $FOUND
