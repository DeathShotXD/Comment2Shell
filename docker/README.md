# Comment2Shell Docker Lab

Vulnerable WordPress 7.1.0 for local testing of CVE-2026-93485.

## Quick Start

```bash
docker compose up -d
```

WordPress will be available at **http://localhost:80** after ~30 seconds (host networking).

Then apply the one-time lab repair:

```bash
bash setup.sh
```

The lab image ships with `$wp_db_version` as the string `"7.1.0"` while
wp-admin compares it to an integer cast of the `db_version` option. On this
build the values never match, so every wp-admin request is redirected to
`upgrade.php` and the plugin-upload nonce fetch fails. `setup.sh` makes the
guard pass and sets `siteurl`/`home` to `http://localhost`.

## Setup

1. Complete the WordPress installation wizard (or use the pre-seeded credentials):
   - Site Title: `Comment2Shell Lab`
   - Username: `admin`
   - Password: `Password123!`
   - Email: `admin@example.com`

2. Ensure comments are open (default) and auto-approve is on:

```bash
# Inside the container (or via WP-CLI)
docker compose exec wordpress sh -c '
  wp option update comment_moderation 0 --allow-root
  wp option update comment_previously_approved 0 --allow-root
  wp option update default_comment_status open --allow-root
'
```

3. Use a block theme (default Twenty Twenty-Five or later):

```bash
docker compose exec wordpress sh -c '
  wp theme activate twentytwentyfive --allow-root 2>/dev/null || true
'
```

## Test the Exploit

```bash
# From the Comment2Shell directory:
python3 comment2shell.py -t http://localhost -c "id"
```

The tool will:
1. Detect WordPress 7.1.0 (vulnerable)
2. Find a commentable post
3. Submit the XSS payload
4. Wait for you to view the post **as admin** while logged in
5. Trigger the in-browser plugin upload
6. Execute `id` and delete the webshell

**Important:** You must be logged in as admin in the same browser, then visit `http://localhost/?p=1` to trigger the XSS -> RCE chain. The `alert()` proof fires once; dismissing it lets the upload chain finish.

## Cleanup

Stop the lab:

```bash
docker compose down -v
```

Clear payload comments and leftover shells between exploit runs:

```bash
bash clean.sh
```

Each exploit run submits a new comment. Only the first autofocus payload on
the page runs, so if older payloads are still present the browser triggers
the oldest one. The tool detects the first live payload and polls its path,
so runs still succeed; `clean.sh` just keeps the page tidy when you test
repeatedly.

## Verify Patch

After updating to 7.1.1, the exploit should fail:

```bash
docker compose exec wordpress sh -c '
  wp core update --version=7.1.1 --allow-root
'
python3 comment2shell.py --scan -t http://localhost
# Expected: "WordPress 7.1.1 - PATCHED"
```
