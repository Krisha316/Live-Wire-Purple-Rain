#!/usr/bin/env python3
"""
log_watcher.py — Real-time attack-signature log watcher for Juice Shop (Blue Team).

Purpose
-------
Tails an access log in real time and flags lines that match known attack
signatures used against OWASP Juice Shop during the "Live Wire, Purple Rain"
Red/Blue/Purple team exercise: SQL injection, XSS, JWT "alg:none" tampering,
IDOR/BOLA-style ID probing on known endpoints, and path traversal.

On a match it:
  1. Prints a clear console alert (timestamp, signature category, pattern, snippet).
  2. Sends a Discord webhook alert (embed) for real-time Blue Team visibility.

Scope & authorization
----------------------
This tool is for use ONLY against a self-hosted, isolated Juice Shop lab
instance as part of an authorized academic ethical-hacking exercise. Do not
point this at any system you do not own or have explicit written authorization
to test/monitor.

Known limitation (read before relying on this for IDOR/BOLA evidence)
-----------------------------------------------------------------------
This script works purely off access-log text. True ownership-based IDOR/BOLA
detection (i.e. "user A's session fetched user B's basket/profile") requires
correlating the authenticated identity (JWT subject / session owner) with the
resource id being accessed — that mapping lives in application-level logs or
middleware, not in a typical access log line. Where the log format includes a
token/cookie value on the same line, this script does a best-effort textual
check (does the numeric id in the URL appear anywhere in the same token/cookie
value?) and flags a MISMATCH if not — but this is a heuristic, not proof of
ownership violation. Treat these flags as "worth investigating", not as
confirmed BOLA. For authoritative IDOR/BOLA detection, correlate with app-level
auth logs or add that correlation server-side.

Configuration (environment variables)
--------------------------------------
JUICESHOP_LOG_PATH   Path to the log file to tail. Default: /var/log/juiceshop/access.log
DISCORD_WEBHOOK_URL  Discord webhook URL to POST alerts to. Required for Discord alerts;
                     if unset, the script still prints console alerts and warns once.

Usage
-----
    python log_watcher.py
    python log_watcher.py --log-path /path/to/access.log
    python log_watcher.py --poll-interval 0.3 --dedup-window 2.0
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None  # Handled at runtime; console alerts still work without it.


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------
# Each signature is (category, compiled_regex). Matching is case-insensitive.
# These are intentionally broad substring/regex matches appropriate for a lab
# exercise, not a production-grade WAF ruleset.

SQLI_PATTERNS = [
    r"union\s+select",
    r"'\s*or\s*1\s*=\s*1",
    r"or\s*'1'\s*=\s*'1'",
    r"--",
    r";--",
]

XSS_PATTERNS = [
    r"<script",
    r"onerror\s*=",
    r"javascript:",
]

JWT_PATTERNS = [
    r'"alg"\s*:\s*"none"',
    r"alg\s*=\s*none",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"%2e%2e%2f",
]

# IDOR/BOLA candidate endpoints: match a known Juice Shop route followed by a
# numeric id in the request line.
IDOR_ENDPOINT_PATTERN = r"(/rest/basket/|/api/Users/)(\d+)"

# Build one combined, labeled list for the generic categories.
SIGNATURES = []
for pat in SQLI_PATTERNS:
    SIGNATURES.append(("SQL Injection", re.compile(pat, re.IGNORECASE)))
for pat in XSS_PATTERNS:
    SIGNATURES.append(("XSS", re.compile(pat, re.IGNORECASE)))
for pat in JWT_PATTERNS:
    SIGNATURES.append(("JWT Tampering (alg:none)", re.compile(pat, re.IGNORECASE)))
for pat in PATH_TRAVERSAL_PATTERNS:
    SIGNATURES.append(("Path Traversal", re.compile(pat, re.IGNORECASE)))

IDOR_REGEX = re.compile(IDOR_ENDPOINT_PATTERN, re.IGNORECASE)

# Attempts to pull a "self" identifier (session cookie / bearer token / id
# cookie) out of a log line, if the log format happens to include one.
# This is best-effort only — see the "Known limitation" docstring above.
SELF_ID_HINT_PATTERN = re.compile(
    r"(?:token=|bearer\s+|sid=|session=|user_id=)([A-Za-z0-9._-]+)", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Dedup / rate limiting
# ---------------------------------------------------------------------------

class AlertDeduper:
    """Suppresses repeat alerts for the exact same line within a time window."""

    def __init__(self, window_seconds: float = 2.0):
        self.window_seconds = window_seconds
        self._last_seen = {}  # line -> last_alert_timestamp

    def should_alert(self, line: str) -> bool:
        now = time.monotonic()
        last = self._last_seen.get(line)
        if last is not None and (now - last) < self.window_seconds:
            return False
        self._last_seen[line] = now
        # Opportunistic cleanup so the dict doesn't grow unbounded on long runs.
        if len(self._last_seen) > 5000:
            cutoff = now - self.window_seconds
            self._last_seen = {
                k: v for k, v in self._last_seen.items() if v >= cutoff
            }
        return True


# ---------------------------------------------------------------------------
# Discord alerting
# ---------------------------------------------------------------------------

def send_discord_alert(webhook_url: str, category: str, pattern: str, snippet: str,
                        extra_note: str = "", timeout: float = 5.0) -> None:
    """POST a Discord webhook embed alert. Never raises — logs and swallows errors
    so a Discord/network failure cannot crash the tail loop."""
    if not webhook_url:
        return
    if requests is None:
        print("[log_watcher] WARNING: 'requests' package not installed; "
              "skipping Discord alert. Run: pip install -r requirements.txt",
              file=sys.stderr)
        return

    iso_ts = datetime.now(timezone.utc).isoformat()
    description = f"**Pattern matched:** `{pattern}`\n**Raw snippet:**\n```\n{snippet[:900]}\n```"
    if extra_note:
        description += f"\n**Note:** {extra_note}"

    payload = {
        "embeds": [
            {
                "title": f"🚨 Juice Shop Alert: {category}",
                "description": description,
                "color": 15158332,  # red
                "timestamp": iso_ts,
                "footer": {"text": "log_watcher.py — Blue Team detection"},
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=timeout)
        if resp.status_code >= 300:
            print(f"[log_watcher] WARNING: Discord webhook returned "
                  f"HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - intentionally broad; must never crash tail loop
        print(f"[log_watcher] WARNING: Discord webhook POST failed: {exc}",
              file=sys.stderr)


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def check_line(line: str):
    """Return a list of (category, pattern, note) tuples for every signature
    that matches this log line."""
    matches = []

    for category, regex in SIGNATURES:
        m = regex.search(line)
        if m:
            matches.append((category, m.group(0), ""))

    idor_match = IDOR_REGEX.search(line)
    if idor_match:
        endpoint, resource_id = idor_match.group(1), idor_match.group(2)
        note = (
            "IDOR/BOLA candidate: numeric id on a sensitive endpoint. "
            "Ownership correlation is a heuristic only (see script docstring) — "
            "full verification requires app-level auth logs, not access logs alone."
        )
        self_hint = SELF_ID_HINT_PATTERN.search(line)
        if self_hint:
            token_value = self_hint.group(1)
            if resource_id not in token_value:
                note += f" Possible MISMATCH: id '{resource_id}' not found in session/token value '{token_value}'."
            else:
                note += f" id '{resource_id}' appears within session/token value — likely self-access."
        else:
            note += " No session/token identifier present in this log line to compare against."
        matches.append(("IDOR/BOLA Candidate", f"{endpoint}{resource_id}", note))

    return matches


# ---------------------------------------------------------------------------
# Tail loop
# ---------------------------------------------------------------------------

def tail_file(path: str, poll_interval: float):
    """Generator yielding new lines appended to `path`, tail -f style.

    Seeks to end of file on open, then polls for new content. Handles the
    file being rotated/truncated by detecting a shrink in size and reopening
    from the start in that case.
    """
    while not os.path.exists(path):
        print(f"[log_watcher] Waiting for log file to appear: {path}", file=sys.stderr)
        time.sleep(poll_interval)

    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    current_size = os.path.getsize(path)

    try:
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
                continue

            time.sleep(poll_interval)

            try:
                new_size = os.path.getsize(path)
            except OSError:
                # File may have been removed/rotated; keep polling.
                continue

            if new_size < current_size:
                # Truncated or rotated — reopen from the start.
                f.close()
                f = open(path, "r", encoding="utf-8", errors="replace")
            current_size = new_size
    finally:
        f.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Real-time Juice Shop attack-signature log watcher with Discord alerting."
    )
    parser.add_argument(
        "--log-path",
        default=os.environ.get("JUICESHOP_LOG_PATH", "/var/log/juiceshop/access.log"),
        help="Path to the access log to tail (env: JUICESHOP_LOG_PATH).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=0.4,
        help="Seconds between polls for new log lines (default: 0.4).",
    )
    parser.add_argument(
        "--dedup-window",
        type=float,
        default=2.0,
        help="Minimum seconds between repeat alerts for the identical line (default: 2.0).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "")

    if not webhook_url:
        print("[log_watcher] WARNING: DISCORD_WEBHOOK_URL is not set. "
              "Console alerts will still print, but no Discord notifications will be sent.",
              file=sys.stderr)

    print(f"[log_watcher] Starting. Tailing: {args.log_path}", flush=True)
    print(f"[log_watcher] Poll interval: {args.poll_interval}s | Dedup window: {args.dedup_window}s", flush=True)
    print("[log_watcher] Lab-only tool for authorized testing against an isolated Juice Shop instance.", flush=True)

    deduper = AlertDeduper(window_seconds=args.dedup_window)

    try:
        for line in tail_file(args.log_path, args.poll_interval):
            if not line.strip():
                continue

            matches = check_line(line)
            if not matches:
                continue

            if not deduper.should_alert(line):
                continue

            ts = datetime.now(timezone.utc).isoformat()
            for category, pattern, note in matches:
                snippet = line.strip()[:500]
                print(f"[{ts}] ALERT [{category}] pattern='{pattern}' :: {snippet}", flush=True)
                if note:
                    print(f"           note: {note}", flush=True)
                send_discord_alert(webhook_url, category, pattern, snippet, extra_note=note)
    except KeyboardInterrupt:
        print("\n[log_watcher] Stopped by user.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"[log_watcher] ERROR: log file not found: {args.log_path}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
