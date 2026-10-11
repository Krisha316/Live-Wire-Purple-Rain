# Juice Shop Blue Team Log Watcher

## What it does

`log_watcher.py` tails a Juice Shop access log in real time (plain-Python
`tail -f` style polling — no external watcher dependency) and scans every new
line against a signature list for SQL injection, XSS, JWT `alg:none`
tampering, IDOR/BOLA-style ID probing on known Juice Shop endpoints
(`/rest/basket/<id>`, `/api/Users/<id>`), and path traversal. On a match it
prints a console alert and posts a Discord webhook embed with the attack
type, matched pattern, raw request snippet, and an ISO timestamp, with simple
per-line dedup so repeated/rapid attack requests don't spam or rate-limit
Discord.

This is a lab/educational Blue Team tool for the "Live Wire, Purple Rain"
exercise, intended for use only against an isolated, self-hosted Juice Shop
instance you are authorized to test.

## Setup

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Create a Discord webhook (3 steps):
   - In your Discord server: **Server Settings → Integrations → Webhooks → New Webhook**
   - Pick the channel you want alerts posted to, give it a name
   - Click **Copy Webhook URL**

3. Set environment variables.

   **bash / Linux / macOS:**
   ```bash
   export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/XXXX/YYYY"
   export JUICESHOP_LOG_PATH="/var/log/juiceshop/access.log"
   ```

   **PowerShell (Windows):**
   ```powershell
   $env:DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/XXXX/YYYY"
   $env:JUICESHOP_LOG_PATH = "C:\path\to\juiceshop\access.log"
   ```

   If `JUICESHOP_LOG_PATH` is not set, it defaults to `/var/log/juiceshop/access.log`.
   `DISCORD_WEBHOOK_URL` is required for Discord alerts; console alerts still
   print without it (a warning is shown).

## Running it

```bash
python log_watcher.py
```

Optional flags (override env vars): `--log-path`, `--poll-interval`, `--dedup-window`.

## Sanity test procedure (do this BEFORE relying on it for real attack evidence)

Before running any real attack against the target, manually trigger one test
alert and confirm the pipeline is actually working end-to-end:

1. Start `log_watcher.py` and leave it running.
2. From another terminal (or a browser), send one harmless test request that
   matches a signature, e.g.:

   ```bash
   curl "http://<target>:3000/rest/products/search?q=<script>alert(1)</script>"
   ```

   (or simply paste that URL into a browser's address bar).
3. Confirm, within a couple of seconds:
   - A console line appears in `log_watcher.py`'s output tagged `ALERT [XSS]`.
   - A corresponding message/embed appears in the Discord channel tied to your webhook.

If either doesn't happen, stop and fix the pipeline (check `JUICESHOP_LOG_PATH`
points at the file Juice Shop is actually writing to, check `DISCORD_WEBHOOK_URL`
is correct and un-expired, check console warnings) before using this for real
attack monitoring/evidence collection. Do not trust the pipeline for live
exercise evidence until this test has passed.

## Known limitations

- **Access-log-only detection.** This script only sees what's in the HTTP
  access log line (method, path, query string, maybe a cookie/token value if
  your log format includes one). True ownership-based IDOR/BOLA detection —
  proving that session/user A accessed a resource belonging to user B —
  requires correlating the authenticated identity with the resource owner,
  which lives in application-level logs, not access logs. The IDOR/BOLA check
  here is a best-effort heuristic (it flags a numeric id on a sensitive
  endpoint, and if a session/token value is present on the same line, checks
  whether the id appears in it) — treat any such flag as "worth
  investigating," not as confirmed proof of a BOLA violation.
- **Signature matching is substring/regex based**, tuned for this lab
  exercise, not a hardened production WAF ruleset. It will miss obfuscated/
  encoded payload variants not covered by the listed patterns.
- **No persistent alert state** — if the script restarts, it only tails from
  the current end of file; it does not replay history.
- **Optional complementary layer:** for a more robust, protocol-aware layer
  of defense (and to catch what this script's regex approach misses),
  consider pairing this with the ModSecurity WAF ruleset produced elsewhere in
  this project: `../detection/modsecurity/juiceshop-rules.conf`.

## Status

This script has been read back for syntax sanity but has **not been run
against a live Juice Shop instance** in this environment — treat it as
**UNVERIFIED** until you run the sanity test procedure above against your
actual lab target.
