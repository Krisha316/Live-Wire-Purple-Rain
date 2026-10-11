# Detection Layer — Live Wire, Purple Rain

## Canonical script: `../detector.py` (repo root)

This is krisha's real, already-running detector (pulled from
`https://github.com/Krisha316/Live-Wire-Purple-Rain`, commit `e254cff`),
with one fix applied: the Discord webhook URL was hardcoded in the original
commit and has been moved to an environment variable here.

**Action required before use:** that original commit leaked a live webhook
URL to GitHub. Regenerate it in Discord (Server Settings → Integrations →
Webhooks → delete the old one → New Webhook → Copy URL) and never commit
the new one — set it via env var only (see below). Treat the old URL as
compromised even if the repo is later made private; assume it was seen.

### What it does

Polls the running Juice Shop Docker container every 2 seconds via
`docker exec`, reads its current `access.log.*` file from inside the
container, and checks each not-yet-seen line against a substring pattern
list (`UNION SELECT`, `' OR`, `<script`, `onerror=`, `alert(`,
`/rest/basket/`, `/api/Users/`). On a match it posts a Discord alert.

This is simpler than a true `tail -f`: it re-reads the whole current log
file each poll and tracks seen lines in memory, which is fine at Juice
Shop's lab-scale log volume but means restarting the script loses the
dedup state (it will NOT re-alert on old lines already in the file at
startup, since `seen_lines` starts empty and the loop only reports lines
it hasn't logged before within that run — but note it will also silently
treat every line present at first poll as "already seen" without
alerting on it, so make sure the script is running *before* you start
attacking, not after).

### Setup

```bash
pip install requests
```

Set environment variables before running:

**bash:**
```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/<new-id>/<new-token>"
export JUICESHOP_CONTAINER_NAME="wizardly_feynman"   # or your actual container name/ID
```

**PowerShell:**
```powershell
$env:DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/<new-id>/<new-token>"
$env:JUICESHOP_CONTAINER_NAME = "wizardly_feynman"
```

Check your actual running container's name with `docker ps` if it's not
`wizardly_feynman` (that's a Docker auto-generated name from krisha's run —
yours will likely differ unless you're using her exact container).

### Run it

```bash
python detector.py
```

### Sanity test (do this before relying on it for real evidence)

1. Start `detector.py` and leave it running.
2. Visit `http://<target>:3000/rest/products/search?q=<script>alert(1)</script>` once.
3. Within ~2-4 seconds (the poll interval) confirm both:
   - Console prints `[ALERT SENT] ...`
   - A message appears in the Discord channel tied to the webhook.

If it doesn't fire, check: is `detector.py` running *before* the test
request; is `JUICESHOP_CONTAINER_NAME` correct (`docker ps`); does the
container actually log to `/juice-shop/logs/access.log.*` (confirm with
`docker exec <container> ls /juice-shop/logs`); is the new webhook URL
correct and not rate-limited/deleted.

### Known limitations

- 2-second polling + full-file re-read, not a true incremental tail — fine
  at this scale, but not how you'd build it for a high-traffic prod system.
- Plain substring matching (not regex) — case-insensitive but will miss
  obfuscated/encoded payload variants (e.g. URL-encoded `<script>`).
- No ownership-based IDOR/BOLA correlation — flags any request to
  `/rest/basket/` or `/api/Users/` regardless of whether it's actually a
  cross-user access; treat those alerts as "worth checking," not proof.
- Depends on `docker exec` working against the named container — if the
  container restarts with a new auto-generated name, update
  `JUICESHOP_CONTAINER_NAME`.

## Alternate implementation: `alternate-log_watcher/`

A more elaborate version (true incremental `tail -f` polling against a
mounted log file path, regex-based signatures incl. JWT `alg:none` and
path traversal, per-line dedup/rate-limiting, console+Discord alerting)
was built and actually tested against synthetic log lines earlier in this
project — see `alternate-log_watcher/README.md` for its own setup and
status. It is **not** currently wired to the real Juice Shop container;
kept as a reference/fallback if `detector.py`'s container-polling approach
runs into trouble (e.g. if `docker exec` access isn't available on the
exam/demo machine) or you want regex coverage beyond `detector.py`'s
plain substrings.

## Optional secondary layer: `modsecurity/`

Optional WAF ruleset for comparison — see `modsecurity/README.md`. Marked
as a time-boxed, skippable addition; not required for the core deliverable.
