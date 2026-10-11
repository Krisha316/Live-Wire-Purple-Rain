# ModSecurity WAF Layer — Juice Shop Blue Team (OPTIONAL)

**Status: NOT REQUIRED — time-boxed cut candidate.**
If your team is short on time, skip this component entirely. The **Python
log-watcher is the primary, required detection layer** for this project. This
ModSecurity setup is a secondary comparison layer only, included to show what
an industry-standard WAF catches side-by-side with the custom detection
script — useful for the report/demo narrative, not required for a passing
submission.

**Status: UNVERIFIED.** These rules and these install steps have **not been
tested against a live Nginx + ModSecurity + Juice Shop install** — there was
no live lab environment available at the time this was written. Everything
below is a best-effort, documentation-based draft. Before you rely on it,
run it yourself: install it, hit Juice Shop with a known attack payload, and
confirm an alert actually appears in the ModSecurity audit log. Do not report
this as "working" until you've seen that with your own eyes.

## Purpose

This is an optional comparison layer sitting in front of OWASP Juice Shop,
alongside the primary Python log-watcher. It lets the Blue Team demonstrate
"here's what a standard open-source WAF (ModSecurity + OWASP CRS-style rules)
flags" next to "here's what our own custom log-watcher script flags" for the
same Red Team attack run — useful evidence for the attack → detect → fix →
retest narrative, but not a replacement for the primary tool.

## Rule coverage summary (`juiceshop-rules.conf`)

| ID range | Category | Notes |
|---|---|---|
| 9000001–9000005 | SQL Injection | UNION SELECT, `OR 1=1` tautologies, SQL comment truncation (`--`, `#`, `/* */`), stacked queries, blind/time-based function probes (`sleep()`, `benchmark()`) |
| 9000010–9000013 | XSS (reflected/stored) | `<script>` tags, inline event handlers (`onerror=`, `onload=`, etc.), `javascript:` URIs, `<img>/<svg>` handler combos |
| 9000020–9000021 | JWT tampering | `alg":"none"` (JSON form) and `alg=none` (form-encoded) in Authorization header or body. **Caveat documented in the rule file**: a base64url-encoded Bearer token won't match these regexes in transit — full JWT-header decoding is out of scope for plain SecRule matching and is better handled by the Python log-watcher. |
| 9000030–9000031 | IDOR/BOLA visibility (log only, never block) | `/rest/basket/\d+` and `/api/Users/\d+` access logging. Clearly commented as **detection/evidence only** — the WAF cannot verify ownership, so true IDOR/BOLA prevention must be fixed in the application layer, not the WAF. |

All rule IDs use the **9000000+ custom range** to avoid colliding with OWASP
CRS rule IDs or ModSecurity's reserved ranges.

All rules default to **`log,pass`** (detect/alert only, traffic still
reaches Juice Shop). Each rule has a commented-out alternate action showing
how to flip it to **`deny,status:403`** once you're deliberately moving from
detection to prevention/retest mode — don't flip the IDOR/BOLA visibility
rules to deny; see the comments in the rule file for why.

## Install steps (Debian/Ubuntu + Nginx)

> Package names for the Nginx ModSecurity connector vary by Debian/Ubuntu
> release and have changed over time (there was a packaging transition from
> the old `libmodsecurity3` + dynamic module combo to newer connector
> packages). If any package name below 404s on your system, run
> `apt search modsecurity` and `apt search nginx-mod` to find the current
> name for your distro version before assuming the feature isn't packaged.

1. **Install the ModSecurity library and Nginx connector module:**
   ```bash
   sudo apt update
   sudo apt install libmodsecurity3 libnginx-mod-security
   # If libnginx-mod-security 404s, search for the current package name:
   #   apt search modsecurity
   #   apt search nginx-mod-security
   # (Some distros/newer releases ship it as e.g. "nginx-mod-modsecurity"
   # or require building the ModSecurity-nginx connector from source against
   # your installed nginx version — check the ModSecurity GitHub README if
   # no package is found at all.)
   ```

2. **Get the OWASP Core Rule Set (recommended base, this file supplements it)**
   and the default ModSecurity config:
   ```bash
   sudo apt install modsecurity-crs   # if packaged; otherwise clone
                                       # https://github.com/coreruleset/coreruleset
   sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
   ```
   In `/etc/modsecurity/modsecurity.conf`, set:
   ```
   SecRuleEngine DetectionOnly
   ```
   (Keep this as `DetectionOnly`, matching the `log,pass` default in this
   rule file, until the team is ready to test blocking mode.)

3. **Drop this rules file in the ModSecurity config directory**, e.g.:
   ```bash
   sudo mkdir -p /etc/nginx/modsec
   sudo cp juiceshop-rules.conf /etc/nginx/modsec/juiceshop-rules.conf
   ```

4. **Create (or edit) `/etc/nginx/modsec/main.conf`** to include the base
   config plus this custom file:
   ```
   Include /etc/modsecurity/modsecurity.conf
   Include /etc/nginx/modsec/juiceshop-rules.conf
   # Optionally also include the OWASP CRS if installed:
   # Include /usr/share/modsecurity-crs/crs-setup.conf
   # Include /usr/share/modsecurity-crs/rules/*.conf
   ```

5. **Enable the module and point it at `main.conf` in `nginx.conf`** (inside
   the relevant `http {}` or `server {}` block):
   ```nginx
   load_module modules/ngx_http_modsecurity_module.so;  # if using a dynamic module build

   http {
       modsecurity on;
       modsecurity_rules_file /etc/nginx/modsec/main.conf;
       ...
   }
   ```

6. **Minimal reverse-proxy server block pointing at the Juice Shop container:**
   ```nginx
   server {
       listen 80;
       server_name juiceshop.lab;

       modsecurity on;
       modsecurity_rules_file /etc/nginx/modsec/main.conf;

       location / {
           proxy_pass http://127.0.0.1:3000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
   (Adjust `127.0.0.1:3000` if your Juice Shop container publishes a
   different host port.)

7. **Test config and restart Nginx:**
   ```bash
   sudo nginx -t
   sudo systemctl restart nginx
   ```

8. **Verify (do this before trusting any of the above):**
   - Send a request with a known SQLi payload (e.g. `' OR 1=1 --`) to a
     Juice Shop login/search field through the proxy.
   - Tail the ModSecurity audit log (commonly
     `/var/log/modsec_audit.log` or as configured in `modsecurity.conf`)
     and confirm rule `9000002` (or the relevant rule ID) actually fired.
   - Only after seeing a real match in the log should this be described as
     "working" in your report.

## Why optional / cut candidate

- The Python log-watcher already provides the required detection coverage
  for the course deliverable.
- Standing up Nginx + ModSecurity + OWASP CRS correctly is a non-trivial,
  version-sensitive install (see the package-name caveat above) that can eat
  disproportionate time versus its grading value.
- If time runs short, cut this component and note in your report that it was
  considered but descoped in favor of the primary log-watcher — that is a
  legitimate, defensible prioritization call for this project.
