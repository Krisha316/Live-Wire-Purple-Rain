# BOLA & JWT Attack Playbook — OWASP Juice Shop

**Project:** Live Wire, Purple Rain — Red/Blue/Purple Team Exercise
**Target:** Self-hosted OWASP Juice Shop (Docker, isolated lab network, authorized)
**App reference:** https://github.com/juice-shop/juice-shop
**Audience:** Two-student attack pair, producing screenshot evidence for the academic report

> Scope note: This playbook targets your own local Juice Shop Docker instance only. All example
> hosts below use `http://localhost:3000` — replace with your container's actual mapped
> host/port if different.

## Shared setup (do this once)

1. Start your Juice Shop container and confirm it's reachable:
   ```
   docker run -d -p 3000:3000 bkimminich/juice-shop
   ```
   Browse to `http://localhost:3000` to confirm it loads.
2. Configure Burp Suite Community as your browser's proxy (127.0.0.1:8080), install/trust the
   Burp CA cert in the browser so HTTPS/HTTP traffic is visible (Juice Shop is plain HTTP by
   default on :3000, so cert trust is usually not an issue here).
3. In Juice Shop, register **two** normal user accounts (e.g. `attacker@test.local` and
   `victim@test.local`) via `/#/register`. You need a second account so you have a real
   "other user" to demonstrate unauthorized access against — using arbitrary id math (id+1)
   alone is less convincing evidence than showing a named victim's actual data.
4. Log in as the **attacker** account in the browser with Burp's Proxy "Intercept" on, and in
   DevTools (F12 → Application → Local Storage, or Network tab) locate the JWT. Juice Shop
   stores the token in browser local storage under the key `token` after login, and sends it
   as `Authorization: Bearer <token>` on API calls.
5. Keep a notes doc open with: your attacker user id, attacker token, victim user id (if
   known/guessed), and the exact timestamp (HH:MM:SS, synced with your Discord alert channel
   clock) of every request you fire. Your methodology pairs each attack screenshot with a
   Discord alert screenshot at matching timestamps, so note the time BEFORE you send each
   request.

---

## Technique 1 — BOLA (Broken Object-Level Authorization)

### Objective
Demonstrate that the API trusts the caller's JWT to prove *who* they are, but does not check
whether the *object id* in the URL (another user's id, or another user's basket id) actually
belongs to that caller — letting an authenticated low-privilege user read another user's
profile or basket by simply changing the id in the path.

### Prerequisites
- Two registered Juice Shop accounts (attacker, victim), as set up above.
- Victim account logged in at least once so a user/basket record exists for it.
- Attacker's own valid Bearer JWT (captured via DevTools or Burp proxy history).
- Burp Suite Community running as proxy; browser configured to use it.

### Step-by-step — Burp Suite (Proxy / Repeater)

1. Log in as the **attacker** in the browser. In Burp's **Proxy > HTTP history**, find a
   request the app made to `GET /api/Users/<id>` (triggered by viewing "My Account" / profile)
   or `GET /rest/basket/<id>` (triggered by opening the shopping basket).
2. Note the attacker's own id in that URL (e.g. `/api/Users/21`) and confirm the request carries
   `Authorization: Bearer <attacker_token>` in the headers.
3. Right-click that request → **Send to Repeater**.
4. In Repeater, duplicate the request (new tab) and edit ONLY the id in the path — change
   `/api/Users/21` to `/api/Users/22` (or `id-1`), **keeping the same Authorization header
   (your own attacker token) unchanged**. This is the core of BOLA: same token, different
   object id.
5. Click **Send**. Repeat the same id-swap test against `/rest/basket/<id>` using whatever
   basket id the victim's session would have (basket ids in Juice Shop typically track user id
   closely; try the victim's id and nearby ids if the exact basket id isn't already known from
   recon).
6. Inspect the response body and status code.

### curl equivalent

```bash
# Attacker's own id/token, request a DIFFERENT user's record:
curl -i -H "Authorization: Bearer <attacker_token>" \
  http://localhost:3000/api/Users/<victim_id>

# Same idea against basket endpoint:
curl -i -H "Authorization: Bearer <attacker_token>" \
  http://localhost:3000/rest/basket/<victim_basket_id>
```

### Expected successful result (vulnerability present)

- **HTTP 200 OK**, with a JSON body containing the *victim's* data (email, profile fields, or
  basket contents/products) — NOT the attacker's own data, and NOT a 403/401.
- This is the "successful attack" condition: an authorization check that should exist (does
  this token's user own this object id?) is missing or incomplete.
- If instead you get `401`, `403`, or a body that silently returns only the attacker's own
  data regardless of the id requested, the endpoint is NOT vulnerable as tested — record that
  as a negative/blocked result; it is still valid evidence.

### What to screenshot for the report

- Screenshot 1: the Repeater (or curl terminal) request pane showing the modified id and the
  attacker's unchanged Authorization header.
- Screenshot 2: the response pane showing HTTP 200 and the victim's data in the body.
- Screenshot 3 (paired): your Discord alert channel at the same timestamp as the request, to
  show whether/when Blue Team's detection fired (or didn't) for this request — crop or
  annotate so the timestamp is visible and matches your attack-log note.
- One-line result note for your detection/remediation table, e.g.: *"BOLA on
  `/api/Users/:id` — 200 OK, victim profile disclosed with attacker's own token; no Discord
  alert fired at T+0s / alert fired at T+Ns"* (fill in what actually happened).

---

## Technique 2 — JWT Tampering

Juice Shop issues JWTs on login and expects them back as `Authorization: Bearer <token>`. Two
distinct sub-techniques are covered below. Both are "attempt and record the outcome" exercises
— do not assume either will succeed before you test it.

### Sub-technique A — Weak/known signing secret recovery and forgery

#### Objective
Check whether the JWT's HMAC signature can be cracked against a wordlist of known/default/weak
secrets. Juice Shop has, in some versions and challenge configurations, been documented
(including in its own "Jwt Issues" / "Forged Signed JWT" security challenges) as a deliberately
vulnerable target for this class of attack. Exact current behavior depends on your installed
version — verify rather than assume.

#### Prerequisites
- A valid JWT captured from a logged-in session (attacker account is fine).
- `jwt_tool` (https://github.com/ticarpi/jwt_tool) or `hashcat` installed, OR use jwt.io purely
  to decode/inspect (jwt.io's "verify" UI can also test a guessed secret manually without
  cracking).
- A small wordlist of common/leaked JWT secrets (jwt_tool ships one; Juice Shop's own
  documented/leaked example secrets from its challenge solutions can also be tried if you have
  them from course material).

#### Step-by-step

1. Copy the raw JWT string (three base64url segments separated by `.`).
2. Decode header and payload for inspection — either paste into jwt.io (header/payload panels
   show JSON; do this only with lab tokens, never real secrets) or decode locally:
   ```bash
   # header
   echo -n "<segment1>" | base64 -d
   # payload
   echo -n "<segment2>" | base64 -d
   ```
   Note the `alg` (expect `HS256` typically) and look at the payload claims — Juice Shop JWT
   payloads commonly include fields like `data` (a nested user object with `email`, `id`,
   `role`) rather than a flat `isAdmin` claim; identify exactly which claim encodes privilege
   in YOUR captured token before planning what to forge.
3. Attempt to crack the signing secret against the signature:
   ```bash
   # jwt_tool dictionary attack
   python3 jwt_tool.py <captured_jwt> -C -d jwt-secrets.txt

   # or hashcat (mode 16500 = JWT)
   hashcat -a 0 -m 16500 <captured_jwt> jwt-secrets.txt
   ```
4. If a secret is recovered: use jwt_tool (or jwt.io's debugger with the secret pasted into the
   "verify signature" box) to re-sign a modified payload — e.g. flip the role/admin-indicating
   claim you identified in step 2 — producing a new, validly-signed token.
5. Replay the forged token:
   - **Burp**: send the original authenticated request to Repeater, replace the Authorization
     header value with the forged token, Send.
   - **curl**:
     ```bash
     curl -i -H "Authorization: Bearer <forged_token>" \
       http://localhost:3000/rest/admin/application-version
     ```
     (or any endpoint believed to require elevated privilege).
6. Observe whether the elevated claim is honored (e.g. access to an admin-only endpoint, or a
   UI element that only appears for admins).

#### Expected result — report honestly either way
- **If secret cracks and forged token is accepted**: document the recovered secret (lab only,
  do not publish it outside the report), the modified claim, and the endpoint/behavior that
  proved privilege escalation.
- **If the secret does not crack** against your wordlist in reasonable time, or the server
  rejects the forged token (401/403) even with a correctly guessed secret structure: record
  this as a negative result. Do not claim success you didn't observe. State explicitly:
  "secret not recovered from wordlist X" or "forged token rejected — server re-validates
  claims server-side" as applicable.

### Sub-technique B — Algorithm confusion / `alg:none`

#### Objective
Test whether the server's JWT verification can be bypassed by declaring `"alg":"none"` in the
token header, which per a well-known class of JWT library bugs causes some verifiers to skip
signature checking entirely. Modern, properly-configured JWT libraries (including current
`jsonwebtoken` versions as used by current Juice Shop releases) explicitly reject `none` unless
the verifier opts in — so this is expected to likely FAIL on a current build. Treat it as a
genuine test, not a guaranteed exploit, and document whichever outcome you observe.

#### Prerequisites
- A valid captured JWT (as above).
- Burp Suite (Proxy + Repeater) for manual header editing.

#### Step-by-step — Burp

1. With Burp Proxy intercepting, log in and capture an authenticated request carrying the
   Authorization header.
2. Send it to Repeater.
3. Decode the header segment (segment 1) — normally `{"alg":"HS256","typ":"JWT"}` base64url
   encoded. Decode it (CyberChef, or `echo -n "<seg1>" | base64 -d`, or jwt.io) so you can edit
   the plaintext JSON.
4. Edit the header JSON to:
   ```json
   {"alg":"none","typ":"JWT"}
   ```
5. Re-encode this edited header to base64url (no padding `=` characters):
   ```bash
   echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
   ```
6. Optionally also edit the payload segment (segment 2) the same way if you want to test
   combining `alg:none` with a modified claim — decode, edit JSON, re-encode to base64url the
   same way.
7. Per the `alg:none` spec quirk, construct the token as `header.payload.` — i.e. keep the
   trailing dot but leave the signature segment EMPTY (some implementations also tolerate a
   non-empty garbage third segment; test the empty-signature form first as it's the canonical
   case).
8. In Repeater, replace the Authorization header value with this new
   `<b64url_header>.<b64url_payload>.` token and click **Send**.
9. Also try the same with the signature segment entirely removed (just
   `<header>.<payload>` with no trailing dot) in a second Repeater tab, since some parsers
   differ on this.

#### curl equivalent

```bash
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<b64url_payload>."
curl -i -H "Authorization: Bearer $FORGED" \
  http://localhost:3000/rest/user/whoami
```

#### Expected result — PASS (blocked) or FAIL (accepted), both are valid evidence

- **FAIL (accepted)**: server returns 200 and treats the request as authenticated/with your
  edited claims despite no valid signature. This would indicate the app or an intermediary is
  vulnerable to algorithm confusion — noteworthy and worth escalating in the report.
- **PASS (blocked)**: server returns 401/403, or an error about malformed/invalid token. This
  is the expected outcome against a current, correctly configured Juice Shop build. Document
  it as a tested-and-not-exploitable control, which is still a legitimate, reportable finding
  ("verified the app correctly rejects alg:none tampering").
- Do not state in the report that Juice Shop "is" or "is not" vulnerable to this in general —
  only state what YOUR specific container, version, and test produced.

#### What to screenshot for the report (both sub-techniques A and B)

- Screenshot 1: decoded JWT header/payload before tampering (jwt.io or CLI decode output).
- Screenshot 2: the Repeater request with the tampered Authorization header (forged-secret
  token for A, `alg:none` token for B) clearly visible.
- Screenshot 3: the response — either the successful elevated-access response (FAIL/accepted
  case) or the rejection response (PASS/blocked case).
- Screenshot 4 (paired): Discord alert channel at matching timestamp, annotated to show
  alert-vs-no-alert at the moment of the tampered request.
- One-line result note, e.g.: *"JWT alg:none on /rest/user/whoami — PASS (401, rejected);
  no further action"* or *"JWT secret cracked (wordlist hit) — forged admin claim accepted,
  200 OK on admin endpoint; Discord alert fired T+2s."*

---

## Evidence checklist

### BOLA (`/api/Users/:id`, `/rest/basket/:id`)
- [ ] Screenshot of request/payload (Repeater or curl, showing swapped id + unchanged attacker token)
- [ ] Screenshot of successful (200, victim data) or blocked (401/403) response
- [ ] Paired Discord alert screenshot with matching timestamp
- [ ] One-line result note for the attack-detection-remediation table

### JWT Tampering (secret-cracking/forgery AND alg:none)
- [ ] Screenshot of request/payload (decoded JWT + tampered header/Authorization value in Repeater or curl)
- [ ] Screenshot of successful (claim honored) or blocked (rejected) response — for EACH sub-technique attempted
- [ ] Paired Discord alert screenshot with matching timestamp
- [ ] One-line result note for the attack-detection-remediation table (state PASS/blocked or FAIL/accepted explicitly)
