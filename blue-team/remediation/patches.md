# Juice Shop Remediation Patches — Live Wire, Purple Rain (Blue Team)

These are source-level fixes applied directly to the team's local checkout of
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), the deliberately-vulnerable
Node.js/Express/Angular training app the Red Team attacked during this exercise. Juice
Shop's file layout and exact line numbers vary between versions/commits, so do not assume
the "before" snippets below match your checkout character-for-character — they illustrate
the vulnerable *pattern* so you can recognize and locate the equivalent spot. Use `grep`
(or VS Code's search) against your own `routes/` and `models/` directories to find the
real file, e.g.:

```
grep -rn "router.post('/rest/user/login'" routes/
grep -rn "jwt.verify" routes/ lib/
grep -rn "basket" routes/
grep -rn "/api/Users" routes/ server.ts app.ts
```

Each section below gives: root cause, an illustrative "before" snippet, the "after" fix,
and the exact re-test to prove the fix holds.

---

## 1. SQL Injection (login bypass)

**Root cause:** The login route builds a SQL query by directly concatenating
user-supplied `email`/`password` strings into a raw SQL string instead of using
parameterized queries. An attacker can break out of the string literal and alter the
query logic (e.g. `' OR 1=1--`), bypassing authentication entirely.

**Before (illustrative — raw concatenated SQL via `sequelize.query`):**
```js
// routes/login.js (illustrative)
models.sequelize.query(
  "SELECT * FROM Users WHERE email = '" + req.body.email +
  "' AND password = '" + security.hash(req.body.password) + "' AND deletedAt IS NULL",
  { model: models.User, plain: true }
).then(authenticatedUser => {
  if (authenticatedUser) {
    const token = security.authorize(authenticatedUser)
    res.status(200).json({ authentication: { token, bid: authenticatedUser.id } })
  } else {
    res.status(401).send(res.__('Invalid email or password.'))
  }
})
```

**After (Sequelize safe query builder — parameterized, no string concatenation):**
```js
// routes/login.js (fixed)
models.User.findOne({
  where: {
    email: req.body.email,
    password: security.hash(req.body.password),
    deletedAt: null
  }
}).then(authenticatedUser => {
  if (authenticatedUser) {
    const token = security.authorize(authenticatedUser)
    res.status(200).json({ authentication: { token, bid: authenticatedUser.id } })
  } else {
    res.status(401).send(res.__('Invalid email or password.'))
  }
}).catch(next)
```

`findOne({ where: {...} })` causes Sequelize to emit a parameterized query under the
hood — user input is always bound as a value, never spliced into the SQL text, so a
payload like `' OR 1=1--` is treated as a literal string to match against, not as SQL
syntax.

**Re-test:** Re-run the original SQLi payload against the login endpoint:
```
POST /rest/user/login
{ "email": "' OR 1=1--", "password": "anything" }
```
Before the fix: HTTP 200 with a valid JWT (`authentication.token`) for the first user
in the table (classic login bypass). After the fix: HTTP 401 `Invalid email or
password.` — the payload is treated as a literal email string that matches no row.

---

## 2. XSS (reflected search, stored review)

**Root cause:** Two related failures. (1) **Reflected** — the search endpoint echoes
the raw query term back into an API response that the Angular frontend renders without
escaping (or via `[innerHTML]`/`bypassSecurityTrust*` on untrusted data), so a payload
like `<script>alert(1)</script>` or an `<iframe onload=...>` executes in the victim's
browser. (2) **Stored** — product reviews/feedback are saved verbatim and rendered the
same unsafe way for every future viewer. (3) No Content-Security-Policy header is set,
so even if a bypass is found, inline scripts still execute freely.

**Before (illustrative — search result passed straight through, no server-side encoding):**
```js
// routes/search.js (illustrative)
exports.searchProducts = () => (req, res, next) => {
  const criteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
  models.Product.findAll({
    where: { name: { [Op.substring]: criteria } } // query itself is parameterized,
  }).then(products => {
    res.json({ data: products, searchTerm: criteria }) // raw criteria echoed back
  })
}
```
```html
<!-- Angular component template (illustrative) -->
<div [innerHTML]="searchTerm"></div>
```
```js
// routes/app.js (illustrative) — no CSP / helmet config
const app = express()
app.use(express.json())
// no helmet(), no CSP header set anywhere
```

**After (server-side output encoding + strict Angular binding + CSP via helmet):**
```js
// routes/search.js (fixed) — encode before it ever leaves the server
const entities = require('entities')

exports.searchProducts = () => (req, res, next) => {
  const criteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
  models.Product.findAll({
    where: { name: { [Op.substring]: criteria } }
  }).then(products => {
    res.json({ data: products, searchTerm: entities.encodeHTML(criteria) })
  })
}
```
```html
<!-- Angular component template (fixed) — plain interpolation, never innerHTML on
     untrusted data; do NOT use bypassSecurityTrustHtml on user-controlled strings -->
<div>{{ searchTerm }}</div>
```
```js
// routes/app.js (fixed) — add helmet with a restrictive CSP
const helmet = require('helmet')

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],       // no 'unsafe-inline', no 'unsafe-eval'
      styleSrc: ["'self'", "'unsafe-inline'"], // tighten further if feasible
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  })
)
```
Apply the same `entities.encodeHTML()` treatment wherever stored content (reviews,
feedback, product descriptions) is written, and ensure the Angular side uses
interpolation (`{{ }}`) or Angular's default `DomSanitizer`-backed bindings rather than
`[innerHTML]` or `bypassSecurityTrustHtml`/`bypassSecurityTrustScript` on anything that
originated from user input.

**Re-test:** Resend the original XSS payload to the search endpoint and to the review
endpoint:
```
GET /rest/products/search?q=<script>alert(document.cookie)</script>
POST /rest/products/:id/reviews   { "message": "<img src=x onerror=alert(1)>" }
```
Before the fix: the payload renders and executes in the browser (alert fires / script
tag intact in the DOM); response has no CSP header. After the fix: the response
contains the HTML-entity-encoded string (`&lt;script&gt;...&lt;/script&gt;`), it
renders as inert text instead of executing, and the response headers include
`Content-Security-Policy: default-src 'self'; script-src 'self'; ...` — confirm with
`curl -I` or the browser's Network tab that the header is present and that the inline
`<script>` is blocked/not executed.

---

## 3. IDOR (basket access)

**Root cause:** `/rest/basket/:id` fetches a basket purely by the `:id` path parameter
and returns it, with no check that the authenticated requester actually owns that
basket. Any logged-in user can increment the id and read/modify another user's basket.

**Before (illustrative — no ownership check):**
```js
// routes/basket.js (illustrative)
exports.retrieveBasket = () => (req, res, next) => {
  const id = req.params.id
  models.Basket.findOne({ where: { id }, include: [...] })
    .then(basket => {
      res.json({ data: basket })
    })
    .catch(next)
}
```

**After (ownership guard before returning data):**
```js
// routes/basket.js (fixed)
exports.retrieveBasket = () => (req, res, next) => {
  const id = req.params.id
  models.Basket.findOne({ where: { id }, include: [...] })
    .then(basket => {
      if (!basket) {
        return res.status(404).json({ error: 'Basket not found' })
      }
      // req.user populated by auth middleware from the verified JWT
      if (basket.UserId !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' })
      }
      res.json({ data: basket })
    })
    .catch(next)
}
```
Or, as reusable Express middleware applied to the route:
```js
// middleware/ownsBasket.js (fixed, alternative style)
module.exports = () => (req, res, next) => {
  models.Basket.findByPk(req.params.id).then(basket => {
    if (!basket) return res.status(404).json({ error: 'Basket not found' })
    if (basket.UserId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' })
    }
    req.basket = basket
    next()
  }).catch(next)
}
// router.get('/rest/basket/:id', ownsBasket(), retrieveBasket())
```

**Re-test:** Log in as User A, note User B's basket id from a prior capture, then
resend:
```
GET /rest/basket/<User_B_basket_id>
Authorization: Bearer <User_A_JWT>
```
Before the fix: HTTP 200 with User B's basket contents. After the fix: HTTP 403
`{"error":"Forbidden"}` when the authenticated user does not own that basket id.

---

## 4. Broken Authentication (JWT weak secret)

**Root cause:** The JWT signing secret is a short, hardcoded, guessable string
committed directly in source (e.g. `"secretkey"` or a well-known Juice Shop CTF
constant). Anyone who reads the source, decompiles the bundle, or brute-forces the
secret (trivial with tools like `hashcat`/`jwt_tool` against a weak secret) can forge
arbitrary valid tokens, including admin tokens.

**Before (illustrative — hardcoded weak secret, no algorithm restriction):**
```js
// lib/insecurity.ts (illustrative)
const jwt = require('jsonwebtoken')
const privateKey = 'secretkey123' // hardcoded, weak, committed to source control

exports.authorize = (user) => jwt.sign(user, privateKey, { expiresIn: '1h' })

exports.verify = (token) => {
  try {
    return jwt.verify(token, privateKey) // no algorithms restriction
  } catch (e) {
    return undefined
  }
}
```

**After (strong secret from environment, explicit algorithm allowlist):**
```js
// lib/insecurity.ts (fixed)
const jwt = require('jsonwebtoken')

// Secret is generated once with: openssl rand -base64 48
// and stored OUTSIDE source control, e.g. injected as an env var:
//   JWT_SECRET=<64+ char random value>   (set in .env, excluded via .gitignore,
//   or in the deployment platform's secrets manager)
const privateKey = process.env.JWT_SECRET
if (!privateKey) {
  throw new Error('JWT_SECRET environment variable is not set')
}

exports.authorize = (user) =>
  jwt.sign(user, privateKey, { expiresIn: '1h', algorithm: 'HS256' })

exports.verify = (token) => {
  try {
    return jwt.verify(token, privateKey, { algorithms: ['HS256'] }) // explicit allowlist
  } catch (e) {
    return undefined
  }
}
```
```
# .env (never committed — add .env to .gitignore)
JWT_SECRET=<output of: openssl rand -base64 48>
```

**Re-test:** Take a token forged offline with the old known/weak secret (e.g. via
`jwt_tool` or a quick script using `jsonwebtoken.sign()` with the leaked
`secretkey123`) and resend it:
```
GET /rest/user/whoami
Authorization: Bearer <token forged with old weak secret>
```
Before the fix: HTTP 200, forged token accepted, attacker-controlled claims (e.g.
`role: admin`) trusted. After the fix: HTTP 401 `invalid signature` — the server now
verifies against the new random `JWT_SECRET`, which the attacker cannot reproduce, so
any token not signed with it is rejected.

---

## 5. BOLA (`/api/Users/:id`)

**Root cause:** Same missing-ownership-check pattern as IDOR (#3), applied to the Users
REST API: the handler fetches and returns a full user record by `:id` without verifying
the requester is that user (or an admin), allowing Broken Object Level Authorization —
any authenticated user can read (or in some endpoints, update) another user's profile
data, including PII fields that shouldn't be exposed beyond what's necessary.

**Before (illustrative — no ownership check, over-broad field exposure):**
```js
// routes/user.js (illustrative) — generic REST exposure via rest/sequelize-restful style route
exports.getUserById = () => (req, res, next) => {
  models.User.findByPk(req.params.id).then(user => {
    if (!user) return res.status(404).json({ error: 'User not found' })
    res.json({ data: user }) // returns entire row: email, password hash, etc.
  }).catch(next)
}
```

**After (ownership/role guard + minimal field projection):**
```js
// routes/user.js (fixed)
exports.getUserById = () => (req, res, next) => {
  models.User.findByPk(req.params.id).then(user => {
    if (!user) return res.status(404).json({ error: 'User not found' })

    const isSelf = req.user && req.user.id === user.id
    const isAdmin = req.user && req.user.role === 'admin'
    if (!isSelf && !isAdmin) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    // Even for self/admin, only return what's needed — never leak password hash,
    // TOTP secrets, or other sensitive internal fields.
    const { id, username, email, role } = user
    res.json({ data: { id, username, email, role } })
  }).catch(next)
}
```

**Re-test:** Log in as User A, then resend the original BOLA request against User B's
id:
```
GET /api/Users/<User_B_id>
Authorization: Bearer <User_A_JWT>
```
Before the fix: HTTP 200 with User B's full record (email, password hash, etc.). After
the fix: HTTP 403 `{"error":"Forbidden"}` for a non-owner/non-admin requester; when User
A requests their own id, HTTP 200 but with only the minimal field set (no password hash
or other sensitive fields) in the response body.

---

## 6. JWT Algorithm Confusion (`alg:none`)

**Root cause:** `jwt.verify()` is called without an explicit `algorithms` allowlist, so
the library trusts whatever `alg` value is in the token's own header. An attacker can
craft a token with header `{"alg":"none"}` (or swap `RS256`→`HS256` and sign with the
public key as if it were an HMAC secret) and the verify call accepts it without ever
checking a signature.

**Before (illustrative — no algorithm restriction, `alg:none` accepted):**
```js
// lib/insecurity.ts (illustrative)
exports.verify = (token) => {
  try {
    return jwt.verify(token, privateKey) // alg not restricted — trusts token header
  } catch (e) {
    return undefined
  }
}
```

**After (explicit algorithm allowlist — `alg:none` and algorithm-swap rejected):**
```js
// lib/insecurity.ts (fixed)
exports.verify = (token) => {
  try {
    // Only ever accept the exact algorithm(s) this server itself signs with.
    // 'none' is never in this list, so unsigned tokens are rejected outright,
    // and an RS256-signed token can't be replayed as HS256 (or vice versa).
    return jwt.verify(token, privateKey, { algorithms: ['HS256'] })
  } catch (e) {
    return undefined
  }
}
```

**Re-test:** Resend the original `alg:none` forged token (header `{"alg":"none","typ":"JWT"}`,
signature stripped) against any authenticated endpoint:
```
GET /rest/user/whoami
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload-base64>.
```
Before the fix: HTTP 200, token accepted with attacker-controlled claims despite no
valid signature. After the fix: HTTP 401 — `jsonwebtoken` throws `JsonWebTokenError:
invalid algorithm` because `none` (and any algorithm other than `HS256`) is outside the
explicit allowlist, so the token is rejected before any claim is trusted.

---

## Applying and re-testing

Apply fixes in this order (batch-fix, not one-at-a-time, to save time per the project's
own time-crunch methodology): **SQLi → XSS → IDOR/BOLA → JWT (auth + alg confusion)**,
then retest all in the same batched order. Make all source edits for a stage first,
restart the local Juice Shop instance once, then fire the corresponding re-test
request(s) for that stage before moving to the next, so you get one clean before/after
comparison per stage instead of restarting the app six separate times.
