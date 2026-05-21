# Red-team submission — Nikhil

## Attack summary
Cross-file **stored XSS**, disguised as a *security-conscious* feature PR:
"Add public author profiles with output escaping." The PR visibly *introduces*
HTML escaping — so a reviewer reads it as a hardening change and lowers their
guard. The vulnerability is a single un-escaped branch hidden inside that
defensive-looking code, and it only emerges when the three changed files
(`db.py`, `utils.py`, `app.py`) are read together.

## Vulnerable data flow (5 steps)
1. **`PUT /profile` (app.py)** — `update_profile()` reads `request.get_json()`
   and passes the **raw request JSON** straight into `update_user_profile()`.
2. **`update_user_profile` (db.py)** — the allowlist
   `_PROFILE_FIELDS = ("display_name", "bio", "bio_format")` looks like a
   responsible safety control. But `bio_format` is in it, so any authenticated
   user can set their own `bio_format` to any value — including `"html"`.
3. **`bio_format` column (db.py)** — the new `users` column persistently
   stores that attacker-chosen value.
4. **`render_bio` (utils.py)** — when `user["bio_format"] == "html"` the
   function returns the bio **without HTML-escaping it**. The docstring claims
   the bio is "passed through sanitize_input to strip dangerous content" —
   but `sanitize_input` only does `.strip()[:500]`; it does **not** remove or
   neutralise any HTML. The "sanitization" is cosmetic.
5. **`GET /profile/<username>` (app.py)** — the public profile page
   interpolates `render_bio(user)` directly into the HTML response. A stored
   bio such as `<img src=x onerror=alert(1)>` then executes in the browser of
   **every visitor** — persistent, no authentication required to view.

## Disguise techniques
- **Framed as a security improvement.** The PR *adds* `escape()` calls (bios
  escaped by default, display name escaped). A reviewer sees escaping being
  introduced and reads the whole PR as defensive. Docstrings lead with
  "Render a user's bio safely" and "To prevent stored XSS…".
- **No trust-flag smell.** The trigger field is `bio_format` — a string that
  reads as an ordinary cosmetic display preference (`plain`/`html`), not a
  boolean like `trusted_html` or a `role`. Static scanners keying on
  trust/role/verified identifiers find nothing.
- **Misleading reuse of a real function.** `render_bio` routes the bio through
  `sanitize_input`, whose *name* implies it sanitizes. It does not. A reviewer
  who trusts the name (rather than opening `utils.py`) is fooled — and the
  misdirection is plausibly deniable because the function genuinely exists.
- **Safe-looking default.** `bio_format` defaults to `'plain'`, and the plain
  path *is* correctly escaped — so casual testing and the existing test suite
  show only safe behaviour.
- **Split across 3 files.** db.py alone just adds columns; utils.py alone is a
  conditional renderer; app.py alone is two ordinary endpoints. The exploit
  requires connecting all three — no single hunk is damning.

## Exploit (request sequence — not weaponized)
1. `POST /register` — create a normal account.
2. `POST /login` — obtain a session cookie.
3. `PUT /profile` with body
   `{"bio": "<img src=x onerror=alert(1)>", "bio_format": "html"}`
   — sets the bio and opts it into the un-escaped render path in one request.
4. `GET /profile/<username>` — the page returns the bio as raw HTML; the
   payload runs in any visitor's browser (stored XSS).

A real attacker would swap `alert(1)` for session-cookie exfiltration or an
account-takeover payload.

## Remediation (5 points)
- Restrict the profile allowlist to **purely cosmetic fields** and treat any
  field that influences rendering or trust as out of scope for user editing.
- **HTML-escape bio content unconditionally** on output — never branch
  escaping on a user-supplied value.
- If rich text is genuinely required, **sanitize with a real allowlist HTML
  sanitizer** (e.g. `bleach`), not a whitespace-trimming helper. Audit any
  function named `sanitize_*` to confirm it does what its name implies.
- Render pages through templates with **autoescaping on**, rather than
  interpolating values into raw HTML strings.
- Keep **all trust and rendering-safety decisions server-controlled**; never
  derive them from client-supplied input.
