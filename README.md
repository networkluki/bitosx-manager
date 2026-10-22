# bitosx-manager — BitosX web

Private repository for the BitosX web front: static sites for bitosx.se and vault.bitosx.se. Two sites, one stylesheet, no build step,
no framework, no CDN. Everything is plain HTML, CSS and JavaScript served from the same origin so a
strict Content-Security-Policy holds. The one piece of third-party code is the vendored Argon2
WebAssembly build the web vault needs (`vault/public/assets/vendor/hash-wasm/`, with its provenance).

| Hostname | Directory | Purpose | Talks to |
|---|---|---|---|
| `bitosx.se` | `www/public/` | Public product page: what BitosX is, how the vault is protected, what works today, live API status, roadmap | `api.bitosx.se` (`GET /health`, `GET /version` only) |
| `vault.bitosx.se` | `vault/public/` | Web **account** app (register, verify email + set account password, sign in, list and revoke sessions, sign out everywhere; since phase 6 reset a forgotten account password by emailed link and delete the account) and, since phase 4, the **web vault**: the encrypted envelope the desktop synced is opened in the browser with the master password; since phase 5 it can be edited there and uploaded with compare-and-set | `api.bitosx.se` (`/v1/auth/*`, `/v1/account/*`, `GET /v1/sync/status`, `GET /v1/sync/envelope`, `PUT /v1/sync/envelope`) |
| `api.bitosx.se` | — | The account API. Lives in [`networkluki/bitosx-api`](https://github.com/networkluki/bitosx-api) and is operated alongside the desktop app; nothing here | — |

The desktop app lives in [`networkluki/bitosx`](https://github.com/networkluki/bitosx).

## The web vault (phase 4)

Signed in, the account page shows what the server holds for the account (`GET /v1/sync/status`:
revision, size, when stored) and asks for the vault's **master password**. On *Open in this browser*:

1. `GET /v1/sync/envelope` — the bytes the desktop uploaded, Base64 in JSON. The response is capped
   at 23 MiB (the envelope itself at 16 MiB, the desktop's own file limit); the size and the SHA-256
   fingerprint the server states must match the bytes, or the answer is refused as unexpected.
2. The bytes are parsed as a v1 envelope with the same fail-closed rules as the desktop
   (`vault-crypto.js`: exactly the nine fields, `argon2id`, `AES-256-GCM`, KDF parameters within the
   desktop's floors and ceilings, field lengths). Anything else is refused before any key work.
3. The master password is encoded as the desktop encodes it — every space separator to U+0020,
   NFC, UTF-8 — and the key is derived with **Argon2id** from the vendored `hash-wasm` build, with
   the vault's own parameters (256 MiB, t=3, p=4 for a vault the desktop created). Vaults keyed by a
   desktop before 0.6.0 (password as typed) open through the same fallback candidates the desktop tries.
4. The vault key is unwrapped and the content decrypted with **AES-256-GCM from WebCrypto**, with
   the associated data built byte for byte as `VaultCryptor` builds it. A wrong password and a
   modified envelope are indistinguishable, as on the desktop.
5. The decrypted JSON is read strictly (schema version 1, `login` items, no unknown fields, no
   duplicate ids) and rendered as **text** — never HTML — with passwords hidden until *Show*.

Nothing decrypted is ever sent anywhere; since phase 5 (below) edits are encrypted in the browser
before they are uploaded. The master password and the items live only in the page's memory while unlocked. The vault locks after 5
minutes without input, when the tab is hidden, on sign-out, and on reload/close. A copied value is
cleared from the clipboard after 30 seconds — only if it is still what was copied, and only when the
browser lets the page read the clipboard back; otherwise it is left alone. JavaScript strings cannot
be wiped, so "dropped" means unreferenced, as in the desktop app.

**What the server can and cannot do.** It can withhold the vault, serve an old revision, or serve
bytes that are not the vault; the fingerprint check and the parser refuse the last, and the first two
leave the user with the desktop copy. It cannot produce a vault that opens with the user's master
password without that password, and it never sees the password: the only requests the web vault makes
are the two `GET`s above and, on *Save to server*, the `PUT` of a freshly encrypted envelope.

**Why `'wasm-unsafe-eval'`.** WebCrypto has no Argon2, so the KDF is WebAssembly. `hash-wasm`
embeds the module as Base64 and instantiates it with `WebAssembly.instantiate`, which the CSP must
allow with `'wasm-unsafe-eval'` in `script-src` on the one page that does it (`vault/public/index.html`
and `_headers`; the other pages keep `script-src 'self'` and the test enforces both). It is not
`'unsafe-eval'`: JavaScript `eval` stays blocked. The build's version, tarball integrity and file hash
are recorded in `vault/public/assets/vendor/hash-wasm/README.md`, and it is checked against Argon2id
vectors computed by the desktop's own KDF before any vault goes near it.

## Editing in the browser (phase 5)

Since web `0.3.0` the vault page can add, change and delete logins. Nothing leaves the browser
until *Save to server*:

1. The items are written as the desktop writes them (`serializeVault`: the same JSON shape, the
   same validation as `VaultValidation` — name required and ≤ 200, username ≤ 320, password ≤ 4096,
   notes ≤ 16384, at most 64 absolute http(s) URLs, `UpdatedAt` never before `CreatedAt`), then
   encrypted **under the vault key that was unwrapped at unlock**, with a fresh 96-bit nonce and the
   desktop's content associated data (`VaultCryptor.ReEncryptContent`). The key-wrap header — salt,
   KDF parameters, wrapped vault key — is carried over untouched, so the desktop's master password
   still opens the result. The ciphertext is decrypted again before it is accepted (self-check).
2. The envelope is serialized byte for byte as `EncryptedVaultSerializer` writes it and sent with
   `PUT /v1/sync/envelope` and the **base revision the vault was opened at**. The server's reply
   must state the size and SHA-256 of exactly what was sent.
3. A **409** means another device uploaded first. Nothing is overwritten; the page offers the two
   ways out the desktop offers: reload the server's vault (the changes here are discarded, the
   master password is asked for again) or replace the server's vault with this browser's version,
   behind an acknowledgement — still compare-and-set against the revision the server holds at that
   moment, so a device that uploads in between is not silently overwritten.

While there are unsaved changes the page says so, the browser warns before the tab is closed, and
hiding the tab does **not** lock (a lock would discard the changes); the idle lock after 5 minutes,
sign-out and unload still do. A delete is asked for and then confirmed, as in the desktop app. The
generator makes 24-character passwords from a fixed alphabet with rejection sampling, from
`crypto.getRandomValues`.

The vault key lives in the page's memory while unlocked, exactly as it lives in the desktop
process; it is zeroed on lock. The master password is still never kept.

**Verified against the desktop's own code:** the e2e suite opens what the mock server holds after
a browser save with `vault-crypto.js` under Node, and the same envelope was opened with
`BitosX.Crypto.VaultCryptor` + `VaultSerializer` + `VaultValidation` from a .NET console program
(parse, unlock with the canonical password encoding, deserialize, validate all items) — see the
pull request for the run. Not verified: a real desktop syncing a browser-written revision through
`api.bitosx.se`.

## Account recovery and deletion (phase 6)

Two more pages and one more panel, all against the phase-6 API endpoints:

- **`/forgot-password`** posts the email to `POST /v1/auth/forgot-password` and shows the same
  generic text for every address (the API answers 202 for unknown, unverified and existing accounts
  alike). The page says plainly that this resets only the *account* password: the vault master
  password was never on the server and cannot be reset by anyone.
- **`/reset-password`** is the `verify-email` page's twin: the token arrives in the URL fragment
  (never sent to the server, scrubbed from the address bar and history on load, kept in memory
  only), the new password is checked against the same 12–128 policy client-side, and
  `POST /v1/auth/reset-password` replaces the account password and signs out every device. The
  token is single-use, so the form stays locked after success or a generic "invalid, expired or
  already used".
- **Delete this account** on the account panel: the account password plus an explicit
  acknowledgement, then `POST /v1/account/delete`. Only the password travels; the account is the
  session's. The server deletes the account, every session and the stored encrypted vault; the page
  signs out locally and says so. A wrong password is a 403 the page shows as such, without treating
  the session as dead.

The e2e suite covers each path against the mock API, including that a verification token is not
accepted as a reset token and that the delete call carries nothing but the password.

## What phase 1 was

Phase 1 used **only endpoints the API already implemented** (`bitosx-api/docs/API.md`):

- `POST /v1/auth/register` — email only, generic 202
- `POST /v1/auth/verify-email` — token from the email link + chosen account password (12–128)
- `POST /v1/auth/resend-verification`
- `POST /v1/auth/login`, `POST /v1/auth/refresh`, `POST /v1/auth/logout`, `POST /v1/auth/logout-all`
- `GET /v1/account/me`, `GET /v1/account/sessions`, `DELETE /v1/account/sessions/{id}`
- `GET /health`, `GET /version`

Phases as presented on the product page, and where each stands:

1. **Phase 1:** public site + web account against the account API — built (this repository, merged).
2. **Phase 2:** the desktop app implements `IBitosXApiClient` (account sign-in, sessions, refresh) —
   `networkluki/bitosx` PR #4.
3. **Phase 3:** encrypted sync — the server stores the encrypted vault envelope as opaque bytes
   (`networkluki/bitosx-api` PR #3, `GET/PUT/DELETE /v1/sync/*`), the desktop uploads and downloads
   ciphertext only (`networkluki/bitosx` PR #5).
4. **Phase 4:** the web vault above — this repository, merged. It needs phase 3 on both sides to be
   deployed: until `/v1/sync/*` exists on `api.bitosx.se` and a desktop has synced, the page says the
   server holds no vault.
5. **Phase 5:** editing in the browser, above — this repository.

## Blockers outside this repository (must be done before vault.bitosx.se works)

1. **CORS on the API.** `bitosx-api/docs/SECURITY_MODEL.md` states: "No CORS is configured … none
   will be added without a concrete consumer requirement." The web app is that requirement. Without
   it every browser request from `https://vault.bitosx.se` fails at the preflight and the app shows
   "The API could not be reached from this browser". Suggested policy, to be added in `bitosx-api`
   (ASP.NET Core CORS middleware, placed before authentication):
   - `Access-Control-Allow-Origin`: exactly `https://vault.bitosx.se` and `https://bitosx.se` (the
     product page only needs it for `/health` and `/version`). No wildcard.
   - `Access-Control-Allow-Methods`: `GET, POST, DELETE, OPTIONS`
   - `Access-Control-Allow-Headers`: `Authorization, Content-Type, Accept`
   - `Access-Control-Expose-Headers`: `Retry-After, X-Correlation-ID`
   - **No** `Access-Control-Allow-Credentials` — the app uses bearer tokens, never cookies.
   - `Vary: Origin`.
2. **Public exposure of the API.** Kestrel is loopback-only and Apache does not proxy to it yet. The
   `[host]` checklist in `bitosx-api/docs/DEPLOYMENT.md` gates that; nothing here changes it.
3. **Verification email base URL.** Set `Email:PublicBaseUrl = https://vault.bitosx.se` and keep
   `Email:VerificationPath = /verify-email` (the default). The link then reads
   `https://vault.bitosx.se/verify-email#token=<base64url>`; the token is in the fragment, which the
   browser never sends to any server, so it stays out of access logs.

## Security properties of the web app

- **Tokens in memory only.** Access and refresh tokens are held in a closure in `api.js`. Nothing is
  written to `localStorage`, `sessionStorage`, cookies or IndexedDB (the theme preference is the only
  stored value). A reload or closed tab means signing in again. This is deliberate for phase 1: it
  removes token theft via storage from the threat model at the cost of convenience.
- **Single-flight refresh.** The API revokes the whole session when a refresh token is presented
  twice. `api.js` guarantees at most one refresh is in flight; the e2e test asserts exactly one refresh
  when `/me` and `/sessions` run in parallel against an expired access token.
- **Strict CSP, no inline anything.** `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self'; connect-src https://api.bitosx.se; base-uri 'none'; form-action 'none'` — plus
  `'wasm-unsafe-eval'` in `script-src` on the vault page only, for the Argon2 WebAssembly (above). Forms are
  handled by JavaScript; `form-action 'none'` means a native submit can never put a password in a URL.
  The policy is set both as a response header (`_headers`, Cloudflare) and as a `<meta>` tag (so the
  GitHub Pages preview is covered; `frame-ancestors` only applies via the header).
- **No HTML from data.** Everything from the network or the URL is rendered with `textContent` or
  `createElement`; `innerHTML` is not used.
- **Responses are untrusted input.** Bodies are size-capped (64 KiB; 23 MiB for the one envelope
  download), must be JSON, and every field the UI shows is type- and format-checked (UUIDs, ISO
  dates, booleans, hex fingerprints, strict Base64) before use.
- **Verification token hygiene.** Read once from `location.hash`, validated as base64url, then removed
  from the address bar and history with `history.replaceState`; sent only in a POST body.
- **Generic errors.** Failures collapse to a fixed set of client-side messages; the server's
  anti-enumeration behaviour (identical 202/401 regardless of account existence) is preserved by
  showing the same text for the same status.
- **Idle sign-out.** After 15 minutes without input the tokens are dropped and `/logout` is called
  best-effort. Passwords are cleared from the fields after every submit, success or failure.
- **No third-party code.** No CDN, fonts, analytics or trackers on either site.

Known limitations: an XSS on `vault.bitosx.se` would still be able to call the API with the in-memory
token while the tab is open, and, while the vault is unlocked, to read the decrypted items — the CSP,
the no-inline rule, text-only rendering and the short vault lock are the controls against that; the
desktop app remains the place for anything that must not depend on a browser. The
`Strict-Transport-Security` header in `_headers` is set without `includeSubDomains`; whether to
enable HSTS zone-wide (with subdomains) is a Cloudflare decision that affects `api.bitosx.se` too.

## Deployment

Each site is a Cloudflare Worker that serves static assets only. From the repository root:

```bash
# bitosx.se
wrangler deploy -c www/wrangler.jsonc

# vault.bitosx.se
wrangler deploy -c vault/wrangler.jsonc
```

Then attach the custom domains (`bitosx.se` → Worker `bitosx-se`, `vault.bitosx.se` → Worker
`bitosx-vault`) under *Workers & Pages → the Worker → Settings → Domains & Routes*. Both zones must be
on Cloudflare DNS (`api.bitosx.se` already is, per `bitosx-api/docs/SECURITY_MODEL.md`).

`_headers` (security headers) and `404.html` (`not_found_handling: "404-page"`) are picked up by Workers
static assets. Verify the `_headers` behaviour against the current Cloudflare documentation for Workers
static assets before relying on it; the `<meta>` CSP is the fallback either way.

This repository is private and is not published by GitHub Pages; the Workers above are the only
deployment path.

## Verification

```bash
# Syntax + lint (eslint 9+/10 flat config; adjust the config path to taste)
for f in www/public/assets/js/*.js vault/public/assets/js/*.js; do node --check "$f"; done

# The browser vault crypto, run under Node against the vendored Argon2 build and Node's WebCrypto:
# desktop-written fixtures open, every malformed envelope and document is refused, Argon2id vectors
# computed by the desktop's KDF match. BITOSX_TEST_SLOW=1 adds the 256 MiB cases.
node --test tests/vault-crypto.test.js

# End-to-end in headless Chromium against the in-process mock API (needs the `playwright` package
# and a Chromium it can find; PLAYWRIGHT_BROWSERS_PATH if it is not the default location).
# BITOSX_E2E_SLOW=1 adds the 256 MiB unlock in Chromium.
node tests/e2e.js
```

The e2e run serves both sites locally, intercepts `https://api.bitosx.se/**` inside the browser with
`tests/mock-api.js` (so the real `config.js` origin and CSP `connect-src` are exercised), and fails on
any console error, page error, CSP violation, inline script/style attribute, or a drift between the two
copies of `bitosx.css`.

After deployment, the live checks are:

```bash
curl -sI https://bitosx.se/ | grep -i -E 'content-security-policy|x-frame-options|strict-transport'
curl -sI https://vault.bitosx.se/verify-email | head -n 1          # expect 200
curl -s  https://vault.bitosx.se/robots.txt                         # expect Disallow: /
# CORS preflight from the vault origin — expect 204 with Access-Control-Allow-Origin: https://vault.bitosx.se
curl -sI -X OPTIONS https://api.bitosx.se/v1/auth/login \
  -H 'Origin: https://vault.bitosx.se' -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' | grep -i access-control
```

## Versioning

`web v0.4.0` (phase 6, account recovery and deletion; `v0.3.0` phase 5 editing in the browser, `v0.2.0` the read-only web vault, `v0.1.0` phase 1). Bump the version in the footers and in
the `?v=` cache-busting query on the stylesheet links together. The desktop app (`0.9.0` on its phase 3
branch) and the API (`0.1.0`) have their own version numbers, shown in the footer of the product page
for orientation only.
