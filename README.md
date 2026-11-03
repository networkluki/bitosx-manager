# bitosx-manager — BitosX web

Private repository for the BitosX web front: static sites for bitosx.se and vault.bitosx.se. Two sites, one stylesheet, no build step,
no framework, no CDN. Everything is plain HTML, CSS and JavaScript served from the same origin so a
strict Content-Security-Policy holds. The one piece of third-party code is the vendored Argon2
WebAssembly build the web vault needs (`vault/public/assets/vendor/hash-wasm/`, with its provenance).

| Hostname | Directory | Purpose | Talks to |
|---|---|---|---|
| `bitosx.se` | `www/public/` | Public product page: what BitosX is, how the vault is protected, what works today, live API status, roadmap | `api.bitosx.se` (`GET /health`, `GET /version` only) |
| `vault.bitosx.se` | `vault/public/` | Web **account** app (register, verify email + set account password, sign in, list and revoke sessions, sign out everywhere; since phase 6 reset a forgotten account password by emailed link and delete the account; since phase 7 set up TOTP two-factor and sign in with a code; since phase 8 change the account password while signed in) and, since phase 4, the **web vault**: the encrypted envelope the desktop synced is opened in the browser with the master password; since phase 5 it can be edited there and uploaded with compare-and-set; since phase 8 with the desktop's generator, favorites and sorting, and a download of the encrypted backup | `api.bitosx.se` (`/v1/auth/*`, `/v1/account/*` including `POST /v1/account/password`, `GET /v1/sync/status`, `GET /v1/sync/envelope`, `PUT /v1/sync/envelope`) |
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
minutes without input (checked against the wall clock too, since phase 8), when the tab is hidden, on
sign-out, and on reload/close. A copied value is cleared from the clipboard after 30 seconds — only if
it is still what was copied, and only when the browser lets the page read the clipboard back, which
browsers allow only while the page is focused (and some only after asking). If the page is not
focused when the time is up it tries again when it is; if the browser refuses, the page says so. A
clipboard history kept by the operating system is out of reach for any web page, and the page says
that too. JavaScript strings cannot be wiped, so "dropped" means unreferenced, as in the desktop app.

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
sign-out and unload still do. A delete is asked for and then confirmed (or cancelled), as in the
desktop app. The generator follows the desktop's rules (phase 8, below).

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

## Two-factor authentication (phase 7)

- **Sign-in in two steps.** When the account has TOTP, `POST /v1/auth/login` answers **202** with a
  one-step challenge token instead of a session. `api.login()` resolves to `{ signedIn: false,
  mfaToken }` (the status decides; a 202 that carries tokens or a 200 that carries a challenge is
  refused), the sign-in page swaps the credentials for a **code** box, and `POST /v1/auth/login/totp`
  with the token and a code from the app (the server's digit count, 6–8) or a recovery code returns
  the session. The challenge token
  lives in a closure, never in the DOM or storage; a refused code keeps the step for another try;
  *Start over* drops it. Obvious non-codes are caught before a round trip; the code never stays on
  the page. A server without the capability (503) is told apart from a wrong password.
- **Setup on the account page.** Password → the secret (Base32, in groups of four) and the
  `otpauth://` link, shown once, with *Copy* buttons and, since phase 8, a tappable *Open in an
  authenticator app* link (on a phone it opens the app). No QR code: that would need a third-party
  encoder, and the page has no CDN and a strict CSP → a first code confirms → **10 recovery codes**,
  shown once with *Copy codes* (cleared from the clipboard like vault secrets) and wiped from the page
  on *I have saved them*. The secret is wiped the moment the code is accepted.
- **Manage.** Status (enabled since, recovery codes left), *New recovery codes* and *Turn off*, each
  behind the account password plus a current code; a refusal is one generic message. Since phase 8
  Enter in that form chooses neither action, and *Turn off* needs a confirmation tick first.
- Nothing here touches the vault: the master password and the envelope are unchanged.

## Fine-tuning and account controls (phase 8)

Web `0.6.0`, against the phase-8 API contract (CORS with `PUT`, UTC timestamps, shared limits,
`POST /v1/account/password`, a code for account deletion with two-factor, revisions that never
restart after a delete).

**New features**

- **Change the account password** on the account page: current password, the new one twice, and a
  code when the account has two-factor (`POST /v1/account/password`). The server signs out every
  other session; this one stays. The page says that the vault master password is not affected — it
  was never on the server.
- **Account deletion with two-factor** asks for a code as well (`{ password, code }`).
- **Password generator options** in the vault editor: length 4–256 (default 20), lower case, upper
  case, digits, symbols, leave out look-alikes — the desktop's `PasswordGenerator` rule for rule (one of
  every selected class, its symbol set, Fisher–Yates, uniform draws). The options, never a password,
  are remembered in this browser (`localStorage` key `bitosx.generator`, the only stored value besides
  the theme). A generated password is shown, as on the desktop.
- **Strength rating** under the password while typing: the desktop's `PasswordStrength` heuristic,
  ported rule for rule and checked against the desktop's own results
  (`tests/fixtures/password-strength-vectors.json`, computed by `BitosX.Core`). It is an estimate from
  length and patterns and says so.
- **Favorites only** and a **sort** (favorites first by name, or recently updated) in the vault list.
- **Download encrypted backup**: the envelope exactly as the server stores it (the same bytes the
  desktop uploaded, checked against the server's SHA-256 first), saved as
  `BitosX-backup-YYYY-MM-DD.bitosx-backup` through a `Blob` download. It works while the vault is
  locked and opens only with the master password; the desktop restores it under Settings, Backup &
  Restore.

**Sessions**

- A **401** on an authenticated call gets exactly one refresh (still single-flight) and one retry; a
  client clock behind the server's no longer signs the user out. If the refresh fails too, the
  session is over: `api.js` dispatches `bitosx:session-ended`, the account page signs out, and an open
  vault is locked and wiped, with a message that says so (and that unsaved changes were discarded).
- Every session has a **generation**; any answer that arrives after its session ended (an enrollment
  secret, an unlock, a refresh) is dropped instead of landing in the next user's session.
- **Leaving the page** (reload, close, navigation, the back/forward cache) wipes the account view —
  details, sessions, a pending two-factor secret, recovery codes — and revokes the session on the
  server best effort (`keepalive` sign-out). A page restored from the back/forward cache shows the
  sign-in. The idle sign-out (15 min) and the vault lock (5 min) also check the wall clock, so a
  computer that slept does not resume with a live session.
- The second sign-in step ends on its own when the challenge expires or after the server's number of
  wrong codes, and says why. A failure *after* a successful sign-in is reported as such, and the
  half-made session is revoked.
- Sign-out buttons are busy while they run; *Sign out everywhere* that does not reach the server
  keeps this session and says the other devices are still signed in; the own row's *Sign out* is a
  plain sign-out; a session that ended by itself is removed from the list.

**Saving safely**

- Edits made while an upload runs stay unsaved and are uploaded next time.
- An item the web cannot write is named, nothing is uploaded, and the page is not left busy.
- **Replace** (after a conflict) is refused when the server's vault has a different key-wrap header
  — its master password was changed, or its key rotated, on another device: re-encrypting under the
  old header would bring the old master password back. The page offers *Reload* only.
- A save the server completed is never reported as "nothing uploaded": an upload that got no answer
  is recognised by its fingerprint at the next save.
- Unsaved changes, including text typed into the open editor, are asked about before signing out
  and before another item replaces the editor; the idle lock warns a minute ahead and its message
  says when changes were discarded.
- Dates of untouched items are written back exactly as the desktop wrote them, in the stored order.

**Smaller things:** 503 texts no longer claim it is always two-factor; time limits of 120 s for the
envelope transfers (15 s otherwise) with their own message; the email limit is the server's 320;
timestamps without an offset are read as UTC; recovery-code fields no longer bring up a digit keypad;
live checks in the editor; notices stay in the accessibility tree while empty so screen readers
announce them; password-manager extensions are asked to keep out of the master password and the
editor; `[hidden]` always hides.

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
5. **Phase 5:** editing in the browser, above — this repository, merged.
6. **Phase 6:** account recovery and deletion — merged.
7. **Phase 7:** two-factor sign-in and setup — merged.
8. **Phase 8:** fine-tuning and account controls, above — this repository.

## Deployment prerequisites outside this repository

1. **CORS on the API** (`bitosx-api`, `Security:Cors`, phase-8 contract §1). The API ships the
   policy; it must be configured as follows, or the browser refuses the calls and the app shows "The
   API could not be reached from this browser":
   - For `https://vault.bitosx.se`: methods **`GET, POST, PUT, DELETE`** (`PUT` is the vault upload,
     `PUT /v1/sync/envelope`; the phase-7 policy lacked it, so *Save to server* could not work in any
     browser), headers `Authorization, Content-Type, Accept`, exposed `Retry-After, X-Correlation-ID`.
   - For `https://bitosx.se`: `GET /health` and `GET /version` only, a separate, narrower policy (the
     product page's status badge; both are simple requests without a preflight).
   - No wildcard origin, **no** `Access-Control-Allow-Credentials` (bearer tokens, never cookies),
     `Vary: Origin`.
   The e2e harness applies exactly this policy (see Verification), so a method missing from it fails
   a test.
2. **Public exposure of the API.** Kestrel is loopback-only and Apache does not proxy to it yet. The
   `[host]` checklist in `bitosx-api/docs/DEPLOYMENT.md` gates that; nothing here changes it.
3. **Verification email base URL.** Set `Email:PublicBaseUrl = https://vault.bitosx.se` and keep
   `Email:VerificationPath = /verify-email` (the default). The link then reads
   `https://vault.bitosx.se/verify-email#token=<base64url>`; the token is in the fragment, which the
   browser never sends to any server, so it stays out of access logs.

## Security properties of the web app

- **Tokens in memory only.** Access and refresh tokens are held in a closure in `api.js`. Nothing is
  written to `localStorage`, `sessionStorage`, cookies or IndexedDB (the theme preference and the
  password generator's options are the only stored values; neither is secret). A reload or closed tab
  means signing in again. This is deliberate for phase 1: it
  removes token theft via storage from the threat model at the cost of convenience.
- **Single-flight refresh.** The API revokes the whole session when a refresh token is presented
  twice. `api.js` guarantees at most one refresh is in flight; the e2e tests assert exactly one refresh
  when `/me` and `/sessions` run in parallel against an access token that is expired, either by the
  client's clock or only by the server's (a 401 the client did not expect: one refresh, one retry).
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
- **Idle sign-out.** After 15 minutes without input (timer and wall clock) the tokens are dropped and
  `/logout` is called best-effort; leaving the page revokes the session best effort too. Passwords
  are cleared from the fields after every submit, success or failure.
- **No third-party code.** No CDN, fonts, analytics or trackers on either site.

Known limitations: an XSS on `vault.bitosx.se` would still be able to call the API with the in-memory
token while the tab is open, and, while the vault is unlocked, to read the decrypted items — the CSP,
the no-inline rule, text-only rendering and the short vault lock are the controls against that; the
desktop app remains the place for anything that must not depend on a browser. Whether a browser's
own password manager offers to save the master password or an item's password after the form
disappears is up to the browser: the fields carry `autocomplete="off"` and the ignore hints the common
extensions read, which is all a page can do (not verified per browser). The back/forward-cache test
dispatches the real `pagehide`/`pageshow` events with `persisted: true`, because the Chromium under test
does not cache pages. The
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
any console error, page error, CSP violation, inline script/style attribute, a drift between the two
copies of `bitosx.css`, or a page whose version is not the one in this README.

**CORS is enforced by the harness.** Playwright answers every CORS preflight of an intercepted
request itself and allows everything, so the browser's own check never sees a policy. The route
handler therefore applies the API's policy (above): a request that needs a preflight the policy would
refuse fails as a network error, as in a browser, and a response carries `Access-Control-Allow-Origin`
only for the origin and path the policy covers. One test removes `PUT` and shows the save failing. The
mock server's clock can be moved or stopped (`mock.clock`), so TOTP codes and expiries are computed
from a time the test controls and a 30-second boundary can never fall inside a test; the page's clock
is Playwright's `page.clock` where idle timers and time limits are tested. `BITOSX_E2E_ONLY=<text>`
runs only the tests whose name contains the text.

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

`web v0.6.0` (phase 8, fine-tuning and account controls; `v0.5.0` phase 7 two-factor sign-in and setup, `v0.4.0` phase 6 account recovery and deletion, `v0.3.0` phase 5 editing in the browser, `v0.2.0` the read-only web vault, `v0.1.0` phase 1). Bump the version in the footers and in
the `?v=` cache-busting query on the stylesheet links together (the e2e hygiene test checks it). The
desktop app (`0.11.0`) and the API (`0.1.0`) have their own version numbers, shown in the footer of the
product page for orientation only.
