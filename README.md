# bitosx-manager — BitosX web (phase 1)

Private repository for the BitosX web front: static sites for bitosx.se and vault.bitosx.se. Two sites, one stylesheet, no build step,
no framework, no third-party CDN. Everything is plain HTML, CSS and JavaScript served from the
same origin so a strict Content-Security-Policy holds.

| Hostname | Directory | Purpose | Talks to |
|---|---|---|---|
| `bitosx.se` | `www/public/` | Public product page: what BitosX is, how the vault is protected, what works today, live API status, roadmap | `api.bitosx.se` (`GET /health`, `GET /version` only) |
| `vault.bitosx.se` | `vault/public/` | Web **account** app: register, verify email + set account password, sign in, list and revoke sessions, sign out (everywhere) | `api.bitosx.se` (`/v1/auth/*`, `/v1/account/*`) |
| `api.bitosx.se` | — | The account API. Lives in [`networkluki/bitosx-api`](https://github.com/networkluki/bitosx-api) and is operated alongside the desktop app; nothing here | — |

The desktop app lives in [`networkluki/bitosx`](https://github.com/networkluki/bitosx).

## What phase 1 is, and is not

Phase 1 uses **only endpoints the API already implements** (`bitosx-api/docs/API.md`):

- `POST /v1/auth/register` — email only, generic 202
- `POST /v1/auth/verify-email` — token from the email link + chosen account password (12–128)
- `POST /v1/auth/resend-verification`
- `POST /v1/auth/login`, `POST /v1/auth/refresh`, `POST /v1/auth/logout`, `POST /v1/auth/logout-all`
- `GET /v1/account/me`, `GET /v1/account/sessions`, `DELETE /v1/account/sessions/{id}`
- `GET /health`, `GET /version`

There is **no vault data anywhere online** in phase 1. The desktop app has no server integration
yet (`BitosX.ApiClient.LocalOnlyApiClient` never makes a network call) and the API has no vault or
sync endpoints. The product page says so explicitly instead of implying otherwise.

Phases as presented on the product page:

1. **Phase 1 (this):** public site + web account against the existing API.
2. **Phase 2:** the desktop app implements `IBitosXApiClient` (account sign-in, sessions, refresh).
3. **Phase 3:** encrypted sync — the server stores the encrypted vault envelope as opaque bytes.
4. **Phase 4:** web vault — decrypt in the browser with the master password (needs Argon2id in the
   browser, which WebCrypto does not provide; a WASM implementation would have to be vetted first).

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
  img-src 'self'; connect-src https://api.bitosx.se; base-uri 'none'; form-action 'none'`. Forms are
  handled by JavaScript; `form-action 'none'` means a native submit can never put a password in a URL.
  The policy is set both as a response header (`_headers`, Cloudflare) and as a `<meta>` tag (so the
  GitHub Pages preview is covered; `frame-ancestors` only applies via the header).
- **No HTML from data.** Everything from the network or the URL is rendered with `textContent` or
  `createElement`; `innerHTML` is not used.
- **Responses are untrusted input.** Bodies are size-capped (64 KiB), must be JSON, and every field the
  UI shows is type- and format-checked (UUIDs, ISO dates, booleans) before use.
- **Verification token hygiene.** Read once from `location.hash`, validated as base64url, then removed
  from the address bar and history with `history.replaceState`; sent only in a POST body.
- **Generic errors.** Failures collapse to a fixed set of client-side messages; the server's
  anti-enumeration behaviour (identical 202/401 regardless of account existence) is preserved by
  showing the same text for the same status.
- **Idle sign-out.** After 15 minutes without input the tokens are dropped and `/logout` is called
  best-effort. Passwords are cleared from the fields after every submit, success or failure.
- **No third-party code.** No CDN, fonts, analytics or trackers on either site.

Known limitations: an XSS on `vault.bitosx.se` would still be able to call the API with the in-memory
token while the tab is open — the CSP and the no-inline rule are the controls against that. The
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

# End-to-end in headless Chromium against the in-process mock API (needs the `playwright` package
# and a Chromium it can find; PLAYWRIGHT_BROWSERS_PATH if it is not the default location)
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

`web v0.1.0`. Bump the version in the footers and in the `?v=` cache-busting query on the stylesheet
links together. The desktop app (`0.7.0`) and the API (`0.1.0`) have their own version numbers, shown
in the footer of the product page for orientation only.
