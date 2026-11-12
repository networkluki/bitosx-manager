# bitosx-manager — BitosX web

Private repository for the BitosX web front: static sites for bitosx.se and vault.bitosx.se. Two sites, one stylesheet, no build step,
no framework, no CDN. Everything is plain HTML, CSS and JavaScript served from the same origin so a
strict Content-Security-Policy holds. The one piece of third-party code is the vendored Argon2
WebAssembly build the web vault needs (`vault/public/assets/vendor/hash-wasm/`, with its provenance).

| Hostname | Directory | Purpose | Talks to |
|---|---|---|---|
| `bitosx.se` | `www/public/` | Public product page: what BitosX is, how the vault is protected, what works today, live API status, roadmap | `api.bitosx.se` (`GET /health`, `GET /version` only) |
| `vault.bitosx.se` | `vault/public/` | Web **account** app (register, verify email + set account password, sign in, list and revoke sessions, sign out everywhere; since phase 6 reset a forgotten account password by emailed link and delete the account; since phase 7 set up TOTP two-factor and sign in with a code; since phase 8 change the account password while signed in; since phase 10 add, rename and remove passkeys and sign in with one) and, since phase 4, the **web vault**: the encrypted envelope the desktop synced is opened in the browser with the master password; since phase 5 it can be edited there and uploaded with compare-and-set; since phase 8 with the desktop's generator, favorites and sorting, and a download of the encrypted backup; since phase 11 it imports the logins other password managers export and exports the vault unencrypted; since phase 12 a login can hold an authenticator key and the vault shows its current code | `api.bitosx.se` (`/v1/auth/*`, `/v1/account/*` including `POST /v1/account/password` and `/v1/account/passkeys*`, `GET /v1/sync/status`, `GET /v1/sync/envelope`, `PUT /v1/sync/envelope`) |
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
5. The decrypted JSON is read strictly (schema version 1, or 2 since phase 12, `login` items, no unknown fields, no
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
pull request for the run. Since phase 9 the live suite (Verification) saves a browser edit to the
real API and opens what that server then returns with `vault-crypto.js`. Not verified: a real desktop
syncing a browser-written revision through `api.bitosx.se`.

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

## Passkeys (phase 10)

Web `0.7.0`, against the phase-10 API (`bitosx-api` `docs/API.md`, "Passkeys (WebAuthn, phase 10)").
A passkey signs in to the **account** with the device's screen lock, a password manager or a security
key (WebAuthn). It never opens the vault: the vault master password stays what it was, and the page
says so wherever a passkey is offered.

- **On top of two-factor, never instead of it.** The *Passkeys* section of the account page lists the
  account's passkeys (name, added, last used, a *Synced* / *Not synced* badge from the authenticator's
  backup state) and offers *Add a passkey* only while TOTP is on; without it the section says to turn
  TOTP on first. While passkeys exist, *Turn off* two-factor is refused by the server (409), and the
  page says why (remove the passkeys first) and that nothing was used up. The desktop app keeps
  signing in with the authenticator code.
- **Add**: a name (1–64 characters, the server's rule), the account password and a code →
  `POST /v1/account/passkeys/registration/options` → `navigator.credentials.create()` with the server's
  options → `POST /v1/account/passkeys/registration` with the name and the credential. The name is asked
  first, so the passkey the browser creates is stored on the server right after the prompt; the
  password and the code are wiped from the page as soon as the server has checked them. A device that
  already holds one of the account's passkeys is refused by the browser (`excludeCredentials`).
- **Rename** (`POST /v1/account/passkeys/{id}/rename`; the API's CORS policy allows no `PATCH`) and
  **Remove** (`POST /v1/account/passkeys/{id}/delete` with the password and a code).
- **Sign in, second step**: when the 202 of `POST /v1/auth/login` lists `passkey` in `methods` (only
  for an account that has one; unknown values are ignored, a missing list means code only), the code
  step shows *Use a passkey* next to the code field (`/v1/auth/login/passkey/options` →
  `navigator.credentials.get()` → `/v1/auth/login/passkey`). A refused passkey uses up one of the
  step's attempts like a wrong code; a cancelled prompt does not.
- **Sign in with a passkey** (no email, no password): a discoverable passkey with user verification
  counts as both factors (`/v1/auth/passkey/options` → `get()` with the browser's default mediation →
  `/v1/auth/passkey`).
- **The JSON.** The API speaks the standard WebAuthn JSON. `assets/js/webauthn.js` uses the browser's
  `PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` and
  `credential.toJSON()` when they exist, and otherwise its own strict base64url conversion of the same
  members (unit-tested in `tests/webauthn.test.js`, and run in Chromium with the browser's helpers
  removed, against the mock and against the real API).
- **Feature detection.** Without `window.PublicKeyCredential` (or outside a secure context) no passkey
  button is shown anywhere; the account page says the browser cannot use passkeys and still lets the
  person rename and remove them.
- **The same protections as everything else.** The browser prompt is cancelled (an `AbortController`)
  when the step is left, the person signs out, the session ends or the page goes away; an answer that
  arrives after its session ended is dropped (session generation), and a sign-in that completes after
  the page cancelled it is revoked at once. Every passkey form is wiped with the account view.
- **`_headers`**: `Permissions-Policy` gains `publickey-credentials-create=(self),
  publickey-credentials-get=(self)` — the feature tokens of WebAuthn Level 3, §5.9 "Permissions Policy
  integration" (default allowlist `'self'` for both); the live suite checks that Chromium knows both
  (`document.featurePolicy.features()`) and reports no unrecognised feature. The CSP is unchanged: WebAuthn needs no CSP source.
- **What the deployment needs.** The API's `Security:WebAuthn` section with RP ID `vault.bitosx.se` and
  origin `https://vault.bitosx.se` (the shipped API configuration). A passkey is bound to that RP ID:
  one made on the local devstack (`localhost`) does not work in production, and the other way round.

## Import and export (phase 11)

Web `0.8.0`. No server change: an import adds ordinary items to the open vault, an export writes a
file in the browser. The rules are the desktop application's `docs/IMPORT_EXPORT.md`
(`networkluki/bitosx`), which both clients follow so that the same file gives the same items in
both. `vault/public/assets/js/import-export.js` is that specification in JavaScript — pure
functions, no DOM, no network, no vault — and `vault.js` is the page around it.

**Import** (*Import…* in the unlocked vault). Choose a file → a preview → two choices → confirm.

- **What is read**, decided from the contents, never from the file's name: CSV exported by Chrome or
  Edge, Firefox, Bitwarden, KeePassXC and KeePass ("KeePass CSV (1.x)", with its own backslash
  quoting), any other CSV file whose first line names a password column and at least one of name,
  address and username (the column names of the specification's alias table; a 1Password file is
  read this way, without a label of its own); Bitwarden's unencrypted JSON; KeePass 2 XML; BitosX's
  own JSON export. An encrypted or password-protected Bitwarden export, a KeePass file with
  protected values, an XML file with a document type declaration, UTF-16 text and anything that is
  not UTF-8 are refused, each with the fixed text the specification gives it.
- **The preview** shows the detected format, how many logins would be added, the duplicates, the
  entries that are not imported with their name and reason, items that are not logins by kind, what
  is in the file's trash, what BitosX has no field for by kind, how many addresses get `https://`
  and how many names are derived, and the columns that are not read. It never shows a password, an
  authenticator key, the value of a custom field or notes. Nothing is added before *Import N logins*.
- **Two choices, both off unless chosen:** *Copy what BitosX has no field for into each item's notes*
  and *Import duplicates too*. A duplicate has the same name, username, password and web addresses
  as an item of the vault or an earlier entry of the file.
- **What is added** are unsaved changes exactly like items added by hand — a new identifier each,
  created and changed at the time of the import — until *Save to server*; the page says that nothing
  is on the server before that, and afterwards reminds that the file still holds every password in
  plain text. *Cancel*, another file, and a lock let go of the file and leave the vault as it was.
- **Limits:** a file of at most 16 MiB (its size is asked before anything is read, and at most the
  limit and one byte are read), at most 10,000 entries in a file, at most 10,000 items in the vault
  afterwards, and the vault's own limits for an item (name 1–200, username 320, password 4096,
  notes 16384, 64 addresses of 2048, absolute http or https). **Nothing is ever cut short:** an entry
  that breaks a limit is not imported and is listed with the reason; a file or an import that breaks
  one is refused as a whole.
- **Not imported:** authenticator (TOTP) keys, custom fields, folder and group names and addresses
  that are not http(s) (kept as text in the notes if the first choice is made, never otherwise);
  everything that is not a login (secure notes, cards, identities, SSH keys, …); items in the
  trash or the recycle bin; an entry's history, passkeys, attachments, tags, icons, expiry dates and
  the times an entry was created and changed.

**Export** (*Export…*). CSV in Chrome's layout (`name,url,username,password,note`, one address for
each item — the panel says how many items have more) or BitosX's JSON (everything an item holds).
The specification's warning, the box *I understand that this file is not encrypted*, and the
**master password once more**: it is checked in this browser — the key is derived as at unlock and
the envelope's vault key is unwrapped and compared with the key the session holds
(`verifyMasterPassword`); no request is made. A wrong password writes nothing. The file is a `Blob`
download named `BitosX-export-YYYY-MM-DD.csv` or `.json`; its object URL is revoked after a minute,
and at once when the vault locks; the password field is cleared on every path. Values are written
exactly as they are: nothing is put in front of one that a spreadsheet program would take for a
formula (a password with a quote mark in front of it is another password), which is why the warning
says not to open the file in such a program. **An empty vault** has nothing to export: the panel
says so, asks for no password and writes no file.

**How untrusted input is handled.** Everything of a file is shown with `textContent`, each piece in
an element of its own (`<bdi>`), and no address of a file is opened or fetched while it is read.
`JSON.parse` accepts three things the specification refuses — more than 64 levels, a name twice in
one object, half of a surrogate pair — so a pass over the text finds those first, without recursion.
KeePass XML is read with the browser's own `DOMParser`; `<!DOCTYPE` anywhere in the text is refused
before the parser sees it, so no entity is ever expanded. Trimming, lower-casing and splitting into
lines are written out character by character: `trim()`, `toLowerCase()` and a split at `\r?\n` do
other things than the specification says. The items that are added are copies, so that they do not
keep the text of the file alive in memory; the bytes of the file are wiped once they are parsed (the
text they became can only be let go of, as everywhere on this page). The Content-Security-Policy is
unchanged.

**A vault that is too large.** The envelope may be 16 MiB — more is refused by this page, the
desktop and the server — which is about 11 MiB of items. Its size can only be estimated before it is
encrypted (`estimateEnvelopeSize`: Base64 writes `+` for one value in 64, which the envelope's JSON
writes as six bytes, and how many there are is new with every save). An import that would bring the
estimate within 32 KiB of the limit is refused as a whole: *The vault would be larger than 16 MiB
after this import, which is the most BitosX can store. Nothing was imported.* And every save checks
the bytes it is about to send: a vault that grew too large by hand is not uploaded, the page says
why, and the changes stay in the browser until items are deleted or shortened. While testing this a
defect of earlier versions surfaced and was fixed: a vault of more than a few MiB could not be
opened or backed up in the browser at all, because the Base64 check was a pattern that overflows the
JavaScript engine's stack on a string of several million characters (`isBase64` is a loop now).

**Where this client differs from the desktop.** For every conformance fixture the results are
identical. Beyond the fixtures, measured against the desktop's own library (built from its sources
in a scratch directory; 4,500 generated CSV files and 4,500 generated JSON files gave identical
results):

- *XML with two faults.* The desktop reads a document forward and reports the first fault; a
  parsed document can only be damaged. A file that has, say, a protected value and further down a
  tag that is never closed is `invalid_xml` here and `protected_values` there (the specification,
  §15.3, says so). 2,400 generated KeePass files in Chromium: 2,360 identical, 40 of this kind.
- *Chromium's own limits and leniencies.* Its XML parser refuses nesting beyond 5,000 elements by
  itself (`invalid_xml` here, `nested_too_deeply` on the desktop; from 101 to 5,000 both say
  `nested_too_deeply`); it reads a document that declares `version="1.1"` as XML 1.0 (the desktop
  refuses it), and refuses an element named `xmlns:…` and an encoding name that is not a name (the
  desktop reads both). A well-formed file that contains an element named `parsererror` in the XHTML
  or Mozilla namespace is taken for the parser's own error report and refused.
- *A console message for a damaged XML file.* Chromium's error document carries inline styles; it
  inherits this page's policy, which refuses them, and Chromium says so on the console twice
  (`Refused to apply inline style …`). Nothing of the file is in the message, and the policy is
  doing what it should.
- *Addresses.* After the specification's shared host rule (§7.3) the two URL parsers still disagree
  about three kinds of web address besides the known invalid-Punycode kind: a host with a part that
  starts with `-` or `_`, or is longer than 63 characters, where the desktop refuses some shapes
  (`https://1.-a/`, `https://a.b.-c/`) and this page accepts them; a backslash in the user-info part
  (`https://u\@example.com/`: refused there, accepted here); and hosts with unusual characters
  outside ASCII (zero-width joiners, a soft hyphen, full-width dots), which the specification
  leaves to each client. Ordinary addresses, ports, paths and queries agreed in every case tried.

## Authenticator codes (phase 12)

Web `0.9.0`, desktop `0.15.0`. No server change. A login may hold one **authenticator key** (RFC 6238
TOTP), and the vault shows its current code. The rules are the desktop application's `docs/TOTP.md`
(`networkluki/bitosx`), which both clients follow; `vault-crypto.js` is that specification in
JavaScript (`readTotpKey`, `totpCode`, `formatTotpCode`, the stored form in `parseVault` and
`serializeVault`), and `vault.js` is the page around it.

- **Entering a key.** The editor has an *Authenticator key* field, masked like the password, with
  *Show*. It takes the key as a site shows it (base32, either case, with spaces or dashes) or the
  whole `otpauth://totp/…` link (`algorithm` SHA1, SHA256 or SHA512; `digits` 6 to 8; `period` 1 to
  300 seconds). Anything else is refused with the specification's fixed text under the field — a
  counter-based (`hotp`) or Steam link, a link without a key, an unsupported algorithm, length or
  time step, a key that is not base32 or is shorter than 10 or longer than 128 bytes — and *Save item*
  stays blocked until it is right. Removing the text removes the key. A stored key is shown again as
  its base32 text, or as a link when it is not SHA1 / 6 digits / 30 seconds.
- **The code.** An item with a key shows its current code in two groups (`123 456`, `123 4567`,
  `1234 5678`), the seconds it has left, *Copy* (the digits alone, through the page's copy path, so
  the clipboard is cleared after 30 seconds as for a password) and the specification's note that
  codes depend on this device's clock. Codes are computed with WebCrypto's HMAC. One timer, at the
  turn of each second, computes a code once for each time step; nothing is computed while the vault
  is locked, and locking stops the timer and clears every code.
- **Where the key is not.** Never in the list, an attribute, an accessible name, a tooltip, a notice
  or the console; only the editor's field holds it, and only while the editor is open. In memory it is
  as secret as the password, and leaves the browser only inside the encrypted vault.
- **Compatibility.** The vault's content is written as **schema version 1** when no item has a key —
  byte for byte as before — and as **version 2** when at least one has (`"Totp": { "Secret",
  "Algorithm", "Digits", "Period" }` after `"Urls"`). Web `0.8.1` and earlier, and desktop `0.14.1`
  and earlier, refuse a version 2 vault with their existing "unsupported schema version" error: they
  never get far enough to save, so nothing is lost, but they cannot open it until they are updated.
  Removing the last key makes the vault version 1 again on the next save. A key in a version 1
  document, a `"Totp": null`, version 3 and above, and a key that is not exactly valid are refused as
  any invalid content is, without quoting it.
- **Both factors in one vault.** Keeping a site's key next to its password means that whoever opens
  the vault has both factors of that login. That is the user's choice, as in other password managers;
  a key kept only on a phone is out of reach of a stolen master password.

**Verified:** `tests/totp.test.js` holds the code to RFC 6238 Appendix B (all 18 codes; the RFC text
was read from two byte-identical copies on GitHub, `pingidentity/ldapsdk` and
`smuellerDD/leancrypto`, SHA-256 `82947ed9…69a7a`, because rfc-editor.org, datatracker.ietf.org and
ietf.org were not reachable from where this was built), to an independent implementation over
`node:crypto` (1,836 combinations of algorithm, digits, period, secret length and time), and to the
desktop's shared fixtures, copied byte for byte into `tests/fixtures/totp`: all 91 texts give the
desktop's key, refusal or no key, all 40 keys and times the desktop's code, display and seconds left.
The mocked suite drives the editor (every kind of refusal, *Save item* blocked, masked, Show), the code
view at a fixed clock (the next step, the countdown, *Copy*), saving as schema 2 and back to 1, and
locking (no HMAC is computed while locked); the live suite adds a key in the page, saves it to the
real API and, signed in again in another browser profile with its clock held at a fixed instant,
gets the code computed in Node for that instant. **Not verified:** browsers other than headless
Chromium; a real desktop opening a browser-written version 2 vault through `api.bitosx.se` (the
desktop's own fixtures and code are what both clients are held to).

**Where this client differs from the desktop.** A stored `Digits` or `Period` written with a fraction
or an exponent (`6.0`, `6e0`): the desktop refuses the document; `JSON.parse` sees the number 6, and
this page reads it. Neither client writes such a number.

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
8. **Phase 8:** fine-tuning and account controls, above — merged.
9. **Phase 9:** tested for real and ready to deploy — the live suite (Verification, below) runs the
   web vault against the real API and a MariaDB database; the API repository gets the local live stack,
   CI and its production deployment files.
10. **Phase 10:** passkeys, above — merged.
11. **Phase 11:** import and export, above — this repository and `networkluki/bitosx` (the desktop
    wrote the specification and the conformance fixtures); the API is not changed.

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
3. **Passkeys** (phase 10): the API's `Security:WebAuthn` must name RP ID `vault.bitosx.se`, RP name
   `BitosX` and the origin `https://vault.bitosx.se` (the shipped values). Without it the passkey
   routes answer 404: the account page then says passkeys are not available, the second sign-in step
   does not offer one, and the CORS policy above needs no change for them (every passkey call is a `GET`
   or `POST`).
4. **Verification email base URL.** Set `Email:PublicBaseUrl = https://vault.bitosx.se` and keep
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
- **No HTML from data.** Everything from the network, the URL or an imported file is rendered with
  `textContent` or `createElement`; `innerHTML` is not used.
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
- **Passkeys authenticate the account only.** The WebAuthn private key never leaves the authenticator;
  the page passes the server's options to the browser and the browser's signed answer back, and keeps
  nothing (no credential id, no challenge) beyond the ceremony. `Permissions-Policy` limits
  `publickey-credentials-create` / `-get` to this origin; `frame-ancestors 'none'` and `X-Frame-Options:
  DENY` keep the page out of frames.
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
Import and export were run in Chromium only (headless, 141): how Firefox and Safari parse XML with
`DOMParser` and report a damaged file (the code looks for their `parsererror` element as documented,
untested), how they decode with `TextDecoder`, whether their URL parsers agree with Chromium's on
unusual addresses, and how soon after the click they let a download's object URL be revoked (Chromium
keeps the download whole even when it is revoked at once, measured) are **not verified**. Nor is a
phone: the vault does not lock on a hidden tab while an import's file chooser is open (from the click
that asks for it until a file is chosen, the chooser is called off or the page is visible again),
because a phone's file chooser is assumed to hide the page — assumed, not seen. With a preview on
screen, or with the panel merely open, a hidden tab locks as always. No real export of Chrome, Firefox, Bitwarden,
KeePassXC or KeePass was imported: the fixtures are written after their source code, by the desktop
side. A vault near 16 MiB opens and saves in the tests, slowly (a few seconds of a busy page). The
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
# The passkey JSON conversion (the fallback for browsers without parse*FromJSON / toJSON) and the
# mapping of the browser's WebAuthn errors.
node --test tests/webauthn.test.js
# Import and export: every conformance fixture of the desktop that needs no XML parser (35 of 44;
# the other nine reach DOMParser and run in Chromium, below), and the rules one by one — the CSV
# reader, the strict JSON check, the address rules, normalisation, duplicates, limits, the exports.
node --test tests/import-export.test.js
# Authenticator codes: RFC 6238 Appendix B, an independent implementation over node:crypto, the
# stored form (schema 1 and 2), the reading of keys and links rule by rule, and the desktop's
# shared fixtures (tests/fixtures/totp: 91 texts, 40 codes).
node --test tests/totp.test.js

# End-to-end in headless Chromium against the in-process mock API (needs the `playwright` package
# and a Chromium it can find; PLAYWRIGHT_BROWSERS_PATH if it is not the default location).
# BITOSX_E2E_SLOW=1 adds the 256 MiB unlock in Chromium.
node tests/e2e.js
```

The e2e run serves both sites locally, intercepts `https://api.bitosx.se/**` inside the browser with
`tests/mock-api.js` (so the real `config.js` origin and CSP `connect-src` are exercised), and fails on
any console error, page error, CSP violation, inline script/style attribute, a drift between the two
copies of `bitosx.css`, or a page whose version is not the one in this README.

**Import and export in the mocked suite.** `tests/fixtures/import` is the desktop's fixture
directory, byte for byte (its README names the commit; `.gitattributes` keeps Git from converting
line ends there). The suite holds the page's own `import-export.js` to **all 44** expected files
inside Chromium, KeePass 2 XML included, and drives the flows: preview → unsaved → save, cancel,
duplicates, extras into the notes, every refusal with its text, a vault at 10,000 items and at
16 MiB, markup in a file shown as text, and the export with its box, its master password, its file
names and its object URLs. A test that feeds the page a damaged XML file expects the two console
messages described above, and counts them.

**CORS is enforced by the harness.** Playwright answers every CORS preflight of an intercepted
request itself and allows everything, so the browser's own check never sees a policy. The route
handler therefore applies the API's policy (above): a request that needs a preflight the policy would
refuse fails as a network error, as in a browser, and a response carries `Access-Control-Allow-Origin`
only for the origin and path the policy covers. One test removes `PUT` and shows the save failing. The
mock server's clock can be moved or stopped (`mock.clock`), so TOTP codes and expiries are computed
from a time the test controls and a 30-second boundary can never fall inside a test; the page's clock
is Playwright's `page.clock` where idle timers and time limits are tested. `BITOSX_E2E_ONLY=<text>`
runs only the tests whose name contains the text.

**Passkeys in the mocked suite.** The vault is served on `http://localhost:<port>` (a WebAuthn RP ID
must be a domain name, so `127.0.0.1` cannot have passkeys), and the passkey tests give each page
Chromium's **virtual authenticator** over CDP (`WebAuthn.enable`, `WebAuthn.addVirtualAuthenticator`
with `protocol: "ctap2"`, `transport: "internal"`, `hasResidentKey`, `hasUserVerification`,
`isUserVerified`; the parameter names are those of the installed Chromium's protocol). The mock server
checks what a WebAuthn server checks that a browser could get wrong — client data type, challenge and
origin, the RP ID hash, the user-presence/verification flags, the ES256 signature with the public key
from the registration, the counter — so the browser's own JSON helpers and the page's fallback are both
proven against it.

### Against the real API (live suite, phases 9 and 10)

`tests/e2e-live.js` runs the unchanged `vault/public` in Chromium against a real API and database: the
local stack of `networkluki/bitosx-api` (`tools/devstack/up.sh`, MariaDB + the API in its Testing
environment, mail held in the outbox). It reads exactly three variables, which `up.sh` writes to
`tools/devstack/.state/env`:

```bash
# in bitosx-api: tools/devstack/up.sh   (and tools/devstack/down.sh afterwards)
set -a; . ../bitosx-api/tools/devstack/.state/env; set +a   # BITOSX_LIVE_API_URL, _WEB_ORIGIN, _MAIL_CMD
node tests/e2e-live.js
```

Without them it prints `live suite not configured: set BITOSX_LIVE_API_URL, BITOSX_LIVE_WEB_ORIGIN,
BITOSX_LIVE_MAIL_CMD` and exits with code **2**, never 0; a stack that does not answer `GET /health`
fails it (exit 1). It also needs `openssl`. The API repository's `e2e.yml` workflow runs it nightly and
on changes to the API. One fresh account per run (`e2e-<random>@example.test`) goes through:
register → verify with the token the mail command reads from the outbox → sign in → sessions (another
device's session listed and revoked) → TOTP enrollment (codes computed in the test, each on a later
30-second step than the last, as the server's replay rule requires) → sign out → sign in with a code →
a fixture envelope written by the desktop's code uploaded through the API (the page cannot create a
vault) → opened with its master password → an item edited and saved (a real `PUT`) → reload, sign in,
re-open, the edit is there, and the server's copy opens under Node → the encrypted backup is byte for
byte `GET /v1/sync/envelope` → account password changed with a code (the other session is signed out,
this one stays) → forgot + reset with the mailed token → sign-in with a recovery code → account
deleted with a code → sign-in fails. Since phase 10, before the account controls: a passkey added on the
account page with Chromium's virtual authenticator (real attestation checked by the API) → turning
TOTP off refused while it exists (nothing used up) → sign-in with the password and the passkey → sign-in
with the passkey alone (the vault still asks for its master password) → a second passkey added and
used from a page whose browser JSON helpers are removed (the page's own conversion, accepted by the
API) → a passkey of another authenticator, never registered, refused → rename (a real preflight for
`POST .../rename`; no `PATCH` is ever sent) → both removed with the password and a code → the removed
passkey refused, and the second step no longer offers one. Since phase 11, after the edit: a
conformance fixture imported through the page (nothing is sent while it is read) → *Save to server*
(a real `PUT`) → reload, sign in again, re-open: the logins are there, and the server's copy opens
under Node with exactly the items the desktop makes of that file → an export that refuses the account
password and, with the master password, downloads the vault's items without asking the API anything.
Since phase 12, before the export: an authenticator key added in the editor (the code shown is the one
computed in Node for the page's own clock) → *Save to server*: the server's copy is content schema 2
and holds the key → signed in again in a second browser profile whose clock is held at a fixed
instant, the vault opened: the code shown is the one computed in Node for that instant; locking clears it.
It runs in a few minutes, mostly waiting for TOTP steps.

**The page origin is `http://localhost:8788`** (the devstack's default since phase 10: `localhost` is a
valid WebAuthn RP ID, an IP address is not, so the API's RP ID there is `localhost`). The browser's
`--host-resolver-rules` leave the two page hosts — the web origin's and `127.0.0.1` for the second,
disallowed origin — to Chromium's own loopback handling (`localhost` never goes to DNS) and make every
other name fail, which the first test checks.

**How the page reaches the live API, with the site unchanged.** `config.js` and every CSP name
`https://api.bitosx.se`, and they stay that way: nothing in `vault/public` knows about tests, so what is
deployed is byte for byte what was tested, and no visitor can switch anything on. The suite starts a
loopback TLS relay with a throw-away self-signed certificate for `api.bitosx.se` (made with `openssl`
in a temporary directory, deleted after the run) and launches its own Chromium with
`--host-resolver-rules` (`api.bitosx.se` resolves to the relay, every other name fails),
`--ignore-certificate-errors-spki-list` (only that one key is trusted) and no proxy (a proxy would
resolve the name itself). The vault is served on `BITOSX_LIVE_WEB_ORIGIN` with the headers of
`vault/public/_headers` on top of each page's `<meta>` CSP, so `connect-src https://api.bitosx.se`
is what lets the requests out. The browser sends its real preflights and requests; the relay passes
them to `BITOSX_LIVE_API_URL` and returns the API's response headers unchanged (only hop-by-hop
framing headers are re-framed), so the browser applies CORS to the API's own `Access-Control-*`
answers. No Playwright interception is used: Playwright answers the preflight of an intercepted
request itself. The first test shows the check is real: from a second local origin the API does not
list, the browser refuses the answer.

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

`web v0.9.0` (phase 12, authenticator codes in logins; `v0.8.1` two fixes to the import: a hidden tab is kept unlocked only while the file chooser is open, and an address with a backslash before the `@` is not imported; `v0.8.0` phase 11, import and export; `v0.7.0` phase 10, passkeys; `v0.6.0` phase 8, fine-tuning and account controls; `v0.5.0` phase 7 two-factor sign-in and setup, `v0.4.0` phase 6 account recovery and deletion, `v0.3.0` phase 5 editing in the browser, `v0.2.0` the read-only web vault, `v0.1.0` phase 1). Bump the version in the footers and in
the `?v=` cache-busting query on the stylesheet links together (the e2e hygiene test checks it). The
desktop app (`0.15.0`) and the API (`0.1.0`) have their own version numbers, shown in the footer of the
product page for orientation only.
