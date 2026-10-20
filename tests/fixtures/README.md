# Test fixtures for the web vault

Every `*.vault.json` here is a real BitosX vault envelope (on-disk format v1) **written by the desktop
app's own code** — `BitosX.Crypto.VaultCryptor`, `EncryptedVaultSerializer`, `VaultSerializer` and
`MasterPasswordEncoding` from `networkluki/bitosx` — not by anything in this repository. The matching
`*.meta.json` holds the password as typed, the exact password bytes the vault was keyed with, the
SHA-256 fingerprint and size of the envelope, the KDF parameters, and the plaintext the envelope
decrypts to. A test that opens one of these in the browser code proves that the browser does what
the desktop does.

| Fixture | KDF | Keyed with | Purpose |
|---|---|---|---|
| `small` | 1 MiB, t=1, p=1 (the desktop's test profile) | canonical encoding of an ASCII password | the fast round trip; tamper and wrong-password cases are derived from it |
| `unicode-canonical` | 1 MiB, t=1, p=1 | canonical encoding (spaces → U+0020, NFC) of a non-ASCII password typed in NFC | the password must open it however it is typed |
| `unicode-legacy-nfd` | 1 MiB, t=1, p=1 | the raw NFD bytes, as desktop versions before 0.6.0 keyed vaults | the legacy candidates still open it |
| `strong` | 256 MiB, t=3, p=4 (what the desktop creates new vaults with) | canonical encoding | the opt-in slow test (`BITOSX_TEST_SLOW=1`, `BITOSX_E2E_SLOW=1`) |

`argon2id-vectors.json` holds Argon2id outputs computed with the desktop's KDF
(`Konscious.Security.Cryptography.Argon2` 1.3.1 through `BitosX.Crypto.Argon2idKeyDerivation`). The
first eight are the reference implementation's `test.c` cases; the vendored WebAssembly build must
agree on all of them before it is trusted with a vault.

The sample vault has three login items, with names and notes that contain markup (`<script>`, `<i>`)
so that the rendering tests can show it is text, never HTML. Nothing here is a real secret.

To regenerate (a .NET 10 SDK and a checkout of `networkluki/bitosx`): build a small console project
referencing `src/BitosX.Core` and `src/BitosX.Crypto`, create the vault with `VaultCryptor.Create`,
serialize with `EncryptedVaultSerializer.Serialize`, and verify with `VaultCryptor.Unlock` before
writing; the generator used is not part of this repository.
