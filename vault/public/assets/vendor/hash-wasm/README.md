# Vendored: hash-wasm 4.12.0 (Argon2 build only)

`argon2.umd.min.js` is the unmodified `dist/argon2.umd.min.js` of the npm package
[`hash-wasm`](https://www.npmjs.com/package/hash-wasm) **4.12.0** (MIT, Dani Biró — see `LICENSE`).
It is the only third-party code on vault.bitosx.se. It exists because WebCrypto has no Argon2, and the
vault key is derived with Argon2id exactly as the desktop app does it.

| | |
|---|---|
| npm tarball | `https://registry.npmjs.org/hash-wasm/-/hash-wasm-4.12.0.tgz` |
| registry `dist.integrity` | `sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==` |
| this file, SHA-256 | `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094` |

The WebAssembly module is embedded in the file as Base64 and instantiated with
`WebAssembly.instantiate`, which is why the CSP carries `'wasm-unsafe-eval'` in `script-src` (and
nothing else beyond `'self'`). It is loaded as a classic script and exposes `window.hashwasm.argon2id`.

Before it is trusted, it is checked against the desktop app's KDF: `tests/fixtures/argon2id-vectors.json`
holds vectors computed with `Konscious.Security.Cryptography.Argon2` through `BitosX.Crypto`, and
`tests/vault-crypto.test.js` fails if this build disagrees on any of them.

To re-vendor: download the tarball, verify `openssl dgst -sha512 -binary <tgz> | base64` against the
registry's `dist.integrity`, copy `package/dist/argon2.umd.min.js` and `package/LICENSE`, update the
table above, and run the tests.
