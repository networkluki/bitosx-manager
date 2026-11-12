// Unit tests for vault/public/assets/js/vault-crypto.js, run with Node's test runner against the
// very file the browser loads, the vendored hash-wasm build, and Node's WebCrypto:
//
//   node --test tests/vault-crypto.test.js
//
// The fixtures in tests/fixtures were written by the desktop app's own code (BitosX.Crypto,
// BitosX.Core) — see tests/fixtures/README.md — so a pass here means the browser opens what the
// desktop writes, with the same password, and nothing else.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hashwasm = require("../vault/public/assets/vendor/hash-wasm/argon2.umd.min.js");
const factory = require("../vault/public/assets/js/vault-crypto.js");
const vc = factory(hashwasm, globalThis.crypto);

const FIX = path.join(__dirname, "fixtures");
const readFixture = (name) => ({
	bytes: new Uint8Array(fs.readFileSync(path.join(FIX, name + ".vault.json"))),
	meta: JSON.parse(fs.readFileSync(path.join(FIX, name + ".meta.json"), "utf8"))
});
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Buffer.from(b).toString("hex");

async function rejectsKind(promise, kind) {
	await assert.rejects(promise, (err) => err instanceof vc.VaultError && err.kind === kind, `expected VaultError ${kind}`);
}
function throwsKind(fn, kind) {
	assert.throws(fn, (err) => err instanceof vc.VaultError && err.kind === kind, `expected VaultError ${kind}`);
}

// ---------------------------------------------------------------- Argon2id
test("the vendored Argon2id agrees with the desktop's KDF on every vector", async () => {
	const { vectors } = JSON.parse(fs.readFileSync(path.join(FIX, "argon2id-vectors.json"), "utf8"));
	assert.ok(vectors.length >= 8);
	for (const v of vectors) {
		if (v.memoryKiB > 65536 && !process.env.BITOSX_TEST_SLOW) { continue; } // 256 MiB vector: opt in
		const out = await hashwasm.argon2id({
			password: utf8(v.password), salt: utf8(v.salt), parallelism: v.parallelism, iterations: v.iterations,
			memorySize: v.memoryKiB, hashLength: v.hashLength, outputType: "binary"
		});
		assert.equal(hex(out), v.expectedHex, `m=${v.memoryKiB} t=${v.iterations} p=${v.parallelism}`);
	}
});

// ----------------------------------------------------------------- envelope
test("a desktop-written envelope parses, and every field comes out as the desktop wrote it", () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	assert.equal(env.version, 1);
	assert.equal(env.kdf, "argon2id");
	assert.equal(env.algorithm, "AES-256-GCM");
	assert.deepEqual(env.kdfParameters, { memoryKiB: meta.kdf.MemoryKiB, iterations: meta.kdf.Iterations, parallelism: meta.kdf.DegreeOfParallelism, keyLengthBytes: 32 });
	assert.equal(env.salt.length, 16);
	assert.equal(env.keyWrapNonce.length, 12);
	assert.equal(env.encryptedVaultKey.length, 48);
	assert.equal(env.contentNonce.length, 12);
	assert.ok(env.ciphertext.length > 16);
	assert.ok(Object.isFrozen(env));
});

test("the associated data is built byte for byte as VaultCryptor builds it", () => {
	const env = vc.parseEnvelope(readFixture("small").bytes);
	const saltB64 = Buffer.from(env.salt).toString("base64");
	assert.equal(Buffer.from(vc.keyWrapAad(env)).toString("utf8"), `BitosX|kek|v1|argon2id|m=1024|t=1|p=1|klen=32|salt=${saltB64}`);
	assert.equal(Buffer.from(vc.contentAad(1)).toString("utf8"), "BitosX|content|v1|AES-256-GCM");
});

function mutate(fn) {
	const doc = JSON.parse(fs.readFileSync(path.join(FIX, "small.vault.json"), "utf8"));
	fn(doc);
	return utf8(JSON.stringify(doc));
}

test("anything that is not exactly a v1 envelope is refused before any key work", () => {
	const cases = {
		"empty": utf8(""),
		"not json": utf8("{"),
		"an array": utf8("[]"),
		"a string": utf8("\"x\""),
		"unknown field": mutate((d) => { d.extra = 1; }),
		"missing field": mutate((d) => { delete d.ciphertext; }),
		"version 2": mutate((d) => { d.version = 2; }),
		"version as string": mutate((d) => { d.version = "1"; }),
		"other kdf": mutate((d) => { d.kdf = "pbkdf2"; }),
		"other algorithm": mutate((d) => { d.algorithm = "AES-128-GCM"; }),
		"kdf params missing": mutate((d) => { d.kdfParameters = null; }),
		"kdf params extra": mutate((d) => { d.kdfParameters.x = 1; }),
		"memory below floor": mutate((d) => { d.kdfParameters.memoryKiB = 4; }),
		"memory above ceiling": mutate((d) => { d.kdfParameters.memoryKiB = 1048577; }),
		"memory < 8*p": mutate((d) => { d.kdfParameters.memoryKiB = 16; d.kdfParameters.parallelism = 4; }),
		"iterations 0": mutate((d) => { d.kdfParameters.iterations = 0; }),
		"iterations 65": mutate((d) => { d.kdfParameters.iterations = 65; }),
		"parallelism 65": mutate((d) => { d.kdfParameters.parallelism = 65; }),
		"key length 16": mutate((d) => { d.kdfParameters.keyLengthBytes = 16; }),
		"salt not base64": mutate((d) => { d.salt = "not*base64!!"; }),
		"salt wrong length": mutate((d) => { d.salt = Buffer.alloc(8).toString("base64"); }),
		"nonce wrong length": mutate((d) => { d.contentNonce = Buffer.alloc(16).toString("base64"); }),
		"wrapped key wrong length": mutate((d) => { d.encryptedVaultKey = Buffer.alloc(32).toString("base64"); }),
		"ciphertext shorter than a tag": mutate((d) => { d.ciphertext = Buffer.alloc(15).toString("base64"); }),
		"invalid utf-8": new Uint8Array([0x7B, 0xC3, 0x28, 0x7D]),
	};
	for (const [name, bytes] of Object.entries(cases)) {
		assert.throws(() => vc.parseEnvelope(bytes), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.FORMAT, name);
	}
	assert.throws(() => vc.parseEnvelope("string"), (e) => e.kind === vc.KINDS.FORMAT);
});

test("a byte order mark is tolerated, as the desktop tolerates it", () => {
	const { bytes } = readFixture("small");
	const withBom = new Uint8Array(bytes.length + 3);
	withBom.set([0xEF, 0xBB, 0xBF]); withBom.set(bytes, 3);
	assert.equal(vc.parseEnvelope(withBom).version, 1);
});

// ------------------------------------------------------------------- unlock
test("the small fixture opens with its password and decrypts to exactly the desktop's plaintext", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const result = await vc.unlock(env, meta.typedPassword);
	assert.equal(Buffer.from(result.plaintext).toString("utf8"), meta.plaintextUtf8);
	assert.equal(result.usedCanonical, true);
	assert.equal(await vc.sha256Hex(bytes), meta.fingerprint);
	assert.equal(bytes.length, meta.sizeBytes);
});

test("a wrong password, an empty password, and a changed envelope are all refused the same way", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	await rejectsKind(vc.unlock(env, "not the password"), vc.KINDS.AUTH);
	await rejectsKind(vc.unlock(env, ""), vc.KINDS.AUTH);
	await rejectsKind(vc.unlock(env, meta.typedPassword + " "), vc.KINDS.AUTH);

	// One flipped ciphertext byte.
	const tampered = mutate((d) => { const b = Buffer.from(d.ciphertext, "base64"); b[5] ^= 0x01; d.ciphertext = b.toString("base64"); });
	await rejectsKind(vc.unlock(vc.parseEnvelope(tampered), meta.typedPassword), vc.KINDS.AUTH);
	// A public header field changed: the AAD no longer matches.
	const retuned = mutate((d) => { d.kdfParameters.iterations = 2; });
	await rejectsKind(vc.unlock(vc.parseEnvelope(retuned), meta.typedPassword), vc.KINDS.AUTH);
	// The wrapped key changed.
	const rewrapped = mutate((d) => { const b = Buffer.from(d.encryptedVaultKey, "base64"); b[0] ^= 0x80; d.encryptedVaultKey = b.toString("base64"); });
	await rejectsKind(vc.unlock(vc.parseEnvelope(rewrapped), meta.typedPassword), vc.KINDS.AUTH);
});

test("the password is canonicalized as MasterPasswordEncoding does: spaces to U+0020, then NFC", async () => {
	const { bytes, meta } = readFixture("unicode-canonical");
	const env = vc.parseEnvelope(bytes);
	const nfc = meta.typedPassword;
	const nfd = nfc.normalize("NFD");
	const plainSpaces = nfc.replace(/　/g, " ");
	const nbsp = plainSpaces.replace(/ /g, " ");
	for (const typed of [nfc, nfd, plainSpaces, nbsp, nbsp.normalize("NFD")]) {
		const result = await vc.unlock(env, typed);
		assert.equal(Buffer.from(result.plaintext).toString("utf8"), meta.plaintextUtf8);
		assert.equal(result.usedCanonical, true, JSON.stringify(typed));
	}
	await rejectsKind(vc.unlock(env, nfc.replace(/é/, "e")), vc.KINDS.AUTH);
	const c = vc.passwordCandidates(nfd);
	assert.equal(hex(c.encodings[0]), Buffer.from(plainSpaces.normalize("NFC"), "utf8").toString("hex"));
	assert.equal(c.firstIsCanonical, true);
	assert.deepEqual(vc.passwordCandidates(""), { encodings: [], firstIsCanonical: false });
	assert.equal(vc.passwordCandidates("ascii only").encodings.length, 1);
});

test("a vault keyed before desktop 0.6.0 with the password as typed still opens, through the legacy candidates", async () => {
	const { bytes, meta } = readFixture("unicode-legacy-nfd");
	const env = vc.parseEnvelope(bytes);
	const result = await vc.unlock(env, meta.typedPassword);           // typed in NFD, as it was keyed
	assert.equal(Buffer.from(result.plaintext).toString("utf8"), meta.plaintextUtf8);
	assert.equal(result.usedCanonical, false);
	const viaNfc = await vc.unlock(env, meta.typedPassword.normalize("NFC")); // typed in NFC: the NFD candidate finds it
	assert.equal(viaNfc.usedCanonical, false);
});

test("the strong profile (256 MiB, t=3, p=4) opens in this runtime", { skip: !process.env.BITOSX_TEST_SLOW && "set BITOSX_TEST_SLOW=1" }, async () => {
	const { bytes, meta } = readFixture("strong");
	const result = await vc.unlock(vc.parseEnvelope(bytes), meta.typedPassword);
	assert.equal(Buffer.from(result.plaintext).toString("utf8"), meta.plaintextUtf8);
});

// ------------------------------------------------------------------ content
test("the decrypted document is read strictly, and the items come out typed", async () => {
	const { bytes, meta } = readFixture("small");
	const vault = vc.parseVault((await vc.unlock(vc.parseEnvelope(bytes), meta.typedPassword)).plaintext);
	assert.equal(vault.schemaVersion, 1);
	assert.equal(vault.items.length, 3);
	const github = vault.items.find((i) => i.name === "GitHub");
	assert.equal(github.id, "11111111-1111-4111-8111-111111111111");
	assert.equal(github.username, "octocat@example.com");
	assert.equal(github.password, "P@ssw0rd-Strong-123");
	assert.deepEqual([...github.urls], ["https://github.com"]);
	assert.equal(github.favorite, true);
	assert.equal(github.notes, null);
	assert.equal(github.createdAt.toISOString(), "2026-10-01T09:00:00.000Z");
	assert.equal(github.updatedAt.toISOString(), "2026-10-02T09:00:00.000Z");
	const bank = vault.items.find((i) => i.id === "22222222-2222-4222-8222-222222222222");
	assert.equal(bank.name, "Bank <script>alert(1)</script>");
	assert.equal(bank.notes, "Security question: first pet.\nSecond line & <i>markup</i>");
	const wifi = vault.items.find((i) => i.id === "33333333-3333-4333-8333-333333333333");
	assert.equal(wifi.username, null);
	assert.equal(wifi.password, "ñandú-Ωmega-🔐");
	assert.deepEqual([...wifi.urls], []);
	assert.ok(Object.isFrozen(vault) && Object.isFrozen(vault.items) && Object.isFrozen(github));
});

test("content this version does not understand is refused rather than guessed at", () => {
	const item = { type: "login", Id: "11111111-1111-4111-8111-111111111111", Name: "x", Favorite: false, CreatedAt: "2026-10-01T09:00:00+00:00", UpdatedAt: "2026-10-01T09:00:00+00:00", Urls: [] };
	const doc = (items, extra) => utf8(JSON.stringify(Object.assign({ schemaVersion: 1, items }, extra || {})));
	assert.equal(vc.parseVault(doc([item])).items.length, 1);
	assert.equal(vc.parseVault(doc(null)).items.length, 0);
	assert.equal(vc.parseVault(utf8('{"schemaVersion":1}')).items.length, 0);

	throwsKind(() => vc.parseVault(utf8("not json")), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(utf8("[]")), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([item], { unknown: true })), vc.KINDS.CONTENT);
	// Version 2 (phase 12: authenticator keys) is read; 3 and above are not. tests/totp.test.js has the rest.
	assert.equal(vc.parseVault(utf8('{"schemaVersion":2,"items":[]}')).schemaVersion, 2);
	throwsKind(() => vc.parseVault(utf8('{"schemaVersion":3,"items":[]}')), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(utf8('{"items":[]}')), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([null])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { type: "card" })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { Extra: 1 })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { Id: "not-a-uuid" })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([item, Object.assign({}, item)])), vc.KINDS.CONTENT); // duplicate id
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { Favorite: "yes" })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { Urls: "https://x" })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { Password: 123 })])), vc.KINDS.CONTENT);
	throwsKind(() => vc.parseVault(doc([Object.assign({}, item, { CreatedAt: "yesterday" })])), vc.KINDS.CONTENT);

	// UpdatedAt before CreatedAt is normalized, as VaultValidation.NormalizeLoaded does.
	const back = vc.parseVault(doc([Object.assign({}, item, { UpdatedAt: "2020-01-01T00:00:00+00:00" })])).items[0];
	assert.equal(back.updatedAt.getTime(), back.createdAt.getTime());
});

// ------------------------------------------------------------------ writing
test("the document and the envelope are written byte for byte as the desktop writes them", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	assert.deepEqual(Buffer.from(vc.serializeEnvelope(env)), Buffer.from(bytes));
	const vault = vc.parseVault((await vc.unlock(env, meta.typedPassword)).plaintext);
	assert.equal(Buffer.from(vc.serializeVault(vault)).toString("utf8"), meta.plaintextUtf8);
	for (const name of ["unicode-canonical", "strong"]) {
		const f = readFixture(name);
		assert.deepEqual(Buffer.from(vc.serializeEnvelope(vc.parseEnvelope(f.bytes))), Buffer.from(f.bytes), name);
	}
});

test("strings and dates are encoded like System.Text.Json's default encoder", () => {
	assert.equal(vc._jsonString("a\"b\\c\nd\te<f>g&h'i+j`k é 🔐"), "\"a\\u0022b\\\\c\\nd\\te\\u003Cf\\u003Eg\\u0026h\\u0027i\\u002Bj\\u0060k \\u00E9 \\uD83D\\uDD10\"");
	assert.equal(vc._jsonString("\u0001"), "\"\\u0001\"");
	assert.equal(vc._jsonDate(new Date("2026-10-01T09:00:00Z")), "2026-10-01T09:00:00+00:00");
	assert.equal(vc._jsonDate(new Date("2026-10-01T09:00:00.120Z")), "2026-10-01T09:00:00.12+00:00");
});

test("a changed vault re-encrypts under the same vault key with a fresh nonce, and opens again with the master password", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const opened = await vc.unlock(env, meta.typedPassword);
	const vault = vc.parseVault(opened.plaintext);
	const now = new Date("2026-10-22T08:00:00Z");
	const added = {
		id: vc.newId(), name: "Added in the browser", username: "web@example.com", password: vc.generatePassword(24),
		urls: ["https://example.com/login"], notes: null, favorite: false, createdAt: now, updatedAt: now
	};
	const plaintext = vc.serializeVault({ items: [...vault.items, added] });

	const next = await vc.encryptContent(env, opened.vaultKey, plaintext);

	assert.notDeepEqual(Buffer.from(next.contentNonce), Buffer.from(env.contentNonce));
	assert.deepEqual(Buffer.from(next.encryptedVaultKey), Buffer.from(env.encryptedVaultKey)); // header untouched
	assert.deepEqual(Buffer.from(next.salt), Buffer.from(env.salt));
	const written = vc.serializeEnvelope(next);
	const reopened = await vc.unlock(vc.parseEnvelope(written), meta.typedPassword);
	const items = vc.parseVault(reopened.plaintext).items;
	assert.equal(items.length, 4);
	const back = items.find((i) => i.id === added.id);
	assert.equal(back.name, "Added in the browser");
	assert.equal(back.password, added.password);
	assert.equal(back.createdAt.toISOString(), "2026-10-22T08:00:00.000Z");
	// Two encryptions of the same plaintext never share a nonce or a ciphertext.
	const again = await vc.encryptContent(env, opened.vaultKey, plaintext);
	assert.notDeepEqual(Buffer.from(again.contentNonce), Buffer.from(next.contentNonce));
	assert.notDeepEqual(Buffer.from(again.ciphertext), Buffer.from(next.ciphertext));
	await assert.rejects(vc.encryptContent(env, new Uint8Array(16), plaintext), (e) => e.kind === vc.KINDS.CONTENT);
});

test("items are validated as VaultValidation validates them before anything is written", () => {
	const now = new Date("2026-10-22T08:00:00Z");
	const ok = { id: vc.newId(), name: "x", username: null, password: null, urls: [], notes: null, favorite: false, createdAt: now, updatedAt: now };
	vc.validateItem(ok);
	const bad = (patch, message) => assert.throws(() => vc.validateItem(Object.assign({}, ok, patch)), (e) => e.kind === vc.KINDS.CONTENT && e.message.includes(message), message);
	bad({ id: "nope" }, "Item id");
	bad({ name: "   " }, "Name is required");
	bad({ name: "n".repeat(201) }, "at most 200");
	bad({ username: "u".repeat(321) }, "Username");
	bad({ password: "p".repeat(4097) }, "Password");
	bad({ notes: "n".repeat(16385) }, "Notes");
	bad({ urls: null }, "URL list");
	bad({ urls: new Array(65).fill("https://x.example") }, "at most 64");
	bad({ urls: [" "] }, "must not be blank");
	bad({ urls: ["ftp://x.example"] }, "not a valid absolute http(s) URL");
	bad({ urls: ["example.com"] }, "not a valid absolute http(s) URL");
	bad({ urls: ["https://" + "x".repeat(2049)] }, "at most 2048");
	bad({ updatedAt: new Date("2020-01-01T00:00:00Z") }, "UpdatedAt");
	bad({ favorite: "yes" }, "Favorite");
	assert.throws(() => vc.serializeVault({ items: [ok, Object.assign({}, ok)] }), (e) => e.message.includes("duplicate"));
});

test("ids and generated passwords come from the CSPRNG and have the expected shape", () => {
	const ids = new Set();
	for (let i = 0; i < 100; i++) {
		const id = vc.newId();
		assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
		ids.add(id);
	}
	assert.equal(ids.size, 100);
	const pw = vc.generatePassword(24);
	assert.equal(pw.length, 24);
	assert.notEqual(pw, vc.generatePassword(24));
	assert.equal(vc.generatePassword().length, 20, "the desktop's default length");
});

// ------------------------------------------------- generator (desktop parity)
const DESKTOP_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
const onlyFrom = (text, alphabet) => [...text].every((c) => alphabet.includes(c));

test("the generator follows the desktop's PasswordGenerator: every selected class present, its symbol set, nothing else", () => {
	const all = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + DESKTOP_SYMBOLS;
	for (let i = 0; i < 2000; i++) {
		const pw = vc.generatePassword({ length: 4 + (i % 30) });
		assert.equal(pw.length, 4 + (i % 30));
		assert.ok(onlyFrom(pw, all), pw);
		// Coverage is guaranteed, not likely: with four classes even a 4-character password has one of each.
		assert.match(pw, /[a-z]/); assert.match(pw, /[A-Z]/); assert.match(pw, /[0-9]/);
		assert.ok([...pw].some((c) => DESKTOP_SYMBOLS.includes(c)), pw);
	}
	for (let i = 0; i < 300; i++) {
		const noSymbols = vc.generatePassword({ length: 16, symbols: false });
		assert.match(noSymbols, /^[A-Za-z0-9]{16}$/);
		const digitsOnly = vc.generatePassword({ length: 8, lowercase: false, uppercase: false, symbols: false });
		assert.match(digitsOnly, /^[0-9]{8}$/);
		const plain = vc.generatePassword({ length: 40, excludeAmbiguous: true });
		assert.ok(!/[Il1O0o]/.test(plain), plain);
	}
});

test("the generator's options are validated with the desktop's messages", () => {
	const refused = (o, message) => assert.throws(() => vc.generatePassword(o), (e) => e instanceof vc.VaultError && e.message.includes(message), message);
	refused({ length: 3 }, "between 4 and 256");
	refused({ length: 257 }, "between 4 and 256");
	refused({ length: 12.5 }, "between 4 and 256");
	refused({ lowercase: false, uppercase: false, digits: false, symbols: false }, "At least one character class");
	assert.equal(vc.generatePassword({ length: 256 }).length, 256);
	assert.deepEqual(vc.generatorOptions(null), { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, excludeAmbiguous: false });
});

test("every character is drawn uniformly (no modulo bias): a chi-square check on one class", () => {
	const counts = new Map();
	const n = 60000;
	const pw = vc.generatePassword({ length: 256, uppercase: false, lowercase: false, symbols: false }); // warm-up
	assert.equal(pw.length, 256);
	for (let i = 0; i < n / 200; i++) {
		for (const c of vc.generatePassword({ length: 200, uppercase: false, lowercase: false, symbols: false })) { counts.set(c, (counts.get(c) || 0) + 1); }
	}
	const expected = n / 10;
	let chi = 0;
	for (const d of "0123456789") { chi += ((counts.get(d) || 0) - expected) ** 2 / expected; }
	assert.ok(chi < 35, `chi-square ${chi.toFixed(1)} with 9 degrees of freedom`); // p < 1e-4
});

// ------------------------------------------- strength (desktop parity vectors)
test("the strength estimate is the desktop's PasswordStrength, on the desktop's own results", () => {
	const { vectors } = JSON.parse(fs.readFileSync(path.join(FIX, "password-strength-vectors.json"), "utf8"));
	assert.ok(vectors.length >= 60);
	for (const v of vectors) {
		assert.ok(Math.abs(vc.estimateEntropyBits(v.password) - v.bits) < 1e-9, `bits for ${JSON.stringify(v.password.slice(0, 40))}: ${vc.estimateEntropyBits(v.password)} != ${v.bits}`);
		assert.equal(vc.estimateStrength(v.password), v.level, `level for ${JSON.stringify(v.password.slice(0, 40))}`);
	}
	assert.equal(vc.STRENGTH_NAMES[vc.estimateStrength("Password123!")], "Very weak");
	// As on the desktop: generated passwords rate Strong or better.
	for (let i = 0; i < 300; i++) { assert.ok(vc.estimateStrength(vc.generatePassword(20)) >= 3); }
});

// ----------------------------------------------- key-wrap header comparison
test("sameKeyWrap tells a re-keyed or re-passworded envelope from a re-encrypted one", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const opened = await vc.unlock(env, meta.typedPassword);
	const next = await vc.encryptContent(env, opened.vaultKey, opened.plaintext);
	assert.equal(vc.sameKeyWrap(env, next), true, "new content, same header");
	const flip = (field) => { const b = Uint8Array.from(env[field]); b[0] ^= 1; return Object.assign({}, env, { [field]: b }); };
	for (const field of ["salt", "keyWrapNonce", "encryptedVaultKey"]) { assert.equal(vc.sameKeyWrap(env, flip(field)), false, field); }
	assert.equal(vc.sameKeyWrap(env, Object.assign({}, env, { kdfParameters: Object.assign({}, env.kdfParameters, { iterations: 2 }) })), false);
});

// ------------------------------------------------- text the desktop refuses
test("item text with half of a surrogate pair is refused before it is written", () => {
	const now = new Date("2026-10-22T08:00:00Z");
	const ok = { id: vc.newId(), name: "x", username: null, password: null, urls: [], notes: null, favorite: false, createdAt: now, updatedAt: now };
	for (const [patch, what] of [[{ name: "a\uD83D" }, "name"], [{ notes: "\uDD10b" }, "notes"], [{ username: "u\uD83D" }, "username"], [{ password: "p\uDBFF" }, "password"], [{ urls: ["https://x.example/\uD83D"] }, "URL"]]) {
		assert.throws(() => vc.validateItem(Object.assign({}, ok, patch)), (e) => e.kind === vc.KINDS.CONTENT && /incomplete character/.test(e.message), what);
	}
	vc.validateItem(Object.assign({}, ok, { name: "fine 🔐" }));
	assert.equal(vc.isWellFormed("🔐"), true);
	assert.equal(vc.isWellFormed("\uD83D"), false);
});

// ------------------------------------------- untouched items stay untouched
test("an item nobody changed is written back with its timestamps exactly as read, in the stored order", () => {
	const items = [
		{ type: "login", Id: "33333333-3333-4333-8333-333333333333", Name: "Zeta", Favorite: false, CreatedAt: "2026-10-01T09:00:00.1234567+00:00", UpdatedAt: "2026-10-02T10:11:12.9876543+00:00", Urls: [] },
		{ type: "login", Id: "11111111-1111-4111-8111-111111111111", Name: "Alpha", Favorite: true, CreatedAt: "2026-10-01T09:00:00+00:00", UpdatedAt: "2026-10-01T09:00:00.5+00:00", Urls: [] }
	];
	const vault = vc.parseVault(utf8(JSON.stringify({ schemaVersion: 1, items })));
	const text = Buffer.from(vc.serializeVault(vault)).toString("utf8");
	assert.ok(text.includes("\"CreatedAt\":\"2026-10-01T09:00:00.1234567+00:00\""), text);
	assert.ok(text.includes("\"UpdatedAt\":\"2026-10-02T10:11:12.9876543+00:00\""), text);
	assert.ok(text.indexOf("Zeta") < text.indexOf("Alpha"), "the stored order, not a sorted one");
	// A changed date is written the way System.Text.Json writes it.
	const changed = Object.assign({}, vault.items[0], { updatedAt: new Date("2026-11-03T08:00:00.250Z") });
	assert.ok(Buffer.from(vc.serializeVault({ items: [changed] })).toString("utf8").includes("\"UpdatedAt\":\"2026-11-03T08:00:00.25+00:00\""));
	// A raw text that does not say the same instant any more is never reused.
	const lying = Object.assign({}, vault.items[0], { createdAtText: "2020-01-01T00:00:00+00:00" });
	assert.ok(Buffer.from(vc.serializeVault({ items: [lying] })).toString("utf8").includes("\"CreatedAt\":\"2026-10-01T09:00:00.123+00:00\""));
});

// ------------------------------------------------ the size an envelope will have
test("the size an envelope will have is estimated from the size of its content, within a few kilobytes", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const opened = await vc.unlock(env, meta.typedPassword);
	// The envelope the desktop wrote: every "+" of its Base64 is six bytes in the file, and how many
	// there are cannot be known beforehand.
	const fixture = vc.estimateEnvelopeSize(env, opened.plaintext.length);
	assert.ok(Math.abs(fixture - bytes.length) < 64, `${fixture} estimated, ${bytes.length} written`);
	// Every envelope this page writes, whatever the length of its content modulo three.
	for (const length of [0, 1, 2, 3, 4, 5, 6, 100, 1000, 4096, 4097, 65537, 1048576, 3000000]) {
		const plaintext = new Uint8Array(length).fill(0x61);
		const next = await vc.encryptContent(env, opened.vaultKey, plaintext);
		const written = vc.serializeEnvelope(next).length;
		const estimated = vc.estimateEnvelopeSize(env, length);
		// Six standard deviations of the number of "+" among the Base64 characters, five bytes each, and the nonce's own.
		const allowed = 6 * 5 * Math.sqrt((4 * Math.ceil((length + 16) / 3)) * 63 / 4096) + 100;
		assert.ok(Math.abs(written - estimated) < allowed, `content of ${length} bytes: ${estimated} estimated, ${written} written`);
		// Never less than the Base64 itself.
		assert.ok(written >= vc.estimateEnvelopeSize(env, 0) - 30 + 4 * Math.ceil((length + 16) / 3) - 4 * Math.ceil(16 / 3));
	}
	// The envelope is about 44 % larger than its content: some 11.1 MiB of content is the most that fits in 16 MiB.
	const growth = (vc.estimateEnvelopeSize(env, 6400000) - vc.estimateEnvelopeSize(env, 0)) / 6400000;
	assert.ok(Math.abs(growth - (4 / 3) * (69 / 64)) < 0.0001, String(growth));
	assert.ok(vc.estimateEnvelopeSize(env, Math.floor(11.1 * 1024 * 1024)) < vc.MAX_ENVELOPE_BYTES);
	assert.ok(vc.estimateEnvelopeSize(env, Math.floor(11.2 * 1024 * 1024)) > vc.MAX_ENVELOPE_BYTES);
	for (const bad of [-1, 1.5, NaN, "10", null, undefined]) { throwsKind(() => vc.estimateEnvelopeSize(env, bad), vc.KINDS.CONTENT); }
	// Nothing of the envelope is changed by asking.
	assert.deepEqual(Buffer.from(vc.serializeEnvelope(env)), Buffer.from(bytes));
});

// --------------------------------------- the master password, asked for again
test("the master password is checked against the key the open session holds, without decrypting the vault again", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const opened = await vc.unlock(env, meta.typedPassword);
	assert.equal(await vc.verifyMasterPassword(env, meta.typedPassword, opened.vaultKey), true);
	for (const wrong of ["not the password", "", meta.typedPassword + " ", meta.typedPassword.toUpperCase(), " " + meta.typedPassword]) {
		assert.equal(await vc.verifyMasterPassword(env, wrong, opened.vaultKey), false, JSON.stringify(wrong));
	}
	// It is the envelope's key wrap that is asked, so the content may have been saved again meanwhile.
	const next = await vc.encryptContent(env, opened.vaultKey, utf8("{\"schemaVersion\":1,\"items\":[]}"));
	assert.equal(await vc.verifyMasterPassword(next, meta.typedPassword, opened.vaultKey), true);
	assert.equal(await vc.verifyMasterPassword(next, "not the password", opened.vaultKey), false);
	// The right password of a vault whose key is not the one this session holds is not this session's password.
	const otherKey = Uint8Array.from(opened.vaultKey); otherKey[0] ^= 0x01;
	assert.equal(await vc.verifyMasterPassword(env, meta.typedPassword, otherKey), false);
	// The key the session holds is neither changed nor wiped by the check.
	assert.deepEqual(Buffer.from(opened.vaultKey), Buffer.from((await vc.unlock(env, meta.typedPassword)).vaultKey));
	// A changed key wrap opens with nothing.
	const flipped = Object.assign({}, env, { encryptedVaultKey: Uint8Array.from(env.encryptedVaultKey, (b, i) => i === 0 ? b ^ 1 : b) });
	assert.equal(await vc.verifyMasterPassword(flipped, meta.typedPassword, opened.vaultKey), false);
	await rejectsKind(vc.verifyMasterPassword(env, meta.typedPassword, new Uint8Array(16)), vc.KINDS.CONTENT);
	await rejectsKind(vc.verifyMasterPassword(env, meta.typedPassword, "key"), vc.KINDS.CONTENT);
});

test("the check accepts the master password however it is typed, exactly as unlocking does", async () => {
	const canonical = readFixture("unicode-canonical");
	const env = vc.parseEnvelope(canonical.bytes);
	const nfc = canonical.meta.typedPassword;
	const key = (await vc.unlock(env, nfc)).vaultKey;
	const plainSpaces = nfc.replace(/　/g, " ");
	for (const typed of [nfc, nfc.normalize("NFD"), plainSpaces, plainSpaces.replace(/ /g, " ")]) {
		assert.equal(await vc.verifyMasterPassword(env, typed, key), true, JSON.stringify(typed));
	}
	assert.equal(await vc.verifyMasterPassword(env, nfc.replace(/é/, "e"), key), false);
	// A vault keyed before desktop 0.6.0 with the password as typed: the legacy candidates find it.
	const legacy = readFixture("unicode-legacy-nfd");
	const legacyEnv = vc.parseEnvelope(legacy.bytes);
	const legacyKey = (await vc.unlock(legacyEnv, legacy.meta.typedPassword)).vaultKey;
	assert.equal(await vc.verifyMasterPassword(legacyEnv, legacy.meta.typedPassword, legacyKey), true);
	assert.equal(await vc.verifyMasterPassword(legacyEnv, legacy.meta.typedPassword.normalize("NFC"), legacyKey), true);
	assert.equal(await vc.verifyMasterPassword(legacyEnv, "something else", legacyKey), false);
});

test("a key derivation that cannot run is said to be that, not a wrong password", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const key = (await vc.unlock(env, meta.typedPassword)).vaultKey;
	const withoutKdf = factory(undefined, globalThis.crypto);
	await assert.rejects(withoutKdf.verifyMasterPassword(env, meta.typedPassword, key), (e) => e instanceof withoutKdf.VaultError && e.kind === vc.KINDS.RESOURCE);
	const failingKdf = factory({ argon2id: () => Promise.reject(new Error("out of memory")) }, globalThis.crypto);
	await assert.rejects(failingKdf.verifyMasterPassword(env, meta.typedPassword, key), (e) => e instanceof failingKdf.VaultError && e.kind === vc.KINDS.RESOURCE);
});

// ------------------------------------------------------- a vault of many MiB
test("Base64 is checked strictly, and in a way that copes with an envelope of 16 MiB", () => {
	for (const ok of ["AAAA", "AA==", "AAA=", "abcdEFGH0123+/==", "+/+/", "QUJD", "AAAAAA=="]) { assert.equal(vc.isBase64(ok), true, ok); }
	for (const bad of ["", "A", "AA", "AAA", "AAAAA", "A===", "====", "=AAA", "AA=A", "AA==AAAA", "AAA=AAAA", "AAA-", "AAA_", "AA A", "AAA\n", "AAAA\n", "\u00C4AAA", "AAA\u0100", "AAA\uFF21", "AA=", "AAAA="]) {
		assert.equal(vc.isBase64(bad), false, JSON.stringify(bad));
		assert.throws(() => vc.base64ToBytes(bad, "x"), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.FORMAT);
	}
	// Every valid length up to 64 bytes agrees with what Node writes.
	for (let n = 1; n <= 64; n++) {
		const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xFF);
		const text = Buffer.from(bytes).toString("base64");
		assert.equal(vc.isBase64(text), true);
		assert.deepEqual(Buffer.from(vc.base64ToBytes(text, "x")), Buffer.from(bytes));
	}
	// The ciphertext of a vault at the limit is some 22 million characters: checked in a moment, not with a pattern
	// that overflows the stack (which made every vault larger than a few MiB impossible to open).
	const large = "QUJD".repeat(5600000) + "QQ==";
	const started = Date.now();
	assert.equal(vc.isBase64(large), true);
	assert.equal(vc.isBase64(large.slice(0, 11000000) + "*" + large.slice(11000001)), false);
	assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
});

test("an envelope near the 16 MiB limit is written, parsed and opened again", async () => {
	const { bytes, meta } = readFixture("small");
	const env = vc.parseEnvelope(bytes);
	const opened = await vc.unlock(env, meta.typedPassword);
	// Some 11 MiB of content: an envelope of about 15.8 MiB.
	const at = new Date("2026-10-01T09:00:00Z");
	const items = Array.from({ length: 690 }, (_, i) => ({ id: "00000000-0000-4000-8000-" + String(i).padStart(12, "0"), type: "login", name: "Large " + i, username: null, password: null, urls: [],
		notes: "n".repeat(16384), favorite: false, createdAt: at, updatedAt: at }));
	const plaintext = vc.serializeVault({ items });
	const written = vc.serializeEnvelope(await vc.encryptContent(env, opened.vaultKey, plaintext));
	assert.ok(written.length > 15.5 * 1024 * 1024 && written.length <= vc.MAX_ENVELOPE_BYTES, `${written.length} bytes`);
	assert.ok(Math.abs(written.length - vc.estimateEnvelopeSize(env, plaintext.length)) < 32 * 1024);
	const again = await vc.unlock(vc.parseEnvelope(written), meta.typedPassword);
	assert.equal(vc.parseVault(again.plaintext).items.length, 690);
	assert.equal(await vc.verifyMasterPassword(vc.parseEnvelope(written), meta.typedPassword, opened.vaultKey), true);
	// One byte over the limit is not an envelope this page reads.
	throwsKind(() => vc.parseEnvelope(new Uint8Array(vc.MAX_ENVELOPE_BYTES + 1)), vc.KINDS.FORMAT);
});
