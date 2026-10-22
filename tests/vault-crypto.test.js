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
	throwsKind(() => vc.parseVault(utf8('{"schemaVersion":2,"items":[]}')), vc.KINDS.CONTENT);
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
	assert.equal(vc.generatePassword().length, 24);
	assert.ok(/^[A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\]^_{|}~]+$/.test(vc.generatePassword(200)));
});
