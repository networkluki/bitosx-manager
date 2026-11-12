// Authenticator codes (RFC 6238 TOTP) and how an authenticator key is stored in a login item:
// vault/public/assets/js/vault-crypto.js under Node's test runner and Node's WebCrypto.
//
//   node --test tests/totp.test.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");

const factory = require("../vault/public/assets/js/vault-crypto.js");
const vc = factory(null, globalThis.crypto);

const utf8 = (s) => new TextEncoder().encode(s);
const text = (bytes) => Buffer.from(bytes).toString("utf8");

// An independent base32 encoder for the tests (bit string, not the code under test).
function base32(bytes) {
	const bits = [...bytes].map((b) => b.toString(2).padStart(8, "0")).join("");
	let out = "";
	for (let i = 0; i < bits.length; i += 5) { out += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)]; }
	return out;
}
// An independent RFC 6238 implementation for the tests' own cases (node:crypto, not WebCrypto).
function referenceCode(secretBytes, algorithm, digits, period, unixSeconds) {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / period)));
	const mac = nodeCrypto.createHmac({ SHA1: "sha1", SHA256: "sha256", SHA512: "sha512" }[algorithm], Buffer.from(secretBytes)).update(counter).digest();
	const offset = mac[mac.length - 1] & 0x0f;
	const binary = mac.readUInt32BE(offset) & 0x7fffffff;
	return String(binary % 10 ** digits).padStart(digits, "0");
}

// ------------------------------------------------------------------ RFC 6238
// Appendix B, Table 1, checked against the RFC text (two byte-identical copies of rfc6238.txt,
// SHA-256 82947ed9064450850547f55959dc79d2de775f0fa33f7b3f9622fb6c93e69a7a). The seeds are those
// of the RFC's reference code: 20, 32 and 64 bytes of "1234567890…" (the table's prose names the
// 20-byte one for all three; the reference code that produced the table uses the longer ones).
const RFC_SEEDS = {
	SHA1: "12345678901234567890",
	SHA256: "12345678901234567890123456789012",
	SHA512: "1234567890123456789012345678901234567890123456789012345678901234"
};
const RFC_TABLE = [
	[59, "94287082", "46119246", "90693936"],
	[1111111109, "07081804", "68084774", "25091201"],
	[1111111111, "14050471", "67062674", "99943326"],
	[1234567890, "89005924", "91819424", "93441116"],
	[2000000000, "69279037", "90698825", "38618901"],
	[20000000000, "65353130", "77737706", "47863826"]
];

test("RFC 6238 Appendix B: every code of the table, for SHA1, SHA256 and SHA512", async () => {
	for (const [time, sha1, sha256, sha512] of RFC_TABLE) {
		for (const [algorithm, expected] of [["SHA1", sha1], ["SHA256", sha256], ["SHA512", sha512]]) {
			const key = { secret: base32(utf8(RFC_SEEDS[algorithm])), algorithm, digits: 8, period: 30 };
			const result = await vc.totpCode(key, time);
			assert.equal(result.code, expected, `${algorithm} at ${time}`);
			assert.equal(result.secondsLeft, 30 - (time % 30));
		}
	}
});

test("own cases: 6 and 7 digits, a period of 60 and of 1 and 300, a 10-byte and a 128-byte secret, T at its boundaries", async () => {
	const secrets = [
		Uint8Array.from({ length: 10 }, (_, i) => i * 17 + 3),
		Uint8Array.from({ length: 20 }, (_, i) => 255 - i),
		Uint8Array.from({ length: 128 }, (_, i) => (i * 31) & 0xff)
	];
	const times = [0, 1, 29, 30, 59, 60, 61, 119, 120, 299, 300, 1700000000, 1700000039, 1700000040, 4294967295, 4294967296 * 30, 2 ** 53 - 1];
	let checked = 0;
	for (const secretBytes of secrets) {
		for (const algorithm of ["SHA1", "SHA256", "SHA512"]) {
			for (const digits of [6, 7, 8]) {
				for (const period of [1, 30, 60, 300]) {
					const key = { secret: base32(secretBytes), algorithm, digits, period };
					for (const time of times) {
						const result = await vc.totpCode(key, time);
						assert.equal(result.code, referenceCode(secretBytes, algorithm, digits, period, time), `${algorithm}/${digits}/${period} at ${time}`);
						assert.equal(result.secondsLeft, period - (time % period));
						checked++;
					}
				}
			}
		}
	}
	assert.equal(checked, 3 * 3 * 3 * 4 * times.length);
});

test("the last second of a period and the first of the next give different codes, and the seconds left count down", async () => {
	const key = { secret: base32(utf8(RFC_SEEDS.SHA1)), algorithm: "SHA1", digits: 6, period: 30 };
	const last = await vc.totpCode(key, 59);
	const first = await vc.totpCode(key, 60);
	assert.equal(last.code, "287082");   // the RFC's 8-digit code, mod 10^6
	assert.equal(last.secondsLeft, 1);
	assert.equal(first.secondsLeft, 30);
	assert.notEqual(first.code, last.code);
	assert.equal(vc.totpSecondsLeft(key, 0), 30);
	assert.equal(vc.totpSecondsLeft({ period: 60 }, 61), 59);
});

test("a code is grouped for the eye, and the digits stay as they are", () => {
	assert.equal(vc.formatTotpCode("123456"), "123 456");
	assert.equal(vc.formatTotpCode("12345678"), "1234 5678");
	assert.equal(vc.formatTotpCode("1234567"), "123 4567");
});

test("no code for a key that is not valid, or a time that is not a whole number of seconds since 1970", async () => {
	const ok = { secret: base32(utf8(RFC_SEEDS.SHA1)), algorithm: "SHA1", digits: 6, period: 30 };
	const refused = (patch, time = 59) => assert.rejects(vc.totpCode(Object.assign({}, ok, patch), time), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.CONTENT);
	await refused({ secret: ok.secret.toLowerCase() });
	await refused({ secret: ok.secret + "=" });
	await refused({ secret: base32(new Uint8Array(9)) });
	await refused({ secret: base32(new Uint8Array(129)) });
	await refused({ algorithm: "MD5" });
	await refused({ algorithm: "sha1" });
	await refused({ digits: 5 });
	await refused({ digits: 9 });
	await refused({ digits: 6.5 });
	await refused({ period: 0 });
	await refused({ period: 301 });
	await refused({}, -1);
	await refused({}, 1.5);
	await refused({}, 2 ** 53);
	await refused({}, NaN);
});

// ------------------------------------------------------------- the stored form
const ITEM = { type: "login", Id: "11111111-1111-4111-8111-111111111111", Name: "x", Favorite: false, CreatedAt: "2026-10-01T09:00:00+00:00", UpdatedAt: "2026-10-01T09:00:00+00:00", Urls: [] };
const TOTP = { Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6, Period: 30 };
const doc = (version, items) => utf8(JSON.stringify({ schemaVersion: version, items }));
const withTotp = (totp) => Object.assign({}, ITEM, { Totp: totp });
function refusedContent(bytes) {
	assert.throws(() => vc.parseVault(bytes), (e) => e instanceof vc.VaultError && e.kind === vc.KINDS.CONTENT);
}

test("version 1 and version 2 documents are read; a key comes out as the item's totp", () => {
	const v1 = vc.parseVault(doc(1, [ITEM]));
	assert.equal(v1.schemaVersion, 1);
	assert.equal(v1.items[0].totp, null);
	const v2 = vc.parseVault(doc(2, [withTotp(TOTP), Object.assign({}, ITEM, { Id: "22222222-2222-4222-8222-222222222222" })]));
	assert.equal(v2.schemaVersion, 2);
	assert.deepEqual({ ...v2.items[0].totp }, { secret: TOTP.Secret, algorithm: "SHA1", digits: 6, period: 30 });
	assert.ok(Object.isFrozen(v2.items[0].totp));
	assert.equal(v2.items[1].totp, null);
	// A version 2 document whose items have no key is read (and written back as version 1).
	assert.equal(vc.parseVault(doc(2, [ITEM])).schemaVersion, 2);
	assert.equal(vc.parseVault(doc(2, [])).items.length, 0);
});

test("a key in a version 1 document, version 0 and 3 and above, and any key that is not exactly valid are refused", () => {
	refusedContent(doc(1, [withTotp(TOTP)]));
	refusedContent(doc(1, [withTotp(null)]));   // "Totp": null is refused in every version (D2)
	refusedContent(doc(2, [withTotp(null)]));
	for (const version of [0, 3, 4, 100, "2", 2.5, null]) { refusedContent(doc(version, [])); }
	const bad = [
		{ Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Algorithm: "SHA1", Digits: 6 },               // a member missing
		Object.assign({}, TOTP, { Extra: 1 }),                                                      // an unknown member
		Object.assign({}, TOTP, { secret: TOTP.Secret, Secret: undefined }),                        // camelCase
		Object.assign({}, TOTP, { Secret: "gezdgnbvgy3tqojqgezdgnbvgy3tqojq" }),                    // lower case
		Object.assign({}, TOTP, { Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====" }),                // padding
		Object.assign({}, TOTP, { Secret: "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ" }),             // spaces
		Object.assign({}, TOTP, { Secret: "AAAAAAAAAAAAAAAAAB" }),                                  // 11 bytes, the 2 leftover bits not zero
		Object.assign({}, TOTP, { Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQA" }),                   // a character that adds no byte
		Object.assign({}, TOTP, { Secret: base32(new Uint8Array(9)) }),                             // 9 bytes
		Object.assign({}, TOTP, { Secret: base32(new Uint8Array(129)) }),                           // 129 bytes
		Object.assign({}, TOTP, { Secret: "" }),
		Object.assign({}, TOTP, { Secret: 12 }),
		Object.assign({}, TOTP, { Algorithm: "sha1" }),
		Object.assign({}, TOTP, { Algorithm: "SHA-1" }),
		Object.assign({}, TOTP, { Algorithm: "MD5" }),
		Object.assign({}, TOTP, { Algorithm: 1 }),
		Object.assign({}, TOTP, { Digits: 5 }),
		Object.assign({}, TOTP, { Digits: 9 }),
		Object.assign({}, TOTP, { Digits: "6" }),
		Object.assign({}, TOTP, { Digits: 6.5 }),
		Object.assign({}, TOTP, { Period: 0 }),
		Object.assign({}, TOTP, { Period: 301 }),
		Object.assign({}, TOTP, { Period: 30.5 }),
		Object.assign({}, TOTP, { Period: null }),
		null,                                                                                       // "Totp": null is not a stored form (D2)
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		[],
		true
	];
	for (const totp of bad) {
		const raw = JSON.parse(JSON.stringify(withTotp(totp)));
		refusedContent(utf8(JSON.stringify({ schemaVersion: 2, items: [raw] })));
	}
	// The refusal never quotes the content.
	try { vc.parseVault(doc(2, [withTotp(Object.assign({}, TOTP, { Algorithm: "MD5" }))])); }
	catch (e) { assert.ok(!e.message.includes(TOTP.Secret) && !e.message.includes("MD5")); }
	// Everything else stays as strict as before.
	refusedContent(doc(2, [Object.assign({}, ITEM, { Extra: 1 })]));
	refusedContent(utf8(JSON.stringify({ schemaVersion: 2, items: [], other: 1 })));
});

test("every algorithm, digit count and period the rules allow is read, at both ends", () => {
	const ok = [
		Object.assign({}, TOTP, { Algorithm: "SHA256", Digits: 7, Period: 1 }),
		Object.assign({}, TOTP, { Algorithm: "SHA512", Digits: 8, Period: 300 }),
		Object.assign({}, TOTP, { Secret: base32(new Uint8Array(10).fill(0xff)) }),
		Object.assign({}, TOTP, { Secret: base32(new Uint8Array(128).fill(0xa5)) })
	];
	for (const totp of ok) {
		const item = vc.parseVault(doc(2, [withTotp(totp)])).items[0];
		assert.deepEqual({ ...item.totp }, { secret: totp.Secret, algorithm: totp.Algorithm, digits: totp.Digits, period: totp.Period });
	}
});

test("written as version 1 without keys, byte for byte as before, and as version 2 with one, Totp after Urls", () => {
	const now = new Date("2026-11-12T08:00:00Z");
	const plain = { id: "11111111-1111-4111-8111-111111111111", name: "x", username: "u", password: "p", urls: ["https://example.com"], notes: null, favorite: false, createdAt: now, updatedAt: now };
	const before = '{"schemaVersion":1,"items":[{"type":"login","Username":"u","Password":"p","Urls":["https://example.com"],"Id":"11111111-1111-4111-8111-111111111111","Name":"x","Favorite":false,"CreatedAt":"2026-11-12T08:00:00+00:00","UpdatedAt":"2026-11-12T08:00:00+00:00"}]}';
	assert.equal(text(vc.serializeVault({ items: [plain] })), before);
	assert.equal(text(vc.serializeVault({ items: [Object.assign({}, plain, { totp: null })] })), before);
	const keyed = Object.assign({}, plain, { id: "22222222-2222-4222-8222-222222222222", totp: { secret: TOTP.Secret, algorithm: "SHA512", digits: 8, period: 60 } });
	const written = text(vc.serializeVault({ items: [plain, keyed] }));
	assert.equal(written, '{"schemaVersion":2,"items":[' + before.slice('{"schemaVersion":1,"items":['.length, -2) + ',' +
		'{"type":"login","Username":"u","Password":"p","Urls":["https://example.com"],"Totp":{"Secret":"' + TOTP.Secret + '","Algorithm":"SHA512","Digits":8,"Period":60},' +
		'"Id":"22222222-2222-4222-8222-222222222222","Name":"x","Favorite":false,"CreatedAt":"2026-11-12T08:00:00+00:00","UpdatedAt":"2026-11-12T08:00:00+00:00"}]}');
	// And it reads back to the same items.
	const back = vc.parseVault(utf8(written));
	assert.equal(back.schemaVersion, 2);
	assert.deepEqual({ ...back.items[1].totp }, { ...keyed.totp });
	assert.equal(text(vc.serializeVault(back)), written);
	// Removing the last key writes version 1 again.
	assert.equal(text(vc.serializeVault({ items: [plain, Object.assign({}, keyed, { totp: null })] })).slice(0, 18), '{"schemaVersion":1');
});

test("an item with a key that is not valid is not written, and the message does not quote it", () => {
	const now = new Date("2026-11-12T08:00:00Z");
	const item = { id: vc.newId(), name: "x", username: null, password: null, urls: [], notes: null, favorite: false, createdAt: now, updatedAt: now };
	for (const totp of [{ secret: "abc", algorithm: "SHA1", digits: 6, period: 30 }, { secret: TOTP.Secret, algorithm: "SHA3", digits: 6, period: 30 }, { secret: TOTP.Secret, algorithm: "SHA1", digits: 6 }, "JBSWY3DPEHPK3PXP"]) {
		assert.throws(() => vc.serializeVault({ items: [Object.assign({}, item, { totp })] }), (e) => e instanceof vc.VaultError && e.message === "The authenticator key is not valid.");
	}
	assert.ok(vc.isValidTotpKey({ secret: TOTP.Secret, algorithm: "SHA1", digits: 6, period: 30 }));
});

// ------------------------------------------------------ reading a key from text
const JBSW = "JBSWY3DPEHPK3PXP";   // 10 bytes: "Hello!\xDE\xAD\xBE\xEF"
const key = (secret, algorithm = "SHA1", digits = 6, period = 30) => ({ secret, algorithm, digits, period });
function reads(input, expected) {
	const result = vc.readTotpKey(input);
	assert.equal(result.refusal, null, `${JSON.stringify(input)} was refused: ${result.refusal}`);
	assert.deepEqual(result.key === null ? null : { ...result.key }, expected, JSON.stringify(input));
	if (result.key) { assert.ok(Object.isFrozen(result.key) && vc.isValidTotpKey(result.key)); }
}
function refuses(input, code) {
	const result = vc.readTotpKey(input);
	assert.equal(result.key, null, JSON.stringify(input));
	assert.equal(result.refusal, code, JSON.stringify(input));
	assert.ok(vc.TOTP_REFUSALS.includes(code));
}

test("§3.1: the length is checked first, then the text is trimmed; empty is no key; otpauth:// and steam:// are told apart from a secret", () => {
	refuses("A".repeat(2049), "too_long");
	refuses(" ".repeat(2049), "too_long");                       // before trimming
	refuses("otpauth://totp/x?secret=" + "A".repeat(2025), "too_long");
	reads("A".repeat(16) + " ".repeat(2032), key("A".repeat(16)));   // 2048 units: read
	for (const empty of ["", " ", "\t\r\n", "  　﻿\u0085"]) { reads(empty, null); }
	reads("　 " + JBSW + " ﻿", key(JBSW));
	reads("OTPAUTH://TOTP/x?SECRET=" + JBSW, key(JBSW));
	refuses("steam://ABCDEFGH", "steam_not_supported");
	refuses("  STEAM://x", "steam_not_supported");
	refuses("steam:/x", "invalid_secret");
	refuses("otpauth:/totp/x?secret=" + JBSW, "invalid_secret");
	// Every character the trim of IMPORT_EXPORT.md §2.1 removes, and no other, is removed here too.
	const ie = require("../vault/public/assets/js/import-export.js")(vc);
	for (let c = 0; c < 0x10000; c++) {
		const ch = String.fromCharCode(c);
		const trimmedHere = vc.readTotpKey(ch + "steam://x" + ch).refusal === "steam_not_supported";
		assert.equal(trimmedHere, ie._trim(ch + "x") === "x", `U+${c.toString(16)}`);
	}
});

test("§3.3: spaces, hyphens and trailing padding go, either case is read, and the stored secret is canonical", () => {
	reads(JBSW, key(JBSW));
	reads(JBSW.toLowerCase(), key(JBSW));
	reads("jbsw y3dp ehpk 3pxp", key(JBSW));
	reads("JBSW-Y3DP-EHPK-3PXP", key(JBSW));
	reads(JBSW + "======", key(JBSW));
	reads(JBSW + "= =-=", key(JBSW));                            // spaces and hyphens go first, then the "=" at the end
	reads("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", key("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
	reads("AAAAAAAAAAAAAAAAAB", key("AAAAAAAAAAAAAAAAAA"));       // 11 bytes: the leftover bits are dropped unchecked
	reads("AAAAAAAAAAAAAAAAA", key("AAAAAAAAAAAAAAAA"));          // 17 characters are 10 bytes
	reads("A".repeat(205), key("A".repeat(205)));                // 128 bytes
	reads("A".repeat(206), key("A".repeat(205)));                // still 128 bytes
	refuses("A".repeat(207), "secret_too_long");                 // 129
	refuses("A".repeat(2000), "secret_too_long");
	refuses("A".repeat(15), "secret_too_short");                 // 9 bytes
	refuses("====", "secret_too_short");
	refuses("- -", "secret_too_short");
	refuses("JBSW=Y3DPEHPK3PXP", "invalid_secret");               // "=" not at the end
	refuses(JBSW + "0", "invalid_secret");
	refuses(JBSW + "1", "invalid_secret");
	refuses(JBSW + "8", "invalid_secret");
	refuses("JBSW\tY3DPEHPK3PXP", "invalid_secret");               // only U+0020 is a space here
	refuses("JBSW Y3DPEHPK3PXP", "invalid_secret");
	refuses("JBSW_Y3DPEHPK3PXP", "invalid_secret");
	refuses("ĴBSWY3DPEHPK3PXP", "invalid_secret");
	refuses("ＪBSWY3DPEHPK3PXP", "invalid_secret");                // full-width letter
	refuses("JBSWY3DPEHPK3PX\uD83D", "invalid_secret");
	refuses("A".repeat(15) + "!", "invalid_secret");             // the alphabet is checked before the length
	// The canonical form is what the bytes are, not what was typed.
	assert.equal(vc.readTotpKey("mzxw6ytboi======").refusal, "secret_too_short");
});

test("§3.2: the type, the query, and the form of every parameter", () => {
	const link = (rest) => "otpauth://" + rest;
	reads(link("totp/Example:alice@example.com?secret=" + JBSW + "&issuer=Example"), key(JBSW));
	reads(link("TOTP/?secret=" + JBSW), key(JBSW));
	reads(link("ToTp/label/with/slashes?secret=" + JBSW), key(JBSW));
	reads(link("totp/label?secret=" + JBSW + "&issuer=a/b"), key(JBSW));   // the label is not read
	refuses(link("hotp/x?secret=" + JBSW + "&counter=1"), "hotp_not_supported");
	refuses(link("HOTP/x?secret=" + JBSW), "hotp_not_supported");
	refuses(link("steam/x?secret=" + JBSW), "invalid_link");
	refuses(link("totp?secret=" + JBSW), "invalid_link");                 // no "/"
	refuses(link("x"), "invalid_link");
	refuses(link(""), "invalid_link");
	refuses(link("/x?secret=" + JBSW), "invalid_link");                   // an empty type
	refuses(link("totp /x?secret=" + JBSW), "invalid_link");
	refuses(link("totp/x"), "invalid_link");                              // no "?"
	// Everything from the first "#" after the type on goes first; the query runs from the first "?"
	// in what is left (the desktop's reading, contract D3).
	refuses(link("totp/x#?secret=" + JBSW), "invalid_link");
	refuses(link("totp/label#not-a-fragment?secret=" + JBSW), "invalid_link");
	refuses(link("totp?x=/y?secret=" + JBSW), "invalid_link");             // the type runs to the first "/", wherever it is
	reads(link("totp/x?secret=" + JBSW + "#&secret=other"), key(JBSW));
	refuses(link("totp/x?#secret=" + JBSW), "missing_secret");
	reads(link("totp/x?&&secret=" + JBSW + "&&"), key(JBSW));             // empty items are skipped
	refuses(link("totp/x?secret=" + JBSW + "&issuer"), "invalid_link");   // an item without "="
	reads(link("totp/x?secret=" + JBSW + "&=x"), key(JBSW));              // an empty name is just another parameter
	reads(link("totp/x?secret=" + JBSW + "&issuer=a=b"), key(JBSW));      // the value runs from the first "="
	refuses(link("totp/x?secret=" + JBSW + "&secret=" + JBSW), "invalid_link");
	refuses(link("totp/x?secret=" + JBSW + "&SECRET=" + JBSW), "invalid_link");
	refuses(link("totp/x?secret=" + JBSW + "&issuer=a&Issuer=b"), "invalid_link");   // any parameter twice
	refuses(link("totp/x?digits=6&secret=" + JBSW + "&digits=6"), "invalid_link");
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%"), "invalid_link");            // every value is decoded
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%4"), "invalid_link");
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%G1"), "invalid_link");
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%C3%28"), "invalid_link");       // not UTF-8
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%ED%A0%80"), "invalid_link");    // an encoded surrogate
	refuses(link("totp/x?secret=" + JBSW + "&issuer=%FF"), "invalid_link");
	reads(link("totp/x?secret=" + JBSW + "&issuer=%C3%A9%e2%82%ac+x"), key(JBSW));
	reads(link("totp/x?secret=%4a%42SWY3DPEHPK3PXP"), key(JBSW));                     // the secret is decoded, then read by §3.3
	reads(link("totp/x?secret=JBSW%20Y3DP-EHPK%203PXP%3D%3D"), key(JBSW));
	refuses(link("totp/x?secret=JBSW+Y3DPEHPK3PXP"), "invalid_secret");               // "+" stays "+"
	reads(link("totp/x?%73ecret=" + JBSW + "&secret=" + JBSW), key(JBSW));            // names are not decoded
	refuses(link("totp/x?secre%74=" + JBSW), "missing_secret");
});

test("§3.2: secret, algorithm, digits and period, and the order the checks run in", () => {
	const link = (query) => "otpauth://totp/Example?" + query;
	refuses(link("issuer=Example"), "missing_secret");
	refuses(link("secret="), "missing_secret");
	refuses(link("secret=&algorithm=MD5"), "missing_secret");
	refuses(link("secret=%20"), "secret_too_short");                       // not empty after decoding; nothing left after §3.3
	refuses(link("secret=JBSW!"), "invalid_secret");
	refuses(link("secret=AAAA"), "secret_too_short");
	refuses(link("secret=" + "A".repeat(207)), "secret_too_long");
	reads(link("secret=" + JBSW + "&algorithm=SHA1"), key(JBSW));
	reads(link("secret=" + JBSW + "&algorithm=sha256"), key(JBSW, "SHA256"));
	reads(link("secret=" + JBSW + "&ALGORITHM=Sha512"), key(JBSW, "SHA512"));
	for (const bad of ["", "MD5", "SHA-1", "SHA224", "SHA3-256", " SHA1", "SHA1 ", "ſha1"]) {
		refuses(link("secret=" + JBSW + "&algorithm=" + encodeURIComponent(bad)), "unsupported_algorithm");
	}
	reads(link("secret=" + JBSW + "&digits=7"), key(JBSW, "SHA1", 7));
	reads(link("secret=" + JBSW + "&digits=8"), key(JBSW, "SHA1", 8));
	for (const bad of ["", "5", "9", "06", "+6", "-6", "6.0", "６", " 6", "10"]) {
		refuses(link("secret=" + JBSW + "&digits=" + encodeURIComponent(bad)), "unsupported_digits");
	}
	reads(link("secret=" + JBSW + "&period=1"), key(JBSW, "SHA1", 6, 1));
	reads(link("secret=" + JBSW + "&period=60"), key(JBSW, "SHA1", 6, 60));
	reads(link("secret=" + JBSW + "&period=300"), key(JBSW, "SHA1", 6, 300));
	for (const bad of ["", "0", "301", "030", "+30", "-30", "30.0", "3e1", "１", "99999999999999999999", " 30"]) {
		refuses(link("secret=" + JBSW + "&period=" + encodeURIComponent(bad)), "unsupported_period");
	}
	// The first failure in the order of the list is the result.
	refuses(link("secret=" + JBSW + "&algorithm=MD5&digits=5&period=0"), "unsupported_algorithm");
	refuses(link("secret=" + JBSW + "&digits=5&period=0"), "unsupported_digits");
	refuses(link("secret=JBSW!&algorithm=MD5"), "invalid_secret");
	refuses(link("algorithm=MD5&issuer=%ZZ"), "invalid_link");
	refuses(link("secret=" + JBSW + "&period=0&secret=x"), "invalid_link");
	// Everything else is ignored, whatever its value.
	reads(link("secret=" + JBSW + "&issuer=&image=https%3A%2F%2Fx&counter=abc&foo=bar"), key(JBSW));
});

test("a refusal never carries the text, and every result can be used as is", () => {
	const secret = "SECRETSECRETSECRET";
	for (const input of ["otpauth://totp/x?secret=" + secret + "&digits=9", secret + "!", "steam://" + secret, "otpauth://hotp/x?secret=" + secret]) {
		const result = vc.readTotpKey(input);
		assert.ok(!JSON.stringify(result).includes(secret));
		assert.ok(Object.isFrozen(result));
	}
	assert.deepEqual(Object.keys(vc.readTotpKey(JBSW)), ["key", "refusal"]);
});

test("every refusal has its fixed text, and no text has anything of the input in it", () => {
	assert.deepEqual(Object.keys(vc.TOTP_REFUSAL_TEXTS).sort(), [...vc.TOTP_REFUSALS].sort());
	for (const code of vc.TOTP_REFUSALS) { assert.match(vc.TOTP_REFUSAL_TEXTS[code], /^[A-Z].+\.$/); }
	assert.equal(vc.TOTP_REFUSAL_TEXTS.invalid_secret, "The key can hold only the letters A to Z and the digits 2 to 7. Spaces and dashes are ignored.");
});

test("the editor's text for a stored key reads back to exactly that key", () => {
	for (const k of [key(JBSW), key(JBSW, "SHA256"), key(JBSW, "SHA1", 8), key(JBSW, "SHA1", 6, 60), key("A".repeat(205), "SHA512", 7, 300)]) {
		const shown = vc.totpKeyText(k);
		assert.deepEqual({ ...vc.readTotpKey(shown).key }, k);
	}
	assert.equal(vc.totpKeyText(key(JBSW)), JBSW);
	assert.equal(vc.totpKeyText(key(JBSW, "SHA256", 8, 60)), "otpauth://totp/?secret=" + JBSW + "&algorithm=SHA256&digits=8&period=60");
});

// ------------------------------------------- the desktop's shared fixtures
// tests/fixtures/totp is a byte-for-byte copy of the desktop's (docs/TOTP.md §7): what its library
// makes of each text, and each key's code at each time. The web must arrive at the same results.
const fs = require("node:fs");
const path = require("node:path");
const TOTP_FIXTURES = path.join(__dirname, "fixtures", "totp");
const loadFixture = (name) => JSON.parse(fs.readFileSync(path.join(TOTP_FIXTURES, name), "utf8"));
const inputOf = (input) => typeof input === "string" ? input : input.parts.map((p) => p.text.repeat(p.repeat)).join("");

test("keys.json: every case gives the desktop's key, refusal or no key", () => {
	const { schema, cases } = loadFixture("keys.json");
	assert.equal(schema, 1);
	assert.equal(cases.length, 91);
	const seen = new Set();
	for (const c of cases) {
		const result = vc.readTotpKey(inputOf(c.input));
		const got = result.key ? { key: { ...result.key } } : result.refusal ? { refused: result.refusal } : { empty: true };
		assert.deepEqual(got, c.result, c.name);
		if (c.result.refused) { seen.add(c.result.refused); }
		if (c.result.key) { assert.ok(vc.isValidTotpKey(c.result.key), c.name); }
	}
	assert.deepEqual([...seen].sort(), [...vc.TOTP_REFUSALS].sort(), "every refusal code is in the fixtures");
});

test("codes.json: every case gives the desktop's code, display and seconds left", async () => {
	const { schema, cases } = loadFixture("codes.json");
	assert.equal(schema, 1);
	assert.equal(cases.length, 40);
	for (const c of cases) {
		assert.ok(vc.isValidTotpKey(c.key), c.name);
		const result = await vc.totpCode(c.key, c.unixSeconds);
		assert.equal(result.code, c.result.code, c.name);
		assert.equal(result.secondsLeft, c.result.secondsLeft, c.name);
		assert.equal(vc.formatTotpCode(result.code), c.result.display, c.name);
		// And the independent implementation agrees.
		assert.equal(referenceCode(Buffer.from(c.key.secret.length ? decodeForReference(c.key.secret) : []), c.key.algorithm, c.key.digits, c.key.period, c.unixSeconds), c.result.code, c.name);
	}
	// The table of RFC 6238 Appendix B is among them, with the same codes as above.
	for (const [time, sha1, sha256, sha512] of RFC_TABLE) {
		for (const [algorithm, code] of [["SHA1", sha1], ["SHA256", sha256], ["SHA512", sha512]]) {
			assert.ok(cases.some((c) => c.key.algorithm === algorithm && c.unixSeconds === time && c.key.secret === base32(utf8(RFC_SEEDS[algorithm])) && c.result.code === code), `${algorithm} at ${time}`);
		}
	}
});
// base32 to bytes for the reference implementation (bit string, not the code under test).
function decodeForReference(secret) {
	const bits = [...secret].map((ch) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch).toString(2).padStart(5, "0")).join("");
	const out = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) { out.push(parseInt(bits.slice(i, i + 8), 2)); }
	return out;
}
