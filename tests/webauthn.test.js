// Unit tests for vault/public/assets/js/webauthn.js (passkeys), run with Node's test runner against
// the very file the browser loads:
//
//   node --test tests/webauthn.test.js
//
// The browser's own conversion (PublicKeyCredential.parseCreationOptionsFromJSON & co.) is used
// whenever it exists; these tests pin the fallback the page uses without it, against the WebAuthn
// JSON the API really sends (a registration and a sign-in answer of the phase-10 server), and the
// mapping of the browser's errors. tests/e2e.js runs both paths in Chromium against the mock
// server, which verifies the signatures; tests/e2e-live.js runs them against the real API.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const factory = require("../vault/public/assets/js/webauthn.js");

const bytes = (buf) => Buffer.from(new Uint8Array(buf));
const ab = (buf) => { const b = Buffer.from(buf); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };

// The API's answers (POST /v1/account/passkeys/registration/options, POST /v1/auth/passkey/options).
const CREATION = {
	rp: { id: "localhost", name: "BitosX" },
	user: { name: "someone@example.test", id: "-g7lu2B1qptNTnJ0i7oNpZ-S9hVdF0dtR4MWcv2XBsk", displayName: "someone@example.test" },
	challenge: "VpUqGjNKKQNOMfGKp2Q_GXhGKGjQMc0hz3sOUNq_I4Q",
	pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }],
	timeout: 300000,
	attestation: "none",
	attestationFormats: [],
	authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
	hints: [],
	excludeCredentials: [{ type: "public-key", id: "Wu9xtaYf8i56wSABju9cYKvXKDmlnyDg5dn3MJFwIHA", transports: ["internal"] }]
};
const REQUEST = {
	challenge: "0yrhdq1hCxexfucBRORNh9ik582stu5puy27BvbWcbg",
	timeout: 300000,
	rpId: "localhost",
	allowCredentials: [{ type: "public-key", id: "Wu9xtaYf8i56wSABju9cYKvXKDmlnyDg5dn3MJFwIHA" }],
	userVerification: "preferred",
	hints: []
};

// A browser without the JSON helpers (the fallback), with navigator.credentials stubbed.
function fallbackEnv(credentials) {
	function PublicKeyCredential() {}
	return { PublicKeyCredential, credentials: credentials || { create: async () => null, get: async () => null }, isSecureContext: true };
}

test("base64url: round trip for every length, the same text Node writes", () => {
	const w = factory(fallbackEnv());
	for (let n = 0; n <= 70; n++) {
		const b = crypto.randomBytes(n);
		const text = w._encode(b);
		assert.equal(text, b.toString("base64url"), `encode ${n}`);
		assert.deepEqual(bytes(w._decode(text)), b, `decode ${n}`);
		assert.ok(w._decode(text) instanceof ArrayBuffer);
		assert.equal(w._encode(new Uint8Array(ab(b))), text, "views encode the same");
	}
	// A view into a larger buffer encodes only its own bytes.
	const big = new Uint8Array([9, 1, 2, 3, 9]);
	assert.equal(w._encode(big.subarray(1, 4)), Buffer.from([1, 2, 3]).toString("base64url"));
});

test("base64url: anything but the canonical unpadded form is refused", () => {
	const w = factory(fallbackEnv());
	const refused = ["AA==", "A", "AAAAA", "+/8", "ab cd", "AB", "AAB", "AAAB=", "é", null, 12];
	for (const t of refused) {
		assert.throws(() => w._decode(t), (e) => e instanceof w.WebAuthnError && e.kind === w.KINDS.INVALID, JSON.stringify(t));
	}
	assert.deepEqual(bytes(w._decode("")), Buffer.alloc(0));
	assert.deepEqual(bytes(w._decode("AA")), Buffer.from([0]));
	assert.deepEqual(bytes(w._decode("_-8")), Buffer.from([0xff, 0xef]));
});

test("creation options (fallback): the binary members become bytes, the rest is kept; extensions are not passed on", () => {
	const w = factory(fallbackEnv());
	const o = w.parseCreationOptions(Object.assign({ extensions: { credProps: true } }, CREATION));
	assert.deepEqual(bytes(o.challenge), Buffer.from(CREATION.challenge, "base64url"));
	assert.deepEqual(bytes(o.user.id), Buffer.from(CREATION.user.id, "base64url"));
	assert.equal(o.user.id.byteLength, 32, "the server's 32-byte user handle");
	assert.equal(o.user.name, CREATION.user.name);
	assert.equal(o.user.displayName, CREATION.user.displayName);
	assert.deepEqual(o.rp, CREATION.rp);
	assert.deepEqual(o.pubKeyCredParams, CREATION.pubKeyCredParams);
	assert.deepEqual(o.authenticatorSelection, CREATION.authenticatorSelection);
	assert.equal(o.timeout, 300000);
	assert.equal(o.attestation, "none");
	assert.deepEqual(o.hints, []);
	assert.equal(o.excludeCredentials.length, 1);
	assert.deepEqual(bytes(o.excludeCredentials[0].id), Buffer.from(CREATION.excludeCredentials[0].id, "base64url"));
	assert.deepEqual(o.excludeCredentials[0].transports, ["internal"]);
	assert.equal(o.extensions, undefined);
	// The JSON object is not changed.
	assert.equal(typeof CREATION.challenge, "string");
});

test("creation options (fallback): malformed answers are refused before the browser sees them", () => {
	const w = factory(fallbackEnv());
	const bad = [
		null, [], "x", {},
		Object.assign({}, CREATION, { challenge: "not base64url!" }),
		Object.assign({}, CREATION, { user: Object.assign({}, CREATION.user, { id: "A" }) }),
		Object.assign({}, CREATION, { user: { id: CREATION.user.id } }),
		Object.assign({}, CREATION, { rp: null }),
		Object.assign({}, CREATION, { pubKeyCredParams: "es256" }),
		Object.assign({}, CREATION, { excludeCredentials: [{ type: "public-key", id: "A==" }] }),
		Object.assign({}, CREATION, { excludeCredentials: [{ type: "public-key", id: CREATION.challenge, transports: "usb" }] }),
		Object.assign({}, CREATION, { excludeCredentials: {} })
	];
	for (const b of bad) {
		assert.throws(() => w.parseCreationOptions(b), (e) => e.kind === w.KINDS.INVALID, JSON.stringify(b));
	}
});

test("request options (fallback): challenge and allowCredentials become bytes", () => {
	const w = factory(fallbackEnv());
	const o = w.parseRequestOptions(REQUEST);
	assert.deepEqual(bytes(o.challenge), Buffer.from(REQUEST.challenge, "base64url"));
	assert.equal(o.rpId, "localhost");
	assert.equal(o.userVerification, "preferred");
	assert.equal(o.timeout, 300000);
	assert.deepEqual(bytes(o.allowCredentials[0].id), Buffer.from(REQUEST.allowCredentials[0].id, "base64url"));
	assert.equal(o.allowCredentials[0].transports, undefined);
	// Sign-in without email and password: an empty list stays empty.
	const d = w.parseRequestOptions(Object.assign({}, REQUEST, { allowCredentials: [], userVerification: "required" }));
	assert.deepEqual(d.allowCredentials, []);
	assert.throws(() => w.parseRequestOptions(Object.assign({}, REQUEST, { challenge: 5 })), (e) => e.kind === w.KINDS.INVALID);
});

test("options: the browser's own parser is used when it exists, and its errors are 'invalid'", () => {
	const seen = [];
	const env = fallbackEnv();
	env.PublicKeyCredential.parseCreationOptionsFromJSON = (j) => { seen.push(["create", j]); return { native: true }; };
	env.PublicKeyCredential.parseRequestOptionsFromJSON = () => { throw new TypeError("bad"); };
	const w = factory(env);
	assert.deepEqual(w.parseCreationOptions(CREATION), { native: true });
	assert.equal(seen[0][1], CREATION);
	assert.throws(() => w.parseRequestOptions(REQUEST), (e) => e.kind === w.KINDS.INVALID);
});

// Credentials as the browser hands them over: ArrayBuffers and getters, no toJSON().
function fakeRegistration() {
	const raw = crypto.randomBytes(32);
	return {
		raw,
		cred: {
			id: raw.toString("base64url"), rawId: ab(raw), type: "public-key", authenticatorAttachment: "platform",
			getClientExtensionResults: () => ({ credProps: { rk: true }, other: { blob: new Uint8Array([1, 2, 3]) } }),
			response: {
				clientDataJSON: ab(Buffer.from('{"type":"webauthn.create"}')),
				attestationObject: ab(Buffer.from([0xa3, 1, 2])),
				getTransports: () => ["internal", "hybrid"],
				getAuthenticatorData: () => ab(Buffer.from([4, 5, 6])),
				getPublicKey: () => ab(Buffer.from([7, 8])),
				getPublicKeyAlgorithm: () => -7
			}
		}
	};
}

test("registration credential (fallback): exactly the members and encoding of toJSON()", () => {
	const w = factory(fallbackEnv());
	const { raw, cred } = fakeRegistration();
	assert.deepEqual(w.credentialToJSON(cred), {
		id: raw.toString("base64url"),
		rawId: raw.toString("base64url"),
		type: "public-key",
		authenticatorAttachment: "platform",
		clientExtensionResults: { credProps: { rk: true }, other: { blob: "AQID" } },
		response: {
			clientDataJSON: Buffer.from('{"type":"webauthn.create"}').toString("base64url"),
			attestationObject: "owEC",
			transports: ["internal", "hybrid"],
			authenticatorData: "BAUG",
			publicKey: "Bwg",
			publicKeyAlgorithm: -7
		}
	});
	// An algorithm the browser cannot export (getPublicKey() is null): the member is left out.
	cred.response.getPublicKey = () => null;
	assert.equal("publicKey" in w.credentialToJSON(cred).response, false);
});

test("assertion credential (fallback): signature and user handle; a null user handle is left out", () => {
	const w = factory(fallbackEnv());
	const raw = crypto.randomBytes(16);
	const cred = {
		id: raw.toString("base64url"), rawId: ab(raw), type: "public-key", authenticatorAttachment: null,
		getClientExtensionResults: () => ({}),
		response: { clientDataJSON: ab(Buffer.from("{}")), authenticatorData: ab(Buffer.from([1])), signature: ab(Buffer.from([2, 3])), userHandle: ab(Buffer.from([4])) }
	};
	assert.deepEqual(w.credentialToJSON(cred), {
		id: raw.toString("base64url"), rawId: raw.toString("base64url"), type: "public-key", clientExtensionResults: {},
		response: { clientDataJSON: "e30", authenticatorData: "AQ", signature: "AgM", userHandle: "BA" }
	});
	cred.response.userHandle = null;
	assert.equal("userHandle" in w.credentialToJSON(cred).response, false);
	// The browser's toJSON() wins when it exists.
	cred.toJSON = () => ({ native: true });
	assert.deepEqual(w.credentialToJSON(cred), { native: true });
});

test("ceremonies: the request reaches navigator.credentials with the signal; the browser's errors are named", async () => {
	const calls = [];
	let fail = null;
	const { cred } = fakeRegistration();
	const env = fallbackEnv({
		create: async (req) => { calls.push(["create", req]); if (fail) { throw fail; } return cred; },
		get: async (req) => { calls.push(["get", req]); if (fail) { throw fail; } return cred; }
	});
	const w = factory(env);
	const controller = new AbortController();
	const json = await w.create(CREATION, controller.signal);
	assert.equal(json.id, cred.id);
	assert.equal(calls[0][1].signal, controller.signal);
	assert.equal(calls[0][1].publicKey.challenge.byteLength, 32);
	await w.get(REQUEST);
	assert.deepEqual(Object.keys(calls[1][1]), ["publicKey"], "no signal, no mediation: the browser's default");

	const expect = { NotAllowedError: "cancelled", InvalidStateError: "exists", SecurityError: "security", AbortError: "aborted", NotSupportedError: "invalid", UnknownError: "failed" };
	for (const [name, kind] of Object.entries(expect)) {
		fail = new DOMException("x", name);
		await assert.rejects(w.create(CREATION), (e) => e instanceof w.WebAuthnError && e.kind === kind, name);
		await assert.rejects(w.get(REQUEST), (e) => e.kind === kind, name);
	}
	fail = null;
	// The page cancelled: whatever the browser answers, it is "aborted".
	const c2 = new AbortController();
	c2.abort();
	await assert.rejects(w.get(REQUEST, c2.signal), (e) => e.kind === "aborted");
	// No credential at all, or malformed options: nothing is sent to the server.
	const nothing = factory(fallbackEnv({ create: async () => null, get: async () => null }));
	await assert.rejects(nothing.get(REQUEST), (e) => e.kind === "failed");
	await assert.rejects(w.create({ challenge: "AA" }), (e) => e.kind === "invalid");
});

test("feature detection: no PublicKeyCredential, no navigator.credentials, or not a secure context -> unsupported", async () => {
	const none = factory({});
	assert.equal(none.supported(), false);
	await assert.rejects(none.get(REQUEST), (e) => e.kind === "unsupported");
	assert.equal(factory(Object.assign(fallbackEnv(), { credentials: undefined })).supported(), false);
	assert.equal(factory(Object.assign(fallbackEnv(), { isSecureContext: false })).supported(), false);
	assert.equal(factory(fallbackEnv()).supported(), true);
});
