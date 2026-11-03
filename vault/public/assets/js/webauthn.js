// Passkeys (WebAuthn) in the browser: the server's options in, the browser's credential out.
//
// The API sends the standard WebAuthn JSON (PublicKeyCredentialCreationOptionsJSON /
// PublicKeyCredentialRequestOptionsJSON: binary members are unpadded base64url strings) and takes
// back what PublicKeyCredential.toJSON() returns. Where the browser has
// PublicKeyCredential.parseCreationOptionsFromJSON / parseRequestOptionsFromJSON and
// credential.toJSON(), those are used; otherwise this file converts the members itself (the same
// members, the same encoding). Extensions are not converted by the fallback: the server asks for
// none, and an unknown one is dropped rather than passed on half-converted.
//
// Nothing here is secret: a passkey's private key never leaves the authenticator, and the
// challenge and credential are single-use on the server. Nothing touches the DOM or the network.
// Works as a browser global (window.bitosxWebAuthn) and as a Node module (module.exports is the
// factory, given an environment), so the unit tests run the exact code the page runs.
(function (root, factory) {
	"use strict";
	if (typeof module === "object" && module.exports) { module.exports = factory; }
	else {
		root.bitosxWebAuthn = factory({
			PublicKeyCredential: root.PublicKeyCredential,
			credentials: root.navigator && root.navigator.credentials,
			isSecureContext: root.isSecureContext
		});
	}
})(typeof self !== "undefined" ? self : this, function (env) {
	"use strict";

	env = env || {};
	var PKC = env.PublicKeyCredential;

	function WebAuthnError(kind) {
		this.name = "WebAuthnError";
		this.kind = kind;
		this.message = kind;
	}
	WebAuthnError.prototype = Object.create(Error.prototype);
	WebAuthnError.prototype.constructor = WebAuthnError;

	var KINDS = Object.freeze({
		UNSUPPORTED: "unsupported", // no WebAuthn in this browser (or not a secure context)
		CANCELLED: "cancelled",     // NotAllowedError: the person said no, it timed out, or no passkey fits
		EXISTS: "exists",           // InvalidStateError on create: this authenticator already holds one of the account's passkeys
		SECURITY: "security",       // SecurityError: the RP ID does not fit this page's origin
		ABORTED: "aborted",         // the page cancelled the ceremony itself
		INVALID: "invalid",         // the server's options could not be read
		FAILED: "failed"            // anything else
	});

	function supported() {
		return !!(PKC && env.credentials && typeof env.credentials.create === "function" &&
			typeof env.credentials.get === "function" && env.isSecureContext !== false);
	}

	// ---- base64url (RFC 4648 §5, unpadded, as WebAuthn JSON uses it) ----
	var B64URL_RE = /^[A-Za-z0-9_-]*$/;
	var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	function toBytes(buf) {
		if (buf instanceof ArrayBuffer) { return new Uint8Array(buf); }
		if (ArrayBuffer.isView(buf)) { return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }
		throw new WebAuthnError(KINDS.INVALID);
	}

	function encode(buf) {
		var b = toBytes(buf);
		var out = "";
		var i = 0;
		for (; i + 2 < b.length; i += 3) {
			var n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
			out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63] + ALPHABET[(n >>> 6) & 63] + ALPHABET[n & 63];
		}
		if (b.length - i === 1) {
			var m = b[i] << 16;
			out += ALPHABET[m >>> 18] + ALPHABET[(m >>> 12) & 63];
		} else if (b.length - i === 2) {
			var k = (b[i] << 16) | (b[i + 1] << 8);
			out += ALPHABET[k >>> 18] + ALPHABET[(k >>> 12) & 63] + ALPHABET[(k >>> 6) & 63];
		}
		return out;
	}

	// Strict: only the base64url alphabet, no padding, no length that cannot occur, and no
	// non-zero bits left over in the last character (one encoding per byte string).
	function decode(text) {
		if (typeof text !== "string" || !B64URL_RE.test(text) || text.length % 4 === 1) { throw new WebAuthnError(KINDS.INVALID); }
		var out = new Uint8Array(Math.floor(text.length * 3 / 4));
		var o = 0, bits = 0, value = 0;
		for (var i = 0; i < text.length; i++) {
			value = (value << 6) | ALPHABET.indexOf(text[i]);
			bits += 6;
			if (bits >= 8) {
				bits -= 8;
				out[o++] = (value >>> bits) & 255;
			}
			value &= (1 << bits) - 1;
		}
		if (value !== 0) { throw new WebAuthnError(KINDS.INVALID); }
		return out.buffer;
	}

	// ---- options: JSON -> what navigator.credentials wants ----
	function isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
	function copyKnown(src, dst, keys) {
		keys.forEach(function (k) { if (src[k] !== undefined) { dst[k] = src[k]; } });
		return dst;
	}
	function descriptors(list) {
		if (list === undefined) { return undefined; }
		if (!Array.isArray(list)) { throw new WebAuthnError(KINDS.INVALID); }
		return list.map(function (d) {
			if (!isObject(d) || typeof d.type !== "string") { throw new WebAuthnError(KINDS.INVALID); }
			var out = { type: d.type, id: decode(d.id) };
			if (d.transports !== undefined) {
				if (!Array.isArray(d.transports) || !d.transports.every(function (t) { return typeof t === "string"; })) { throw new WebAuthnError(KINDS.INVALID); }
				out.transports = d.transports.slice();
			}
			return out;
		});
	}

	function creationOptionsFallback(json) {
		if (!isObject(json.rp) || !isObject(json.user) || typeof json.user.name !== "string" || typeof json.user.displayName !== "string" ||
			!Array.isArray(json.pubKeyCredParams)) {
			throw new WebAuthnError(KINDS.INVALID);
		}
		var out = copyKnown(json, {}, ["timeout", "authenticatorSelection", "hints", "attestation", "attestationFormats"]);
		out.rp = copyKnown(json.rp, {}, ["id", "name"]);
		out.user = { id: decode(json.user.id), name: json.user.name, displayName: json.user.displayName };
		out.challenge = decode(json.challenge);
		out.pubKeyCredParams = json.pubKeyCredParams.map(function (p) {
			if (!isObject(p)) { throw new WebAuthnError(KINDS.INVALID); }
			return { type: p.type, alg: p.alg };
		});
		var exclude = descriptors(json.excludeCredentials);
		if (exclude) { out.excludeCredentials = exclude; }
		return out;
	}

	function requestOptionsFallback(json) {
		var out = copyKnown(json, {}, ["timeout", "rpId", "userVerification", "hints"]);
		out.challenge = decode(json.challenge);
		var allow = descriptors(json.allowCredentials);
		if (allow) { out.allowCredentials = allow; }
		return out;
	}

	function parseWith(nativeName, fallback, json) {
		if (!isObject(json) || typeof json.challenge !== "string") { throw new WebAuthnError(KINDS.INVALID); }
		if (PKC && typeof PKC[nativeName] === "function") {
			try { return PKC[nativeName](json); }
			catch (e) { throw new WebAuthnError(KINDS.INVALID); }
		}
		return fallback(json);
	}
	function parseCreationOptions(json) { return parseWith("parseCreationOptionsFromJSON", creationOptionsFallback, json); }
	function parseRequestOptions(json) { return parseWith("parseRequestOptionsFromJSON", requestOptionsFallback, json); }

	// ---- the credential -> JSON for the server ----
	// Client extension outputs: binary values become base64url, as toJSON() does.
	function extensionsJSON(v, depth) {
		if (depth > 8) { throw new WebAuthnError(KINDS.FAILED); }
		if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) { return encode(v); }
		if (Array.isArray(v)) { return v.map(function (x) { return extensionsJSON(x, depth + 1); }); }
		if (isObject(v)) {
			var out = {};
			Object.keys(v).forEach(function (k) { out[k] = extensionsJSON(v[k], depth + 1); });
			return out;
		}
		return v;
	}

	function credentialJSONFallback(cred) {
		var r = cred.response;
		var out = {
			id: cred.id,
			rawId: encode(cred.rawId),
			type: cred.type,
			clientExtensionResults: extensionsJSON(typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {}, 0),
			response: { clientDataJSON: encode(r.clientDataJSON) }
		};
		if (typeof cred.authenticatorAttachment === "string") { out.authenticatorAttachment = cred.authenticatorAttachment; }
		if (r.attestationObject !== undefined) {
			// AuthenticatorAttestationResponse (registration)
			out.response.attestationObject = encode(r.attestationObject);
			out.response.transports = typeof r.getTransports === "function" ? r.getTransports().slice() : [];
			if (typeof r.getAuthenticatorData === "function") { out.response.authenticatorData = encode(r.getAuthenticatorData()); }
			if (typeof r.getPublicKey === "function") {
				var key = r.getPublicKey();
				if (key) { out.response.publicKey = encode(key); }
			}
			if (typeof r.getPublicKeyAlgorithm === "function") { out.response.publicKeyAlgorithm = r.getPublicKeyAlgorithm(); }
		} else {
			// AuthenticatorAssertionResponse (sign-in)
			out.response.authenticatorData = encode(r.authenticatorData);
			out.response.signature = encode(r.signature);
			if (r.userHandle) { out.response.userHandle = encode(r.userHandle); }
		}
		return out;
	}

	function credentialToJSON(cred) {
		if (!cred || typeof cred !== "object" || !cred.response) { throw new WebAuthnError(KINDS.FAILED); }
		if (typeof cred.toJSON === "function") { return cred.toJSON(); }
		return credentialJSONFallback(cred);
	}

	// ---- the two ceremonies ----
	function classify(err) {
		if (err instanceof WebAuthnError) { return err; }
		var name = err && err.name;
		if (name === "NotAllowedError") { return new WebAuthnError(KINDS.CANCELLED); }
		if (name === "InvalidStateError") { return new WebAuthnError(KINDS.EXISTS); }
		if (name === "SecurityError") { return new WebAuthnError(KINDS.SECURITY); }
		if (name === "AbortError") { return new WebAuthnError(KINDS.ABORTED); }
		if (name === "TypeError" || name === "NotSupportedError") { return new WebAuthnError(KINDS.INVALID); }
		return new WebAuthnError(KINDS.FAILED);
	}

	function ceremony(method, parse, optionsJSON, signal) {
		if (!supported()) { return Promise.reject(new WebAuthnError(KINDS.UNSUPPORTED)); }
		var publicKey;
		try { publicKey = parse(optionsJSON); } catch (e) { return Promise.reject(classify(e)); }
		var request = { publicKey: publicKey };
		if (signal) { request.signal = signal; }
		var pending;
		try { pending = env.credentials[method](request); } catch (e) { return Promise.reject(classify(e)); }
		return Promise.resolve(pending).then(function (cred) {
			if (signal && signal.aborted) { throw new WebAuthnError(KINDS.ABORTED); }
			return credentialToJSON(cred);
		}).catch(function (e) {
			if (signal && signal.aborted) { throw new WebAuthnError(KINDS.ABORTED); }
			throw classify(e);
		});
	}

	// Registration: resolves to the new credential as JSON.
	function create(optionsJSON, signal) { return ceremony("create", parseCreationOptions, optionsJSON, signal); }
	// Sign-in (second step or discoverable): resolves to the assertion as JSON.
	function get(optionsJSON, signal) { return ceremony("get", parseRequestOptions, optionsJSON, signal); }

	return Object.freeze({
		WebAuthnError: WebAuthnError,
		KINDS: KINDS,
		supported: supported,
		create: create,
		get: get,
		parseCreationOptions: parseCreationOptions,
		parseRequestOptions: parseRequestOptions,
		credentialToJSON: credentialToJSON,
		_encode: encode,
		_decode: decode
	});
});
