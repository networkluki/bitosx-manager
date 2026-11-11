// Opening a BitosX vault in the browser: the same construction as the desktop app
// (BitosX.Crypto.VaultCryptor, EncryptedVaultSerializer, MasterPasswordEncoding,
// VaultSerializer), so that an envelope the desktop wrote opens here with the same master
// password, and nothing else does.
//
//   master password --Argon2id(salt, m, t, p)--> KEK
//   KEK --AES-256-GCM(keyWrapNonce, AAD = key-wrap header)--> vault key
//   vault key --AES-256-GCM(contentNonce, AAD = content header)--> plaintext JSON
//
// Pure functions over bytes; nothing here touches the DOM or the network. Works as a browser
// global (window.bitosxVaultCrypto, given window.hashwasm and window.crypto) and as a Node module
// (module.exports is the factory), so the unit tests run the exact code the page runs.
(function (root, factory) {
	"use strict";
	if (typeof module === "object" && module.exports) { module.exports = factory; }
	else { root.bitosxVaultCrypto = factory(root.hashwasm, root.crypto); }
})(typeof self !== "undefined" ? self : this, function (hashwasm, webcrypto) {
	"use strict";

	// Format version 1 constants (BitosX.Crypto.CryptoConstants).
	var FORMAT_VERSION = 1;
	var KDF_ARGON2ID = "argon2id";
	var ALGORITHM = "AES-256-GCM";
	var SALT_BYTES = 16, NONCE_BYTES = 12, KEY_BYTES = 32, TAG_BYTES = 16;
	var MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;   // FileLocalVaultStorage.MaxFileSizeBytes
	var MIN_MEMORY_KIB = 8, MAX_MEMORY_KIB = 1024 * 1024, MAX_ITERATIONS = 64, MAX_PARALLELISM = 64; // Argon2Parameters.Validate
	var MAX_ITEMS = 10000;

	var ENVELOPE_KEYS = ["version", "kdf", "kdfParameters", "salt", "algorithm", "keyWrapNonce", "encryptedVaultKey", "contentNonce", "ciphertext"];
	var KDF_KEYS = ["memoryKiB", "iterations", "parallelism", "keyLengthBytes"];
	var ITEM_KEYS = ["type", "Id", "Name", "Notes", "Favorite", "CreatedAt", "UpdatedAt", "Username", "Password", "Urls"];
	var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

	var KINDS = Object.freeze({
		FORMAT: "format",     // not a vault envelope this version can read (fails before any key work)
		AUTH: "auth",         // wrong master password, or the envelope was changed (indistinguishable)
		CONTENT: "content",   // decrypted, but the content is not a vault this version understands
		RESOURCE: "resource"  // the key derivation could not get the memory it asks for
	});

	function VaultError(kind, message) {
		this.name = "VaultError";
		this.kind = kind;
		this.message = message;
	}
	VaultError.prototype = Object.create(Error.prototype);
	VaultError.prototype.constructor = VaultError;

	var encoder = new TextEncoder();
	function utf8(text) { return encoder.encode(text); }
	function decodeUtf8Strict(bytes) {
		// Invalid sequences are rejected, never replaced; a leading byte order mark is accepted.
		var view = bytes;
		if (view.length >= 3 && view[0] === 0xEF && view[1] === 0xBB && view[2] === 0xBF) { view = view.subarray(3); }
		return new TextDecoder("utf-8", { fatal: true }).decode(view);
	}

	function isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
	function hasExactKeys(obj, keys) {
		var own = Object.keys(obj);
		if (own.length !== keys.length) { return false; }
		return keys.every(function (k) { return Object.prototype.hasOwnProperty.call(obj, k); });
	}
	function isInt(v) { return typeof v === "number" && Number.isInteger(v); }

	// Strict Base64 (RFC 4648 §4, padded): only the alphabet, and "=" or "==" at the very end where the
	// length asks for it. Written as a loop: a pattern with a repeated group overflows the engine's
	// stack on a string of several million characters, which a vault of a few MiB already is.
	function isBase64(text) {
		var length = text.length;
		if (length === 0 || length % 4 !== 0) { return false; }
		var end = length;
		if (text.charCodeAt(end - 1) === 0x3D) { end--; }
		if (text.charCodeAt(end - 1) === 0x3D) { end--; }
		for (var i = 0; i < end; i++) {
			var c = text.charCodeAt(i);
			if (!((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c === 0x2B || c === 0x2F)) { return false; }
		}
		return true;
	}
	function base64ToBytes(text, field) {
		if (typeof text !== "string" || !isBase64(text)) {
			throw new VaultError(KINDS.FORMAT, "The vault field '" + field + "' is not valid base64.");
		}
		var binary = atob(text);
		var out = new Uint8Array(binary.length);
		for (var i = 0; i < binary.length; i++) { out[i] = binary.charCodeAt(i); }
		return out;
	}
	function bytesToBase64(bytes) {
		var s = "";
		for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
		return btoa(s);
	}
	function bytesToHex(bytes) {
		var s = "";
		for (var i = 0; i < bytes.length; i++) { s += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16); }
		return s;
	}
	function bytesEqual(a, b) {
		if (a.length !== b.length) { return false; }
		var d = 0;
		for (var i = 0; i < a.length; i++) { d |= a[i] ^ b[i]; }
		return d === 0;
	}

	// ---- the envelope (EncryptedVaultSerializer.Deserialize, fail closed) ----
	function parseEnvelope(bytes) {
		if (!(bytes instanceof Uint8Array)) { throw new VaultError(KINDS.FORMAT, "The vault must be given as bytes."); }
		if (bytes.length === 0 || bytes.length > MAX_ENVELOPE_BYTES) { throw new VaultError(KINDS.FORMAT, "The vault file is empty or too large."); }

		var doc;
		try { doc = JSON.parse(decodeUtf8Strict(bytes)); }
		catch (e) { throw new VaultError(KINDS.FORMAT, "The vault file is not valid JSON."); }

		// Every field is security relevant; nothing this version does not understand belongs in it.
		// (JSON.parse keeps the last of duplicate keys where the desktop rejects duplicates; a duplicate
		// that changed a bound field changes the AAD or the KDF input and fails authentication below.)
		if (!isPlainObject(doc) || !hasExactKeys(doc, ENVELOPE_KEYS)) { throw new VaultError(KINDS.FORMAT, "The vault file does not have the fields of a BitosX vault."); }
		if (doc.version !== FORMAT_VERSION) { throw new VaultError(KINDS.FORMAT, "Unsupported vault format version."); }
		if (doc.kdf !== KDF_ARGON2ID) { throw new VaultError(KINDS.FORMAT, "Unsupported key-derivation function."); }
		if (doc.algorithm !== ALGORITHM) { throw new VaultError(KINDS.FORMAT, "Unsupported encryption algorithm."); }

		var p = doc.kdfParameters;
		if (!isPlainObject(p) || !hasExactKeys(p, KDF_KEYS) || !KDF_KEYS.every(function (k) { return isInt(p[k]); })) {
			throw new VaultError(KINDS.FORMAT, "The vault field 'kdfParameters' is invalid.");
		}
		// Attacker-controlled on a tampered file, and Argon2 runs before anything is authenticated:
		// floors and ceilings, exactly as the desktop enforces them.
		if (p.keyLengthBytes !== KEY_BYTES
			|| p.iterations < 1 || p.iterations > MAX_ITERATIONS
			|| p.parallelism < 1 || p.parallelism > MAX_PARALLELISM
			|| p.memoryKiB < MIN_MEMORY_KIB || p.memoryKiB > MAX_MEMORY_KIB || p.memoryKiB < 8 * p.parallelism) {
			throw new VaultError(KINDS.FORMAT, "The vault's key-derivation parameters are outside the supported range.");
		}

		var salt = base64ToBytes(doc.salt, "salt");
		var keyWrapNonce = base64ToBytes(doc.keyWrapNonce, "keyWrapNonce");
		var encryptedVaultKey = base64ToBytes(doc.encryptedVaultKey, "encryptedVaultKey");
		var contentNonce = base64ToBytes(doc.contentNonce, "contentNonce");
		var ciphertext = base64ToBytes(doc.ciphertext, "ciphertext");
		if (salt.length !== SALT_BYTES || keyWrapNonce.length !== NONCE_BYTES || contentNonce.length !== NONCE_BYTES
			|| encryptedVaultKey.length !== KEY_BYTES + TAG_BYTES || ciphertext.length < TAG_BYTES) {
			throw new VaultError(KINDS.FORMAT, "A field of the vault has the wrong length.");
		}

		return Object.freeze({
			version: doc.version,
			kdf: doc.kdf,
			kdfParameters: Object.freeze({ memoryKiB: p.memoryKiB, iterations: p.iterations, parallelism: p.parallelism, keyLengthBytes: p.keyLengthBytes }),
			salt: salt,
			algorithm: doc.algorithm,
			keyWrapNonce: keyWrapNonce,
			encryptedVaultKey: encryptedVaultKey,
			contentNonce: contentNonce,
			ciphertext: ciphertext
		});
	}

	// ---- associated data (VaultCryptor.BuildKeyWrapAad / BuildContentAad), byte for byte ----
	function keyWrapAad(envelope) {
		var p = envelope.kdfParameters;
		return utf8("BitosX|kek|v" + envelope.version + "|" + KDF_ARGON2ID + "|m=" + p.memoryKiB + "|t=" + p.iterations
			+ "|p=" + p.parallelism + "|klen=" + p.keyLengthBytes + "|salt=" + bytesToBase64(envelope.salt));
	}
	function contentAad(version) {
		return utf8("BitosX|content|v" + version + "|" + ALGORITHM);
	}

	// ---- the password as bytes (MasterPasswordEncoding.EncodeCandidates) ----
	// Canonical: every space separator (Zs) becomes U+0020, then NFC, then UTF-8. Vaults from before
	// desktop 0.6.0 were keyed with the password as typed, so those encodings are tried after it.
	function passwordCandidates(typed) {
		if (typeof typed !== "string" || typed.length === 0) { return { encodings: [], firstIsCanonical: false }; }
		var wellFormed = typeof typed.isWellFormed === "function" ? typed.isWellFormed() : true;
		var encodings = [];
		function add(bytes) {
			for (var i = 0; i < encodings.length; i++) { if (bytesEqual(encodings[i], bytes)) { return; } }
			encodings.push(bytes);
		}
		if (wellFormed) { add(utf8(typed.replace(/\p{Zs}/gu, " ").normalize("NFC"))); }
		add(utf8(typed));
		if (wellFormed) {
			add(utf8(typed.normalize("NFC")));
			add(utf8(typed.normalize("NFD")));
		}
		return { encodings: encodings, firstIsCanonical: wellFormed };
	}

	// ---- key derivation (Argon2id, the vendored hash-wasm build) ----
	function deriveKek(passwordBytes, envelope) {
		if (!hashwasm || typeof hashwasm.argon2id !== "function") {
			return Promise.reject(new VaultError(KINDS.RESOURCE, "The key-derivation module did not load."));
		}
		var p = envelope.kdfParameters;
		return hashwasm.argon2id({
			password: passwordBytes,
			salt: envelope.salt,
			parallelism: p.parallelism,
			iterations: p.iterations,
			memorySize: p.memoryKiB,
			hashLength: p.keyLengthBytes,
			outputType: "binary"
		}).catch(function () {
			// Parameters are within bounds, so this is the browser, not the file: usually memory.
			throw new VaultError(KINDS.RESOURCE, "The browser could not provide the memory this vault's key derivation needs.");
		});
	}

	// ---- AES-256-GCM (WebCrypto); the layout is ciphertext || tag, as the desktop writes it ----
	function aesGcmDecrypt(keyBytes, nonce, ciphertextWithTag, aad) {
		return webcrypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"])
			.then(function (key) {
				return webcrypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: TAG_BYTES * 8 }, key, ciphertextWithTag);
			})
			.then(function (plain) { return new Uint8Array(plain); })
			.catch(function () { throw new VaultError(KINDS.AUTH, "The master password is incorrect, or the vault was modified."); });
	}

	// Unlocks an envelope with the password as typed. Resolves to { plaintext: Uint8Array,
	// usedCanonical: boolean }. Rejects with a VaultError: AUTH for a wrong password or a changed
	// envelope (every candidate encoding was refused), RESOURCE when the key derivation cannot run.
	function unlock(envelope, typedPassword) {
		var candidates = passwordCandidates(typedPassword);
		if (candidates.encodings.length === 0) {
			return Promise.reject(new VaultError(KINDS.AUTH, "The master password is incorrect, or the vault was modified."));
		}
		var wrapAad = keyWrapAad(envelope);
		var dataAad = contentAad(envelope.version);

		function attempt(i) {
			var kek = null, vaultKey = null;
			return deriveKek(candidates.encodings[i], envelope)
				.then(function (derived) {
					kek = derived;
					return aesGcmDecrypt(kek, envelope.keyWrapNonce, envelope.encryptedVaultKey, wrapAad);
				})
				.then(function (unwrapped) {
					vaultKey = unwrapped;
					return aesGcmDecrypt(vaultKey, envelope.contentNonce, envelope.ciphertext, dataAad);
				})
				.then(function (plaintext) {
					// The vault key is handed to the caller (who wipes it on lock); the KEK is not.
					var key = vaultKey;
					vaultKey = null;
					return { plaintext: plaintext, vaultKey: key, usedCanonical: i === 0 && candidates.firstIsCanonical };
				})
				.catch(function (err) {
					// Not this encoding; the vault may have been keyed with an earlier one. The last
					// refusal is what the caller sees — exactly as for a wrong password.
					if (err instanceof VaultError && err.kind === KINDS.AUTH && i < candidates.encodings.length - 1) { return attempt(i + 1); }
					throw err;
				})
				.finally(function () {
					if (kek) { kek.fill(0); }
					if (vaultKey) { vaultKey.fill(0); }
				});
		}
		return attempt(0).finally(function () {
			candidates.encodings.forEach(function (b) { b.fill(0); });
		});
	}

	// ---- the decrypted document (VaultSerializer + VaultValidation, read-only) ----
	function parseDate(v, field) {
		if (typeof v !== "string" || v.length > 64) { throw new VaultError(KINDS.CONTENT, "The vault contains an invalid item (" + field + ")."); }
		var t = new Date(v).getTime();
		if (!Number.isFinite(t)) { throw new VaultError(KINDS.CONTENT, "The vault contains an invalid item (" + field + ")."); }
		return new Date(t);
	}
	// The desktop writes DateTimeOffset with up to seven fractional digits; a JavaScript Date keeps
	// three. The text as read is kept so that an item nobody changed is written back exactly as it
	// was, not rounded to the millisecond.
	var DATE_TEXT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/;
	function dateText(v) { return typeof v === "string" && DATE_TEXT_RE.test(v) ? v : null; }
	function optionalString(v, field, max) {
		if (v === undefined || v === null) { return null; }
		if (typeof v !== "string" || v.length > max) { throw new VaultError(KINDS.CONTENT, "The vault contains an invalid item (" + field + ")."); }
		return v;
	}

	function parseVault(plaintext) {
		var doc;
		try { doc = JSON.parse(decodeUtf8Strict(plaintext)); }
		catch (e) { throw new VaultError(KINDS.CONTENT, "The decrypted vault content is not valid JSON."); }
		if (!isPlainObject(doc) || !Object.keys(doc).every(function (k) { return k === "schemaVersion" || k === "items"; })) {
			throw new VaultError(KINDS.CONTENT, "The decrypted vault content is not a vault.");
		}
		if (doc.schemaVersion !== 1) { throw new VaultError(KINDS.CONTENT, "Unsupported vault schema version."); }
		var rawItems = doc.items === undefined || doc.items === null ? [] : doc.items;
		if (!Array.isArray(rawItems) || rawItems.length > MAX_ITEMS) { throw new VaultError(KINDS.CONTENT, "The vault's item list is invalid."); }

		var seen = Object.create(null);
		var items = rawItems.map(function (raw) {
			if (!isPlainObject(raw)) { throw new VaultError(KINDS.CONTENT, "The vault contains an empty item entry."); }
			if (!Object.keys(raw).every(function (k) { return ITEM_KEYS.indexOf(k) >= 0; })) { throw new VaultError(KINDS.CONTENT, "The vault contains an item with a field this version does not understand."); }
			if (raw.type !== "login") { throw new VaultError(KINDS.CONTENT, "The vault contains an item of an unknown type."); }
			if (typeof raw.Id !== "string" || !UUID_RE.test(raw.Id)) { throw new VaultError(KINDS.CONTENT, "The vault contains an item without a valid identifier."); }
			var id = raw.Id.toLowerCase();
			if (seen[id]) { throw new VaultError(KINDS.CONTENT, "The vault contains duplicate item identifiers."); }
			seen[id] = true;
			if (raw.Favorite !== undefined && typeof raw.Favorite !== "boolean") { throw new VaultError(KINDS.CONTENT, "The vault contains an invalid item (Favorite)."); }
			if (raw.Urls !== undefined && raw.Urls !== null && (!Array.isArray(raw.Urls) || raw.Urls.length > 100 || !raw.Urls.every(function (u) { return typeof u === "string" && u.length <= 2048; }))) {
				throw new VaultError(KINDS.CONTENT, "The vault contains an invalid item (Urls).");
			}
			var created = raw.CreatedAt === undefined ? new Date(0) : parseDate(raw.CreatedAt, "CreatedAt");
			var updated = raw.UpdatedAt === undefined ? created : parseDate(raw.UpdatedAt, "UpdatedAt");
			if (updated < created) { updated = created; } // VaultValidation.NormalizeLoaded
			var updatedNormalized = raw.UpdatedAt !== undefined && updated === created && parseDate(raw.UpdatedAt, "UpdatedAt").getTime() !== created.getTime();
			return Object.freeze({
				id: id,
				type: "login",
				name: optionalString(raw.Name, "Name", 1024) || "",
				notes: optionalString(raw.Notes, "Notes", 65536),
				favorite: raw.Favorite === true,
				createdAt: created,
				updatedAt: updated,
				createdAtText: raw.CreatedAt === undefined ? null : dateText(raw.CreatedAt),
				updatedAtText: raw.UpdatedAt === undefined || updatedNormalized ? null : dateText(raw.UpdatedAt),
				username: optionalString(raw.Username, "Username", 1024),
				password: optionalString(raw.Password, "Password", 4096),
				urls: Object.freeze((raw.Urls || []).slice())
			});
		});
		return Object.freeze({ schemaVersion: 1, items: Object.freeze(items) });
	}

	// ---- writing (VaultSerializer.SerializeToUtf8Bytes, EncryptedVaultSerializer.Serialize) ----
	// System.Text.Json's default encoder escapes the quote, the HTML-sensitive characters and every
	// non-ASCII character as \uXXXX (uppercase hex, UTF-16 units), so the bytes come out as the
	// desktop writes them. The desktop parses JSON, so this is for consistency, not correctness.
	function jsonString(text) {
		var out = "\"";
		for (var i = 0; i < text.length; i++) {
			var c = text.charCodeAt(i);
			if (c === 0x5C) { out += "\\\\"; }
			else if (c === 0x0A) { out += "\\n"; }
			else if (c === 0x0D) { out += "\\r"; }
			else if (c === 0x09) { out += "\\t"; }
			else if (c === 0x08) { out += "\\b"; }
			else if (c === 0x0C) { out += "\\f"; }
			else if (c < 0x20 || c > 0x7E || c === 0x22 || c === 0x26 || c === 0x27 || c === 0x2B || c === 0x3C || c === 0x3E || c === 0x60) {
				out += "\\u" + ("000" + c.toString(16).toUpperCase()).slice(-4);
			}
			else { out += text[i]; }
		}
		return out + "\"";
	}

	// The text a date was read as, when it still says the same instant; otherwise jsonDate.
	function itemDate(date, text) {
		if (typeof text === "string" && DATE_TEXT_RE.test(text) && new Date(text).getTime() === date.getTime()) { return text; }
		return jsonDate(date);
	}

	// DateTimeOffset as System.Text.Json writes a UTC value: seconds, a trimmed fraction, "+00:00".
	function jsonDate(date) {
		var iso = date.toISOString();            // 2026-10-01T09:00:00.123Z
		var base = iso.slice(0, 19);
		var ms = iso.slice(20, 23);
		var fraction = ms === "000" ? "" : "." + ms.replace(/0+$/, "");
		return base + fraction + "+00:00";
	}

	var LIMITS = Object.freeze({ name: 200, username: 320, password: 4096, notes: 16384, url: 2048, urls: 64 }); // VaultValidation

	// A string with half of a surrogate pair (half an emoji) cannot be written as UTF-8 and is
	// refused by the desktop's JSON reader; it is never written.
	var LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;
	function isWellFormed(text) {
		return typeof text.isWellFormed === "function" ? text.isWellFormed() : !LONE_SURROGATE_RE.test(text);
	}
	function requireWellFormed(text, what) {
		if (typeof text === "string" && !isWellFormed(text)) {
			throw new VaultError(KINDS.CONTENT, what + " contains an incomplete character (half of an emoji or symbol). Remove it and type it again.");
		}
	}

	// VaultValidation.IsValidUrl as the web vault has it: an absolute http or https address to this
	// browser's own URL parser. Says nothing about its length, which LIMITS.url limits.
	function isValidUrl(url) {
		if (typeof url !== "string") { return false; }
		var parsed;
		try { parsed = new URL(url); } catch (e) { return false; }
		return parsed.protocol === "http:" || parsed.protocol === "https:";
	}

	// VaultValidation.Validate for a login item, with the desktop's messages.
	function validateItem(item) {
		if (!isPlainObject(item)) { throw new VaultError(KINDS.CONTENT, "Item is required."); }
		if (typeof item.id !== "string" || !UUID_RE.test(item.id)) { throw new VaultError(KINDS.CONTENT, "Item id must not be empty."); }
		if (typeof item.name !== "string" || item.name.trim().length === 0) { throw new VaultError(KINDS.CONTENT, "Name is required."); }
		requireWellFormed(item.name, "The name");
		requireWellFormed(item.username, "The username");
		requireWellFormed(item.password, "The password");
		requireWellFormed(item.notes, "The notes");
		if (Array.isArray(item.urls)) { item.urls.forEach(function (u) { requireWellFormed(u, "A URL"); }); }
		if (item.name.length > LIMITS.name) { throw new VaultError(KINDS.CONTENT, "Name must be at most " + LIMITS.name + " characters."); }
		if (item.notes != null && (typeof item.notes !== "string" || item.notes.length > LIMITS.notes)) { throw new VaultError(KINDS.CONTENT, "Notes must be at most " + LIMITS.notes + " characters."); }
		if (item.username != null && (typeof item.username !== "string" || item.username.length > LIMITS.username)) { throw new VaultError(KINDS.CONTENT, "Username must be at most " + LIMITS.username + " characters."); }
		if (item.password != null && (typeof item.password !== "string" || item.password.length > LIMITS.password)) { throw new VaultError(KINDS.CONTENT, "Password must be at most " + LIMITS.password + " characters."); }
		if (!Array.isArray(item.urls)) { throw new VaultError(KINDS.CONTENT, "The URL list must not be null."); }
		if (item.urls.length > LIMITS.urls) { throw new VaultError(KINDS.CONTENT, "An item may have at most " + LIMITS.urls + " URLs."); }
		item.urls.forEach(function (url) {
			if (typeof url !== "string" || url.trim().length === 0) { throw new VaultError(KINDS.CONTENT, "A URL must not be blank."); }
			if (url.length > LIMITS.url) { throw new VaultError(KINDS.CONTENT, "A URL must be at most " + LIMITS.url + " characters."); }
			if (!isValidUrl(url)) { throw new VaultError(KINDS.CONTENT, "'" + url + "' is not a valid absolute http(s) URL."); }
		});
		if (!(item.createdAt instanceof Date) || !(item.updatedAt instanceof Date) || isNaN(item.createdAt) || isNaN(item.updatedAt)) { throw new VaultError(KINDS.CONTENT, "Item dates are required."); }
		if (item.updatedAt < item.createdAt) { throw new VaultError(KINDS.CONTENT, "UpdatedAt must not be earlier than CreatedAt."); }
		if (typeof item.favorite !== "boolean") { throw new VaultError(KINDS.CONTENT, "Favorite must be a boolean."); }
	}

	// The decrypted document as the desktop writes it: compact, "type" first, the login fields, then
	// the common ones, nulls omitted. Every item is validated and ids must be unique.
	function serializeVault(vault) {
		if (!isPlainObject(vault) || !Array.isArray(vault.items) || vault.items.length > MAX_ITEMS) { throw new VaultError(KINDS.CONTENT, "The vault's item list is invalid."); }
		var seen = Object.create(null);
		var parts = vault.items.map(function (item) {
			validateItem(item);
			var id = item.id.toLowerCase();
			if (seen[id]) { throw new VaultError(KINDS.CONTENT, "The vault contains duplicate item identifiers."); }
			seen[id] = true;
			var fields = ["\"type\":\"login\""];
			if (item.username != null) { fields.push("\"Username\":" + jsonString(item.username)); }
			if (item.password != null) { fields.push("\"Password\":" + jsonString(item.password)); }
			fields.push("\"Urls\":[" + item.urls.map(jsonString).join(",") + "]");
			fields.push("\"Id\":" + jsonString(id));
			fields.push("\"Name\":" + jsonString(item.name));
			if (item.notes != null) { fields.push("\"Notes\":" + jsonString(item.notes)); }
			fields.push("\"Favorite\":" + (item.favorite ? "true" : "false"));
			// Dates are written by System.Text.Json's date formatter, not its string encoder: no escaping.
			fields.push("\"CreatedAt\":\"" + itemDate(item.createdAt, item.createdAtText) + "\"");
			fields.push("\"UpdatedAt\":\"" + itemDate(item.updatedAt, item.updatedAtText) + "\"");
			return "{" + fields.join(",") + "}";
		});
		return utf8("{\"schemaVersion\":1,\"items\":[" + parts.join(",") + "]}");
	}

	// The envelope as the desktop writes it: indented with two spaces, the fields in this order.
	function serializeEnvelope(envelope) {
		var p = envelope.kdfParameters;
		var text = "{\n"
			+ "  \"version\": " + envelope.version + ",\n"
			+ "  \"kdf\": " + jsonString(envelope.kdf) + ",\n"
			+ "  \"kdfParameters\": {\n"
			+ "    \"memoryKiB\": " + p.memoryKiB + ",\n"
			+ "    \"iterations\": " + p.iterations + ",\n"
			+ "    \"parallelism\": " + p.parallelism + ",\n"
			+ "    \"keyLengthBytes\": " + p.keyLengthBytes + "\n"
			+ "  },\n"
			+ "  \"salt\": " + jsonString(bytesToBase64(envelope.salt)) + ",\n"
			+ "  \"algorithm\": " + jsonString(envelope.algorithm) + ",\n"
			+ "  \"keyWrapNonce\": " + jsonString(bytesToBase64(envelope.keyWrapNonce)) + ",\n"
			+ "  \"encryptedVaultKey\": " + jsonString(bytesToBase64(envelope.encryptedVaultKey)) + ",\n"
			+ "  \"contentNonce\": " + jsonString(bytesToBase64(envelope.contentNonce)) + ",\n"
			+ "  \"ciphertext\": " + jsonString(bytesToBase64(envelope.ciphertext)) + "\n"
			+ "}";
		return utf8(text);
	}

	// About how many bytes serializeEnvelope will write for this envelope once its content is
	// `plaintextLength` bytes. The ciphertext is the plaintext and a tag, in Base64; and Base64
	// writes "+" for one value in 64, which the envelope's JSON writes as \u002B, six bytes for one
	// (as the desktop's encoder does). How many there are depends on the ciphertext, which is new
	// with every save, so the size can only be estimated: this is its expected value. What comes out
	// is within a few kilobytes of it (a standard deviation of about 2.5 KiB at 16 MiB). An envelope
	// larger than MAX_ENVELOPE_BYTES is one this page, the desktop and the server all refuse to read.
	function estimateEnvelopeSize(envelope, plaintextLength) {
		if (!Number.isInteger(plaintextLength) || plaintextLength < 0) { throw new VaultError(KINDS.CONTENT, "Invalid content length."); }
		var withoutContent = serializeEnvelope({
			version: envelope.version, kdf: envelope.kdf, kdfParameters: envelope.kdfParameters, salt: envelope.salt,
			algorithm: envelope.algorithm, keyWrapNonce: envelope.keyWrapNonce, encryptedVaultKey: envelope.encryptedVaultKey,
			contentNonce: envelope.contentNonce, ciphertext: new Uint8Array(0)
		}).length;
		var base64Length = 4 * Math.ceil((plaintextLength + TAG_BYTES) / 3);
		return withoutContent + Math.ceil(base64Length * 69 / 64);
	}

	// Whether the password as typed is the master password of the vault that is open: the key is
	// derived as unlock derives it (every candidate encoding), the envelope's vault key is unwrapped
	// with it, and the result is compared with the key the unlocked session holds. Nothing is
	// decrypted beyond the 32-byte key, and nothing is sent anywhere. Resolves to true or false;
	// rejects with RESOURCE when the key derivation cannot run.
	function verifyMasterPassword(envelope, typedPassword, vaultKey) {
		if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) { return Promise.reject(new VaultError(KINDS.CONTENT, "Invalid vault key length.")); }
		var candidates = passwordCandidates(typedPassword);
		var wrapAad = keyWrapAad(envelope);

		function attempt(i) {
			if (i >= candidates.encodings.length) { return Promise.resolve(false); }
			var kek = null;
			return deriveKek(candidates.encodings[i], envelope)
				.then(function (derived) {
					kek = derived;
					return aesGcmDecrypt(kek, envelope.keyWrapNonce, envelope.encryptedVaultKey, wrapAad);
				})
				.then(function (unwrapped) {
					var same = bytesEqual(unwrapped, vaultKey);
					unwrapped.fill(0);
					return same;
				}, function (err) {
					// Not this encoding; the vault may have been keyed with an earlier one.
					if (err instanceof VaultError && err.kind === KINDS.AUTH) { return attempt(i + 1); }
					throw err;
				})
				.finally(function () { if (kek) { kek.fill(0); } });
		}
		return attempt(0).finally(function () {
			candidates.encodings.forEach(function (b) { b.fill(0); });
		});
	}

	function aesGcmEncrypt(keyBytes, nonce, plaintext, aad) {
		return webcrypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"])
			.then(function (key) {
				return webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: TAG_BYTES * 8 }, key, plaintext);
			})
			.then(function (out) { return new Uint8Array(out); });
	}

	// VaultCryptor.ReEncryptContent: new plaintext under the same vault key and header, with a fresh
	// content nonce. The result is checked by decrypting it again before it is returned, so an
	// envelope that would not open can never leave this function.
	function encryptContent(envelope, vaultKey, plaintext) {
		if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) { return Promise.reject(new VaultError(KINDS.CONTENT, "Invalid vault key length.")); }
		var nonce = new Uint8Array(NONCE_BYTES);
		webcrypto.getRandomValues(nonce);
		var aad = contentAad(envelope.version);
		return aesGcmEncrypt(vaultKey, nonce, plaintext, aad).then(function (ciphertext) {
			var next = Object.freeze({
				version: envelope.version, kdf: envelope.kdf, kdfParameters: envelope.kdfParameters, salt: envelope.salt,
				algorithm: envelope.algorithm, keyWrapNonce: envelope.keyWrapNonce, encryptedVaultKey: envelope.encryptedVaultKey,
				contentNonce: nonce, ciphertext: ciphertext
			});
			return aesGcmDecrypt(vaultKey, nonce, ciphertext, aad).then(function (check) {
				if (!bytesEqual(check, plaintext)) { throw new VaultError(KINDS.CONTENT, "Encryption self-check failed."); }
				check.fill(0);
				return next;
			});
		});
	}

	function newId() {
		if (typeof webcrypto.randomUUID === "function") { return webcrypto.randomUUID().toLowerCase(); }
		var b = new Uint8Array(16);
		webcrypto.getRandomValues(b);
		b[6] = (b[6] & 0x0F) | 0x40;
		b[8] = (b[8] & 0x3F) | 0x80;
		var h = bytesToHex(b);
		return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
	}

	// ---- the password generator (BitosX.Core.Generation.PasswordGenerator, the same rules) ----
	// Every selected class is represented when the length allows, the rest is drawn from all of
	// them, and the result is shuffled (Fisher–Yates). Every draw is uniform: rejection sampling
	// over 32-bit values from the CSPRNG, never a modulo of a biased range.
	var GENERATOR_CLASSES = Object.freeze({
		lowercase: "abcdefghijklmnopqrstuvwxyz",
		uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		digits: "0123456789",
		symbols: "!@#$%^&*()-_=+[]{};:,.?/"
	});
	var AMBIGUOUS = "Il1O0o";
	var GENERATOR_DEFAULTS = Object.freeze({
		length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, excludeAmbiguous: false
	});
	var GENERATOR_MIN_LENGTH = 4, GENERATOR_MAX_LENGTH = 256;

	function randomInt(n) {
		var limit = Math.floor(4294967296 / n) * n;
		var buf = new Uint32Array(1);
		do { webcrypto.getRandomValues(buf); } while (buf[0] >= limit);
		return buf[0] % n;
	}

	// The options as the generator takes them; anything missing is the desktop's default.
	function generatorOptions(options) {
		var o = {};
		Object.keys(GENERATOR_DEFAULTS).forEach(function (k) {
			o[k] = options && options[k] !== undefined ? options[k] : GENERATOR_DEFAULTS[k];
		});
		return o;
	}

	// PasswordGenerationOptions.Validate, with the desktop's messages.
	function validateGeneratorOptions(o) {
		if (!Number.isInteger(o.length) || o.length < GENERATOR_MIN_LENGTH || o.length > GENERATOR_MAX_LENGTH) {
			throw new VaultError(KINDS.CONTENT, "Password length must be between " + GENERATOR_MIN_LENGTH + " and " + GENERATOR_MAX_LENGTH + ".");
		}
		if (!o.lowercase && !o.uppercase && !o.digits && !o.symbols) {
			throw new VaultError(KINDS.CONTENT, "At least one character class must be selected.");
		}
	}

	// generatePassword(20) still works; otherwise an options object as above.
	function generatePassword(options) {
		var o = generatorOptions(typeof options === "number" ? { length: options } : options);
		validateGeneratorOptions(o);
		var classes = ["lowercase", "uppercase", "digits", "symbols"]
			.filter(function (k) { return o[k]; })
			.map(function (k) {
				var set = GENERATOR_CLASSES[k];
				return o.excludeAmbiguous ? set.split("").filter(function (c) { return AMBIGUOUS.indexOf(c) < 0; }).join("") : set;
			})
			.filter(function (set) { return set.length > 0; });
		var combined = classes.join("");
		var out = [];
		if (o.length >= classes.length) {
			classes.forEach(function (set) { out.push(set[randomInt(set.length)]); });
		}
		while (out.length < o.length) { out.push(combined[randomInt(combined.length)]); }
		for (var i = out.length - 1; i > 0; i--) {
			var j = randomInt(i + 1);
			var t = out[i]; out[i] = out[j]; out[j] = t;
		}
		return out.join("");
	}

	// ---- password strength (BitosX.Core.Security.PasswordStrength, ported rule for rule) ----
	// A rough local heuristic: length and character classes, discounted for repeats, runs such as
	// "abcd" or "qwerty", a repeated block, and the most common passwords (also with the usual
	// substitutions). It has no dictionary and knows nothing about breaches. Text is looked at in
	// UTF-16 code units, as .NET's char is; tests/fixtures/password-strength-vectors.json holds the
	// desktop's own results for the same inputs.
	var STRENGTH_NAMES = Object.freeze(["Very weak", "Weak", "Fair", "Strong", "Very strong"]);
	var PATTERN_CONTINUATION_BITS = 1.0;
	var COMMON_PASSWORD_BITS = 7.0;
	var KEYBOARD_ROWS = ["1234567890", "qwertyuiop\u00E5", "asdfghjkl\u00F6\u00E4", "zxcvbnm"];
	var COMMON_PASSWORDS = [
		"administrator", "qwertyuiop", "1q2w3e4r5t", "password", "iloveyou", "sunshine", "princess",
		"football", "baseball", "superman", "starwars", "whatever", "trustno1", "changeme", "zaq12wsx",
		"1q2w3e4r", "letmein", "welcome", "freedom", "bitosx", "qwerty", "azerty", "monkey", "dragon",
		"master", "shadow", "secret", "hunter", "batman", "summer", "winter", "asdfgh", "zxcvbn",
		"abc123", "admin", "login", "hello"
	];
	var RE_LOWER = /^\p{Ll}$/u, RE_UPPER = /^\p{Lu}$/u, RE_DIGIT = /^\p{Nd}$/u, RE_LETTER = /^\p{L}$/u;

	// char.ToLowerInvariant / ToUpperInvariant: one UTF-16 unit in, one out (simple case mapping).
	function lowerUnit(c) {
		if (c === "\u0130") { return "i"; }
		var l = c.toLowerCase();
		return l.length === 1 ? l : c;
	}
	function upperUnit(c) {
		var u = c.toUpperCase();
		return u.length === 1 ? u : c;
	}
	function normalizeUnit(c) {
		switch (c) {
			case "0": return "o";
			case "1": case "!": case "|": return "i";
			case "3": return "e";
			case "4": case "@": return "a";
			case "5": case "$": return "s";
			case "7": return "t";
			default: return lowerUnit(c);
		}
	}

	function poolSize(text) {
		var lower = false, upper = false, digit = false, symbol = false;
		for (var i = 0; i < text.length; i++) {
			var c = text[i];
			if (RE_LOWER.test(c)) { lower = true; }
			else if (RE_UPPER.test(c)) { upper = true; }
			else if (RE_DIGIT.test(c)) { digit = true; }
			else { symbol = true; }
		}
		return (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 32 : 0);
	}

	function smallestPeriod(text) {
		for (var period = 1; period <= Math.floor(text.length / 2); period++) {
			if (text.length % period !== 0) { continue; }
			var repeats = true;
			for (var i = period; i < text.length && repeats; i++) { repeats = text[i] === text[i - period]; }
			if (repeats) { return period; }
		}
		return text.length;
	}

	function commonPasswordLengthAt(text, normalized, start) {
		for (var k = 0; k < COMMON_PASSWORDS.length; k++) {
			var common = COMMON_PASSWORDS[k];
			if (text.length - start < common.length) { continue; }
			var asTyped = true, substituted = true;
			for (var i = 0; i < common.length && (asTyped || substituted); i++) {
				if (asTyped && upperUnit(text[start + i]) !== upperUnit(common[i])) { asTyped = false; }
				if (substituted && normalized[start + i] !== common[i]) { substituted = false; }
			}
			if (asTyped || substituted) { return common.length; }
		}
		return 0;
	}

	function continuesPattern(previous, current) {
		if (previous === current) { return true; }
		var sameKind = (RE_LETTER.test(previous) && RE_LETTER.test(current)) || (RE_DIGIT.test(previous) && RE_DIGIT.test(current));
		if (sameKind && Math.abs(current.charCodeAt(0) - previous.charCodeAt(0)) === 1) { return true; }
		var a = lowerUnit(previous), b = lowerUnit(current);
		for (var r = 0; r < KEYBOARD_ROWS.length; r++) {
			var row = KEYBOARD_ROWS[r];
			var index = row.indexOf(a);
			if (index >= 0) {
				return (index > 0 && row[index - 1] === b) || (index < row.length - 1 && row[index + 1] === b);
			}
		}
		return false;
	}

	function estimateSequence(text, bitsPerCharacter) {
		var normalized = [];
		for (var i = 0; i < text.length; i++) { normalized.push(normalizeUnit(text[i])); }
		var bits = 0, position = 0;
		while (position < text.length) {
			var common = commonPasswordLengthAt(text, normalized, position);
			if (common > 0) { bits += COMMON_PASSWORD_BITS; position += common; continue; }
			var continues = position > 0 && continuesPattern(text[position - 1], text[position]);
			bits += continues ? PATTERN_CONTINUATION_BITS : bitsPerCharacter;
			position++;
		}
		return bits;
	}

	// Approximate guessing entropy in bits (PasswordStrength.EstimateEntropyBits).
	function estimateEntropyBits(password) {
		if (typeof password !== "string" || password.length === 0) { return 0; }
		var bitsPerCharacter = Math.log2(poolSize(password));
		var period = smallestPeriod(password);
		if (period < password.length) {
			return estimateSequence(password.slice(0, period), bitsPerCharacter) + Math.log2(password.length / period);
		}
		return estimateSequence(password, bitsPerCharacter);
	}

	// 0 very weak .. 4 very strong (PasswordStrength.Estimate).
	function estimateStrength(password) {
		if (typeof password !== "string" || password.length === 0) { return 0; }
		var bits = estimateEntropyBits(password);
		return bits < 40 ? 0 : bits < 60 ? 1 : bits < 80 ? 2 : bits < 100 ? 3 : 4;
	}

	// The envelopes protect their vault key the same way: same KDF and parameters, same salt, the
	// same wrapped key under the same nonce. Differs after a master-password change or a key
	// rotation on another device.
	function sameKeyWrap(a, b) {
		var pa = a.kdfParameters, pb = b.kdfParameters;
		return a.version === b.version && a.kdf === b.kdf && a.algorithm === b.algorithm &&
			pa.memoryKiB === pb.memoryKiB && pa.iterations === pb.iterations && pa.parallelism === pb.parallelism &&
			pa.keyLengthBytes === pb.keyLengthBytes &&
			bytesEqual(a.salt, b.salt) && bytesEqual(a.keyWrapNonce, b.keyWrapNonce) && bytesEqual(a.encryptedVaultKey, b.encryptedVaultKey);
	}

	function sha256Hex(bytes) {
		return webcrypto.subtle.digest("SHA-256", bytes).then(function (d) { return bytesToHex(new Uint8Array(d)); });
	}

	return Object.freeze({
		VaultError: VaultError,
		KINDS: KINDS,
		MAX_ENVELOPE_BYTES: MAX_ENVELOPE_BYTES,
		MAX_ITEMS: MAX_ITEMS,
		parseEnvelope: parseEnvelope,
		passwordCandidates: passwordCandidates,
		keyWrapAad: keyWrapAad,
		contentAad: contentAad,
		deriveKek: deriveKek,
		unlock: unlock,
		parseVault: parseVault,
		sha256Hex: sha256Hex,
		isBase64: isBase64,
		base64ToBytes: base64ToBytes,
		bytesToHex: bytesToHex,
		bytesToBase64: bytesToBase64,
		LIMITS: LIMITS,
		isValidUrl: isValidUrl,
		validateItem: validateItem,
		estimateEnvelopeSize: estimateEnvelopeSize,
		verifyMasterPassword: verifyMasterPassword,
		serializeVault: serializeVault,
		serializeEnvelope: serializeEnvelope,
		encryptContent: encryptContent,
		newId: newId,
		generatePassword: generatePassword,
		GENERATOR_DEFAULTS: GENERATOR_DEFAULTS,
		GENERATOR_MIN_LENGTH: GENERATOR_MIN_LENGTH,
		GENERATOR_MAX_LENGTH: GENERATOR_MAX_LENGTH,
		generatorOptions: generatorOptions,
		validateGeneratorOptions: validateGeneratorOptions,
		estimateEntropyBits: estimateEntropyBits,
		estimateStrength: estimateStrength,
		STRENGTH_NAMES: STRENGTH_NAMES,
		sameKeyWrap: sameKeyWrap,
		isWellFormed: isWellFormed,
		_jsonString: jsonString,
		_jsonDate: jsonDate
	});
});
