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
	var BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

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

	function base64ToBytes(text, field) {
		if (typeof text !== "string" || text.length === 0 || text.length % 4 !== 0 || !BASE64_RE.test(text)) {
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
			return Object.freeze({
				id: id,
				type: "login",
				name: optionalString(raw.Name, "Name", 1024) || "",
				notes: optionalString(raw.Notes, "Notes", 65536),
				favorite: raw.Favorite === true,
				createdAt: created,
				updatedAt: updated,
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

	// DateTimeOffset as System.Text.Json writes a UTC value: seconds, a trimmed fraction, "+00:00".
	function jsonDate(date) {
		var iso = date.toISOString();            // 2026-10-01T09:00:00.123Z
		var base = iso.slice(0, 19);
		var ms = iso.slice(20, 23);
		var fraction = ms === "000" ? "" : "." + ms.replace(/0+$/, "");
		return base + fraction + "+00:00";
	}

	var LIMITS = Object.freeze({ name: 200, username: 320, password: 4096, notes: 16384, url: 2048, urls: 64 }); // VaultValidation

	// VaultValidation.Validate for a login item, with the desktop's messages.
	function validateItem(item) {
		if (!isPlainObject(item)) { throw new VaultError(KINDS.CONTENT, "Item is required."); }
		if (typeof item.id !== "string" || !UUID_RE.test(item.id)) { throw new VaultError(KINDS.CONTENT, "Item id must not be empty."); }
		if (typeof item.name !== "string" || item.name.trim().length === 0) { throw new VaultError(KINDS.CONTENT, "Name is required."); }
		if (item.name.length > LIMITS.name) { throw new VaultError(KINDS.CONTENT, "Name must be at most " + LIMITS.name + " characters."); }
		if (item.notes != null && (typeof item.notes !== "string" || item.notes.length > LIMITS.notes)) { throw new VaultError(KINDS.CONTENT, "Notes must be at most " + LIMITS.notes + " characters."); }
		if (item.username != null && (typeof item.username !== "string" || item.username.length > LIMITS.username)) { throw new VaultError(KINDS.CONTENT, "Username must be at most " + LIMITS.username + " characters."); }
		if (item.password != null && (typeof item.password !== "string" || item.password.length > LIMITS.password)) { throw new VaultError(KINDS.CONTENT, "Password must be at most " + LIMITS.password + " characters."); }
		if (!Array.isArray(item.urls)) { throw new VaultError(KINDS.CONTENT, "The URL list must not be null."); }
		if (item.urls.length > LIMITS.urls) { throw new VaultError(KINDS.CONTENT, "An item may have at most " + LIMITS.urls + " URLs."); }
		item.urls.forEach(function (url) {
			if (typeof url !== "string" || url.trim().length === 0) { throw new VaultError(KINDS.CONTENT, "A URL must not be blank."); }
			if (url.length > LIMITS.url) { throw new VaultError(KINDS.CONTENT, "A URL must be at most " + LIMITS.url + " characters."); }
			var parsed;
			try { parsed = new URL(url); } catch (e) { parsed = null; }
			if (!parsed || (parsed.protocol !== "http:" && parsed.protocol !== "https:")) { throw new VaultError(KINDS.CONTENT, "'" + url + "' is not a valid absolute http(s) URL."); }
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
			fields.push("\"CreatedAt\":\"" + jsonDate(item.createdAt) + "\"");
			fields.push("\"UpdatedAt\":\"" + jsonDate(item.updatedAt) + "\"");
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

	// A random password from a fixed alphabet, without modulo bias (rejection sampling).
	var PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~";
	function generatePassword(length) {
		length = length || 24;
		var out = "";
		var limit = 256 - (256 % PASSWORD_ALPHABET.length);
		var buf = new Uint8Array(64);
		while (out.length < length) {
			webcrypto.getRandomValues(buf);
			for (var i = 0; i < buf.length && out.length < length; i++) {
				if (buf[i] < limit) { out += PASSWORD_ALPHABET[buf[i] % PASSWORD_ALPHABET.length]; }
			}
		}
		return out;
	}

	function sha256Hex(bytes) {
		return webcrypto.subtle.digest("SHA-256", bytes).then(function (d) { return bytesToHex(new Uint8Array(d)); });
	}

	return Object.freeze({
		VaultError: VaultError,
		KINDS: KINDS,
		MAX_ENVELOPE_BYTES: MAX_ENVELOPE_BYTES,
		parseEnvelope: parseEnvelope,
		passwordCandidates: passwordCandidates,
		keyWrapAad: keyWrapAad,
		contentAad: contentAad,
		deriveKek: deriveKek,
		unlock: unlock,
		parseVault: parseVault,
		sha256Hex: sha256Hex,
		base64ToBytes: base64ToBytes,
		bytesToHex: bytesToHex,
		bytesToBase64: bytesToBase64,
		LIMITS: LIMITS,
		validateItem: validateItem,
		serializeVault: serializeVault,
		serializeEnvelope: serializeEnvelope,
		encryptContent: encryptContent,
		newId: newId,
		generatePassword: generatePassword,
		_jsonString: jsonString,
		_jsonDate: jsonDate
	});
});
