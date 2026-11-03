// Minimal client for the BitosX account API (api.bitosx.se).
//
// Security posture:
//  - Tokens live only in this module's memory. Nothing is written to
//    localStorage, sessionStorage, cookies or IndexedDB. A page reload means
//    signing in again; that is intentional for now.
//  - The access token goes only in the Authorization header, the refresh token
//    only in a POST body; neither is ever logged, put in a URL or in the DOM.
//  - Refresh is single-flighted: the API revokes the whole session if a
//    refresh token is presented twice, so two concurrent refreshes must never
//    happen. A 401 on an authenticated call gets exactly one refresh and one
//    retry; if that fails too, the session is over and "bitosx:session-ended"
//    is dispatched on document so the page can lock and say so.
//  - Every session has a generation number; a response that arrives after the
//    session it belonged to ended never touches the next one.
//  - Every response is size-capped and type-checked before it is trusted.
//  - All failures collapse to a small set of kinds; the server's generic
//    ProblemDetails "detail" is only surfaced for statuses where it is known
//    to be a fixed, non-sensitive string.
(function (global) {
	"use strict";

	var cfg = global.BITOSX_CONFIG;
	if (!cfg) { throw new Error("BITOSX_CONFIG missing"); }

	var state = {
		accessToken: null,
		accessExpiresAt: 0,
		refreshToken: null,
		refreshExpiresAt: 0
	};
	var refreshInFlight = null;
	// Changes whenever a session starts or ends. Callers capture it before a request and compare
	// afterwards, so a late answer never writes into a session that started since.
	var generation = 0;

	function ApiError(kind, status, retryAfterSeconds) {
		this.name = "ApiError";
		this.kind = kind;                 // see KINDS below
		this.status = status || 0;
		this.retryAfterSeconds = retryAfterSeconds || null;
		this.message = kind;
	}
	ApiError.prototype = Object.create(Error.prototype);
	ApiError.prototype.constructor = ApiError;

	var KINDS = Object.freeze({
		NETWORK: "network",             // offline, DNS, CORS, connection dropped
		TIMEOUT: "timeout",             // no complete answer within the client's time limit
		INVALID: "invalid",             // 400
		UNAUTHENTICATED: "unauthenticated", // 401
		FORBIDDEN: "forbidden",         // 403: authenticated, but the password confirmation failed
		NOT_FOUND: "not_found",         // 404
		TOO_LARGE: "too_large",         // 413
		RATE_LIMITED: "rate_limited",   // 429
		UNAVAILABLE: "unavailable",     // 503
		CONFLICT: "conflict",           // 409: the server holds a newer revision than the upload was based on
		UNEXPECTED: "unexpected"        // anything else, incl. malformed bodies
	});

	function clearSession() {
		state.accessToken = null;
		state.accessExpiresAt = 0;
		state.refreshToken = null;
		state.refreshExpiresAt = 0;
		refreshInFlight = null;
		generation++;
	}

	// The server ended the session (a 401 that one refresh could not cure, or a refused refresh).
	// Drops the tokens and tells the page once.
	function endSession() {
		var had = state.refreshToken !== null;
		clearSession();
		if (had && global.document && typeof global.CustomEvent === "function") {
			global.document.dispatchEvent(new global.CustomEvent("bitosx:session-ended"));
		}
	}

	function isSignedIn() {
		return typeof state.refreshToken === "string" && state.refreshExpiresAt > Date.now();
	}

	function parseRetryAfter(res) {
		var v = res.headers.get("Retry-After");
		if (!v) { return null; }
		var n = parseInt(v, 10);
		return (Number.isFinite(n) && n >= 0 && n <= 86400) ? n : null;
	}

	function kindForStatus(status) {
		switch (status) {
			case 400: return KINDS.INVALID;
			case 401: return KINDS.UNAUTHENTICATED;
			case 403: return KINDS.FORBIDDEN;
			case 404: return KINDS.NOT_FOUND;
			case 409: return KINDS.CONFLICT;
			case 413: return KINDS.TOO_LARGE;
			case 429: return KINDS.RATE_LIMITED;
			case 503: return KINDS.UNAVAILABLE;
			default: return KINDS.UNEXPECTED;
		}
	}

	// Low-level request. Resolves to { status, body } where body is the parsed
	// JSON (or null for 204 / empty). Rejects with ApiError. options.maxBytes
	// raises the response cap and options.timeoutMs the time limit for the calls
	// that need it (the envelope transfers, the session list). The time limit
	// covers the whole exchange, body included.
	function request(method, path, options) {
		options = options || {};
		var maxBytes = options.maxBytes || cfg.maxResponseBytes;
		var controller = new AbortController();
		var timedOut = false;
		var timer = setTimeout(function () { timedOut = true; controller.abort(); }, options.timeoutMs || cfg.requestTimeoutMs);
		function transportError() { return new ApiError(timedOut ? KINDS.TIMEOUT : KINDS.NETWORK, 0); }
		var headers = { "Accept": "application/json" };
		var init = {
			method: method,
			headers: headers,
			credentials: "omit",
			cache: "no-store",
			redirect: "error",
			signal: controller.signal
		};
		if (options.body !== undefined) {
			headers["Content-Type"] = "application/json";
			init.body = JSON.stringify(options.body);
		}
		if (options.accessToken) {
			headers["Authorization"] = "Bearer " + options.accessToken;
		}

		return fetch(cfg.apiBase + path, init)
			.catch(function () { throw transportError(); })
			.then(function (res) {
				var status = res.status;
				var retryAfter = parseRetryAfter(res);
				if (status === 204) { return { status: status, body: null }; }
				var type = res.headers.get("content-type") || "";
				var isJson = type.indexOf("application/json") === 0 || type.indexOf("application/problem+json") === 0;
				var declared = parseInt(res.headers.get("content-length") || "", 10);
				if (Number.isFinite(declared) && declared > maxBytes) { throw new ApiError(KINDS.UNEXPECTED, status); }
				return res.text().catch(function () { throw transportError(); }).then(function (text) {
					if (text.length > maxBytes) { throw new ApiError(KINDS.UNEXPECTED, status); }
					var body = null;
					if (isJson && text.length > 0) {
						try { body = JSON.parse(text); } catch (e) { throw new ApiError(KINDS.UNEXPECTED, status); }
					}
					if (status >= 200 && status < 300) { return { status: status, body: body }; }
					throw new ApiError(kindForStatus(status), status, retryAfter);
				});
			})
			.finally(function () { clearTimeout(timer); });
	}

	// ---- shape validation (the API is ours, but a response is still input) ----
	function isNonEmptyString(v, max) { return typeof v === "string" && v.length > 0 && v.length <= (max || 8192); }
	// Every timestamp the API sends is UTC with an explicit offset. One without an offset is still
	// read as UTC, never as the browser's local time.
	var NO_OFFSET_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?$/;
	var ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/i;
	function parseUtc(v) {
		if (typeof v !== "string" || v.length > 64) { return NaN; }
		if (NO_OFFSET_RE.test(v)) { v += "Z"; }
		else if (!ISO_RE.test(v)) { return NaN; }
		return new Date(v).getTime();
	}
	var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

	function adoptTokens(body) {
		if (!body || typeof body !== "object") { throw new ApiError(KINDS.UNEXPECTED, 200); }
		var accessExp = parseUtc(body.accessTokenExpiresAt);
		var refreshExp = parseUtc(body.refreshTokenExpiresAt);
		if (!isNonEmptyString(body.accessToken) || !isNonEmptyString(body.refreshToken, 256) ||
			!Number.isFinite(accessExp) || !Number.isFinite(refreshExp) ||
			(body.tokenType !== undefined && body.tokenType !== "Bearer")) {
			throw new ApiError(KINDS.UNEXPECTED, 200);
		}
		state.accessToken = body.accessToken;
		state.accessExpiresAt = accessExp;
		state.refreshToken = body.refreshToken;
		state.refreshExpiresAt = refreshExp;
	}

	// ---- unauthenticated endpoints ----
	function register(email) {
		return request("POST", "/v1/auth/register", { body: { email: email } }).then(function () { return true; });
	}
	function resendVerification(email) {
		return request("POST", "/v1/auth/resend-verification", { body: { email: email } }).then(function () { return true; });
	}
	function verifyEmail(token, password) {
		return request("POST", "/v1/auth/verify-email", { body: { token: token, password: password } }).then(function () { return true; });
	}
	function forgotPassword(email) {
		return request("POST", "/v1/auth/forgot-password", { body: { email: email } }).then(function () { return true; });
	}
	function resetPassword(token, password) {
		return request("POST", "/v1/auth/reset-password", { body: { token: token, password: password } }).then(function () { return true; });
	}
	// 43 unpadded Base64URL characters, as the refresh token is.
	var MFA_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

	// Resolves to { signedIn: true } when the password alone signs in, or
	// { signedIn: false, mfaToken, mfaTokenExpiresAt } when the account has a second factor
	// (HTTP 202: the password was accepted, no session exists yet). The status decides; a 202 that
	// carries session tokens, or a 200 that carries a challenge, is refused.
	function login(email, password) {
		clearSession();
		return request("POST", "/v1/auth/login", { body: { email: email, password: password } })
			.then(function (r) {
				var b = r.body;
				if (r.status === 202) {
					var exp = b ? parseUtc(b.mfaTokenExpiresAt) : NaN;
					if (!b || typeof b.mfaToken !== "string" || !MFA_TOKEN_RE.test(b.mfaToken) || !Number.isFinite(exp) ||
						b.accessToken !== undefined || b.refreshToken !== undefined ||
						(b.method !== undefined && b.method !== "totp")) {
						throw new ApiError(KINDS.UNEXPECTED, 202);
					}
					return { signedIn: false, mfaToken: b.mfaToken, mfaTokenExpiresAt: new Date(exp) };
				}
				if (b && b.mfaToken !== undefined) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
				adoptTokens(b);
				generation++;
				return { signedIn: true };
			})
			.catch(function (err) { clearSession(); throw err; });
	}

	// Second sign-in step: the challenge token from login() and a TOTP or recovery code.
	function loginTotp(mfaToken, code) {
		if (typeof mfaToken !== "string" || !MFA_TOKEN_RE.test(mfaToken) || typeof code !== "string" || code.length === 0 || code.length > 32) {
			return Promise.reject(new ApiError(KINDS.UNAUTHENTICATED, 401));
		}
		clearSession();
		return request("POST", "/v1/auth/login/totp", { body: { mfaToken: mfaToken, code: code } })
			.then(function (r) { adoptTokens(r.body); generation++; return true; })
			.catch(function (err) { clearSession(); throw err; });
	}

	// Single-flight refresh. A refused refresh ends the session; a network failure does not.
	function refresh() {
		if (refreshInFlight) { return refreshInFlight; }
		var token = state.refreshToken;
		if (!token) { return Promise.reject(new ApiError(KINDS.UNAUTHENTICATED, 401)); }
		var gen = generation;
		var p = request("POST", "/v1/auth/refresh", { body: { refreshToken: token } })
			.then(function (r) {
				// The session this refresh belonged to ended meanwhile: its tokens are not adopted.
				if (gen !== generation) { throw new ApiError(KINDS.UNAUTHENTICATED, 401); }
				try { adoptTokens(r.body); }
				catch (e) { endSession(); throw e; } // a malformed answer leaves nothing usable
				return true;
			})
			.catch(function (err) {
				if (gen === generation && err instanceof ApiError && (err.kind === KINDS.UNAUTHENTICATED || err.kind === KINDS.INVALID)) {
					endSession();
				}
				throw err;
			})
			.finally(function () { if (refreshInFlight === p) { refreshInFlight = null; } });
		refreshInFlight = p;
		return p;
	}

	// ---- authenticated endpoints ----
	function withAccessToken() {
		if (!isSignedIn()) {
			if (state.refreshToken !== null) { endSession(); } // the refresh token ran out
			return Promise.reject(new ApiError(KINDS.UNAUTHENTICATED, 401));
		}
		var needsRefresh = !state.accessToken || (state.accessExpiresAt - Date.now()) < cfg.refreshSkewMs;
		var ready = needsRefresh ? refresh() : Promise.resolve(true);
		return ready.then(function () { return state.accessToken; });
	}

	function authed(method, path, options) {
		var gen = generation;
		function send(token) { return request(method, path, Object.assign({}, options || {}, { accessToken: token })); }
		return withAccessToken().then(function (token) {
			return send(token).catch(function (err) {
				if (!(err instanceof ApiError && err.kind === KINDS.UNAUTHENTICATED) || gen !== generation) { throw err; }
				// The server refused a token this client believed valid (a clock behind the server's,
				// or the session ended there). Exactly one refresh — or the one another call has
				// finished meanwhile — and exactly one retry; the server never ran the refused request.
				var ready = (state.accessToken && state.accessToken !== token) ? Promise.resolve(true) : refresh();
				return ready
					.then(function () {
						if (gen !== generation) { throw err; }
						return send(state.accessToken);
					})
					.catch(function (err2) {
						if (err2 instanceof ApiError && err2.kind === KINDS.UNAUTHENTICATED && gen === generation) { endSession(); }
						throw err2;
					});
			});
		});
	}

	function me() {
		return authed("GET", "/v1/account/me").then(function (r) {
			var b = r.body;
			var created = b ? parseUtc(b.createdAt) : NaN;
			if (!b || !UUID_RE.test(String(b.accountId)) || !isNonEmptyString(b.email, 320) ||
				typeof b.emailVerified !== "boolean" || !Number.isFinite(created)) {
				throw new ApiError(KINDS.UNEXPECTED, r.status);
			}
			return { accountId: b.accountId, email: b.email, emailVerified: b.emailVerified, createdAt: new Date(created) };
		});
	}

	function sessions() {
		return authed("GET", "/v1/account/sessions", { maxBytes: cfg.maxSessionsResponseBytes }).then(function (r) {
			if (!Array.isArray(r.body) || r.body.length > 1000) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
			return r.body.map(function (s) {
				var created = parseUtc(s && s.createdAt);
				var seen = parseUtc(s && s.lastSeenAt);
				var exp = parseUtc(s && s.expiresAt);
				if (!s || !UUID_RE.test(String(s.id)) || !Number.isFinite(created) || !Number.isFinite(seen) ||
					!Number.isFinite(exp) || typeof s.current !== "boolean") {
					throw new ApiError(KINDS.UNEXPECTED, r.status);
				}
				return { id: s.id, createdAt: new Date(created), lastSeenAt: new Date(seen), expiresAt: new Date(exp), current: s.current };
			});
		});
	}

	function revokeSession(id) {
		if (!UUID_RE.test(String(id))) { return Promise.reject(new ApiError(KINDS.INVALID, 400)); }
		return authed("DELETE", "/v1/account/sessions/" + encodeURIComponent(id)).then(function () { return true; });
	}

	// ---- encrypted sync: what the server holds, and the envelope itself (opaque bytes) ----
	var HEX64_RE = /^[0-9a-f]{64}$/;
	var BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
	var MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;

	function parseSyncStatus(b, status) {
		var updated = b ? parseUtc(b.updatedAt) : NaN;
		if (!b || typeof b !== "object" || !Number.isInteger(b.revision) || b.revision < 1 ||
			typeof b.fingerprint !== "string" || !HEX64_RE.test(b.fingerprint) ||
			!Number.isInteger(b.sizeBytes) || b.sizeBytes < 1 || b.sizeBytes > MAX_ENVELOPE_BYTES || !Number.isFinite(updated)) {
			throw new ApiError(KINDS.UNEXPECTED, status);
		}
		return { revision: b.revision, fingerprint: b.fingerprint, sizeBytes: b.sizeBytes, updatedAt: new Date(updated) };
	}

	function notFoundAsNull(err) {
		if (err instanceof ApiError && err.kind === KINDS.NOT_FOUND) { return null; }
		throw err;
	}

	// null when the server holds no vault for the account.
	function syncStatus() {
		return authed("GET", "/v1/sync/status")
			.then(function (r) { return parseSyncStatus(r.body, r.status); })
			.catch(notFoundAsNull);
	}

	// The stored envelope as bytes, with the server's statements about it. The caller checks the
	// fingerprint; the size is checked here. null when the server holds nothing.
	function syncEnvelope() {
		return authed("GET", "/v1/sync/envelope", { maxBytes: cfg.maxEnvelopeResponseBytes, timeoutMs: cfg.envelopeTimeoutMs })
			.then(function (r) {
				var meta = parseSyncStatus(r.body, r.status);
				var text = r.body.envelope;
				if (typeof text !== "string" || text.length === 0 || text.length % 4 !== 0 || !BASE64_RE.test(text)) {
					throw new ApiError(KINDS.UNEXPECTED, r.status);
				}
				var binary = atob(text);
				if (binary.length !== meta.sizeBytes) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
				var bytes = new Uint8Array(binary.length);
				for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
				meta.envelope = bytes;
				return meta;
			})
			.catch(notFoundAsNull);
	}

	// Stores the envelope as the account's vault if the server still holds baseRevision (0 for
	// "nothing yet"); CONFLICT otherwise, and the server keeps what it had. The caller checks the
	// fingerprint the server reports against the bytes it sent.
	function syncUpload(baseRevision, envelopeBytes) {
		if (!Number.isInteger(baseRevision) || baseRevision < 0) { return Promise.reject(new ApiError(KINDS.INVALID, 400)); }
		if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length === 0 || envelopeBytes.length > MAX_ENVELOPE_BYTES) {
			return Promise.reject(new ApiError(KINDS.TOO_LARGE, 413));
		}
		var binary = "";
		for (var i = 0; i < envelopeBytes.length; i++) { binary += String.fromCharCode(envelopeBytes[i]); }
		return authed("PUT", "/v1/sync/envelope", { body: { baseRevision: baseRevision, envelope: btoa(binary) }, timeoutMs: cfg.envelopeTimeoutMs })
			.then(function (r) {
				var stored = parseSyncStatus(r.body, r.status);
				if (stored.sizeBytes !== envelopeBytes.length || stored.revision <= baseRevision) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
				return stored;
			});
	}

	// ---- two-factor authentication (TOTP) for the signed-in account ----
	var BASE32_RE = /^[A-Z2-7]{16,128}$/;

	function totpStatus() {
		return authed("GET", "/v1/account/totp").then(function (r) {
			var b = r.body;
			if (!b || typeof b.enabled !== "boolean" || typeof b.pendingEnrollment !== "boolean" ||
				!Number.isInteger(b.recoveryCodesRemaining) || b.recoveryCodesRemaining < 0 || b.recoveryCodesRemaining > 100) {
				throw new ApiError(KINDS.UNEXPECTED, r.status);
			}
			var confirmed = b.confirmedAt === undefined || b.confirmedAt === null ? null : parseUtc(b.confirmedAt);
			if (confirmed !== null && !Number.isFinite(confirmed)) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
			return { enabled: b.enabled, confirmedAt: confirmed === null ? null : new Date(confirmed), recoveryCodesRemaining: b.recoveryCodesRemaining, pendingEnrollment: b.pendingEnrollment };
		});
	}

	// The new secret comes back exactly once; the caller shows it and never stores it.
	function totpEnroll(password) {
		if (typeof password !== "string" || password.length === 0 || password.length > cfg.passwordMaxLength) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		return authed("POST", "/v1/account/totp/enroll", { body: { password: password } }).then(function (r) {
			var b = r.body;
			if (!b || typeof b.secret !== "string" || !BASE32_RE.test(b.secret) ||
				typeof b.otpauthUri !== "string" || b.otpauthUri.indexOf("otpauth://totp/") !== 0 || b.otpauthUri.length > 2048 ||
				!isNonEmptyString(b.issuer, 64) || !isNonEmptyString(b.label, 320) ||
				!Number.isInteger(b.digits) || b.digits < 6 || b.digits > 8 || !Number.isInteger(b.periodSeconds) || b.periodSeconds < 15 || b.periodSeconds > 120) {
				throw new ApiError(KINDS.UNEXPECTED, r.status);
			}
			return { secret: b.secret, otpauthUri: b.otpauthUri, issuer: b.issuer, label: b.label, digits: b.digits, periodSeconds: b.periodSeconds };
		});
	}

	function parseRecoveryCodes(r) {
		var list = r.body && r.body.recoveryCodes;
		if (!Array.isArray(list) || list.length < 1 || list.length > 20 ||
			!list.every(function (c) { return typeof c === "string" && /^[a-z2-9]{5}-[a-z2-9]{5}$/.test(c); })) {
			throw new ApiError(KINDS.UNEXPECTED, r.status);
		}
		return list.slice();
	}

	function totpConfirm(code) {
		if (typeof code !== "string" || code.length === 0 || code.length > 32) { return Promise.reject(new ApiError(KINDS.INVALID, 400)); }
		return authed("POST", "/v1/account/totp/confirm", { body: { code: code } }).then(parseRecoveryCodes);
	}

	function totpDisable(password, code) {
		if (typeof password !== "string" || password.length === 0 || password.length > cfg.passwordMaxLength || typeof code !== "string" || code.length === 0 || code.length > 32) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		return authed("POST", "/v1/account/totp/disable", { body: { password: password, code: code } }).then(function () { return true; });
	}

	function totpRecoveryCodes(password, code) {
		if (typeof password !== "string" || password.length === 0 || password.length > cfg.passwordMaxLength || typeof code !== "string" || code.length === 0 || code.length > 32) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		return authed("POST", "/v1/account/totp/recovery-codes", { body: { password: password, code: code } }).then(parseRecoveryCodes);
	}

	function optionalCode(code) {
		return code === undefined || code === null || code === "" ? null : code;
	}
	function badCode(code) { return code !== null && (typeof code !== "string" || code.length > 32); }

	// Permanently deletes the signed-in account (and the vault stored on the server) after the
	// server re-checks the account password, and the second factor when the account has one. On
	// success the server session is gone; the caller clears the local one. A refusal is a 403 and
	// the session stays valid.
	function deleteAccount(password, code) {
		code = optionalCode(code);
		if (typeof password !== "string" || password.length === 0 || password.length > cfg.passwordMaxLength || badCode(code)) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		var body = { password: password };
		if (code !== null) { body.code = code; }
		return authed("POST", "/v1/account/delete", { body: body })
			.then(function () { return true; }); // the caller ends the local session (it is gone on the server)
	}

	// Replaces the account password. Every other session is revoked by the server; this one stays.
	// The vault master password is not involved: the server has never seen it.
	function changePassword(currentPassword, newPassword, code) {
		code = optionalCode(code);
		if (typeof currentPassword !== "string" || currentPassword.length === 0 || currentPassword.length > cfg.passwordMaxLength || badCode(code)) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		if (typeof newPassword !== "string" || newPassword.length < cfg.passwordMinLength || newPassword.length > cfg.passwordMaxLength) {
			return Promise.reject(new ApiError(KINDS.INVALID, 400));
		}
		var body = { currentPassword: currentPassword, newPassword: newPassword };
		if (code !== null) { body.code = code; }
		return authed("POST", "/v1/account/password", { body: body }).then(function () { return true; });
	}

	// Signing out here always signs out locally, whether or not the server could be told.
	function logout() {
		return authed("POST", "/v1/auth/logout").then(function () { clearSession(); return true; })
			.catch(function (err) { clearSession(); throw err; });
	}

	// Signing out everywhere keeps this session when the server could not be told, so the user can
	// try again: the other devices are still signed in.
	function logoutAll() {
		return authed("POST", "/v1/auth/logout-all").then(function () { clearSession(); return true; });
	}

	// The page is going away: drop the tokens and, best effort, revoke the session on the server so
	// it does not stay listed as active. Fire and forget; nothing waits for the answer.
	function revokeOnUnload() {
		var token = state.accessToken;
		var usable = typeof token === "string" && isSignedIn() && state.accessExpiresAt - Date.now() > 5000;
		clearSession();
		if (!usable || typeof global.fetch !== "function") { return false; }
		try {
			global.fetch(cfg.apiBase + "/v1/auth/logout", {
				method: "POST", keepalive: true, credentials: "omit", cache: "no-store", redirect: "error",
				headers: { "Accept": "application/json", "Authorization": "Bearer " + token }
			}).catch(function () { /* best effort */ });
		} catch (e) { return false; }
		return true;
	}

	global.bitosxApi = Object.freeze({
		ApiError: ApiError,
		KINDS: KINDS,
		isSignedIn: isSignedIn,
		clearSession: clearSession,
		generation: function () { return generation; },
		revokeOnUnload: revokeOnUnload,
		changePassword: changePassword,
		register: register,
		resendVerification: resendVerification,
		verifyEmail: verifyEmail,
		login: login,
		loginTotp: loginTotp,
		totpStatus: totpStatus,
		totpEnroll: totpEnroll,
		totpConfirm: totpConfirm,
		totpDisable: totpDisable,
		totpRecoveryCodes: totpRecoveryCodes,
		me: me,
		sessions: sessions,
		revokeSession: revokeSession,
		forgotPassword: forgotPassword,
		resetPassword: resetPassword,
		deleteAccount: deleteAccount,
		syncStatus: syncStatus,
		syncEnvelope: syncEnvelope,
		syncUpload: syncUpload,
		logout: logout,
		logoutAll: logoutAll,
		_parseUtc: parseUtc
	});
})(window);
