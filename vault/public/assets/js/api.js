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
//    happen.
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
		NETWORK: "network",             // offline, DNS, CORS, timeout
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
	// raises the response cap for the one call that needs it (the envelope).
	function request(method, path, options) {
		options = options || {};
		var maxBytes = options.maxBytes || cfg.maxResponseBytes;
		var controller = new AbortController();
		var timer = setTimeout(function () { controller.abort(); }, cfg.requestTimeoutMs);
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
			.catch(function () { throw new ApiError(KINDS.NETWORK, 0); })
			.then(function (res) {
				var status = res.status;
				var retryAfter = parseRetryAfter(res);
				if (status === 204) { return { status: status, body: null }; }
				var type = res.headers.get("content-type") || "";
				var isJson = type.indexOf("application/json") === 0 || type.indexOf("application/problem+json") === 0;
				var declared = parseInt(res.headers.get("content-length") || "", 10);
				if (Number.isFinite(declared) && declared > maxBytes) { throw new ApiError(KINDS.UNEXPECTED, status); }
				return res.text().then(function (text) {
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
	function parseUtc(v) {
		if (typeof v !== "string" || v.length > 64) { return NaN; }
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
			clearSession();
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
	function login(email, password) {
		clearSession();
		return request("POST", "/v1/auth/login", { body: { email: email, password: password } })
			.then(function (r) { adoptTokens(r.body); return true; });
	}

	// Single-flight refresh. A failed refresh ends the local session.
	function refresh() {
		if (refreshInFlight) { return refreshInFlight; }
		var token = state.refreshToken;
		if (!token) { return Promise.reject(new ApiError(KINDS.UNAUTHENTICATED, 401)); }
		refreshInFlight = request("POST", "/v1/auth/refresh", { body: { refreshToken: token } })
			.then(function (r) { adoptTokens(r.body); return true; })
			.catch(function (err) {
				if (err instanceof ApiError && (err.kind === KINDS.UNAUTHENTICATED || err.kind === KINDS.INVALID)) {
					clearSession();
				}
				throw err;
			})
			.finally(function () { refreshInFlight = null; });
		return refreshInFlight;
	}

	// ---- authenticated endpoints ----
	function withAccessToken() {
		if (!isSignedIn()) { return Promise.reject(new ApiError(KINDS.UNAUTHENTICATED, 401)); }
		var needsRefresh = !state.accessToken || (state.accessExpiresAt - Date.now()) < cfg.refreshSkewMs;
		var ready = needsRefresh ? refresh() : Promise.resolve(true);
		return ready.then(function () { return state.accessToken; });
	}

	function authed(method, path, options) {
		return withAccessToken().then(function (token) {
			var opts = Object.assign({}, options || {}, { accessToken: token });
			return request(method, path, opts).catch(function (err) {
				// A 401 on a token we believed valid means the session is gone server-side.
				if (err instanceof ApiError && err.kind === KINDS.UNAUTHENTICATED) { clearSession(); }
				throw err;
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
		return authed("GET", "/v1/account/sessions").then(function (r) {
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
		return authed("GET", "/v1/sync/envelope", { maxBytes: cfg.maxEnvelopeResponseBytes })
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
		return authed("PUT", "/v1/sync/envelope", { body: { baseRevision: baseRevision, envelope: btoa(binary) } })
			.then(function (r) {
				var stored = parseSyncStatus(r.body, r.status);
				if (stored.sizeBytes !== envelopeBytes.length || stored.revision <= baseRevision) { throw new ApiError(KINDS.UNEXPECTED, r.status); }
				return stored;
			});
	}

	// Permanently deletes the signed-in account (and the vault stored on the server) after the
	// server re-checks the account password. The local session is gone either way on success.
	function deleteAccount(password) {
		if (typeof password !== "string" || password.length === 0 || password.length > cfg.passwordMaxLength) {
			return Promise.reject(new ApiError(KINDS.FORBIDDEN, 403));
		}
		return authed("POST", "/v1/account/delete", { body: { password: password } })
			.then(function () { clearSession(); return true; });
	}

	function logout() {
		return authed("POST", "/v1/auth/logout").then(function () { clearSession(); return true; })
			.catch(function (err) { clearSession(); throw err; });
	}

	function logoutAll() {
		return authed("POST", "/v1/auth/logout-all").then(function () { clearSession(); return true; })
			.catch(function (err) { clearSession(); throw err; });
	}

	global.bitosxApi = Object.freeze({
		ApiError: ApiError,
		KINDS: KINDS,
		isSignedIn: isSignedIn,
		clearSession: clearSession,
		register: register,
		resendVerification: resendVerification,
		verifyEmail: verifyEmail,
		login: login,
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
		logoutAll: logoutAll
	});
})(window);
