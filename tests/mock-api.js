// In-process mock of the BitosX account API, used by the Playwright e2e test.
// It mirrors the documented contract in bitosx-api/docs/API.md closely enough
// to exercise every path the web app takes: generic 202s, generic 401s,
// ProblemDetails bodies, 204s, Retry-After on 429, single-use refresh tokens.
// It is NOT a reference implementation of the server.
"use strict";

const crypto = require("node:crypto");

function problem(status, title, detail) {
	return {
		status,
		contentType: "application/problem+json",
		body: JSON.stringify({ type: "about:blank", title, status, detail })
	};
}
function json(status, obj) {
	return { status, contentType: "application/json", body: JSON.stringify(obj) };
}
function noContent() { return { status: 204, contentType: null, body: "" }; }

function createMockApi(options = {}) {
	const now = () => Date.now();
	const accounts = new Map(); // email -> { id, password, verified, createdAt }
	const verificationTokens = new Map(); // token -> email
	const resetTokens = new Map(); // token -> email (password reset, verified accounts only)
	const sessions = new Map(); // sessionId -> { accountId, createdAt, lastSeenAt, expiresAt, revoked }
	const refreshTokens = new Map(); // refreshToken -> { sessionId, consumed }
	const accessTokens = new Map(); // accessToken -> sessionId
	const calls = []; // { method, path, body, headers }
	const envelopes = new Map(); // accountId -> { bytes, revision, updatedAt, fingerprintOverride }
	const totp = new Map(); // accountId -> { secret (Buffer), confirmed, lastUsedStep, recoveryCodes: Map(code -> used) }
	const mfaChallenges = new Map(); // mfaToken -> { accountId, expiresAt, attempts, consumed, password }

	const accessLifetimeMs = options.accessLifetimeMs ?? 15 * 60 * 1000;
	const flags = { emailDelivery: true, rateLimitLogin: false, rateLimitForgot: false, failHealth: false, totpCapability: true };

	function seedAccount(email, password) {
		const id = crypto.randomUUID();
		accounts.set(email.toLowerCase(), { id, email, password, verified: true, createdAt: new Date(now() - 86400000).toISOString() });
		return id;
	}
	function seedVerificationToken(email) {
		const token = crypto.randomBytes(32).toString("base64url");
		verificationTokens.set(token, email.toLowerCase());
		if (!accounts.has(email.toLowerCase())) {
			accounts.set(email.toLowerCase(), { id: crypto.randomUUID(), email, password: null, verified: false, createdAt: new Date().toISOString() });
		}
		return token;
	}
	// Gives an account a confirmed TOTP secret (as the real enrollment would). Returns the raw secret.
	function seedTotp(accountId, recoveryCodes = ["abcde-fghjk", "mnpqr-stuvw"]) {
		const secret = crypto.randomBytes(20);
		totp.set(accountId, { secret, confirmed: true, lastUsedStep: null, recoveryCodes: new Map(recoveryCodes.map(c => [c, false])) });
		return secret;
	}
	function totpStatusOf(accountId) {
		const t = totp.get(accountId);
		if (!t) { return { enabled: false, confirmedAt: null, recoveryCodesRemaining: 0, pendingEnrollment: false }; }
		const remaining = [...t.recoveryCodes.values()].filter(used => !used).length;
		return { enabled: t.confirmed, confirmedAt: t.confirmed ? new Date(now() - 60000).toISOString() : null, recoveryCodesRemaining: t.confirmed ? remaining : 0, pendingEnrollment: !t.confirmed };
	}
	function newRecoveryCodes() {
		const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
		const codes = [];
		while (codes.length < 10) {
			let c = "";
			for (let i = 0; i < 10; i++) { c += alphabet[crypto.randomInt(alphabet.length)]; }
			codes.push(c.slice(0, 5) + "-" + c.slice(5));
		}
		return codes;
	}
	// Verifies and consumes a TOTP code (±1 step, replay guard) or a recovery code. Mirrors the server.
	function consumeCode(t, code) {
		const trimmed = String(code).trim();
		if (/^[0-9]{6}$/.test(trimmed)) {
			const step = totpStep(now());
			for (const candidate of [step - 1, step, step + 1]) {
				if (t.lastUsedStep !== null && candidate <= t.lastUsedStep) { continue; }
				if (totpCode(t.secret, candidate) === trimmed) { t.lastUsedStep = candidate; return true; }
			}
			return false;
		}
		const canonical = trimmed.toLowerCase().replace(/[- ]/g, "");
		for (const [c, used] of t.recoveryCodes) {
			if (!used && c.replace("-", "") === canonical) { t.recoveryCodes.set(c, true); return true; }
		}
		return false;
	}
	function seedResetToken(email) {
		const token = crypto.randomBytes(32).toString("base64url");
		resetTokens.set(token, email.toLowerCase());
		return token;
	}
	function revokeAllSessions(accountId) {
		for (const s of sessions.values()) { if (s.accountId === accountId) { s.revoked = true; } }
	}
	function seedSession(accountId, ageMs) {
		const id = crypto.randomUUID();
		sessions.set(id, {
			accountId, createdAt: new Date(now() - ageMs).toISOString(),
			lastSeenAt: new Date(now() - ageMs / 2).toISOString(),
			expiresAt: new Date(now() + 30 * 86400000).toISOString(), revoked: false
		});
		return id;
	}

	// Puts an encrypted envelope on the "server" for an account, as a desktop sync would.
	// fingerprintOverride lets a test make the server lie about the bytes.
	function seedEnvelope(accountId, bytes, options = {}) {
		const prev = envelopes.get(accountId);
		envelopes.set(accountId, {
			bytes: Buffer.from(bytes), revision: prev ? prev.revision + 1 : 1,
			updatedAt: new Date(now()).toISOString(), fingerprintOverride: options.fingerprintOverride || null
		});
	}
	function envelopeStatus(e) {
		return {
			revision: e.revision,
			fingerprint: e.fingerprintOverride || crypto.createHash("sha256").update(e.bytes).digest("hex"),
			sizeBytes: e.bytes.length,
			updatedAt: e.updatedAt
		};
	}

	function issueTokens(sessionId) {
		const accessToken = "jwt." + crypto.randomBytes(24).toString("base64url");
		const refreshToken = crypto.randomBytes(32).toString("base64url");
		accessTokens.set(accessToken, sessionId);
		refreshTokens.set(refreshToken, { sessionId, consumed: false });
		return {
			accessToken,
			accessTokenExpiresAt: new Date(now() + accessLifetimeMs).toISOString(),
			refreshToken,
			refreshTokenExpiresAt: new Date(now() + 30 * 86400000).toISOString(),
			tokenType: "Bearer"
		};
	}

	function authenticate(headers) {
		const auth = headers["authorization"] || "";
		if (!auth.startsWith("Bearer ")) { return null; }
		const sid = accessTokens.get(auth.slice(7));
		if (!sid) { return null; }
		const s = sessions.get(sid);
		if (!s || s.revoked) { return null; }
		s.lastSeenAt = new Date(now()).toISOString();
		return { sessionId: sid, session: s };
	}

	// The real server caps auth bodies at 4 KiB and only the envelope upload at ~22 MiB.
	function parseBody(raw, limit) {
		if (!raw) { return {}; }
		if (Buffer.byteLength(raw) > limit) { return { __tooLarge: true }; }
		try { return JSON.parse(raw); } catch { return { __malformed: true }; }
	}

	// Returns { status, contentType, body, headers? }
	function handle(method, path, headers, rawBody) {
		const isUpload = method === "PUT" && path === "/v1/sync/envelope";
		const body = parseBody(rawBody, isUpload ? 23 * 1024 * 1024 : 4096);
		calls.push({ method, path, body, headers });
		if (body.__tooLarge) { return problem(413, "Payload Too Large", "Request body too large."); }
		if (body.__malformed) { return problem(400, "Bad Request", "Malformed JSON."); }

		if (method === "GET" && path === "/health") {
			return flags.failHealth ? problem(503, "Service unavailable", "down") : json(200, { service: "BitosX API", status: "healthy" });
		}
		if (method === "GET" && path === "/version") { return json(200, { service: "BitosX API", version: "0.1.0" }); }

		if (method === "POST" && (path === "/v1/auth/register" || path === "/v1/auth/resend-verification")) {
			if (typeof body.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
				return problem(400, "Bad Request", "Invalid email address.");
			}
			if (!flags.emailDelivery) { return problem(503, "Service unavailable", "Service temporarily unavailable. Try again later."); }
			if (path === "/v1/auth/register" && !accounts.has(body.email.toLowerCase())) {
				seedVerificationToken(body.email);
			}
			return json(202, { message: "If the address can be registered or needs verification, check your email." });
		}

		if (method === "POST" && path === "/v1/auth/verify-email") {
			if (typeof body.password !== "string" || body.password.length < 12 || body.password.length > 128) {
				return problem(400, "Bad Request", "Password must be 12-128 characters.");
			}
			const email = typeof body.token === "string" ? verificationTokens.get(body.token) : undefined;
			if (!email) { return problem(400, "Bad Request", "Invalid or expired verification token."); }
			verificationTokens.delete(body.token);
			const acct = accounts.get(email);
			acct.password = body.password;
			acct.verified = true;
			return json(200, { message: "Your email is verified and your password is set." });
		}

		if (method === "POST" && path === "/v1/auth/forgot-password") {
			if (flags.rateLimitForgot) {
				return { ...problem(429, "Too Many Requests", "Too many requests. Try again later."), headers: { "Retry-After": "60" } };
			}
			if (!flags.emailDelivery) { return problem(503, "Service unavailable", "Email verification is temporarily unavailable."); }
			// Generic for every address; a reset token exists only for a verified account with a password.
			const acct = typeof body.email === "string" ? accounts.get(body.email.toLowerCase()) : undefined;
			if (acct && acct.verified && acct.password !== null) { seedResetToken(acct.email); }
			return json(202, { message: "If an account exists for this address, check your email for a password-reset link." });
		}

		if (method === "POST" && path === "/v1/auth/reset-password") {
			if (typeof body.password !== "string" || body.password.length < 12 || body.password.length > 128) {
				return problem(400, "Invalid request", "Password must be between 12 and 128 characters.");
			}
			const email = typeof body.token === "string" ? resetTokens.get(body.token) : undefined;
			const acct = email ? accounts.get(email) : undefined;
			if (!acct || !acct.verified || acct.password === null) { return problem(400, "Invalid request", "Invalid or expired password-reset token."); }
			resetTokens.delete(body.token);
			for (const [t, e] of resetTokens) { if (e === email) { resetTokens.delete(t); } }
			acct.password = body.password;
			revokeAllSessions(acct.id);
			return json(200, { message: "Your password has been reset. Sign in again on every device." });
		}

		if (method === "POST" && path === "/v1/auth/login") {
			if (flags.rateLimitLogin) {
				return { ...problem(429, "Too Many Requests", "Too many requests. Try again later."), headers: { "Retry-After": "30" } };
			}
			const acct = typeof body.email === "string" ? accounts.get(body.email.toLowerCase()) : undefined;
			if (!acct || !acct.verified || acct.password === null || acct.password !== body.password) {
				return problem(401, "Unauthorized", "Invalid email or password.");
			}
			const t = totp.get(acct.id);
			if (t && t.confirmed) {
				if (!flags.totpCapability) { return problem(503, "Service unavailable", "Two-factor sign-in is temporarily unavailable."); }
				const token = crypto.randomBytes(32).toString("base64url");
				mfaChallenges.set(token, { accountId: acct.id, expiresAt: now() + 5 * 60000, attempts: 0, consumed: false, password: acct.password, userAgent: headers["user-agent"] });
				return json(202, { mfaToken: token, mfaTokenExpiresAt: new Date(now() + 5 * 60000).toISOString(), method: "totp" });
			}
			const sid = seedSession(acct.id, 0);
			return json(200, issueTokens(sid));
		}

		if (method === "POST" && path === "/v1/auth/login/totp") {
			if (!flags.totpCapability) { return problem(503, "Service unavailable", "Two-factor sign-in is temporarily unavailable."); }
			const generic = () => problem(401, "Unauthorized", "Invalid or expired sign-in code.");
			const ch = typeof body.mfaToken === "string" ? mfaChallenges.get(body.mfaToken) : undefined;
			if (!ch || ch.consumed || ch.expiresAt <= now()) { return generic(); }
			const acct = [...accounts.values()].find(a => a.id === ch.accountId);
			const t = totp.get(ch.accountId);
			if (!acct || acct.password !== ch.password || !t || !t.confirmed) { ch.consumed = true; return generic(); }
			if (typeof body.code !== "string" || !consumeCode(t, body.code)) {
				ch.attempts++;
				if (ch.attempts >= 5) { ch.consumed = true; }
				return generic();
			}
			ch.consumed = true;
			const sid = seedSession(acct.id, 0);
			return json(200, issueTokens(sid));
		}

		if (method === "POST" && path === "/v1/auth/refresh") {
			const rec = typeof body.refreshToken === "string" ? refreshTokens.get(body.refreshToken) : undefined;
			if (!rec) { return problem(401, "Unauthorized", "Invalid or expired refresh token."); }
			const s = sessions.get(rec.sessionId);
			if (rec.consumed || !s || s.revoked) {
				// Strict reuse: revoke the whole session.
				if (s) { s.revoked = true; }
				return problem(401, "Unauthorized", "Invalid or expired refresh token.");
			}
			rec.consumed = true;
			return json(200, issueTokens(rec.sessionId));
		}

		// ---- authenticated ----
		const auth = authenticate(headers);
		if (!auth) { return problem(401, "Unauthorized", "Unauthorized"); }

		if (method === "POST" && path === "/v1/auth/logout") { auth.session.revoked = true; return noContent(); }
		if (method === "POST" && path === "/v1/auth/logout-all") {
			for (const s of sessions.values()) { if (s.accountId === auth.session.accountId) { s.revoked = true; } }
			return noContent();
		}
		if (path === "/v1/account/totp" || path.startsWith("/v1/account/totp/")) {
			if (!flags.totpCapability) { return problem(503, "Service unavailable", "Two-factor authentication is temporarily unavailable."); }
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			const t = totp.get(acct.id);
			const forbidden = () => problem(403, "Forbidden", "Password confirmation failed.");
			if (method === "GET" && path === "/v1/account/totp") { return json(200, totpStatusOf(acct.id)); }
			if (method === "POST" && path === "/v1/account/totp/enroll") {
				if (typeof body.password !== "string" || body.password !== acct.password) { return forbidden(); }
				if (t && t.confirmed) { return problem(409, "Conflict", "Two-factor authentication is already enabled. Disable it first."); }
				const secret = crypto.randomBytes(20);
				totp.set(acct.id, { secret, confirmed: false, lastUsedStep: null, recoveryCodes: new Map() });
				const b32 = base32(secret);
				return json(200, { secret: b32, otpauthUri: `otpauth://totp/BitosX:${encodeURIComponent(acct.email)}?secret=${b32}&issuer=BitosX&algorithm=SHA1&digits=6&period=30`, issuer: "BitosX", label: acct.email, digits: 6, periodSeconds: 30 });
			}
			if (method === "POST" && path === "/v1/account/totp/confirm") {
				if (!t || t.confirmed) { return problem(409, "Conflict", "There is no enrollment to confirm. Start enrollment first."); }
				const step = totpStep(now());
				const ok = typeof body.code === "string" && [step - 1, step, step + 1].some(s => totpCode(t.secret, s) === body.code.trim());
				if (!ok) { return problem(400, "Invalid request", "The code is not valid. Check the time on your device and try the next code."); }
				t.confirmed = true;
				t.lastUsedStep = step;
				const codes = newRecoveryCodes();
				t.recoveryCodes = new Map(codes.map(c => [c, false]));
				return json(200, { recoveryCodes: codes });
			}
			if (method === "POST" && (path === "/v1/account/totp/disable" || path === "/v1/account/totp/recovery-codes")) {
				if (!t || !t.confirmed) { return problem(409, "Conflict", "Two-factor authentication is not enabled."); }
				if (typeof body.password !== "string" || body.password !== acct.password) { return forbidden(); }
				if (typeof body.code !== "string" || !consumeCode(t, body.code)) { return forbidden(); }
				if (path === "/v1/account/totp/disable") {
					totp.delete(acct.id);
					for (const [k, ch] of mfaChallenges) { if (ch.accountId === acct.id) { mfaChallenges.delete(k); } }
					return noContent();
				}
				const codes = newRecoveryCodes();
				t.recoveryCodes = new Map(codes.map(c => [c, false]));
				return json(200, { recoveryCodes: codes });
			}
			return problem(404, "Not Found", "Not found.");
		}
		if (method === "POST" && path === "/v1/account/delete") {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			if (typeof body.password !== "string" || body.password.length === 0 || !acct || acct.password !== body.password) {
				return problem(403, "Forbidden", "Password confirmation failed.");
			}
			accounts.delete(acct.email.toLowerCase());
			revokeAllSessions(acct.id);
			envelopes.delete(acct.id);
			for (const [t, e] of resetTokens) { if (e === acct.email.toLowerCase()) { resetTokens.delete(t); } }
			return noContent();
		}
		if (method === "GET" && path === "/v1/account/me") {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			return json(200, { accountId: acct.id, email: acct.email, emailVerified: acct.verified, createdAt: acct.createdAt });
		}
		if (method === "GET" && path === "/v1/account/sessions") {
			const list = [...sessions.entries()]
				.filter(([, s]) => s.accountId === auth.session.accountId && !s.revoked)
				.map(([id, s]) => ({ id, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt, expiresAt: s.expiresAt, current: id === auth.sessionId }));
			return json(200, list);
		}
		if (method === "GET" && path === "/v1/sync/status") {
			const e = envelopes.get(auth.session.accountId);
			return e ? json(200, envelopeStatus(e)) : problem(404, "Not Found", "No vault is stored for this account.");
		}
		if (method === "GET" && path === "/v1/sync/envelope") {
			const e = envelopes.get(auth.session.accountId);
			if (!e) { return problem(404, "Not Found", "No vault is stored for this account."); }
			const r = json(200, Object.assign(envelopeStatus(e), { envelope: e.bytes.toString("base64") }));
			r.headers = { "Cache-Control": "no-store" };
			return r;
		}
		if (method === "PUT" && path === "/v1/sync/envelope") {
			if (!Number.isInteger(body.baseRevision) || body.baseRevision < 0 || typeof body.envelope !== "string") {
				return problem(400, "Bad Request", "baseRevision and envelope are required.");
			}
			if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body.envelope) || body.envelope.length % 4 !== 0 || body.envelope.length === 0) {
				return problem(400, "Bad Request", "envelope must be Base64.");
			}
			const bytes = Buffer.from(body.envelope, "base64");
			if (bytes.length > 16 * 1024 * 1024) { return problem(413, "Payload Too Large", "The envelope is larger than allowed."); }
			let doc;
			try { doc = JSON.parse(bytes.toString("utf8")); } catch { doc = null; }
			if (!doc || typeof doc !== "object" || Array.isArray(doc) || !Number.isInteger(doc.version) || doc.version < 1) {
				return problem(400, "Bad Request", "The envelope is not a vault envelope.");
			}
			const current = envelopes.get(auth.session.accountId);
			const currentRevision = current ? current.revision : 0;
			if (body.baseRevision !== currentRevision) {
				const p = problem(409, "Conflict", "The server holds a newer revision.");
				p.body = JSON.stringify(Object.assign(JSON.parse(p.body), { currentRevision }));
				return p;
			}
			seedEnvelope(auth.session.accountId, bytes);
			return json(200, envelopeStatus(envelopes.get(auth.session.accountId)));
		}
		if (method === "DELETE" && path === "/v1/sync/envelope") {
			envelopes.delete(auth.session.accountId);
			return noContent();
		}
		const m = /^\/v1\/account\/sessions\/([0-9a-f-]{36})$/i.exec(path);
		if (method === "DELETE" && m) {
			const s = sessions.get(m[1]);
			if (!s || s.accountId !== auth.session.accountId) { return problem(404, "Not Found", "Not found."); }
			s.revoked = true;
			return noContent();
		}
		return problem(404, "Not Found", "Not found.");
	}

	return { handle, calls, flags, seedAccount, seedVerificationToken, seedResetToken, seedSession, seedEnvelope, seedTotp, sessions, accounts, envelopes, resetTokens, totp, mfaChallenges };
}

// ---- RFC 6238 (HMAC-SHA1, 6 digits, 30 s) and RFC 4648 Base32, for the mock and the tests ----
function totpStep(unixMs) { return Math.floor(unixMs / 1000 / 30); }
function totpCode(secret, step) {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(step));
	const mac = crypto.createHmac("sha1", secret).update(counter).digest();
	const offset = mac[19] & 0x0f;
	const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
	return String(binary % 1000000).padStart(6, "0");
}
function base32(buf) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = 0, value = 0, out = "";
	for (const b of buf) {
		value = (value << 8) | b; bits += 8;
		while (bits >= 5) { bits -= 5; out += alphabet[(value >>> bits) & 31]; }
	}
	if (bits > 0) { out += alphabet[(value << (5 - bits)) & 31]; }
	return out;
}
function base32Decode(text) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = 0, value = 0;
	const out = [];
	for (const ch of text.toUpperCase().replace(/=+$/, "")) {
		const v = alphabet.indexOf(ch);
		if (v < 0) { throw new Error("not base32"); }
		value = (value << 5) | v; bits += 5;
		if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 255); }
	}
	return Buffer.from(out);
}

module.exports = { createMockApi, totpStep, totpCode, base32, base32Decode };
