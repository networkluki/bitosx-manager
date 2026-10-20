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
	const sessions = new Map(); // sessionId -> { accountId, createdAt, lastSeenAt, expiresAt, revoked }
	const refreshTokens = new Map(); // refreshToken -> { sessionId, consumed }
	const accessTokens = new Map(); // accessToken -> sessionId
	const calls = []; // { method, path, body, headers }

	const accessLifetimeMs = options.accessLifetimeMs ?? 15 * 60 * 1000;
	const flags = { emailDelivery: true, rateLimitLogin: false, failHealth: false };

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
	function seedSession(accountId, ageMs) {
		const id = crypto.randomUUID();
		sessions.set(id, {
			accountId, createdAt: new Date(now() - ageMs).toISOString(),
			lastSeenAt: new Date(now() - ageMs / 2).toISOString(),
			expiresAt: new Date(now() + 30 * 86400000).toISOString(), revoked: false
		});
		return id;
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

	function parseBody(raw) {
		if (!raw) { return {}; }
		if (Buffer.byteLength(raw) > 4096) { return { __tooLarge: true }; }
		try { return JSON.parse(raw); } catch { return { __malformed: true }; }
	}

	// Returns { status, contentType, body, headers? }
	function handle(method, path, headers, rawBody) {
		const body = parseBody(rawBody);
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

		if (method === "POST" && path === "/v1/auth/login") {
			if (flags.rateLimitLogin) {
				return { ...problem(429, "Too Many Requests", "Too many requests. Try again later."), headers: { "Retry-After": "30" } };
			}
			const acct = typeof body.email === "string" ? accounts.get(body.email.toLowerCase()) : undefined;
			if (!acct || !acct.verified || acct.password === null || acct.password !== body.password) {
				return problem(401, "Unauthorized", "Invalid email or password.");
			}
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
		const m = /^\/v1\/account\/sessions\/([0-9a-f-]{36})$/i.exec(path);
		if (method === "DELETE" && m) {
			const s = sessions.get(m[1]);
			if (!s || s.accountId !== auth.session.accountId) { return problem(404, "Not Found", "Not found."); }
			s.revoked = true;
			return noContent();
		}
		return problem(404, "Not Found", "Not found.");
	}

	return { handle, calls, flags, seedAccount, seedVerificationToken, seedSession, sessions, accounts };
}

module.exports = { createMockApi };
