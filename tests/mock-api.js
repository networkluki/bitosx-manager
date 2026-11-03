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
	// The server's clock: real time, unless a test moves it (offsetMs) or stops it (frozenAt), so
	// that TOTP codes and expiries are computed from a time the test controls.
	const clock = { offsetMs: 0, frozenAt: null, freeze(ms) { this.frozenAt = ms; }, unfreeze() { this.frozenAt = null; } };
	const now = () => (clock.frozenAt !== null ? clock.frozenAt : Date.now() + clock.offsetMs);
	const accounts = new Map(); // email -> { id, password, verified, createdAt }
	const verificationTokens = new Map(); // token -> email
	const resetTokens = new Map(); // token -> email (password reset, verified accounts only)
	const sessions = new Map(); // sessionId -> { accountId, createdAt, lastSeenAt, expiresAt, revoked }
	const refreshTokens = new Map(); // refreshToken -> { sessionId, consumed }
	const accessTokens = new Map(); // accessToken -> { sessionId, expiresAt }
	const calls = []; // { method, path, body, headers }
	const envelopes = new Map(); // accountId -> { bytes, revision, updatedAt, fingerprintOverride }
	const totp = new Map(); // accountId -> { secret (Buffer), confirmed, lastUsedStep, recoveryCodes: Map(code -> used) }
	const mfaChallenges = new Map(); // mfaToken -> { accountId, expiresAt, attempts, consumed, password }
	const lastRevisions = new Map(); // accountId -> the last revision ever stored (revisions never restart)
	// Passkeys (phase 10). The mock checks what a WebAuthn server checks that a browser could get
	// wrong: the client data (type, challenge, origin), the RP ID hash, the flags, and the ES256
	// signature against the public key the registration delivered (toJSON's response.publicKey).
	const passkeys = new Map(); // accountId -> [{ id, credentialId, publicKey (DER SPKI), name, createdAt, lastUsedAt, backedUp, signCount }]
	const userHandles = new Map(); // accountId -> base64url of 32 random bytes
	const ceremonies = new Map(); // registrationId / assertionId -> { purpose, accountId, challenge, expiresAt, used }
	const passkeyMax = 10;
	const rpId = options.rpId ?? "localhost";
	const webauthn = { origin: options.webOrigin ?? null }; // the page origin the client data must name (a test sets it)

	const accessLifetimeMs = options.accessLifetimeMs ?? 15 * 60 * 1000;
	// JwtOptions.ClockSkew: the server still accepts an access token this long after its expiry.
	const accessClockSkewMs = 60 * 1000;
	// TotpOptions: the digit count is configurable (6..8, default 6); a challenge allows 5 wrong codes.
	const totpDigits = options.totpDigits ?? 6;
	const mfaMaxAttempts = 5;
	const flags = { emailDelivery: true, rateLimitLogin: false, rateLimitForgot: false, failHealth: false, totpCapability: true, capacity503: false, passkeyCapability: true };

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
	function matchTotp(t, trimmed) {
		const step = totpStep(now());
		for (const candidate of [step - 1, step, step + 1]) {
			if (t.lastUsedStep !== null && candidate <= t.lastUsedStep) { continue; }
			if (totpCode(t.secret, candidate, totpDigits) === trimmed) { return candidate; }
		}
		return null;
	}
	function consumeCode(t, code) {
		const trimmed = String(code).trim();
		if (/^[0-9]+$/.test(trimmed)) {
			if (trimmed.length !== totpDigits) { return false; }
			const matched = matchTotp(t, trimmed);
			if (matched === null) { return false; }
			t.lastUsedStep = matched;
			return true;
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
	function revokeAllSessions(accountId, exceptSessionId) {
		for (const [id, s] of sessions) { if (s.accountId === accountId && id !== exceptSessionId) { s.revoked = true; } }
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
		const revision = (lastRevisions.get(accountId) || 0) + 1;
		lastRevisions.set(accountId, revision);
		envelopes.set(accountId, {
			bytes: Buffer.from(bytes), revision,
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
		accessTokens.set(accessToken, { sessionId, expiresAt: now() + accessLifetimeMs });
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
		const rec = accessTokens.get(auth.slice(7));
		// The server checks the token's own expiry (with its clock skew), whatever the client believes.
		if (!rec || now() > rec.expiresAt + accessClockSkewMs) { return null; }
		const sid = rec.sessionId;
		const s = sessions.get(sid);
		if (!s || s.revoked) { return null; }
		s.lastSeenAt = new Date(now()).toISOString();
		return { sessionId: sid, session: s };
	}

	// The real server caps the bodies of these endpoints at 4 KiB (RejectOversizedBody), the three
	// that carry a WebAuthn credential at 16 KiB; the rest are bounded by Kestrel's 64 KiB, and only
	// the envelope upload may be ~22 MiB.
	const SMALL_BODY = new Set(["/v1/auth/forgot-password", "/v1/auth/reset-password", "/v1/auth/login", "/v1/auth/login/totp",
		"/v1/auth/refresh", "/v1/account/delete", "/v1/account/password", "/v1/account/totp/enroll", "/v1/account/totp/confirm",
		"/v1/account/totp/disable", "/v1/account/totp/recovery-codes", "/v1/auth/login/passkey/options", "/v1/auth/passkey/options",
		"/v1/account/passkeys/registration/options"]);
	const CREDENTIAL_BODY = new Set(["/v1/auth/login/passkey", "/v1/auth/passkey", "/v1/account/passkeys/registration"]);
	const bodyLimit = (path) => SMALL_BODY.has(path) || /^\/v1\/account\/passkeys\/[^/]+\/(rename|delete)$/.test(path) ? 4096 : CREDENTIAL_BODY.has(path) ? 16384 : 64 * 1024;
	function parseBody(raw, limit) {
		if (!raw) { return {}; }
		if (Buffer.byteLength(raw) > limit) { return { __tooLarge: true }; }
		try { return JSON.parse(raw); } catch { return { __malformed: true }; }
	}

	// ---- WebAuthn, as far as a mock server needs it ----
	function requestOptions(challenge, list, userVerification) {
		return { challenge, timeout: 300000, rpId, allowCredentials: list.map(p => ({ type: "public-key", id: p.credentialId })), userVerification, hints: [] };
	}
	function publicPasskey(p) {
		const out = { id: p.id, name: p.name, createdAt: p.createdAt, backedUp: p.backedUp };
		if (p.lastUsedAt) { out.lastUsedAt = p.lastUsedAt; }
		return out;
	}
	function fromB64u(text) {
		if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) { return null; }
		return Buffer.from(text, "base64url");
	}
	// The client data must be this ceremony's: type, challenge and the page origin.
	function clientDataOk(response, type, challenge) {
		const raw = fromB64u(response && response.clientDataJSON);
		if (!raw) { return false; }
		let cd;
		try { cd = JSON.parse(raw.toString("utf8")); } catch { return false; }
		return cd.type === type && cd.challenge === challenge && (webauthn.origin === null || cd.origin === webauthn.origin);
	}
	// authenticatorData: rpIdHash(32) flags(1) signCount(4) ...
	function authDataOk(authData, requireUv) {
		if (!authData || authData.length < 37) { return null; }
		if (!authData.subarray(0, 32).equals(crypto.createHash("sha256").update(rpId).digest())) { return null; }
		const flags = authData[32];
		if (!(flags & 0x01) || (requireUv && !(flags & 0x04))) { return null; }
		return { flags, signCount: authData.readUInt32BE(33) };
	}
	function verifyRegistration(credential, challenge) {
		if (!credential || credential.type !== "public-key" || typeof credential.id !== "string" || credential.rawId !== credential.id) { return null; }
		const r = credential.response || {};
		if (!clientDataOk(r, "webauthn.create", challenge) || typeof r.attestationObject !== "string") { return null; }
		const authData = fromB64u(r.authenticatorData);
		const ad = authDataOk(authData, true);
		const spki = fromB64u(r.publicKey);
		if (!ad || !spki || r.publicKeyAlgorithm !== -7) { return null; }
		try { crypto.createPublicKey({ key: spki, format: "der", type: "spki" }); } catch { return null; }
		return { credentialId: credential.id, publicKey: spki, backedUp: !!(ad.flags & 0x10), signCount: ad.signCount };
	}
	function verifyAssertion(credential, challenge, list, requireUv) {
		if (!credential || credential.type !== "public-key" || typeof credential.id !== "string" || credential.rawId !== credential.id) { return null; }
		const pk = list.find(p => p.credentialId === credential.id);
		const r = credential.response || {};
		if (!pk || !clientDataOk(r, "webauthn.get", challenge)) { return null; }
		const authData = fromB64u(r.authenticatorData);
		const ad = authDataOk(authData, requireUv);
		const sig = fromB64u(r.signature);
		if (!ad || !sig) { return null; }
		const signed = Buffer.concat([authData, crypto.createHash("sha256").update(fromB64u(r.clientDataJSON)).digest()]);
		let ok = false;
		try { ok = crypto.verify("sha256", signed, crypto.createPublicKey({ key: pk.publicKey, format: "der", type: "spki" }), sig); } catch { ok = false; }
		if (!ok) { return null; }
		if ((ad.signCount !== 0 || pk.signCount !== 0) && ad.signCount <= pk.signCount) { return null; } // a possible clone
		pk.signCount = ad.signCount;
		pk.backedUp = !!(ad.flags & 0x10);
		pk.lastUsedAt = new Date(now()).toISOString();
		return pk;
	}

	// Returns { status, contentType, body, headers? }
	function handle(method, path, headers, rawBody) {
		const isUpload = method === "PUT" && path === "/v1/sync/envelope";
		const body = parseBody(rawBody, isUpload ? 23 * 1024 * 1024 : bodyLimit(path));
		calls.push({ method, path, body, headers });
		if (body.__tooLarge) { return problem(413, "Payload Too Large", "Request body too large."); }
		if (body.__malformed) { return problem(400, "Bad Request", "Malformed JSON."); }

		if (method === "GET" && path === "/health") {
			return flags.failHealth ? problem(503, "Service unavailable", "down") : json(200, { service: "BitosX API", status: "healthy" });
		}
		if (method === "GET" && path === "/version") { return json(200, { service: "BitosX API", version: "0.1.0" }); }

		// Argon2 admission overload: a generic 503 with Retry-After: 1 (AuthEndpoints.CapacityUnavailable).
		const capacity = () => ({ ...problem(503, "Service unavailable", "The service is temporarily unavailable. Try again shortly."), headers: { "Retry-After": "1" } });

		if (method === "POST" && path === "/v1/auth/resend-verification") {
			// Always the same generic 202 once delivery is on, whatever the address (AuthEndpoints, API.md).
			if (!flags.emailDelivery) { return problem(503, "Service unavailable", "Email verification is temporarily unavailable."); }
			return json(202, { message: "If the address can be registered or needs verification, check your email." });
		}
		if (method === "POST" && path === "/v1/auth/register") {
			if (typeof body.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
				return problem(400, "Bad Request", "Invalid email address.");
			}
			if (!flags.emailDelivery) { return problem(503, "Service unavailable", "Email verification is temporarily unavailable."); }
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
			if (flags.capacity503) { return capacity(); }
			const acct = typeof body.email === "string" ? accounts.get(body.email.toLowerCase()) : undefined;
			if (!acct || !acct.verified || acct.password === null || acct.password !== body.password) {
				return problem(401, "Unauthorized", "Invalid email or password.");
			}
			const t = totp.get(acct.id);
			if (t && t.confirmed) {
				if (!flags.totpCapability) { return problem(503, "Service unavailable", "Two-factor sign-in is temporarily unavailable."); }
				const token = crypto.randomBytes(32).toString("base64url");
				mfaChallenges.set(token, { accountId: acct.id, expiresAt: now() + 5 * 60000, attempts: 0, consumed: false, password: acct.password, userAgent: headers["user-agent"] });
				// (The response states the same expiry.) `methods` lists the passkey only when the account has one.
				const methods = ["totp", "recovery"];
				if (flags.passkeyCapability && (passkeys.get(acct.id) || []).length > 0) { methods.push("passkey"); }
				const answer = { mfaToken: token, mfaTokenExpiresAt: new Date(now() + 5 * 60000).toISOString(), method: "totp" };
				if (!options.legacyLogin) { answer.methods = methods; }
				if (flags.methodsOverride !== undefined) { answer.methods = flags.methodsOverride; } // a test's malformed or future list
				return json(202, answer);
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
				if (ch.attempts >= mfaMaxAttempts) { ch.consumed = true; }
				return generic();
			}
			ch.consumed = true;
			const sid = seedSession(acct.id, 0);
			return json(200, issueTokens(sid));
		}

		const passkeyRoute = path.startsWith("/v1/auth/login/passkey") || path.startsWith("/v1/auth/passkey") || path.startsWith("/v1/account/passkeys");
		if (passkeyRoute && !flags.passkeyCapability) { return problem(404, "Not Found", "Not found."); }
		if (method === "POST" && path === "/v1/auth/login/passkey/options") {
			const generic = () => problem(401, "Unauthorized", "Passkey sign-in failed.");
			const ch = typeof body.mfaToken === "string" ? mfaChallenges.get(body.mfaToken) : undefined;
			if (!ch || ch.consumed || ch.expiresAt <= now()) { return generic(); }
			const list = passkeys.get(ch.accountId) || [];
			if (list.length === 0) { return generic(); }
			ch.passkeyChallenge = b64u(crypto.randomBytes(32)); // replaces the previous one of this token
			return json(200, { options: requestOptions(ch.passkeyChallenge, list, "preferred") });
		}
		if (method === "POST" && path === "/v1/auth/login/passkey") {
			const generic = () => problem(401, "Unauthorized", "Passkey sign-in failed.");
			const ch = typeof body.mfaToken === "string" ? mfaChallenges.get(body.mfaToken) : undefined;
			if (!ch || ch.consumed || ch.expiresAt <= now()) { return generic(); }
			// The attempt is reserved before anything is verified, exactly like a code.
			ch.attempts++;
			if (ch.attempts >= mfaMaxAttempts) { ch.consumed = true; }
			const challenge = ch.passkeyChallenge;
			ch.passkeyChallenge = null; // single use, whatever the outcome
			const acct = [...accounts.values()].find(a => a.id === ch.accountId);
			if (!challenge || !acct || acct.password !== ch.password) { return generic(); }
			const pk = verifyAssertion(body.credential, challenge, passkeys.get(acct.id) || [], false);
			if (!pk) { return generic(); }
			ch.consumed = true;
			return json(200, issueTokens(seedSession(acct.id, 0)));
		}
		if (method === "POST" && path === "/v1/auth/passkey/options") {
			const id = b64u(crypto.randomBytes(32));
			const challenge = b64u(crypto.randomBytes(32));
			ceremonies.set(id, { purpose: "passwordless", accountId: null, challenge, expiresAt: now() + 5 * 60000, used: false });
			return json(200, { assertionId: id, options: requestOptions(challenge, [], "required") });
		}
		if (method === "POST" && path === "/v1/auth/passkey") {
			const generic = () => problem(401, "Unauthorized", "Passkey sign-in failed.");
			const c = typeof body.assertionId === "string" ? ceremonies.get(body.assertionId) : undefined;
			if (!c || c.purpose !== "passwordless" || c.used || c.expiresAt <= now()) { return generic(); }
			c.used = true;
			const owner = body.credential && typeof body.credential.id === "string"
				? [...passkeys.entries()].find(([, list]) => list.some(p => p.credentialId === body.credential.id)) : undefined;
			if (!owner) { return generic(); }
			const [accountId, list] = owner;
			const acct = [...accounts.values()].find(a => a.id === accountId);
			const t = totp.get(accountId);
			if (!acct || !acct.verified || !t || !t.confirmed) { return generic(); }
			const response = body.credential.response || {};
			if (response.userHandle !== userHandles.get(accountId)) { return generic(); }
			const pk = verifyAssertion(body.credential, c.challenge, list, true);
			if (!pk) { return generic(); }
			return json(200, issueTokens(seedSession(accountId, 0)));
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
				return json(200, { secret: b32, otpauthUri: `otpauth://totp/BitosX:${encodeURIComponent(acct.email)}?secret=${b32}&issuer=BitosX&algorithm=SHA1&digits=${totpDigits}&period=30`, issuer: "BitosX", label: acct.email, digits: totpDigits, periodSeconds: 30 });
			}
			if (method === "POST" && path === "/v1/account/totp/confirm") {
				if (!t || t.confirmed) { return problem(409, "Conflict", "There is no enrollment to confirm. Start enrollment first."); }
				// The step that matched is recorded (TotpEnrollmentService passes TryMatchTotp's step on).
				const matched = typeof body.code === "string" ? matchTotp(t, body.code.trim()) : null;
				if (matched === null) { return problem(400, "Invalid request", "The code is not valid. Check the time on your device and try the next code."); }
				t.confirmed = true;
				t.lastUsedStep = matched;
				const codes = newRecoveryCodes();
				t.recoveryCodes = new Map(codes.map(c => [c, false]));
				return json(200, { recoveryCodes: codes });
			}
			if (method === "POST" && (path === "/v1/account/totp/disable" || path === "/v1/account/totp/recovery-codes")) {
				if (!t || !t.confirmed) { return problem(409, "Conflict", "Two-factor authentication is not enabled."); }
				if (path === "/v1/account/totp/disable" && (passkeys.get(acct.id) || []).length > 0) {
					return problem(409, "Conflict", "The account has passkeys. Remove the passkeys first.");
				}
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
		if (path.startsWith("/v1/account/passkeys")) {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			const list = passkeys.get(acct.id) || [];
			const t = totp.get(acct.id);
			const forbidden = () => problem(403, "Forbidden", "Password confirmation failed.");
			const notFound = () => problem(404, "Not found", "Passkey not found.");
			const checkFactors = () => typeof body.password === "string" && body.password === acct.password && typeof body.code === "string" && consumeCode(t, body.code);
			if (method === "GET" && path === "/v1/account/passkeys") {
				return json(200, { passkeys: list.map(publicPasskey), max: passkeyMax });
			}
			if (method === "POST" && path === "/v1/account/passkeys/registration/options") {
				if (!t || !t.confirmed) { return problem(409, "Conflict", "Two-factor authentication is required before a passkey can be added."); }
				if (list.length >= passkeyMax) { return problem(409, "Conflict", "The account already has the most passkeys allowed."); }
				if (!checkFactors()) { return forbidden(); }
				if (!userHandles.has(acct.id)) { userHandles.set(acct.id, b64u(crypto.randomBytes(32))); }
				const id = b64u(crypto.randomBytes(32));
				const challenge = b64u(crypto.randomBytes(32));
				ceremonies.set(id, { purpose: "register", accountId: acct.id, challenge, expiresAt: now() + 5 * 60000, used: false });
				return json(200, { registrationId: id, options: {
					rp: { id: rpId, name: "BitosX" },
					user: { name: acct.email, id: userHandles.get(acct.id), displayName: acct.email },
					challenge,
					pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }],
					timeout: 300000, attestation: "none", attestationFormats: [],
					authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
					hints: [],
					excludeCredentials: list.map(p => ({ type: "public-key", id: p.credentialId }))
				} });
			}
			if (method === "POST" && path === "/v1/account/passkeys/registration") {
				const c = typeof body.registrationId === "string" ? ceremonies.get(body.registrationId) : undefined;
				if (!c || c.purpose !== "register" || c.accountId !== acct.id || c.used || c.expiresAt <= now()) {
					return problem(410, "Gone", "The passkey registration expired or was already used. Start again.");
				}
				const name = normalizePasskeyName(body.name);
				if (name === null) { return problem(400, "Invalid request", "A passkey name must be 1-64 characters without control characters."); }
				c.used = true;
				if (!t || !t.confirmed) { return problem(409, "Conflict", "Two-factor authentication is required before a passkey can be added."); }
				if (list.length >= passkeyMax) { return problem(409, "Conflict", "The account already has the most passkeys allowed."); }
				const reg = verifyRegistration(body.credential, c.challenge);
				if (!reg || [...passkeys.values()].some(l => l.some(p => p.credentialId === reg.credentialId))) {
					return problem(400, "Invalid request", "The passkey could not be verified.");
				}
				const pk = Object.assign(reg, { id: crypto.randomUUID(), name, createdAt: new Date(now()).toISOString(), lastUsedAt: null });
				passkeys.set(acct.id, list.concat([pk]));
				return json(201, { id: pk.id, name: pk.name, createdAt: pk.createdAt, backedUp: pk.backedUp });
			}
			const pm = /^\/v1\/account\/passkeys\/([0-9a-f-]{36})\/(rename|delete)$/i.exec(path);
			if (method === "POST" && pm) {
				const pk = list.find(p => p.id === pm[1]);
				if (!pk) { return notFound(); }
				if (pm[2] === "rename") {
					const name = normalizePasskeyName(body.name);
					if (name === null) { return problem(400, "Invalid request", "A passkey name must be 1-64 characters without control characters."); }
					pk.name = name;
					return noContent();
				}
				if (!t || !t.confirmed || !checkFactors()) { return forbidden(); }
				passkeys.set(acct.id, list.filter(p => p !== pk));
				return noContent();
			}
			return problem(404, "Not Found", "Not found.");
		}
		// A password confirmation, plus the second factor when the account has one (phase-8 contract §6, §7).
		function confirmed(acct, password, code) {
			if (typeof password !== "string" || password.length === 0 || !acct || acct.password !== password) { return false; }
			const t = totp.get(acct.id);
			if (t && t.confirmed) { return typeof code === "string" && consumeCode(t, code); }
			return true;
		}
		// Contract deviation (API): with TOTP confirmed but the server's TOTP capability off, these
		// answer a 503 without Retry-After, not a 403 — fail closed, the session stays valid.
		const secondFactorOff = (acct) => {
			const t = acct && totp.get(acct.id);
			return t && t.confirmed && !flags.totpCapability ? problem(503, "Service unavailable", "Two-factor authentication is temporarily unavailable.") : null;
		};
		if (method === "POST" && path === "/v1/account/password") {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			if (flags.capacity503) { return capacity(); }
			const off = secondFactorOff(acct);
			if (off) { return off; }
			if (typeof body.newPassword !== "string" || body.newPassword.length < 12 || body.newPassword.length > 128) {
				return problem(400, "Invalid request", "Password must be between 12 and 128 characters.");
			}
			if (!confirmed(acct, body.currentPassword, body.code)) { return problem(403, "Forbidden", "Password confirmation failed."); }
			acct.password = body.newPassword;
			revokeAllSessions(acct.id, auth.sessionId);
			for (const [t, e] of resetTokens) { if (e === acct.email.toLowerCase()) { resetTokens.delete(t); } }
			return noContent();
		}
		if (method === "POST" && path === "/v1/account/delete") {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			const off = secondFactorOff(acct);
			if (off) { return off; }
			if (!confirmed(acct, body.password, body.code)) {
				return problem(403, "Forbidden", "Password confirmation failed.");
			}
			accounts.delete(acct.email.toLowerCase());
			revokeAllSessions(acct.id);
			envelopes.delete(acct.id);
			passkeys.delete(acct.id);
			userHandles.delete(acct.id);
			for (const [t, e] of resetTokens) { if (e === acct.email.toLowerCase()) { resetTokens.delete(t); } }
			return noContent();
		}
		if (method === "GET" && path === "/v1/account/me") {
			const acct = [...accounts.values()].find(a => a.id === auth.session.accountId);
			return json(200, { accountId: acct.id, email: acct.email, emailVerified: acct.verified, createdAt: acct.createdAt });
		}
		if (method === "GET" && path === "/v1/account/sessions") {
			// At most 200, newest first (phase-8 contract §3).
			const list = [...sessions.entries()]
				.filter(([, s]) => s.accountId === auth.session.accountId && !s.revoked)
				.sort(([, a], [, b]) => b.createdAt.localeCompare(a.createdAt))
				.slice(0, 200)
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

	return { handle, calls, flags, clock, now, totpDigits, passkeys, userHandles, ceremonies, webauthn, seedAccount, seedVerificationToken, seedResetToken, seedSession, seedEnvelope, seedTotp, sessions, accounts, envelopes, resetTokens, totp, mfaChallenges, accessTokens };
}

function b64u(buf) { return Buffer.from(buf).toString("base64url"); }
// The server's passkey name rule (WebAuthnOptions.NormalizeName): trimmed, 1-64 scalar values, no
// lone surrogates, control characters, line/paragraph separators or bidirectional controls.
function normalizePasskeyName(name) {
	if (typeof name !== "string") { return null; }
	const t = name.trim();
	if (t.length === 0 || !t.isWellFormed() || [...t].length > 64) { return null; }
	if (/[\p{Cc}\p{Zl}\p{Zp}\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/u.test(t)) { return null; }
	return t;
}

// ---- RFC 6238 (HMAC-SHA1, 6-8 digits, 30 s) and RFC 4648 Base32, for the mock and the tests ----
function totpStep(unixMs) { return Math.floor(unixMs / 1000 / 30); }
function totpCode(secret, step, digits = 6) {
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(step));
	const mac = crypto.createHmac("sha1", secret).update(counter).digest();
	const offset = mac[19] & 0x0f;
	const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
	return String(binary % (10 ** digits)).padStart(digits, "0");
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
