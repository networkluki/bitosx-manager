// End-to-end test of the BitosX phase-1 sites in real Chromium (Playwright).
//
// - Serves bitosx/www/public and bitosx/vault/public from two local origins
//   with the same extensionless-HTML resolution Cloudflare / GitHub Pages use.
// - Intercepts every request to https://api.bitosx.se inside the browser and
//   answers it from mock-api.js, so the real config (API origin, CSP
//   connect-src) is exercised without touching the network.
// - Fails on any console error or CSP violation.
//
// Run:  node bitosx/tests/e2e.js        (needs the `playwright` package + Chromium)
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { createMockApi, totpCode, totpStep, base32Decode } = require("./mock-api.js");
const { serveStatic, watchConsole } = require("./harness.js");

const ROOT = path.resolve(__dirname, "..");
const API_ORIGIN = "https://api.bitosx.se";

// ---- The API's browser (CORS) policy, as the API ships it (phase-8 contract §1) ----
// The vault site may use every method the web vault needs; the product page may read /health and
// /version and nothing else. The local test origins stand in for the production ones.
const CORS_POLICY = {
	vault: { production: "https://vault.bitosx.se", methods: ["GET", "POST", "PUT", "DELETE"], headers: ["authorization", "content-type", "accept"], paths: null },
	www: { production: "https://bitosx.se", methods: ["GET"], headers: ["accept"], paths: ["/health", "/version"] }
};
const SAFELISTED_CONTENT_TYPES = ["application/x-www-form-urlencoded", "multipart/form-data", "text/plain"];
const corsRefusals = []; // { origin, method, path, why }

// Route https://api.bitosx.se/** to the mock, with the API's CORS policy enforced here. Playwright
// answers every CORS preflight of an intercepted request itself and allows everything, so the
// browser's preflight check never sees the policy; this handler applies it instead. A request the
// policy would not have allowed fails as it would in a browser (a network error), so a method or
// header missing from the policy fails a test. A response carries Access-Control-Allow-Origin only
// when the policy covers that origin and path, so the browser itself refuses to hand anything else
// to the page.
async function routeApi(page, mock, policyOverride) {
	await page.route(`${API_ORIGIN}/**`, async (route) => {
		const req = route.request();
		const h = req.headers();
		const url = new URL(req.url());
		const method = req.method();
		const origin = h["origin"];
		const site = origin === sites.vault ? "vault" : origin === sites.www ? "www" : null;
		const policy = site ? Object.assign({}, CORS_POLICY[site], (policyOverride || {})[site] || {}) : null;
		const pathAllowed = policy && (!policy.paths || policy.paths.includes(url.pathname));
		const authorHeaders = ["authorization", "content-type"].filter((k) => k in h &&
			!(k === "content-type" && SAFELISTED_CONTENT_TYPES.includes(h[k].split(";")[0].trim().toLowerCase())));
		const needsPreflight = !["GET", "HEAD", "POST"].includes(method) || authorHeaders.length > 0;
		if (origin && needsPreflight) {
			const why = !policy ? "origin not allowed" : !pathAllowed ? "path not allowed for this origin"
				: !policy.methods.includes(method) && !["GET", "HEAD", "POST"].includes(method) ? `method ${method} not allowed`
				: authorHeaders.find((k) => !policy.headers.includes(k)) ? "header not allowed" : null;
			if (why) { corsRefusals.push({ origin, method, path: url.pathname, why }); return route.abort("failed").catch(() => {}); }
		}
		// Tests can hold a request (mock.hold returns a promise) or drop the connection before or
		// after the server handled it (mock.dropBefore / mock.dropAfter: sets of "METHOD /path").
		const key = `${method} ${url.pathname}`;
		if (mock.dropBefore && mock.dropBefore.has(key)) { return route.abort("connectionreset").catch(() => {}); }
		if (mock.hold) { await mock.hold(method, url.pathname); }
		const r = mock.handle(method, url.pathname, h, req.postData());
		if (mock.holdAfter) { await mock.holdAfter(method, url.pathname); } // the server is done; the answer is late
		if (mock.dropAfter && mock.dropAfter.has(key)) { return route.abort("connectionreset").catch(() => {}); }
		const headers = Object.assign({}, r.headers || {}, { "X-Correlation-ID": "test" });
		if (origin && pathAllowed) {
			Object.assign(headers, { "Access-Control-Allow-Origin": origin, "Access-Control-Expose-Headers": "Retry-After, X-Correlation-ID", "Vary": "Origin" });
		} else if (origin) {
			// Playwright adds Access-Control-Allow-Origin to a fulfilled response that has none, which
			// would let the page read it; an origin that is not the page's makes the browser refuse,
			// exactly as a response without the header would.
			headers["Access-Control-Allow-Origin"] = CORS_POLICY.vault.production;
		}
		if (r.contentType) { headers["Content-Type"] = r.contentType; }
		// The page may have given up on the request meanwhile (a time-out, a page going away).
		return route.fulfill({ status: r.status, headers, body: r.body }).catch(() => {});
	});
}
const sites = { vault: null, www: null };

const results = [];
async function test(name, fn) {
	// BITOSX_E2E_ONLY=<text> runs only the tests whose name contains it (plus the hygiene checks).
	if (process.env.BITOSX_E2E_ONLY && !name.includes(process.env.BITOSX_E2E_ONLY) && !name.startsWith("no console errors") && !name.startsWith("static CSP")) { return; }
	try { await fn(); results.push({ name, ok: true }); console.log(`  ok   ${name}`); }
	catch (err) { results.push({ name, ok: false, err }); console.log(`  FAIL ${name}\n       ${err.stack || err}`); }
}

(async () => {
	const www = await serveStatic(path.join(ROOT, "www", "public"));
	// The vault on localhost, as the devstack serves it: a WebAuthn RP ID must be a domain name
	// (127.0.0.1 is not one), and passkeys are exercised with Chromium's virtual authenticator.
	const vault = await serveStatic(path.join(ROOT, "vault", "public"), { host: "localhost" });
	sites.vault = vault.origin;
	sites.www = www.origin;
	// A request that escapes interception (one sent while a page is going away, say) must never
	// reach the real api.bitosx.se: the name does not resolve in this browser.
	const browser = await chromium.launch({ args: ["--host-resolver-rules=MAP api.bitosx.se ~NOTFOUND"] });
	const errors = [];

	async function newPage(mock, options = {}) {
		const context = await browser.newContext(options.context || {});
		const page = await context.newPage();
		page.on("close", () => { context.close().catch(() => {}); });
		watchConsole(page, errors);
		if (options.beforeRoute) { await options.beforeRoute(page, context); }
		await routeApi(page, mock, options.cors);
		return page;
	}

	const TOKEN_43 = "A".repeat(43);

	// ------------------------------------------------------------ bitosx.se
	console.log("bitosx.se");
	await test("product page renders and shows live API status", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${www.origin}/`);
		assert.equal(await page.title(), "BitosX — Your Security");
		await page.waitForFunction(() => document.getElementById("api-badge").textContent !== "checking…");
		assert.equal(await page.textContent("#api-badge"), "healthy · v0.1.0");
		assert.deepEqual(mock.calls.map(c => c.path).sort(), ["/health", "/version"]);
		assert.ok((await page.textContent("body")).includes("Argon2id"));
		await page.close();
	});
	await test("product page shows API as unreachable when it fails", async () => {
		const mock = createMockApi();
		mock.flags.failHealth = true;
		const page = await newPage(mock);
		await page.goto(`${www.origin}/`);
		await page.waitForFunction(() => document.getElementById("api-badge").textContent !== "checking…");
		assert.equal(await page.textContent("#api-badge"), "unreachable from your browser");
		await page.close();
	});
	await test("product page 404 handling", async () => {
		const page = await browser.newPage();
		const res = await page.goto(`${www.origin}/does-not-exist`);
		assert.equal(res.status(), 404);
		assert.ok((await page.textContent("h1")).includes("404"));
		await page.close();
	});

	// ------------------------------------------------------- verify-email
	console.log("vault.bitosx.se — verify-email");
	await test("verify-email: token read from fragment, fragment scrubbed, password set", async () => {
		const mock = createMockApi();
		const token = mock.seedVerificationToken("new@example.com");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/verify-email#token=${token}`);
		await page.waitForFunction(() => !window.location.hash);
		assert.equal(new URL(page.url()).hash, "", "fragment must be removed from the address bar");
		await page.fill("#verify-password", "correct horse battery");
		await page.fill("#verify-password2", "correct horse battery");
		await page.click("#verify-submit");
		await page.waitForSelector("#verify-notice.ok");
		assert.match(await page.textContent("#verify-notice"), /verified/);
		const call = mock.calls.find(c => c.path === "/v1/auth/verify-email");
		assert.deepEqual(call.body, { token, password: "correct horse battery" });
		assert.equal(mock.accounts.get("new@example.com").password, "correct horse battery");
		assert.equal(await page.isDisabled("#verify-submit"), true, "single-use token: form stays disabled after success");
		await page.close();
	});
	await test("verify-email: client-side policy mirrors server (length, match) without calling the API", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/verify-email#token=${TOKEN_43}`);
		await page.fill("#verify-password", "short");
		await page.fill("#verify-password2", "short");
		await page.click("#verify-submit");
		assert.match(await page.textContent("#verify-notice"), /12–128/);
		await page.fill("#verify-password", "correct horse battery");
		await page.fill("#verify-password2", "correct horse battery!");
		await page.click("#verify-submit");
		assert.match(await page.textContent("#verify-notice"), /do not match/);
		assert.equal(mock.calls.length, 0, "no request leaves the browser for invalid input");
		await page.close();
	});
	await test("verify-email: spent/unknown token -> generic invalid message, form locked", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/verify-email#token=${TOKEN_43}`);
		await page.fill("#verify-password", "correct horse battery");
		await page.fill("#verify-password2", "correct horse battery");
		await page.click("#verify-submit");
		await page.waitForSelector("#verify-notice.err");
		assert.match(await page.textContent("#verify-notice"), /invalid, expired or already used/);
		assert.equal(await page.isDisabled("#verify-submit"), true);
		await page.close();
	});
	await test("verify-email: missing or malformed token disables the form", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/verify-email`);
		assert.match(await page.textContent("#verify-notice"), /incomplete or malformed/);
		assert.equal(await page.isDisabled("#verify-submit"), true);
		await page.goto(`${vault.origin}/verify-email#token=<script>alert(1)</script>`);
		assert.match(await page.textContent("#verify-notice"), /incomplete or malformed/);
		assert.equal(mock.calls.length, 0);
		await page.close();
	});

	// ----------------------------------------------------------- register
	console.log("vault.bitosx.se — register");
	await test("register: valid email -> generic accepted message; invalid email -> no request", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/register`);
		await page.fill("#register-email", "not-an-email");
		await page.click("#register-submit");
		assert.match(await page.textContent("#register-notice"), /valid email/);
		assert.equal(mock.calls.length, 0);
		await page.fill("#register-email", "someone@example.com");
		await page.click("#register-submit");
		await page.waitForSelector("#register-notice.ok");
		assert.match(await page.textContent("#register-notice"), /an email is on its way/);
		assert.deepEqual(mock.calls[0].body, { email: "someone@example.com" });
		assert.equal(await page.inputValue("#register-email"), "");
		await page.close();
	});
	await test("register/resend: 503 when delivery is off -> clear message, nothing created", async () => {
		const mock = createMockApi();
		mock.flags.emailDelivery = false;
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/register#resend`);
		assert.equal(await page.evaluate(() => document.activeElement && document.activeElement.id), "resend-email");
		await page.fill("#resend-email", "someone@example.com");
		await page.click("#resend-submit");
		await page.waitForSelector("#resend-notice.err");
		assert.match(await page.textContent("#resend-notice"), /not available right now/);
		assert.equal(mock.accounts.size, 0);
		await page.close();
	});

	// ------------------------------------------------- forgot / reset password
	console.log("vault.bitosx.se — forgot / reset password");
	await test("forgot-password: sign-in page links to it; valid email -> generic message; invalid -> no request", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.click("a[href='/forgot-password']");
		await page.waitForSelector("#forgot-form");
		await page.waitForFunction(() => document.activeElement && document.activeElement.id === "forgot-email");
		await page.fill("#forgot-email", "not-an-email");
		await page.click("#forgot-submit");
		assert.match(await page.textContent("#forgot-notice"), /valid email/);
		assert.equal(mock.calls.length, 0);
		// Unknown and known addresses show the very same text.
		await page.fill("#forgot-email", "nobody@example.com");
		await page.click("#forgot-submit");
		await page.waitForSelector("#forgot-notice.ok");
		const unknownText = await page.textContent("#forgot-notice");
		await page.fill("#forgot-email", "user@example.com");
		await page.click("#forgot-submit");
		await page.waitForFunction(() => document.getElementById("forgot-email").value === "");
		assert.equal(await page.textContent("#forgot-notice"), unknownText);
		assert.match(unknownText, /reset link is on its way/);
		assert.deepEqual(mock.calls.map(c => c.path), ["/v1/auth/forgot-password", "/v1/auth/forgot-password"]);
		assert.equal(mock.resetTokens.size, 1, "only the real account got a token");
		assert.ok((await page.textContent("#forgot-panel")).includes("master password"), "the page says the vault is out of scope");
		await page.close();
	});
	await test("forgot-password: 503 when delivery is off and 429 when limited -> clear messages", async () => {
		const mock = createMockApi();
		mock.flags.emailDelivery = false;
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/forgot-password`);
		await page.fill("#forgot-email", "user@example.com");
		await page.click("#forgot-submit");
		await page.waitForSelector("#forgot-notice.err");
		assert.match(await page.textContent("#forgot-notice"), /not available right now/);
		mock.flags.emailDelivery = true;
		mock.flags.rateLimitForgot = true;
		await page.fill("#forgot-email", "user@example.com");
		await page.click("#forgot-submit");
		await page.waitForFunction(() => /Too many attempts/.test(document.getElementById("forgot-notice").textContent));
		assert.match(await page.textContent("#forgot-notice"), /about 60 seconds/);
		await page.close();
	});
	await test("reset-password: token read from fragment, fragment scrubbed, password replaced, sessions revoked", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const oldSession = mock.seedSession(accountId, 3600000);
		const token = mock.seedResetToken("user@example.com");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/reset-password#token=${token}`);
		await page.waitForFunction(() => !window.location.hash);
		assert.equal(new URL(page.url()).hash, "", "fragment must be removed from the address bar");
		await page.fill("#reset-password", "brand new password 42");
		await page.fill("#reset-password2", "brand new password 42");
		await page.click("#reset-submit");
		await page.waitForSelector("#reset-notice.ok");
		assert.match(await page.textContent("#reset-notice"), /reset and every device is signed out/);
		const call = mock.calls.find(c => c.path === "/v1/auth/reset-password");
		assert.deepEqual(call.body, { token, password: "brand new password 42" });
		assert.equal(mock.accounts.get("user@example.com").password, "brand new password 42");
		assert.equal(mock.sessions.get(oldSession).revoked, true);
		assert.equal(await page.isDisabled("#reset-submit"), true, "single-use token: form stays disabled after success");
		assert.ok(!(await page.content()).includes(token), "token never lands in the DOM");
		// The new password signs in; the old one does not.
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "brand new password 42");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.close();
	});
	await test("reset-password: client-side policy mirrors server (length, match) without calling the API", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/reset-password#token=${TOKEN_43}`);
		await page.fill("#reset-password", "short");
		await page.fill("#reset-password2", "short");
		await page.click("#reset-submit");
		assert.match(await page.textContent("#reset-notice"), /12–128/);
		await page.fill("#reset-password", "brand new password 42");
		await page.fill("#reset-password2", "brand new password 43");
		await page.click("#reset-submit");
		assert.match(await page.textContent("#reset-notice"), /do not match/);
		assert.equal(mock.calls.length, 0, "no request leaves the browser for invalid input");
		await page.close();
	});
	await test("reset-password: spent/unknown token -> generic invalid message, form locked; a verification token is not a reset token", async () => {
		const mock = createMockApi();
		const verifyToken = mock.seedVerificationToken("new@example.com");
		const page = await newPage(mock);
		for (const token of [TOKEN_43, verifyToken]) {
			await page.goto(`${vault.origin}/`); // a fresh document each time (a fragment-only change would not reload)
			await page.goto(`${vault.origin}/reset-password#token=${token}`);
			await page.fill("#reset-password", "brand new password 42");
			await page.fill("#reset-password2", "brand new password 42");
			await page.click("#reset-submit");
			await page.waitForSelector("#reset-notice.err");
			assert.match(await page.textContent("#reset-notice"), /reset link is invalid, expired or already used/);
			assert.equal(await page.isDisabled("#reset-submit"), true);
		}
		assert.equal(mock.accounts.get("new@example.com").password, null, "a verification token never sets a password through reset");
		await page.close();
	});
	await test("reset-password: missing or malformed token disables the form", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/reset-password`);
		assert.match(await page.textContent("#reset-notice"), /incomplete or malformed/);
		assert.equal(await page.isDisabled("#reset-submit"), true);
		await page.goto(`${vault.origin}/reset-password#token=<script>alert(1)</script>`);
		assert.match(await page.textContent("#reset-notice"), /incomplete or malformed/);
		assert.equal(mock.calls.length, 0);
		await page.close();
	});

	// ------------------------------------------------------ sign in / account
	console.log("vault.bitosx.se — sign in and sessions");
	await test("login: wrong password -> generic 401 message; nothing stored", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "wrong wrong wrong");
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		assert.equal(await page.textContent("#login-notice"), "Invalid email or password.");
		assert.equal(await page.inputValue("#login-password"), "", "password field cleared");
		assert.equal(await page.evaluate(() => Object.keys(localStorage).filter(k => k !== "theme" && k !== "bitosx.generator").length + sessionStorage.length), 0, "no token in web storage");
		await page.close();
	});
	await test("login: 429 with Retry-After is surfaced", async () => {
		const mock = createMockApi();
		mock.flags.rateLimitLogin = true;
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /about 30 seconds/);
		await page.close();
	});
	await test("login -> account + sessions; revoke another session; sign out", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const otherSession = mock.seedSession(accountId, 3600 * 1000);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		assert.equal(await page.textContent("#acct-email"), "user@example.com");
		assert.equal(await page.textContent("#acct-verified"), "Yes");
		assert.equal(await page.textContent("#acct-id"), accountId);
		assert.equal(await page.locator("#sessions-body tr").count(), 2);
		assert.equal(await page.locator("#sessions-body .current").count(), 1);
		// Authorization header carried the bearer token; no token in any URL.
		const me = mock.calls.find(c => c.path === "/v1/account/me");
		assert.match(me.headers["authorization"], /^Bearer jwt\./);
		assert.ok(mock.calls.every(c => !/jwt\./.test(c.path)));
		// Revoke the other session.
		await page.click(`button[data-session-id="${otherSession}"]`);
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(mock.sessions.get(otherSession).revoked, true);
		assert.equal(await page.textContent("#account-notice"), "Session revoked.");
		// Sign out: 204 -> back to the login panel, tokens gone.
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.textContent("#login-notice"), "You are signed out.");
		assert.equal(await page.evaluate(() => window.bitosxApi.isSignedIn()), false);
		await page.close();
	});
	await test("expired access token: exactly one single-flight refresh before parallel calls", async () => {
		// Access tokens that are already inside the refresh skew force a refresh
		// before /me and /sessions, which run in parallel.
		const mock = createMockApi({ accessLifetimeMs: 1000 });
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		// /me and /sessions run in parallel right after login: exactly one refresh precedes them.
		const paths = mock.calls.map(c => c.path);
		const firstMe = paths.indexOf("/v1/account/me");
		assert.equal(paths.slice(0, firstMe).filter(p => p === "/v1/auth/refresh").length, 1, "refresh must be single-flighted (reuse revokes the session server-side)");
		assert.equal(paths.filter(p => p === "/v1/account/me").length, 1);
		// Later calls (the vault status check) may refresh again, but never twice in a row: every
		// refresh is followed by an authenticated call that used it before the next refresh.
		paths.forEach((p, i) => {
			if (p === "/v1/auth/refresh" && i > 0 && paths[i - 1] === "/v1/auth/refresh") { assert.fail("two refreshes back to back"); }
		});
		await page.close();
	});
	await test("session revoked server-side -> next action returns to sign-in", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		// The calls that follow a sign-in by themselves (two-factor and passkey state, vault status)
		// are done first, so that the click below is the next action.
		await page.waitForFunction(() => document.getElementById("passkey-status").textContent !== "" &&
			!document.getElementById("vault-status-text").textContent.startsWith("Checking"));
		for (const s of mock.sessions.values()) { s.revoked = true; }
		await page.click("#refresh-sessions");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /session has ended/);
		await page.close();
	});
	await test("sign out everywhere", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		mock.seedSession(accountId, 1000);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.click("#logout-all");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.ok([...mock.sessions.values()].every(s => s.revoked));
		await page.close();
	});
	await test("reload drops the session (memory-only tokens)", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.reload();
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.isHidden("#account-panel"), true);
		await page.close();
	});

	// ---------------------------------------------------- two-factor (TOTP)
	console.log("vault.bitosx.se — two-factor authentication");
	async function signedInPlain(mock) {
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		return page;
	}
	// The mock server's clock is stopped in the middle of a 30-second step, and every code is
	// computed from that clock: a step boundary can never fall between computing a code and the
	// server checking it.
	function freezeMidStep(mock) {
		const t = Math.floor(Date.now() / 30000) * 30000 + 15000;
		mock.clock.freeze(t);
		return t;
	}
	const codeAt = (mock, secret, offset = 0) => totpCode(secret, totpStep(mock.now()) + offset, mock.totpDigits);

	await test("2fa sign-in: password alone gives a 202 and the code step; the code signs in; nothing stored meanwhile", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const secret = mock.seedTotp(accountId);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		assert.equal(await page.isHidden("#login-form"), true);
		assert.equal(await page.isHidden("#account-panel"), true, "no session yet");
		assert.equal(await page.inputValue("#login-password"), "", "the password never waits on the page");
		assert.match(await page.textContent("#login-notice"), /authenticator app/);
		assert.equal(await page.evaluate(() => document.activeElement && document.activeElement.id), "login-code");
		assert.equal(mock.sessions.size, 0);
		// Only the password step has happened; the challenge token is not in the DOM.
		const token = [...mock.mfaChallenges.keys()][0];
		assert.ok(!(await page.content()).includes(token), "challenge token never in the DOM");

		await page.fill("#login-code", "12345");
		await page.click("#code-submit");
		assert.match(await page.textContent("#login-notice"), /6 to 8 digits/);
		assert.equal(await page.getAttribute("#login-code", "aria-invalid"), "true");
		assert.equal(await page.getAttribute("#login-code", "aria-describedby"), "login-notice");
		// Recovery codes have letters: the field must not ask phones for a digit keypad.
		assert.equal(await page.getAttribute("#login-code", "inputmode"), "text");
		assert.equal(mock.calls.filter(c => c.path === "/v1/auth/login/totp").length, 0, "no request for a non-code");

		await page.fill("#login-code", codeAt(mock, secret));
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		const call = mock.calls.find(c => c.path === "/v1/auth/login/totp");
		assert.deepEqual(call.body, { mfaToken: token, code: codeAt(mock, secret) });
		assert.equal(await page.evaluate(() => document.activeElement && document.activeElement.id), "account-title", "focus moves to the account panel");
		assert.equal(mock.sessions.size, 1);
		assert.equal(await page.isHidden("#code-form"), true);
		await page.waitForFunction(() => /Enabled/.test(document.getElementById("totp-status").textContent));
		assert.match(await page.textContent("#totp-status"), /Recovery codes left: 2/);
		assert.equal(await page.isHidden("#totp-manage-form"), false);
		assert.equal(await page.isHidden("#totp-enroll-form"), true);
		await page.close();
	});

	await test("2fa sign-in: wrong code -> generic message, stays on the code step; recovery code works once; start over returns to the password", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		mock.seedTotp(accountId, ["abcde-fghjk"]);
		const page = await newPage(mock);
		async function passwordStep() {
			await page.fill("#login-email", "user@example.com");
			await page.fill("#login-password", "correct horse battery");
			await page.click("#login-submit");
			await page.waitForSelector("#code-form:not([hidden])");
		}
		await page.goto(`${vault.origin}/`);
		await passwordStep();
		await page.fill("#login-code", "000000");
		await page.click("#code-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /not accepted/);
		assert.equal(await page.isHidden("#code-form"), false, "a refused code keeps the step");
		assert.equal(await page.inputValue("#login-code"), "", "the code never stays on the page");

		await page.click("#code-cancel");
		await page.waitForSelector("#login-form:not([hidden])");
		assert.equal(await page.isHidden("#code-form"), true);

		await passwordStep();
		await page.fill("#login-code", "ABCDE FGHJK"); // separators and case are the user's business
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.waitForFunction(() => /Recovery codes left: 0/.test(document.getElementById("totp-status").textContent));
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");

		await passwordStep();
		await page.fill("#login-code", "abcde-fghjk");
		await page.click("#code-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /not accepted/); // used once, never again
		await page.close();
	});

	await test("2fa sign-in: server without the capability -> a generic 503 text at the password step (503 has other causes there), no password-only session", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		mock.seedTotp(accountId);
		mock.flags.totpCapability = false;
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		assert.equal(await page.textContent("#login-notice"), "The service is temporarily unavailable. Try again shortly.");
		assert.equal(await page.isHidden("#account-panel"), true);
		assert.equal(mock.sessions.size, 0);
		await page.close();
	});

	await test("2fa setup: password -> secret shown once -> code confirms -> recovery codes shown once; wrong code refused", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const page = await signedInPlain(mock);
		await page.waitForFunction(() => document.getElementById("totp-status").textContent === "Not enabled.");
		assert.equal(await page.isHidden("#totp-enroll-form"), false);

		await page.fill("#totp-enroll-password", "wrong wrong wrong wrong");
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-notice.err");
		assert.match(await page.textContent("#totp-notice"), /password or the code was not accepted/);
		assert.equal(await page.isHidden("#totp-setup"), true);

		await page.fill("#totp-enroll-password", "correct horse battery");
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-setup:not([hidden])");
		// Shown in groups of four for typing; authenticator apps ignore the spaces.
		const secretText = (await page.textContent("#totp-setup-secret")).replace(/ /g, "");
		assert.match(await page.textContent("#totp-setup-secret"), /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
		assert.match(secretText, /^[A-Z2-7]{32}$/);
		const uri = await page.textContent("#totp-setup-uri");
		assert.match(uri, /^otpauth:\/\/totp\/BitosX:user%40example\.com\?secret=[A-Z2-7]{32}&issuer=BitosX/);
		// A tappable link opens the authenticator app on a phone.
		assert.equal(await page.getAttribute("#totp-setup-link", "href"), uri);
		assert.equal(await page.isVisible("#totp-setup-link"), true);
		assert.equal(await page.inputValue("#totp-enroll-password"), "");
		const secret = base32Decode(secretText);

		// A pending setup is not a factor: the mock's status says so, and the server would still sign in with the password alone.
		await page.fill("#totp-confirm-code", "000000");
		await page.click("#totp-confirm-submit");
		await page.waitForSelector("#totp-notice.err");
		assert.match(await page.textContent("#totp-notice"), /code is not valid/);
		assert.equal(await page.isHidden("#totp-setup"), false);

		await page.fill("#totp-confirm-code", codeAt(mock, secret));
		await page.click("#totp-confirm-submit");
		await page.waitForSelector("#totp-codes:not([hidden])");
		const codes = (await page.textContent("#totp-codes-list")).trim().split("\n");
		assert.equal(codes.length, 10);
		for (const c of codes) { assert.match(c, /^[a-z2-9]{5}-[a-z2-9]{5}$/); }
		assert.match(await page.textContent("#totp-notice"), /is enabled/);
		assert.equal(await page.textContent("#totp-setup-secret"), "", "the secret is wiped from the page once confirmed");
		assert.equal(await page.getAttribute("#totp-setup-link", "href"), null, "and so is the link");
		await page.waitForFunction(() => /Recovery codes left: 10/.test(document.getElementById("totp-status").textContent));
		assert.equal(await page.isHidden("#totp-manage-form"), false);

		await page.click("#totp-codes-done");
		assert.equal(await page.isHidden("#totp-codes"), true);
		assert.equal(await page.textContent("#totp-codes-list"), "", "codes are wiped once acknowledged");
		assert.equal(mock.totp.get(mock.accounts.get("user@example.com").id).confirmed, true);
		await page.close();
	});

	await test("2fa manage: new recovery codes and turn off need password + current code; a wrong one changes nothing", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const secret = mock.seedTotp(accountId, ["abcde-fghjk"]);
		// Sign in through the code step first.
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		await page.fill("#login-code", codeAt(mock, secret));
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.waitForSelector("#totp-manage-form:not([hidden])");

		await page.fill("#totp-manage-password", "correct horse battery");
		await page.fill("#totp-manage-code", "000000");
		await page.click("#totp-regenerate");
		await page.waitForSelector("#totp-notice.err");
		assert.match(await page.textContent("#totp-notice"), /not accepted/);
		assert.equal(await page.isHidden("#totp-codes"), true);
		assert.equal(await page.inputValue("#totp-manage-password"), "");

		await page.fill("#totp-manage-password", "correct horse battery");
		await page.fill("#totp-manage-code", codeAt(mock, secret, 1)); // the sign-in used the current step; the next one is fresh
		await page.click("#totp-regenerate");
		await page.waitForSelector("#totp-codes:not([hidden])");
		const fresh = (await page.textContent("#totp-codes-list")).trim().split("\n");
		assert.equal(fresh.length, 10);
		assert.ok(!fresh.includes("abcde-fghjk"));
		await page.waitForFunction(() => /Recovery codes left: 10/.test(document.getElementById("totp-status").textContent));

		await page.fill("#totp-manage-password", "correct horse battery");
		await page.fill("#totp-manage-code", fresh[0]);
		assert.equal(await page.isDisabled("#totp-disable"), true, "turning off needs the confirmation first");
		await page.check("#totp-disable-ack");
		await page.click("#totp-disable");
		await page.waitForFunction(() => document.getElementById("totp-status").textContent === "Not enabled.");
		assert.match(await page.textContent("#totp-notice"), /turned off/);
		assert.equal(await page.isHidden("#totp-enroll-form"), false);
		assert.equal(mock.totp.has(accountId), false);

		// Password alone signs in again.
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		assert.equal(await page.isHidden("#code-form"), true);
		await page.close();
	});

	// --------------------------------------------------------- delete account
	console.log("vault.bitosx.se — delete account");
	await test("delete account: button needs the acknowledgement; wrong password -> 403 message, nothing deleted, still signed in", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		assert.equal(await page.isDisabled("#delete-submit"), true, "disabled until acknowledged");
		await page.fill("#delete-password", "wrong wrong wrong wrong");
		await page.check("#delete-ack");
		assert.equal(await page.isDisabled("#delete-submit"), false);
		await page.click("#delete-submit");
		await page.waitForSelector("#delete-notice.err");
		assert.match(await page.textContent("#delete-notice"), /password or the code was not accepted. Nothing was deleted/);
		assert.equal(await page.isHidden("#delete-code-field"), true, "no code field without two-factor");
		assert.equal(mock.accounts.size, 1);
		assert.equal(await page.isHidden("#account-panel"), false, "a 403 is not a dead session");
		assert.equal(await page.inputValue("#delete-password"), "", "password field cleared");
		const call = mock.calls.find(c => c.path === "/v1/account/delete");
		assert.deepEqual(Object.keys(call.body), ["password"], "only the password travels; the account is the session's");
		assert.ok(call.headers["authorization"].startsWith("Bearer "));
		await page.close();
	});
	await test("delete account: correct password -> account, sessions and stored vault gone; signed out; login fails", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		const accountId = mock.accounts.get("user@example.com").id;
		mock.seedEnvelope(accountId, Buffer.from(JSON.stringify({ version: 1, kdf: "argon2id" })));
		mock.seedSession(accountId, 3600000);
		await page.fill("#delete-password", "correct horse battery");
		await page.check("#delete-ack");
		await page.click("#delete-submit");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /account and the vault stored on the server are deleted/);
		assert.equal(mock.accounts.size, 0);
		assert.equal(mock.envelopes.size, 0);
		assert.ok([...mock.sessions.values()].every(s => s.revoked));
		assert.equal(await page.isHidden("#vault-panel"), true, "the vault panel is gone with the session");
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		assert.equal(await page.textContent("#login-notice"), "Invalid email or password.");
		await page.close();
	});

	// ------------------------------------------------------------- the vault
	console.log("vault.bitosx.se — vault");
	const FIX = path.join(__dirname, "fixtures");
	const fixture = (name) => ({
		bytes: fs.readFileSync(path.join(FIX, name + ".vault.json")),
		meta: JSON.parse(fs.readFileSync(path.join(FIX, name + ".meta.json"), "utf8"))
	});
	async function signedIn(mock, page) {
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", "correct horse battery");
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.waitForSelector("#vault-panel:not([hidden])");
		await page.waitForFunction(() => !document.getElementById("vault-status-text").textContent.startsWith("Checking"));
	}
	async function unlockWith(page, password) {
		await page.fill("#vault-master-password", password);
		await page.click("#vault-unlock-submit");
		await page.waitForFunction(() => document.getElementById("vault-notice").classList.contains("is-visible"));
	}
	const SECRETS = ["P@ssw0rd-Strong-123", "hunter2 & \"quotes\" <b>", "ñandú-Ωmega-🔐"];
	async function assertNoSecretInDom(page) {
		const html = await page.content();
		for (const s of SECRETS) { assert.ok(!html.includes(s), `secret in DOM: ${s}`); }
	}

	await test("vault: nothing stored -> says so, no unlock form, GET /v1/sync/status carried the token", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", "correct horse battery");
		const page = await newPage(mock);
		await signedIn(mock, page);
		assert.match(await page.textContent("#vault-status-text"), /holds no vault for this account yet/);
		assert.equal(await page.isHidden("#vault-unlock-form"), true);
		const call = mock.calls.find(c => c.path === "/v1/sync/status");
		assert.match(call.headers["authorization"], /^Bearer jwt\./);
		await page.close();
	});

	await test("vault: wrong master password -> refused, nothing shown, field cleared", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		mock.seedEnvelope(accountId, fixture("small").bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		assert.match(await page.textContent("#vault-status-text"), /revision 1, 1\.8 KiB/);
		await unlockWith(page, "definitely not it");
		assert.match(await page.textContent("#vault-notice"), /master password is incorrect, or the vault on the server was modified/);
		assert.equal(await page.isHidden("#vault-items-section"), true);
		assert.equal(await page.inputValue("#vault-master-password"), "");
		await assertNoSecretInDom(page);
		// The master password never left the browser: no request body contains it.
		assert.ok(mock.calls.every(c => JSON.stringify(c.body).indexOf("definitely not it") < 0));
		await page.close();
	});

	await test("vault: the right master password opens it read-only; secrets stay out of the DOM until shown; search; lock", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /^Vault opened\. Changes are uploaded only when you press Save to server/);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		assert.equal(await page.locator("#vault-items .vault-item").count(), 3);
		assert.equal(await page.textContent("#vault-count"), "3 items");
		// Favorites first, then by name; names are text, never markup.
		const names = await page.locator(".vault-item__name").allTextContents();
		assert.equal(names[0].trim(), "GitHub ★");
		assert.equal(names[1].trim(), "Bank <script>alert(1)</script>");
		assert.equal(await page.locator("#vault-items script").count(), 0);
		// Passwords hidden until shown.
		await assertNoSecretInDom(page);
		const github = page.locator('.vault-item[data-item-id="11111111-1111-4111-8111-111111111111"]');
		assert.equal(await github.locator(".vault-secret").textContent(), "••••••••••••");
		await github.locator("button[data-reveal]").click();
		assert.equal(await github.locator(".vault-secret").textContent(), "P@ssw0rd-Strong-123");
		assert.equal(await github.locator("button[data-reveal]").textContent(), "Hide");
		await github.locator("button[data-reveal]").click();
		assert.equal(await github.locator(".vault-secret").textContent(), "••••••••••••");
		// URLs are links only when they parse as http(s); notes keep their line breaks as text.
		assert.equal(await page.locator('a.vault-url[href="https://github.com/"]').count(), 1);
		assert.equal(await page.locator("a.vault-url").first().getAttribute("rel"), "noopener noreferrer");
		assert.match(await page.locator(".vault-notes").first().textContent(), /Second line & <i>markup<\/i>/);
		assert.equal(await page.locator(".vault-notes i").count(), 0);
		// Search.
		await page.fill("#vault-search", "bank");
		assert.equal(await page.locator("#vault-items .vault-item").count(), 1);
		assert.equal(await page.textContent("#vault-count"), "1 of 3 items");
		await page.fill("#vault-search", "zzz");
		assert.match(await page.textContent("#vault-items"), /No items match/);
		// Only the two sync reads went to the server; nothing was uploaded.
		assert.deepEqual(mock.calls.filter(c => c.path.startsWith("/v1/sync")).map(c => c.method + " " + c.path), ["GET /v1/sync/status", "GET /v1/sync/envelope"]);
		// Lock.
		await page.click("#vault-lock");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.isHidden("#vault-items-section"), true);
		assert.equal(await page.locator("#vault-items .vault-item").count(), 0);
		await assertNoSecretInDom(page);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		await page.close();
	});

	await test("vault: copy puts the secret on the clipboard without showing it", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const context = await browser.newContext();
		await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: vault.origin });
		const page = await context.newPage();
		watchConsole(page, errors);
		await routeApi(page, mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.locator('.vault-item[data-item-id="11111111-1111-4111-8111-111111111111"] button[data-copy="password"]').click();
		await page.waitForFunction(() => /Copied/.test(document.getElementById("vault-notice").textContent));
		assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "P@ssw0rd-Strong-123");
		await assertNoSecretInDom(page);
		await context.close();
	});

	await test("vault: a tampered envelope, a lying server, and an unreadable envelope are each refused", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const { bytes, meta } = fixture("small");
		const page = await newPage(mock);
		// 1. One flipped ciphertext byte: authenticated decryption fails.
		const doc = JSON.parse(bytes.toString("utf8"));
		const ct = Buffer.from(doc.ciphertext, "base64"); ct[3] ^= 0x01; doc.ciphertext = ct.toString("base64");
		mock.seedEnvelope(accountId, Buffer.from(JSON.stringify(doc)));
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /incorrect, or the vault on the server was modified/);
		assert.equal(await page.isHidden("#vault-items-section"), true);
		// 2. The server's fingerprint does not describe the bytes it sent: refused before any key work.
		mock.seedEnvelope(accountId, bytes, { fingerprintOverride: "0".repeat(64) });
		await page.click("#logout"); await page.waitForSelector("#login-panel:not([hidden])");
		await signedIn(mock, page);
		const before = mock.calls.length;
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /Something unexpected happened/);
		assert.equal(mock.calls.slice(before).filter(c => c.path === "/v1/sync/envelope").length, 1);
		// 3. Not an envelope this version reads.
		mock.seedEnvelope(accountId, Buffer.from(JSON.stringify(Object.assign({}, JSON.parse(bytes.toString("utf8")), { version: 2 }))));
		await page.click("#logout"); await page.waitForSelector("#login-panel:not([hidden])");
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /not a vault this version of the web app can read/);
		await assertNoSecretInDom(page);
		await page.close();
	});

	await test("vault: the master password opens the vault however it is typed (NFD, other spaces), and a pre-0.6.0 vault still opens", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const canonical = fixture("unicode-canonical");
		mock.seedEnvelope(accountId, canonical.bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, canonical.meta.typedPassword.normalize("NFD").replace(/\u3000/g, "\u00A0"));
		assert.match(await page.textContent("#vault-notice"), /^Vault opened\. Changes are uploaded/);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-lock");
		// The legacy vault, keyed with the raw NFD bytes.
		const legacy = fixture("unicode-legacy-nfd");
		mock.seedEnvelope(accountId, legacy.bytes);
		await page.click("#logout"); await page.waitForSelector("#login-panel:not([hidden])");
		await signedIn(mock, page);
		await unlockWith(page, legacy.meta.typedPassword.normalize("NFC"));
		assert.match(await page.textContent("#vault-notice"), /opened with the password as it was typed when the vault was created/);
		await page.close();
	});

	await test("vault: signing out, or the session ending, locks and hides the vault", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.isHidden("#vault-panel"), true);
		assert.equal(await page.locator("#vault-items .vault-item").count(), 0);
		await assertNoSecretInDom(page);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		await page.close();
	});

	// ------------------------------------------------------- editing (phase 5)
	console.log("vault.bitosx.se — editing");
	const vcNode = require("../vault/public/assets/js/vault-crypto.js")(require("../vault/public/assets/vendor/hash-wasm/argon2.umd.min.js"), globalThis.crypto);
	// Opens what the mock server holds with the fixture's password, as the desktop would.
	async function serverItems(mock, accountId, password) {
		const e = mock.envelopes.get(accountId);
		const opened = await vcNode.unlock(vcNode.parseEnvelope(new Uint8Array(e.bytes)), password);
		return vcNode.parseVault(opened.plaintext).items;
	}
	async function openedVault(mock) {
		const accountId = mock.seedAccount("user@example.com", "correct horse battery");
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		return { page, accountId, meta, bytes };
	}

	await test("edit: add a login, save -> the server holds a new revision that opens with the master password and contains it; the desktop's header is untouched", async () => {
		const mock = createMockApi();
		const { page, accountId, meta, bytes } = await openedVault(mock);
		assert.equal(await page.isDisabled("#vault-save"), true);
		await page.click("#vault-add");
		await page.waitForSelector("#vault-editor:not([hidden])");
		await page.fill("#edit-name", "Added here <b>");
		await page.fill("#edit-username", "web@example.com");
		await page.click("#edit-password-generate");
		const generated = await page.inputValue("#edit-password");
		// The desktop generator's defaults: 20 characters, every class present, its symbol set.
		assert.equal(generated.length, 20);
		assert.match(generated, /[a-z]/); assert.match(generated, /[A-Z]/); assert.match(generated, /[0-9]/);
		assert.match(generated, /^[A-Za-z0-9!@#$%^&*()\-_=+[\]{};:,.?/]+$/);
		assert.equal(await page.getAttribute("#edit-password", "type"), "text", "a generated password is shown, as on the desktop");
		assert.match(await page.textContent("#edit-password-strength"), /^Strength: (Strong|Very strong)/);
		await page.fill("#edit-urls", "https://example.com/login\n\nhttps://example.org");
		await page.fill("#edit-notes", "line one\nline two");
		await page.check("#edit-favorite");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		assert.equal(await page.locator("#vault-items .vault-item").count(), 4);
		assert.equal(await page.isHidden("#vault-dirty"), false);
		assert.equal(await page.isDisabled("#vault-save"), false);
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		assert.equal(mock.calls.filter(c => c.method === "PUT").length, 0, "nothing uploaded before Save");

		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		assert.equal(await page.isHidden("#vault-dirty"), true);
		const put = mock.calls.find(c => c.method === "PUT" && c.path === "/v1/sync/envelope");
		assert.equal(put.body.baseRevision, 1);
		assert.match(put.headers["authorization"], /^Bearer jwt\./);
		// The master password never left the browser; the body carries only the envelope.
		assert.deepEqual(Object.keys(put.body).sort(), ["baseRevision", "envelope"]);
		assert.ok(!JSON.stringify(put.body).includes(meta.typedPassword));
		// What the server holds now opens with the same master password and has the new item.
		const items = await serverItems(mock, accountId, meta.typedPassword);
		assert.equal(items.length, 4);
		const added = items.find(i => i.name === "Added here <b>");
		assert.equal(added.username, "web@example.com");
		assert.equal(added.password, generated);
		assert.deepEqual([...added.urls], ["https://example.com/login", "https://example.org"]);
		assert.equal(added.notes, "line one\nline two");
		assert.equal(added.favorite, true);
		// The key-wrap header is exactly the desktop's: only the content changed.
		const before = JSON.parse(bytes.toString("utf8"));
		const after = JSON.parse(mock.envelopes.get(accountId).bytes.toString("utf8"));
		for (const k of ["version", "kdf", "kdfParameters", "salt", "algorithm", "keyWrapNonce", "encryptedVaultKey"]) {
			assert.deepEqual(after[k], before[k], k);
		}
		assert.notEqual(after.contentNonce, before.contentNonce);
		if (process.env.BITOSX_E2E_DUMP) {
			fs.mkdirSync(process.env.BITOSX_E2E_DUMP, { recursive: true });
			fs.writeFileSync(path.join(process.env.BITOSX_E2E_DUMP, "web-written.vault.json"), mock.envelopes.get(accountId).bytes);
			fs.writeFileSync(path.join(process.env.BITOSX_E2E_DUMP, "web-written.expected.json"), JSON.stringify({ password: meta.typedPassword, generated, itemCount: 4 }));
		}
		await page.close();
	});

	await test("edit: change and delete, with the delete asked for and then confirmed; save uploads once", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		const github = page.locator('.vault-item[data-item-id="11111111-1111-4111-8111-111111111111"]');
		await github.locator("button[data-edit]").click();
		await page.waitForSelector("#vault-editor:not([hidden])");
		assert.equal(await page.inputValue("#edit-name"), "GitHub");
		assert.equal(await page.inputValue("#edit-password"), "P@ssw0rd-Strong-123");
		await page.fill("#edit-name", "GitHub (work)");
		await page.fill("#edit-password", "new-password-42");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		// Delete needs two presses.
		const bank = page.locator('.vault-item[data-item-id="22222222-2222-4222-8222-222222222222"]');
		await bank.locator("button[data-delete]").click();
		assert.equal(await bank.locator("button[data-delete]").textContent(), "Confirm delete");
		assert.equal(await page.locator("#vault-items .vault-item").count(), 3);
		await bank.locator("button[data-delete]").click();
		await page.waitForFunction(() => document.querySelectorAll("#vault-items .vault-item").length === 2);
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		assert.equal(mock.calls.filter(c => c.method === "PUT").length, 1);
		const items = await serverItems(mock, accountId, meta.typedPassword);
		assert.deepEqual(items.map(i => i.name).sort(), ["GitHub (work)", "Wi-Fi café"]);
		const edited = items.find(i => i.name === "GitHub (work)");
		assert.equal(edited.password, "new-password-42");
		assert.equal(edited.createdAt.toISOString(), "2026-10-01T09:00:00.000Z", "CreatedAt kept");
		assert.ok(edited.updatedAt > edited.createdAt, "UpdatedAt stamped");
		await page.close();
	});

	await test("edit: the editor validates as the desktop does, and nothing invalid is kept", async () => {
		const mock = createMockApi();
		const { page } = await openedVault(mock);
		await page.click("#vault-add");
		await page.click("#edit-save");
		assert.match(await page.textContent("#vault-editor-notice"), /Name is required/);
		await page.fill("#edit-name", "x");
		await page.fill("#edit-urls", "not a url");
		await page.click("#edit-save");
		assert.match(await page.textContent("#vault-editor-notice"), /not a valid absolute http\(s\) URL/);
		assert.equal(await page.isHidden("#vault-editor"), false);
		assert.equal(await page.getAttribute("#edit-urls", "aria-invalid"), "true");
		assert.match(await page.textContent("#edit-urls-error"), /not a valid absolute http\(s\) URL/);
		assert.equal(await page.evaluate(() => document.activeElement.id), "edit-urls", "focus goes to the field at fault");
		// Text typed into the open editor is unsaved work too.
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		await page.click("#edit-cancel");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		assert.equal(await page.isHidden("#vault-editor"), true);
		assert.equal(await page.locator("#vault-items .vault-item").count(), 3);
		await page.close();
	});

	await test("edit: a conflict (another device uploaded first) uploads nothing and offers both ways out; overwrite is compare-and-set and needs the acknowledgement", async () => {
		const mock = createMockApi();
		const { page, accountId, meta, bytes } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		// Meanwhile another device uploads revision 2.
		mock.seedEnvelope(accountId, bytes);
		await page.click("#vault-save");
		await page.waitForSelector("#vault-conflict:not([hidden])");
		assert.match(await page.textContent("#vault-notice"), /Another device changed the vault on the server first/);
		assert.equal(mock.envelopes.get(accountId).revision, 2, "the server kept the other device's revision");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		assert.equal(await page.isDisabled("#vault-overwrite"), true);
		await page.check("#vault-overwrite-ack");
		assert.equal(await page.isDisabled("#vault-overwrite"), false);
		await page.click("#vault-overwrite");
		await page.waitForFunction(() => /this browser's version/.test(document.getElementById("vault-notice").textContent));
		const puts = mock.calls.filter(c => c.method === "PUT");
		assert.deepEqual(puts.map(p => p.body.baseRevision), [1, 2], "first against what was opened, then against what the server holds now");
		assert.equal(mock.envelopes.get(accountId).revision, 3);
		assert.equal(await page.isHidden("#vault-conflict"), true);
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		const items = await serverItems(mock, accountId, meta.typedPassword);
		assert.ok(items.some(i => i.name === "Mine"));
		await page.close();
	});

	await test("edit: 'reload the server's vault' discards the changes and asks for the master password again", async () => {
		const mock = createMockApi();
		const { page, accountId, bytes } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		mock.seedEnvelope(accountId, bytes);
		await page.click("#vault-save");
		await page.waitForSelector("#vault-conflict:not([hidden])");
		await page.click("#vault-reload");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		await page.waitForFunction(() => /revision 2/.test(document.getElementById("vault-status-text").textContent));
		assert.equal(mock.envelopes.get(accountId).revision, 2);
		assert.equal(await page.textContent("#vault-notice"), "Changes discarded. Enter the master password to open the server's vault again.", "the notice is not erased by the status load");
		await page.close();
	});

	await test("edit: unsaved changes survive the tab being hidden, but locking discards them and wipes the DOM", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await page.evaluate(() => {
			Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
			document.dispatchEvent(new Event("visibilitychange"));
		});
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), true, "not locked while there are unsaved changes");
		await page.click("#vault-lock");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		await assertNoSecretInDom(page);
		assert.equal((await serverItems(mock, accountId, meta.typedPassword)).length, 3, "nothing was uploaded");
		await page.close();
	});

	if (process.env.BITOSX_E2E_SLOW) {
		await test("vault (slow, opt-in): the desktop's default profile — 256 MiB Argon2id — opens in Chromium", async () => {
			const mock = createMockApi();
			const accountId = mock.seedAccount("user@example.com", "correct horse battery");
			const { bytes, meta } = fixture("strong");
			mock.seedEnvelope(accountId, bytes);
			const page = await newPage(mock);
			await signedIn(mock, page);
			const t0 = Date.now();
			await page.fill("#vault-master-password", meta.typedPassword);
			await page.click("#vault-unlock-submit");
			await page.waitForFunction(() => document.getElementById("vault-notice").classList.contains("is-visible"), null, { timeout: 180000 });
			console.log(`       256 MiB unlock took ${Date.now() - t0} ms`);
			assert.match(await page.textContent("#vault-notice"), /Vault opened/);
			await page.close();
		});
	}

	// ------------------------------------------------- phase 8: sessions
	console.log("vault.bitosx.se — sessions that end, and the signs of it");
	const PASSWORD = "correct horse battery";
	async function signIn(page, password = PASSWORD) {
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", password);
		await page.click("#login-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
	}
	async function until(fn, what, timeoutMs = 10000) {
		const t0 = Date.now();
		while (!(await fn())) {
			if (Date.now() - t0 > timeoutMs) { throw new Error("timed out waiting for " + what); }
			await new Promise((r) => setTimeout(r, 20));
		}
	}
	// Holds every request for METHOD path until released; resolves `held` once one arrived.
	function holdOnce(mock, method, path, after = false) {
		let release, arrived;
		const held = new Promise((r) => { arrived = r; });
		const gate = new Promise((r) => { release = r; });
		let used = false;
		mock[after ? "holdAfter" : "hold"] = (m, p) => {
			if (used || m !== method || p !== path) { return null; }
			used = true;
			arrived();
			return gate;
		};
		return { held, release: () => release() };
	}
	// Under a fake clock, a click's scroll-into-view can deliver its scroll event (activity) on a
	// later animation frame; let pending frames run before jumping ahead.
	async function settle(page) { await page.clock.runFor(500); }
	const callsTo = (mock, path, method) => mock.calls.filter((c) => c.path === path && (!method || c.method === method)).length;

	await test("401 on a token the client still trusts (its clock is behind the server's): one refresh, one retry, still signed in; parallel calls share that refresh", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		await page.waitForFunction(() => document.getElementById("totp-status").textContent === "Not enabled.");
		// Every access token the server issued so far is past its expiry and its clock skew there.
		for (const rec of mock.accessTokens.values()) { rec.expiresAt = mock.now() - 5 * 60000; }
		const before = mock.calls.length;
		await page.evaluate(() => Promise.all([window.bitosxApi.me(), window.bitosxApi.sessions(), window.bitosxApi.syncStatus()]));
		const paths = mock.calls.slice(before).map((c) => c.path);
		assert.equal(paths.filter((p) => p === "/v1/auth/refresh").length, 1, "exactly one refresh (reuse would revoke the session)");
		assert.equal(paths.filter((p) => p === "/v1/account/me").length, 2, "refused once, retried once");
		assert.equal(paths.filter((p) => p === "/v1/account/sessions").length, 2);
		assert.equal(await page.evaluate(() => window.bitosxApi.isSignedIn()), true);
		assert.equal(await page.isHidden("#account-panel"), false);
		await page.close();
	});

	await test("a session that ends while the vault is open (revoked elsewhere): Save locks and wipes the vault and says so; so does Unlock", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		for (const s of mock.sessions.values()) { s.revoked = true; } // "Sign out everywhere" on another device
		await page.click("#vault-save");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /^Your session has ended\. Sign in again\. Unsaved vault changes in this browser were discarded\.$/);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		assert.equal(await page.isHidden("#vault-panel"), true);
		assert.equal(await page.locator("#vault-items .vault-item").count(), 0);
		await assertNoSecretInDom(page);
		assert.equal(mock.envelopes.get(accountId).revision, 1, "nothing was stored");
		// Unlocking against a session that ended meanwhile: the same.
		await signIn(page);
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		for (const s of mock.sessions.values()) { s.revoked = true; }
		await page.fill("#vault-master-password", meta.typedPassword);
		await page.click("#vault-unlock-submit");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /session has ended/);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		await page.close();
	});

	await test("leaving the page (also into the back/forward cache) wipes the account view and revokes the session; coming back shows the sign-in", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		await page.waitForSelector("#totp-enroll-form:not([hidden])");
		await page.fill("#totp-enroll-password", PASSWORD);
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-setup:not([hidden])");
		const sid = [...mock.sessions.keys()][0];
		// Chromium under test does not keep pages in the back/forward cache, so the page gets the
		// very events a cached page gets: pagehide (persisted) when it is stored, pageshow on return.
		await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
		assert.equal(await page.isHidden("#account-panel"), true, "the snapshot a cache would keep holds no account view");
		assert.equal(await page.textContent("#totp-setup-secret"), "");
		assert.equal(await page.getAttribute("#totp-setup-link", "href"), null);
		assert.equal(await page.textContent("#acct-email"), "");
		assert.equal(await page.locator("#sessions-body tr").count(), 0);
		assert.equal(await page.evaluate(() => window.bitosxApi.isSignedIn()), false);
		await until(() => mock.sessions.get(sid).revoked, "the session to be revoked");
		await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
		assert.equal(await page.isHidden("#login-panel"), false);
		assert.match(await page.textContent("#login-notice"), /You left this page, so you were signed out/);
		// A real navigation away revokes too.
		await signIn(page);
		const sid2 = [...mock.sessions.entries()].find(([, s]) => !s.revoked)[0];
		// A request sent while the document goes away is not intercepted by Playwright; that it is
		// sent, with the session's token, is what the page controls.
		const leaving = [];
		page.on("request", (r) => { if (r.url() === `${API_ORIGIN}/v1/auth/logout` && r.method() === "POST") { leaving.push(r.headers()["authorization"] || ""); } });
		page.expectedConsole = /net::ERR_NAME_NOT_RESOLVED|net::ERR_FAILED/;
		await page.goto(`${vault.origin}/register`);
		await until(() => leaving.length === 1 || mock.sessions.get(sid2).revoked, "the revoking request on navigation");
		assert.ok(mock.sessions.get(sid2).revoked || /^Bearer jwt\./.test(leaving[0]));
		await page.close();
	});

	await test("idle sign-out after 15 minutes wipes the account view, a pending two-factor secret and recovery codes; the wall clock counts, not only the timer", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", PASSWORD);
		const page = await newPage(mock, { beforeRoute: (p) => p.clock.install() });
		await page.goto(`${vault.origin}/`);
		await signIn(page);
		await page.waitForSelector("#totp-enroll-form:not([hidden])");
		await page.fill("#totp-enroll-password", PASSWORD);
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-setup:not([hidden])");
		await settle(page);
		await page.clock.fastForward("14:00");
		assert.equal(await page.isHidden("#account-panel"), false, "not before 15 minutes");
		await page.clock.fastForward("01:05");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /Signed out after 15 minutes without activity/);
		assert.equal(await page.textContent("#totp-setup-secret"), "");
		assert.equal(await page.textContent("#totp-setup-uri"), "");
		assert.equal(await page.isHidden("#totp-setup"), true);
		assert.equal(await page.textContent("#acct-email"), "");
		await until(() => callsTo(mock, "/v1/auth/logout") === 1, "the server sign-out");
		// With recovery codes on screen, and a clock that jumped (sleep): the next look at the clock signs out.
		const secret = mock.seedTotp(mock.accounts.get("user@example.com").id);
		freezeMidStep(mock);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		await page.fill("#login-code", codeAt(mock, secret));
		await page.click("#code-submit");
		await page.waitForSelector("#totp-manage-form:not([hidden])");
		await page.fill("#totp-manage-password", PASSWORD);
		await page.fill("#totp-manage-code", codeAt(mock, secret, 1));
		await page.click("#totp-regenerate");
		await page.waitForSelector("#totp-codes:not([hidden])");
		const t = await page.evaluate(() => Date.now());
		await page.clock.setSystemTime(t + 16 * 60 * 1000); // no timer fires
		await page.evaluate(() => window.dispatchEvent(new Event("focus")));
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.textContent("#totp-codes-list"), "", "recovery codes are wiped with the sign-out");
		assert.equal(await page.isHidden("#totp-codes"), true);
		await page.close();
	});

	await test("2fa sign-in: the challenge's expiry and the attempt limit end the code step and say why", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const secret = mock.seedTotp(accountId);
		const page = await newPage(mock, { beforeRoute: (p) => p.clock.install() });
		async function passwordStep() {
			await page.fill("#login-email", "user@example.com");
			await page.fill("#login-password", PASSWORD);
			await page.click("#login-submit");
			await page.waitForSelector("#code-form:not([hidden])");
		}
		await page.goto(`${vault.origin}/`);
		await passwordStep();
		await settle(page);
		await page.clock.fastForward("05:01");
		await page.waitForSelector("#login-form:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /sign-in step timed out\. Enter your password again/);
		assert.equal(await page.isHidden("#code-form"), true);
		assert.equal(await page.evaluate(() => document.activeElement.id), "login-password");
		// Five wrong codes: the server's limit; the page says so and starts over.
		const good = [-1, 0, 1].map((o) => codeAt(mock, secret, o));
		const wrong = ["000000", "111111", "222222"].find((c) => !good.includes(c));
		await passwordStep();
		for (let i = 1; i <= 5; i++) {
			await page.fill("#login-code", wrong);
			await page.click("#code-submit");
			await until(() => callsTo(mock, "/v1/auth/login/totp") === i, `attempt ${i}`);
			if (i < 5) { await page.waitForFunction(() => !document.getElementById("code-form").querySelector("button").disabled); }
		}
		await page.waitForSelector("#login-form:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /Too many wrong codes/);
		// A challenge that expired while the page was asleep is not even sent.
		await passwordStep();
		const t = await page.evaluate(() => Date.now());
		await page.clock.setSystemTime(t + 6 * 60 * 1000);
		await page.fill("#login-code", codeAt(mock, secret));
		const sent = callsTo(mock, "/v1/auth/login/totp");
		await page.click("#code-submit");
		await page.waitForSelector("#login-form:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /timed out/);
		assert.equal(callsTo(mock, "/v1/auth/login/totp"), sent);
		await page.close();
	});

	await test("2fa sign-in: an 8-digit server, a 503 at the code step names the second factor, a busy server at the password step does not", async () => {
		const mock = createMockApi({ totpDigits: 8 });
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const secret = mock.seedTotp(accountId);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		mock.flags.capacity503 = true;
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForSelector("#login-notice.err");
		assert.equal(await page.textContent("#login-notice"), "The server is busy right now. Try again in a moment.");
		mock.flags.capacity503 = false;
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		mock.flags.totpCapability = false;
		await page.fill("#login-code", codeAt(mock, secret));
		await page.click("#code-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /Two-factor sign-in is temporarily unavailable/);
		assert.equal(await page.isHidden("#code-form"), false, "the challenge is kept for another try");
		mock.flags.totpCapability = true;
		const code = codeAt(mock, secret);
		assert.equal(code.length, 8);
		await page.fill("#login-code", code);
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.close();
	});

	await test("post-sign-in failure is not a credential failure, and the half-made session is revoked", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", PASSWORD);
		const page = await newPage(mock);
		page.expectedConsole = /net::ERR_CONNECTION_RESET|net::ERR_FAILED/;
		mock.dropBefore = new Set(["GET /v1/account/me"]);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForFunction(() => /could not be loaded/.test(document.getElementById("login-notice").textContent));
		assert.doesNotMatch(await page.textContent("#login-notice"), /Invalid email or password/);
		await until(() => [...mock.sessions.values()].every((s) => s.revoked), "the half-made session to be revoked");
		assert.equal(await page.isHidden("#account-panel"), true);
		await page.close();
	});

	await test("sign-out: busy while it runs; 'Sign out everywhere' that does not reach the server keeps this session and says the others are still signed in; the own row's button signs out cleanly", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		const other = mock.seedSession(mock.accounts.get("user@example.com").id, 3600000);
		page.expectedConsole = /net::ERR_CONNECTION_RESET|net::ERR_FAILED/;
		mock.dropBefore = new Set(["POST /v1/auth/logout-all"]);
		await page.click("#logout-all");
		await page.waitForSelector("#account-notice.err");
		assert.match(await page.textContent("#account-notice"), /Other devices are still signed in, and so is this browser/);
		assert.equal(await page.isHidden("#account-panel"), false);
		assert.equal(await page.evaluate(() => window.bitosxApi.isSignedIn()), true);
		assert.equal(mock.sessions.get(other).revoked, false);
		mock.dropBefore.clear();
		// The list, with labels that tell the rows apart.
		await page.click("#refresh-sessions");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 2);
		const labels = await page.locator("#sessions-body button").evaluateAll((bs) => bs.map((b) => b.getAttribute("aria-label")));
		assert.equal(new Set(labels).size, 2);
		assert.ok(labels.some((l) => /^Sign out this session/.test(l)) && labels.some((l) => /^Revoke the session started/.test(l)));
		// A session that ended by itself meanwhile: the list is refreshed, not left with a dead row.
		mock.sessions.delete(other);
		await page.click(`button[data-session-id="${other}"]`);
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(await page.textContent("#account-notice"), "That session had already ended.");
		// Busy while signing out, then the own row's "Sign out" is a plain sign-out.
		const gate = holdOnce(mock, "POST", "/v1/auth/logout");
		await page.click('#sessions-body button[data-current="1"]');
		await gate.held;
		assert.equal(await page.isDisabled("#logout"), true);
		assert.equal(await page.isDisabled("#logout-all"), true);
		gate.release();
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.textContent("#login-notice"), "You are signed out.");
		assert.ok(await page.$("#login-notice.ok"), "a normal sign-out, not a warning");
		await page.close();
	});

	await test("a late answer after sign-out never shows one user's two-factor secret to the next", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		await page.waitForSelector("#totp-enroll-form:not([hidden])");
		// The server has made the secret; its answer arrives only after the user signed out.
		const gate = holdOnce(mock, "POST", "/v1/account/totp/enroll", true);
		await page.fill("#totp-enroll-password", PASSWORD);
		await page.click("#totp-enroll-submit");
		await gate.held;
		assert.equal(mock.totp.size, 1);
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		gate.release();
		await page.waitForTimeout(200);
		assert.equal(await page.isHidden("#totp-setup"), true);
		assert.equal(await page.textContent("#totp-setup-secret"), "");
		await signIn(page);
		await page.waitForFunction(() => /Not enabled/.test(document.getElementById("totp-status").textContent));
		assert.equal(await page.isHidden("#totp-setup"), true);
		assert.equal(await page.textContent("#totp-setup-secret"), "");
		await page.close();
	});

	await test("unsaved vault changes (also text typed in the open editor) are asked about before sign-out and before another item replaces the editor", async () => {
		const mock = createMockApi();
		const { page } = await openedVault(mock);
		assert.equal(await page.isHidden("#nav-signin"), true, "no 'Sign in' link that would sign out by leaving");
		assert.equal(await page.isHidden("#nav-register"), true);
		await page.click("#vault-add");
		await page.fill("#edit-name", "half typed");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		// Hiding the tab does not lock away typed text.
		await page.evaluate(() => {
			Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
			document.dispatchEvent(new Event("visibilitychange"));
			Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
		});
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), true);
		const dialogs = [];
		let answer = false;
		page.on("dialog", (d) => { dialogs.push(d.message()); return answer ? d.accept() : d.dismiss(); });
		await page.locator('.vault-item[data-item-id="11111111-1111-4111-8111-111111111111"] button[data-edit]').click();
		assert.match(dialogs[0], /Discard what you typed in the editor/);
		assert.equal(await page.inputValue("#edit-name"), "half typed", "kept when the user says no");
		await page.click("#logout");
		assert.match(dialogs[1], /unsaved changes in this browser\. Signing out discards them/);
		assert.equal(await page.isHidden("#account-panel"), false, "not signed out when the user says no");
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), true);
		answer = true;
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.textContent("#login-notice"), "You are signed out. Unsaved vault changes in this browser were discarded.");
		assert.equal(await page.isHidden("#nav-signin"), false);
		await page.close();
	});

	await test("vault idle lock: a warning a minute before when there are unsaved changes, a lock that says they were discarded, and the wall clock counts", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock, { beforeRoute: (p) => p.clock.install() });
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await settle(page);
		await page.clock.fastForward("04:01");
		await page.waitForFunction(() => /locks in 60 seconds/.test(document.getElementById("vault-notice").textContent));
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), true);
		await page.clock.fastForward("01:00");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.textContent("#vault-notice"), "Vault locked after 5 minutes without activity. Your unsaved changes were discarded.");
		await assertNoSecretInDom(page);
		// A clean vault and a clock that jumped: locked at the next look at the clock.
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		const t = await page.evaluate(() => Date.now());
		await page.clock.setSystemTime(t + 6 * 60 * 1000);
		await page.evaluate(() => window.dispatchEvent(new Event("focus")));
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.textContent("#vault-notice"), "Vault locked after 5 minutes without activity.");
		await page.close();
	});

	// ------------------------------------------------- phase 8: saving safely
	console.log("vault.bitosx.se — saving safely");
	await test("edits made while a save is uploading stay unsaved (and are saved next time), not marked saved and lost", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		const bank = page.locator('.vault-item[data-item-id="22222222-2222-4222-8222-222222222222"]');
		await bank.locator("button[data-delete]").click();
		await bank.locator("button[data-delete]").click();
		const gate = holdOnce(mock, "PUT", "/v1/sync/envelope");
		await page.click("#vault-save");
		await gate.held;
		const wifi = page.locator(".vault-item", { hasText: "Wi-Fi" });
		await wifi.locator("button[data-delete]").click();
		await wifi.locator("button[data-delete]").click();
		gate.release();
		await page.waitForFunction(() => /changes you made during the upload are not on the server yet/.test(document.getElementById("vault-notice").textContent));
		assert.equal(await page.isHidden("#vault-dirty"), false);
		assert.equal(await page.isDisabled("#vault-save"), false);
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		assert.equal((await serverItems(mock, accountId, meta.typedPassword)).length, 2);
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 3/.test(document.getElementById("vault-notice").textContent));
		assert.deepEqual((await serverItems(mock, accountId, meta.typedPassword)).map((i) => i.name), ["GitHub"]);
		await page.close();
	});

	await test("an item the web cannot write (desktop-accepted URL) is named, nothing is uploaded, and the page is not stuck busy", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		const env = vcNode.parseEnvelope(new Uint8Array(bytes));
		const o = await vcNode.unlock(env, meta.typedPassword);
		const doc = JSON.parse(Buffer.from(o.plaintext).toString("utf8"));
		doc.items.push({ type: "login", Urls: ["http://intranet.42"], Id: "44444444-4444-4444-8444-444444444444", Name: "Intranet", Favorite: false, CreatedAt: "2026-10-04T09:00:00+00:00", UpdatedAt: "2026-10-04T09:00:00+00:00" });
		const next = await vcNode.encryptContent(env, o.vaultKey, new TextEncoder().encode(JSON.stringify(doc)));
		mock.seedEnvelope(accountId, Buffer.from(vcNode.serializeEnvelope(next)));
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await page.click("#vault-save");
		await page.waitForSelector("#vault-notice.err");
		assert.match(await page.textContent("#vault-notice"), /The item 'Intranet' cannot be saved: 'http:\/\/intranet\.42' is not a valid absolute http\(s\) URL\. Nothing was uploaded\./);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 0);
		assert.equal(await page.isDisabled("#vault-save"), false, "not left busy");
		await page.click("#vault-lock");
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /^Vault opened/, "unlock works again: busy was reset");
		await page.close();
	});

	await test("a vault at the web's limit of 10,000 items: adding one more is refused in the editor, not by a stuck save", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		const env = vcNode.parseEnvelope(new Uint8Array(bytes));
		const o = await vcNode.unlock(env, meta.typedPassword);
		const at = new Date("2026-10-01T09:00:00Z");
		const items = [];
		for (let i = 0; i < 10000; i++) {
			items.push({ id: "00000000-0000-4000-8000-" + String(i).padStart(12, "0"), type: "login", name: "Item " + i, username: null, password: null, urls: [], notes: null, favorite: false, createdAt: at, updatedAt: at });
		}
		const next = await vcNode.encryptContent(env, o.vaultKey, vcNode.serializeVault({ items }));
		mock.seedEnvelope(accountId, Buffer.from(vcNode.serializeEnvelope(next)));
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		assert.equal(await page.textContent("#vault-count"), "10000 items");
		await page.click("#vault-add");
		await page.fill("#edit-name", "One too many");
		await page.click("#edit-save");
		assert.match(await page.textContent("#vault-editor-notice"), /already holds 10000 items, the most the web vault can save/);
		assert.equal(await page.isDisabled("#vault-save"), true, "nothing to save");
		await page.close();
	});

	await test("Replace is refused when the server's vault has a new master password or key (another device); reload stays possible", async () => {
		const mock = createMockApi();
		const { page, accountId, bytes } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		// Another device changed the master password: same vault key, re-wrapped under a new salt.
		const doc = JSON.parse(bytes.toString("utf8"));
		doc.salt = require("node:crypto").randomBytes(16).toString("base64");
		doc.keyWrapNonce = require("node:crypto").randomBytes(12).toString("base64");
		doc.encryptedVaultKey = require("node:crypto").randomBytes(48).toString("base64");
		mock.seedEnvelope(accountId, Buffer.from(JSON.stringify(doc, null, 2)));
		await page.click("#vault-save");
		await page.waitForSelector("#vault-conflict:not([hidden])");
		await page.check("#vault-overwrite-ack");
		await page.click("#vault-overwrite");
		await page.waitForFunction(() => /new master password or key/.test(document.getElementById("vault-notice").textContent));
		assert.match(await page.textContent("#vault-conflict-text"), /master password or encryption settings were changed on another device/);
		assert.equal(await page.isHidden("#vault-overwrite-row"), true, "Replace is not offered any more");
		assert.equal(await page.isVisible("#vault-reload"), true);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 1, "only the first, refused, upload");
		assert.equal(mock.envelopes.get(accountId).revision, 2);
		await page.click("#vault-reload");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		await page.waitForFunction(() => /Changes discarded/.test(document.getElementById("vault-notice").textContent));
		await page.close();
	});

	await test("double-clicking Replace uploads once and reports the truth", async () => {
		const mock = createMockApi();
		const { page, accountId, bytes } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		mock.seedEnvelope(accountId, bytes);
		await page.click("#vault-save");
		await page.waitForSelector("#vault-conflict:not([hidden])");
		await page.check("#vault-overwrite-ack");
		await page.dblclick("#vault-overwrite");
		await page.waitForFunction(() => /this browser's version \(revision 3\)/.test(document.getElementById("vault-notice").textContent));
		await page.waitForTimeout(150);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 2, "the refused upload and one replacement");
		assert.equal(mock.envelopes.get(accountId).revision, 3);
		assert.equal(await page.isHidden("#vault-conflict"), true);
		assert.match(await page.textContent("#vault-notice"), /Other devices offer to download it when they sync/);
		await page.close();
	});

	await test("a save the server completed is never reported as 'nothing uploaded': locked meanwhile, or an answer that never came", async () => {
		const mock = createMockApi();
		const { page, accountId } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		const gate = holdOnce(mock, "PUT", "/v1/sync/envelope");
		await page.click("#vault-save");
		await gate.held;
		await page.click("#vault-lock");
		gate.release();
		await page.waitForFunction(() => /Saved: the server now holds revision 2\. The vault was locked meanwhile\./.test(document.getElementById("vault-notice").textContent));
		assert.equal(mock.envelopes.get(accountId).revision, 2);
		// The server stores the upload, but the answer is lost on the way.
		await unlockWith(page, fixture("small").meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine too");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		page.expectedConsole = /net::ERR_CONNECTION_RESET|net::ERR_FAILED/;
		mock.dropAfter = new Set(["PUT /v1/sync/envelope"]);
		await page.click("#vault-save");
		await page.waitForSelector("#vault-notice.err");
		assert.match(await page.textContent("#vault-notice"), /The upload got no answer.*may or may not have stored it/);
		assert.equal(mock.envelopes.get(accountId).revision, 3, "it did arrive");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), true);
		mock.dropAfter.clear();
		await page.click("#vault-save");
		await page.waitForFunction(() => /earlier upload had reached the server, which holds revision 3/.test(document.getElementById("vault-notice").textContent));
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		assert.equal(await page.isHidden("#vault-conflict"), true, "its own upload is not a conflict");
		await page.close();
	});

	await test("unlock: a vault removed from the server meanwhile is said to be gone; an unlock that finishes after sign-out or in a hidden tab shows nothing", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		mock.envelopes.delete(accountId);
		await unlockWith(page, meta.typedPassword);
		await page.waitForFunction(() => /no longer holds a vault/.test(document.getElementById("vault-notice").textContent));
		assert.match(await page.textContent("#vault-status-text"), /holds no vault for this account yet/);
		assert.equal(await page.isHidden("#vault-unlock-form"), true);
		// Signed out while the vault was being downloaded: nothing opens in the next session.
		mock.seedEnvelope(accountId, bytes);
		await page.click("#logout");
		await signedIn(mock, page);
		const gate = holdOnce(mock, "GET", "/v1/sync/envelope");
		await page.fill("#vault-master-password", meta.typedPassword);
		await page.click("#vault-unlock-submit");
		await gate.held;
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		await signIn(page);
		gate.release();
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		await page.waitForTimeout(300);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		assert.equal(await page.locator("#vault-items .vault-item").count(), 0);
		// The tab was hidden when the key derivation finished: locked again at once.
		await page.evaluate(() => Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true }));
		await unlockWith(page, meta.typedPassword);
		assert.match(await page.textContent("#vault-notice"), /opened while this tab was hidden, so it was locked again/);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		await assertNoSecretInDom(page);
		await page.close();
	});

	await test("clipboard: cleared after 30 s while focused; left alone if something else was copied; retried when focus returns; a refusal is reported", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock, {
			context: { permissions: ["clipboard-read", "clipboard-write"] },
			beforeRoute: (p) => p.clock.install()
		});
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		// Each copy waits for its own "Copied" notice: the clear is timed from when the copy completed.
		const copy = async () => {
			await page.evaluate(() => { document.getElementById("vault-notice").textContent = ""; });
			await page.locator('.vault-item[data-item-id="11111111-1111-4111-8111-111111111111"] button[data-copy="password"]').click();
			await page.waitForFunction(() => /^Copied/.test(document.getElementById("vault-notice").textContent));
		};
		const clipboard = () => page.evaluate(() => navigator.clipboard.readText());
		await copy();
		await page.waitForFunction(() => /^Copied\. After 30 seconds/.test(document.getElementById("vault-notice").textContent));
		assert.match(await page.textContent("#vault-notice"), /clipboard history kept by your system is not cleared/);
		assert.equal(await clipboard(), "P@ssw0rd-Strong-123");
		await page.clock.fastForward("00:31");
		await until(async () => (await clipboard()) === "", "the clipboard to be cleared");
		// Something copied afterwards is never erased.
		await copy();
		await page.evaluate(() => navigator.clipboard.writeText("something else"));
		await page.clock.fastForward("00:31");
		await page.waitForTimeout(100);
		assert.equal(await clipboard(), "something else");
		// Not focused when the time is up: tried again when the page has focus.
		await copy();
		await page.evaluate(() => { window.__hasFocus = document.hasFocus; document.hasFocus = () => false; });
		await page.clock.fastForward("00:31");
		await page.waitForTimeout(100);
		assert.equal(await clipboard(), "P@ssw0rd-Strong-123", "a browser refuses an unfocused page anyway");
		await page.evaluate(() => { document.hasFocus = window.__hasFocus; window.dispatchEvent(new Event("focus")); });
		await until(async () => (await clipboard()) === "", "the clipboard to be cleared on return");
		// Copy, then the tab is hidden to paste elsewhere: the lock leaves the clipboard to its timer.
		await copy();
		await page.evaluate(() => {
			Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
			document.dispatchEvent(new Event("visibilitychange"));
			Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
		});
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		await page.waitForTimeout(100);
		assert.equal(await clipboard(), "P@ssw0rd-Strong-123", "still there to be pasted");
		await page.clock.fastForward("00:31");
		await until(async () => (await clipboard()) === "", "the clipboard to be cleared by its timer");
		// An explicit Lock takes the copied secret with it at once.
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await copy();
		await page.click("#vault-lock");
		await until(async () => (await clipboard()) === "", "the clipboard to be cleared on Lock");
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		// The browser refuses to let the page check: the user is told.
		await copy();
		await page.evaluate(() => Object.defineProperty(navigator.clipboard, "readText", { value: () => Promise.reject(new Error("denied")), configurable: true }));
		await page.clock.fastForward("00:31");
		await page.waitForFunction(() => /could not be cleared/.test(document.getElementById("vault-notice").textContent));
		await page.close();
	});

	// --------------------------------------------- phase 8: editor and list
	console.log("vault.bitosx.se — editor, generator, list");
	await test("generator options (desktop rules) are used and remembered per browser; a live strength rating; invalid options are refused", async () => {
		const mock = createMockApi();
		const { page, meta } = await openedVault(mock);
		await page.click("#vault-add");
		await page.click(".vault-generator summary");
		await page.fill("#gen-length", "32");
		await page.locator("#gen-length").dispatchEvent("change");
		await page.uncheck("#gen-symbols");
		await page.click("#edit-password-generate");
		const pw = await page.inputValue("#edit-password");
		assert.match(pw, /^[A-Za-z0-9]{32}$/);
		assert.match(pw, /[a-z]/); assert.match(pw, /[A-Z]/); assert.match(pw, /[0-9]/);
		const stored = JSON.parse(await page.evaluate(() => localStorage.getItem("bitosx.generator")));
		assert.deepEqual(stored, { length: 32, lowercase: true, uppercase: true, digits: true, symbols: false, excludeAmbiguous: false });
		assert.ok(!JSON.stringify(stored).includes(pw), "the options, never a password");
		await page.fill("#edit-password", "Password123!");
		assert.match(await page.textContent("#edit-password-strength"), /^Strength: Very weak/);
		await page.fill("#gen-length", "3");
		await page.locator("#gen-length").dispatchEvent("change");
		assert.match(await page.textContent("#vault-editor-notice"), /between 4 and 256/);
		await page.fill("#gen-length", "32");
		await page.locator("#gen-length").dispatchEvent("change");
		// Remembered in this browser.
		await page.click("#edit-cancel");
		await page.reload();
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.click("#vault-add");
		assert.equal(await page.inputValue("#gen-length"), "32");
		assert.equal(await page.isChecked("#gen-symbols"), false);
		// Storage that holds something else is ignored.
		await page.evaluate(() => localStorage.setItem("bitosx.generator", "{not json"));
		await page.click("#edit-cancel");
		await page.reload();
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.click("#vault-add");
		assert.equal(await page.inputValue("#gen-length"), "20");
		await page.close();
	});

	await test("editor: problems shown at the field while typing; half a surrogate pair refused; whitespace-only notes are no notes; a note counter", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		await page.click("#vault-add");
		await page.fill("#edit-urls", "https://ok.example\nnot a url");
		assert.match(await page.textContent("#edit-urls-error"), /'not a url' is not a valid absolute http\(s\) URL/);
		assert.equal(await page.getAttribute("#edit-urls", "aria-invalid"), "true");
		await page.fill("#edit-urls", "https://ok.example");
		assert.equal(await page.isHidden("#edit-urls-error"), true);
		await page.evaluate(() => { const n = document.getElementById("edit-name"); n.value = "Broken \uD83D"; n.dispatchEvent(new Event("input", { bubbles: true })); });
		assert.match(await page.textContent("#edit-name-error"), /incomplete character/);
		await page.click("#edit-save");
		assert.equal(await page.evaluate(() => document.activeElement.id), "edit-name");
		await page.fill("#edit-name", "Whole 🔐");
		await page.fill("#edit-notes", "   \n  ");
		assert.equal(await page.textContent("#edit-notes-count"), "6 / 16384 characters");
		assert.equal(await page.getAttribute("#edit-notes", "maxlength"), "16384");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const items = await serverItems(mock, accountId, meta.typedPassword);
		const added = items.find((i) => i.name === "Whole 🔐");
		assert.equal(added.notes, null);
		// The desktop's order is kept: the new item is last, the others as they were.
		assert.deepEqual(items.map((i) => i.id).slice(0, 3), ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"]);
		await page.close();
	});

	await test("an armed Delete can be cancelled; favorites filter; sort by recently updated", async () => {
		const mock = createMockApi();
		const { page } = await openedVault(mock);
		const bank = page.locator('.vault-item[data-item-id="22222222-2222-4222-8222-222222222222"]');
		await bank.locator("button[data-delete]").click();
		assert.equal(await bank.locator("button[data-delete]").textContent(), "Confirm delete");
		await bank.locator("button[data-disarm]").click();
		assert.equal(await bank.locator("button[data-delete]").textContent(), "Delete");
		assert.equal(await page.locator("#vault-items .vault-item").count(), 3);
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		await page.check("#vault-favorites");
		assert.deepEqual((await page.locator(".vault-item__name").allTextContents()).map((n) => n.trim()), ["GitHub ★"]);
		assert.equal(await page.textContent("#vault-count"), "1 of 3 items");
		await page.uncheck("#vault-favorites");
		await page.selectOption("#vault-sort", "updated");
		assert.deepEqual((await page.locator(".vault-item__name").allTextContents()).map((n) => n.trim()), ["Wi-Fi café", "GitHub ★", "Bank <script>alert(1)</script>"]);
		await page.close();
	});

	await test("download encrypted backup: the server's bytes exactly, as a dated .bitosx-backup file, without unlocking", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock);
		await signedIn(mock, page);
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		const [download] = await Promise.all([page.waitForEvent("download"), page.click("#vault-backup")]);
		assert.match(download.suggestedFilename(), /^BitosX-backup-\d{4}-\d{2}-\d{2}\.bitosx-backup$/);
		const saved = fs.readFileSync(await download.path());
		assert.deepEqual(saved, bytes, "byte for byte what the desktop uploaded");
		await page.waitForFunction(() => /exactly as the server stores it \(revision 1/.test(document.getElementById("vault-notice").textContent));
		// Nothing stored: no button.
		mock.envelopes.delete(accountId);
		await page.click("#logout");
		await signedIn(mock, page);
		assert.equal(await page.isHidden("#vault-backup"), true);
		await page.close();
	});

	// ----------------------------------------- phase 8: account controls
	console.log("vault.bitosx.se — account controls");
	await test("change the account password: other sessions are signed out, this one stays; a wrong current password changes nothing", async () => {
		const mock = createMockApi();
		const page = await signedInPlain(mock);
		const acct = mock.accounts.get("user@example.com");
		const other = mock.seedSession(acct.id, 3600000);
		assert.equal(await page.isHidden("#pw-code-field"), true, "no code field without two-factor");
		await page.fill("#pw-current", "wrong wrong wrong wrong");
		await page.fill("#pw-new", "brand new password 42");
		await page.fill("#pw-new2", "brand new password 42");
		await page.click("#pw-submit");
		await page.waitForSelector("#pw-notice.err");
		assert.match(await page.textContent("#pw-notice"), /current password or the code was not accepted\. The password was not changed/);
		assert.equal(await page.isHidden("#account-panel"), false, "a 403 is not a dead session");
		assert.equal(mock.sessions.get(other).revoked, false);
		await page.fill("#pw-current", PASSWORD);
		await page.fill("#pw-new", "brand new password 42");
		await page.fill("#pw-new2", "brand new password 43");
		const sent = callsTo(mock, "/v1/account/password");
		await page.click("#pw-submit");
		assert.match(await page.textContent("#pw-notice"), /do not match/);
		assert.equal(callsTo(mock, "/v1/account/password"), sent, "no request for a mismatch");
		await page.fill("#pw-current", PASSWORD);
		await page.fill("#pw-new", "brand new password 42");
		await page.fill("#pw-new2", "brand new password 42");
		await page.click("#pw-submit");
		await page.waitForFunction(() => /password is changed/.test(document.getElementById("pw-notice").textContent));
		assert.match(await page.textContent("#pw-notice"), /Every other device and browser was signed out; this one stays signed in\. Your vault master password is unchanged/);
		const call = mock.calls.filter((c) => c.path === "/v1/account/password").pop();
		assert.deepEqual(call.body, { currentPassword: PASSWORD, newPassword: "brand new password 42" });
		assert.equal(mock.sessions.get(other).revoked, true);
		assert.equal(acct.password, "brand new password 42");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(await page.inputValue("#pw-current"), "");
		await page.click("#refresh-sessions");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(await page.isHidden("#account-panel"), false, "this session is still valid");
		await page.close();
	});

	await test("with two-factor on: password change and account deletion ask for a code; Enter in the manage form regenerates nothing", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const secret = mock.seedTotp(accountId, ["abcde-fghjk", "mnpqr-stuvw"]);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		await page.fill("#login-code", codeAt(mock, secret));
		await page.click("#code-submit");
		await page.waitForSelector("#totp-manage-form:not([hidden])");
		// Enter in the password field of the manage form: no action is chosen for the user.
		await page.fill("#totp-manage-password", PASSWORD);
		await page.fill("#totp-manage-code", "abcde-fghjk");
		await page.press("#totp-manage-password", "Enter");
		await page.press("#totp-manage-code", "Enter");
		await page.waitForTimeout(150);
		assert.equal(callsTo(mock, "/v1/account/totp/recovery-codes") + callsTo(mock, "/v1/account/totp/disable"), 0);
		assert.equal(await page.isHidden("#totp-codes"), true, "the recovery codes were not replaced");
		assert.equal(await page.inputValue("#totp-manage-password"), PASSWORD, "nothing was submitted");
		// Password change needs the code.
		assert.equal(await page.isHidden("#pw-code-field"), false);
		await page.fill("#pw-current", PASSWORD);
		await page.fill("#pw-new", "brand new password 42");
		await page.fill("#pw-new2", "brand new password 42");
		await page.click("#pw-submit");
		assert.match(await page.textContent("#pw-notice"), /Enter a current code/);
		assert.equal(callsTo(mock, "/v1/account/password"), 0);
		await page.fill("#pw-current", PASSWORD);
		await page.fill("#pw-new", "brand new password 42");
		await page.fill("#pw-new2", "brand new password 42");
		await page.fill("#pw-code", "mnpqr-stuvw");
		await page.click("#pw-submit");
		await page.waitForFunction(() => /password is changed/.test(document.getElementById("pw-notice").textContent));
		assert.equal(mock.calls.find((c) => c.path === "/v1/account/password").body.code, "mnpqr-stuvw");
		// The server's second factor switched off meanwhile: a 503 without Retry-After (contract
		// deviation), the generic text, nothing changed, still signed in.
		mock.flags.totpCapability = false;
		await page.fill("#pw-current", "brand new password 42");
		await page.fill("#pw-new", "another new password 43");
		await page.fill("#pw-new2", "another new password 43");
		await page.fill("#pw-code", codeAt(mock, secret, 1));
		await page.click("#pw-submit");
		await page.waitForSelector("#pw-notice.err");
		assert.equal(await page.textContent("#pw-notice"), "The service is temporarily unavailable. Try again shortly.");
		assert.equal(mock.accounts.get("user@example.com").password, "brand new password 42");
		assert.equal(await page.isHidden("#account-panel"), false);
		mock.flags.totpCapability = true;
		// Deletion needs the code too: a wrong one is the generic 403, the right one deletes.
		assert.equal(await page.isHidden("#delete-code-field"), false);
		const good = [-1, 0, 1].map((o) => codeAt(mock, secret, o));
		const wrong = ["000000", "111111", "222222"].find((c) => !good.includes(c));
		await page.fill("#delete-password", "brand new password 42");
		await page.fill("#delete-code", wrong);
		await page.check("#delete-ack");
		await page.click("#delete-submit");
		await page.waitForSelector("#delete-notice.err");
		assert.match(await page.textContent("#delete-notice"), /password or the code was not accepted\. Nothing was deleted/);
		assert.equal(mock.accounts.size, 1);
		await page.fill("#delete-password", "brand new password 42");
		await page.fill("#delete-code", codeAt(mock, secret, 1));
		await page.click("#delete-submit");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /account and the vault stored on the server are deleted/);
		assert.equal(mock.accounts.size, 0);
		assert.deepEqual(Object.keys(mock.calls.filter((c) => c.path === "/v1/account/delete").pop().body), ["password", "code"]);
		await page.close();
	});

	await test("two-factor setup: copy buttons for the secret and the link; recovery codes survive a failing status call", async () => {
		const mock = createMockApi();
		freezeMidStep(mock);
		mock.seedAccount("user@example.com", PASSWORD);
		const page = await newPage(mock, { context: { permissions: ["clipboard-read", "clipboard-write"] } });
		await page.goto(`${vault.origin}/`);
		await signIn(page);
		await page.waitForSelector("#totp-enroll-form:not([hidden])");
		await page.fill("#totp-enroll-password", PASSWORD);
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-setup:not([hidden])");
		await page.click("#totp-secret-copy");
		await page.waitForFunction(() => /^Copied/.test(document.getElementById("totp-notice").textContent));
		const copied = await page.evaluate(() => navigator.clipboard.readText());
		assert.match(copied, /^[A-Z2-7]{32}$/, "the secret without the display spaces");
		await page.click("#totp-uri-copy");
		await until(async () => /^otpauth:\/\/totp\//.test(await page.evaluate(() => navigator.clipboard.readText())), "the link on the clipboard");
		// The status call after confirming would fail: nothing is asked of the server while the codes are shown.
		page.expectedConsole = /net::ERR_CONNECTION_RESET|net::ERR_FAILED/;
		mock.dropBefore = new Set(["GET /v1/account/totp"]);
		await page.fill("#totp-confirm-code", codeAt(mock, base32Decode(copied)));
		await page.click("#totp-confirm-submit");
		await page.waitForSelector("#totp-codes:not([hidden])");
		await page.waitForTimeout(150);
		assert.equal((await page.textContent("#totp-codes-list")).trim().split("\n").length, 10);
		assert.match(await page.textContent("#totp-status"), /Recovery codes left: 10/);
		await page.close();
	});

	await test("limits and formats: a 320-character email is accepted; timestamps without an offset are UTC; the session list is read up to the server's 200", async () => {
		const mock = createMockApi();
		const page = await newPage(mock, { context: { timezoneId: "America/New_York" } });
		await page.goto(`${vault.origin}/forgot-password`);
		const email = "a".repeat(308) + "@example.com";
		assert.equal(email.length, 320);
		await page.fill("#forgot-email", email);
		await page.click("#forgot-submit");
		await page.waitForSelector("#forgot-notice.ok");
		assert.equal(mock.calls[0].body.email, email);
		await page.goto(`${vault.origin}/`);
		const parsed = await page.evaluate(() => [
			window.bitosxApi._parseUtc("2026-10-01T09:00:00"),
			window.bitosxApi._parseUtc("2026-10-01T09:00:00.1234567"),
			window.bitosxApi._parseUtc("2026-10-01T09:00:00.1234567+00:00"),
			window.bitosxApi._parseUtc("2026-10-01T11:00:00+02:00"),
			window.bitosxApi._parseUtc("October 1, 2026")
		]);
		const utc9 = Date.UTC(2026, 9, 1, 9);
		assert.deepEqual(parsed.slice(0, 4), [utc9, utc9 + 123, utc9 + 123, utc9]);
		assert.ok(Number.isNaN(parsed[4]), "not ISO 8601: refused");
		const acct = mock.seedAccount("user@example.com", PASSWORD);
		for (let i = 1; i <= 250; i++) { mock.seedSession(acct, i * 1000); }
		await signIn(page);
		assert.equal(await page.locator("#sessions-body tr").count(), 200);
		assert.equal(await page.locator("#sessions-body .current").count(), 1, "newest first: this session is in the list");
		await page.close();
	});

	await test("time limits: an ordinary call gives up after 15 s, an envelope transfer only after 120 s, each with a clear message", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock, { beforeRoute: (p) => p.clock.install() });
		await signedIn(mock, page);
		const slowList = holdOnce(mock, "GET", "/v1/account/sessions");
		await page.click("#refresh-sessions");
		await slowList.held;
		await page.clock.fastForward("00:16");
		await page.waitForFunction(() => /did not answer in time/.test(document.getElementById("account-notice").textContent));
		slowList.release();
		const slowEnvelope = holdOnce(mock, "GET", "/v1/sync/envelope");
		await page.fill("#vault-master-password", meta.typedPassword);
		await page.click("#vault-unlock-submit");
		await slowEnvelope.held;
		await page.clock.fastForward("01:00");
		await page.waitForTimeout(100);
		assert.equal(await page.textContent("#vault-progress"), "Downloading the encrypted vault…", "still waiting after 60 s");
		await page.clock.fastForward("01:01");
		await page.waitForFunction(() => /did not answer in time/.test(document.getElementById("vault-notice").textContent));
		slowEnvelope.release();
		await page.close();
	});

	await test("CORS as the API ships it: without PUT a save fails as in a browser; the product page may read only /health and /version", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const page = await newPage(mock, { cors: { vault: { methods: ["GET", "POST", "DELETE"] } } });
		page.expectedConsole = /net::ERR_FAILED/;
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		const refusedBefore = corsRefusals.length;
		await page.click("#vault-save");
		await page.waitForSelector("#vault-notice.err");
		assert.match(await page.textContent("#vault-notice"), /could not be reached/);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 0, "the browser never sent it");
		assert.deepEqual(corsRefusals.slice(refusedBefore).map((r) => r.method + " " + r.path + ": " + r.why), ["PUT /v1/sync/envelope: method PUT not allowed"]);
		await page.close();
		// The product page: the status badge works (other tests), anything else is refused.
		const wwwPage = await newPage(mock);
		wwwPage.expectedConsole = /net::ERR_FAILED|blocked by CORS policy/;
		await wwwPage.goto(`${www.origin}/`);
		await wwwPage.waitForFunction(() => document.getElementById("api-badge").textContent !== "checking…");
		assert.equal(await wwwPage.textContent("#api-badge"), "healthy · v0.1.0");
		const outcomes = await wwwPage.evaluate(async () => {
			const tryFetch = (path, init) => fetch("https://api.bitosx.se" + path, init).then(() => "read", () => "refused");
			return [
				await tryFetch("/v1/account/me", { headers: { "Authorization": "Bearer x" } }),
				await tryFetch("/v1/sync/status", { headers: { "Accept": "application/json" } }),
				await tryFetch("/version", { headers: { "Accept": "application/json" } })
			];
		});
		assert.deepEqual(outcomes, ["refused", "refused", "read"]);
		await wwwPage.close();
	});

	await test("mock fidelity: resend is always 202, a confirmation records the step that matched, revisions never restart", async () => {
		const m = createMockApi();
		freezeMidStep(m);
		assert.equal(m.handle("POST", "/v1/auth/resend-verification", {}, JSON.stringify({ email: "not an email" })).status, 202);
		const accountId = m.seedAccount("user@example.com", PASSWORD);
		const login = () => JSON.parse(m.handle("POST", "/v1/auth/login", {}, JSON.stringify({ email: "user@example.com", password: PASSWORD })).body);
		const H = { authorization: "Bearer " + login().accessToken };
		const enroll = JSON.parse(m.handle("POST", "/v1/account/totp/enroll", H, JSON.stringify({ password: PASSWORD })).body);
		const secret = base32Decode(enroll.secret);
		assert.equal(m.handle("POST", "/v1/account/totp/confirm", H, JSON.stringify({ code: codeAt(m, secret, -1) })).status, 200);
		const challenge = login();
		assert.equal(m.handle("POST", "/v1/auth/login/totp", {}, JSON.stringify({ mfaToken: challenge.mfaToken, code: codeAt(m, secret, 0) })).status, 200,
			"the current step is newer than the one that confirmed");
		m.seedEnvelope(accountId, Buffer.from(JSON.stringify({ version: 1 })));
		assert.equal(m.handle("DELETE", "/v1/sync/envelope", H, "").status, 204);
		const put = m.handle("PUT", "/v1/sync/envelope", H, JSON.stringify({ baseRevision: 0, envelope: Buffer.from(JSON.stringify({ version: 1 })).toString("base64") }));
		assert.equal(JSON.parse(put.body).revision, 2, "after a delete the next upload is revision 2, not 1");
	});

	await test("notices stay rendered while empty (live regions), and the inline note states the configured times", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		for (const id of ["login-notice", "account-notice", "totp-notice", "vault-notice", "pw-notice"]) {
			const display = await page.evaluate((i) => getComputedStyle(document.getElementById(i)).display, id);
			assert.notEqual(display, "none", id);
		}
		assert.equal(await page.textContent("#note-clipboard-seconds"), "30");
		assert.equal(await page.textContent("#note-vault-minutes"), "5");
		assert.equal(await page.textContent("#note-idle-minutes"), "15");
		for (const id of ["vault-master-password", "edit-password", "edit-username"]) {
			assert.equal(await page.getAttribute("#" + id, "autocomplete"), "off");
			assert.equal(await page.getAttribute("#" + id, "data-lpignore"), "true", "password-manager extensions are asked to keep out");
		}
		await page.close();
	});

	// ------------------------------------------------------ phase 10: passkeys
	console.log("vault.bitosx.se — passkeys");
	const nodeCrypto = require("node:crypto");
	// Chromium's virtual authenticator (CDP WebAuthn domain): a platform authenticator with resident
	// keys and user verification that answers at once, as a person would.
	async function virtualAuthenticator(page, extra = {}) {
		const cdp = await page.context().newCDPSession(page);
		await cdp.send("WebAuthn.enable", { enableUI: false });
		const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
			options: Object.assign({ protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
				hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }, extra)
		});
		return {
			cdp, id: authenticatorId,
			credentials: async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials
		};
	}
	// A passkey that exists in the authenticator and (unless serverKnows is false) on the mock
	// server: a fresh P-256 key, as if registered earlier.
	async function seedPasskey(mock, accountId, auth, options = {}) {
		const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
		const credentialId = nodeCrypto.randomBytes(32);
		if (!mock.userHandles.has(accountId)) { mock.userHandles.set(accountId, nodeCrypto.randomBytes(32).toString("base64url")); }
		const userHandle = options.userHandle || Buffer.from(mock.userHandles.get(accountId), "base64url");
		await auth.cdp.send("WebAuthn.addCredential", { authenticatorId: auth.id, credential: {
			credentialId: credentialId.toString("base64"), isResidentCredential: true, rpId: "localhost",
			privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
			userHandle: userHandle.toString("base64"), signCount: 0
		} });
		const pk = { id: nodeCrypto.randomUUID(), credentialId: credentialId.toString("base64url"), publicKey: publicKey.export({ type: "spki", format: "der" }),
			name: options.name || "Seeded laptop", createdAt: new Date(mock.now() - 3600000).toISOString(), lastUsedAt: null, backedUp: !!options.backedUp, signCount: 0 };
		if (options.serverKnows !== false) { mock.passkeys.set(accountId, (mock.passkeys.get(accountId) || []).concat([pk])); }
		return pk;
	}
	const RECOVERY = ["aaaaa-bbbbb", "ccccc-ddddd", "eeeee-fffff", "ggggg-hhhhh", "jjjjj-kkkkk", "mmmmm-nnnnn"];
	// An account with two-factor on, a page with a virtual authenticator, the vault on localhost.
	async function passkeyAccount(options = {}) {
		const mock = createMockApi(options.mock);
		mock.webauthn.origin = vault.origin;
		freezeMidStep(mock);
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const secret = mock.seedTotp(accountId, RECOVERY.slice());
		const page = await newPage(mock, { beforeRoute: options.beforeRoute });
		const auth = await virtualAuthenticator(page, options.authenticator);
		return { mock, accountId, secret, page, auth };
	}
	async function passwordThenCode(page, code) {
		await page.fill("#login-email", "user@example.com");
		await page.fill("#login-password", PASSWORD);
		await page.click("#login-submit");
		await page.waitForSelector("#code-form:not([hidden])");
		if (code) {
			await page.fill("#login-code", code);
			await page.click("#code-submit");
			await page.waitForSelector("#account-panel:not([hidden])");
		}
	}
	const passkeyStatus = (page) => page.textContent("#passkey-status");
	const lastCall = (mock, p) => mock.calls.filter((c) => c.path === p).pop();

	await test("passkeys: without two-factor the account page says it comes first and offers no passkey; the sign-in page offers passkey sign-in", async () => {
		const mock = createMockApi();
		mock.seedAccount("user@example.com", PASSWORD);
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		assert.equal(await page.isVisible("#passkey-signin-submit"), true, "this browser supports passkeys");
		assert.match(await page.textContent("#passkey-signin"), /opening the vault still needs your vault master password/);
		await signIn(page);
		await page.waitForFunction(() => document.getElementById("passkey-status").textContent !== "");
		assert.equal(await passkeyStatus(page), "Turn on two-factor authentication above first: passkeys are added on top of it.");
		assert.equal(await page.isHidden("#passkey-add-form"), true);
		assert.equal(await page.locator("#passkey-list li").count(), 0);
		assert.match(await page.textContent("#account-panel"), /opening the vault still needs your vault master password/);
		await page.close();
	});

	await test("passkeys: add one with password + code -> the browser's authenticator -> listed with its name, dates and synced badge; a wrong code adds nothing", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount({ authenticator: { defaultBackupEligibility: true, defaultBackupState: true } });
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page, RECOVERY[0]);
		await page.waitForSelector("#passkey-add-form:not([hidden])");
		assert.equal(await passkeyStatus(page), "No passkeys yet.");
		// Client-side checks first: no request without a name, a password and a code.
		await page.fill("#passkey-add-name", "  ");
		await page.click("#passkey-add-submit");
		assert.match(await page.textContent("#passkey-notice"), /name of 1–64 characters/);
		assert.equal(callsTo(mock, "/v1/account/passkeys/registration/options"), 0);
		// A wrong code: the server's generic 403, nothing created in the authenticator.
		await page.fill("#passkey-add-name", "Work laptop");
		await page.fill("#passkey-add-password", PASSWORD);
		await page.fill("#passkey-add-code", "000000");
		await page.click("#passkey-add-submit");
		await page.waitForSelector("#passkey-notice.err");
		assert.match(await page.textContent("#passkey-notice"), /password or the code was not accepted/);
		assert.equal((await auth.credentials()).length, 0);
		assert.equal(await page.inputValue("#passkey-add-password"), "", "the password never waits on the page");
		assert.equal(await page.inputValue("#passkey-add-code"), "");
		// The real thing.
		await page.fill("#passkey-add-password", PASSWORD);
		await page.fill("#passkey-add-code", RECOVERY[1]);
		await page.click("#passkey-add-submit");
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 1);
		assert.match(await page.textContent("#passkey-notice"), /Passkey “Work laptop” added\. .*vault master password/);
		assert.equal(await passkeyStatus(page), "1 of at most 10 passkeys.");
		const item = page.locator("#passkey-list li").first();
		assert.match(await item.locator(".passkey-item__name").textContent(), /^Work laptop Synced$/);
		assert.match(await item.locator(".passkey-item__meta").textContent(), /^Added .+ · not used yet$/);
		assert.equal(await page.inputValue("#passkey-add-name"), "");
		// What travelled: the options asked with password + code, the completion with the ceremony id,
		// the trimmed name and the browser's credential JSON (never the password).
		assert.deepEqual(lastCall(mock, "/v1/account/passkeys/registration/options").body, { password: PASSWORD, code: RECOVERY[1] });
		const reg = lastCall(mock, "/v1/account/passkeys/registration").body;
		assert.deepEqual(Object.keys(reg).sort(), ["credential", "name", "registrationId"]);
		assert.equal(reg.name, "Work laptop");
		assert.equal(reg.credential.type, "public-key");
		assert.deepEqual(Object.keys(reg.credential.response).sort(), ["attestationObject", "authenticatorData", "clientDataJSON", "publicKey", "publicKeyAlgorithm", "transports"]);
		const creds = await auth.credentials();
		assert.equal(creds.length, 1);
		assert.equal(creds[0].isResidentCredential, true, "a discoverable credential");
		assert.equal(creds[0].rpId, "localhost");
		assert.equal(Buffer.from(creds[0].userHandle, "base64").toString("base64url"), mock.userHandles.get(accountId), "user.id is the server's random handle");
		assert.equal(mock.passkeys.get(accountId).length, 1);
		assert.equal(mock.passkeys.get(accountId)[0].backedUp, true);
		// The same authenticator again: the server excludes its credential, the browser refuses.
		await page.fill("#passkey-add-name", "Again");
		await page.fill("#passkey-add-password", PASSWORD);
		await page.fill("#passkey-add-code", RECOVERY[2]);
		await page.click("#passkey-add-submit");
		await page.waitForSelector("#passkey-notice.err");
		assert.match(await page.textContent("#passkey-notice"), /already holds a passkey for this account. Nothing was added/);
		assert.equal(mock.passkeys.get(accountId).length, 1);
		assert.equal(callsTo(mock, "/v1/account/passkeys/registration"), 1, "nothing to complete");
		assert.equal(await page.isHidden("#passkey-add-form"), false, "another device can still be added");
		await page.close();
	});

	await test("passkeys: the second sign-in step offers 'Use a passkey' only when the server lists it; the passkey signs in", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		await page.goto(`${vault.origin}/`);
		// No passkey on the account: the server does not list it, the page does not offer it.
		await passwordThenCode(page);
		assert.equal(await page.isHidden("#code-passkey"), true);
		assert.doesNotMatch(await page.textContent("#login-notice"), /passkey/);
		assert.equal(await page.isHidden("#passkey-signin"), true, "no passwordless button inside the second step");
		await page.click("#code-cancel");
		await page.waitForSelector("#passkey-signin:not([hidden])");
		await seedPasskey(mock, accountId, auth);
		await passwordThenCode(page);
		assert.equal(await page.isVisible("#code-passkey"), true);
		assert.match(await page.textContent("#login-notice"), /or use a passkey/);
		const token = [...mock.mfaChallenges.keys()].pop();
		await page.click("#code-passkey");
		await page.waitForSelector("#account-panel:not([hidden])");
		assert.deepEqual(lastCall(mock, "/v1/auth/login/passkey/options").body, { mfaToken: token });
		const done = lastCall(mock, "/v1/auth/login/passkey").body;
		assert.equal(done.mfaToken, token);
		assert.equal(typeof done.credential.response.signature, "string");
		assert.equal(mock.mfaChallenges.get(token).consumed, true);
		assert.equal(await page.isHidden("#code-form"), true);
		await page.waitForFunction(() => /not used yet|last used/.test(document.getElementById("passkey-list").textContent));
		assert.match(await page.textContent("#passkey-list"), /last used/);
		await page.close();
	});

	await test("passkeys: an older server without `methods`, an unreadable `methods`, and a server without passkeys: the second step is code-only", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount({ mock: { legacyLogin: true } });
		await seedPasskey(mock, accountId, auth);
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page);
		assert.equal(await page.isHidden("#code-passkey"), true);
		await page.click("#code-cancel");
		// Read tolerantly: values this page does not know are ignored; a list that is not a list is
		// read as "code only" (the step itself is never skipped).
		mock.flags.methodsOverride = ["sms", 7, "passkey", { x: 1 }, "totp"];
		await passwordThenCode(page);
		assert.equal(await page.isVisible("#code-passkey"), true);
		await page.click("#code-cancel");
		mock.flags.methodsOverride = "passkey";
		await passwordThenCode(page);
		assert.equal(await page.isHidden("#code-passkey"), true);
		assert.equal(await page.isHidden("#account-panel"), true);
		await page.click("#code-cancel");
		const off = await passkeyAccount();
		await seedPasskey(off.mock, off.accountId, off.auth);
		off.mock.flags.passkeyCapability = false;
		await off.page.goto(`${vault.origin}/`);
		await passwordThenCode(off.page, RECOVERY[0]);
		assert.equal(await off.page.isHidden("#code-passkey"), true);
		await off.page.waitForFunction(() => document.getElementById("passkey-status").textContent !== "");
		assert.equal(await off.page.textContent("#passkey-status"), "Passkeys are not available on this server.");
		assert.equal(await off.page.isHidden("#passkey-add-form"), true);
		// Passwordless on such a server: a plain answer, no session.
		await off.page.click("#logout");
		await off.page.waitForSelector("#login-panel:not([hidden])");
		await off.page.click("#passkey-signin-submit");
		await off.page.waitForSelector("#login-notice.err");
		assert.equal(await off.page.textContent("#login-notice"), "Passkey sign-in is not available on this server.");
		await page.close();
		await off.page.close();
	});

	await test("passkeys: second step — a cancelled prompt keeps the step and uses no attempt; a refused passkey uses one, like a wrong code", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		await seedPasskey(mock, accountId, auth);
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page);
		const token = [...mock.mfaChallenges.keys()].pop();
		// The prompt ends without a passkey (here: the authenticator holds none for this site; the
		// browser reports NotAllowedError, exactly as when the person cancels).
		const saved = await auth.credentials();
		await auth.cdp.send("WebAuthn.clearCredentials", { authenticatorId: auth.id });
		await page.click("#code-passkey");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /No passkey was used: the browser's prompt was cancelled or timed out.*Try again, or enter a code/);
		assert.equal(await page.isHidden("#code-form"), false, "the step stays");
		assert.equal(callsTo(mock, "/v1/auth/login/passkey"), 0, "nothing was sent");
		assert.equal(mock.mfaChallenges.get(token).attempts, 0);
		// A passkey the server refuses (here: the page origin is not the one the server expects).
		await auth.cdp.send("WebAuthn.addCredential", { authenticatorId: auth.id, credential: saved[0] });
		mock.webauthn.origin = "https://vault.bitosx.se";
		await page.click("#code-passkey");
		await page.waitForFunction(() => /passkey was not accepted/.test(document.getElementById("login-notice").textContent));
		assert.equal(mock.mfaChallenges.get(token).attempts, 1);
		assert.equal(await page.isHidden("#code-form"), false);
		// The code still works after both.
		mock.webauthn.origin = vault.origin;
		await page.fill("#login-code", RECOVERY[0]);
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.close();
	});

	await test("passkeys: sign in without email and password; the account opens, the vault still needs its master password", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		await seedPasskey(mock, accountId, auth);
		mock.seedEnvelope(accountId, fs.readFileSync(path.join(__dirname, "fixtures", "small.vault.json")));
		await page.goto(`${vault.origin}/`);
		await page.click("#passkey-signin-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		assert.equal(await page.textContent("#acct-email"), "user@example.com");
		const opts = lastCall(mock, "/v1/auth/passkey/options");
		assert.deepEqual(opts.body, {}, "the options request carries nothing");
		assert.equal(opts.headers["content-type"], undefined, "and no JSON content type: a simple request");
		const done = lastCall(mock, "/v1/auth/passkey").body;
		assert.equal(done.credential.response.userHandle, mock.userHandles.get(accountId));
		assert.equal(callsTo(mock, "/v1/auth/login"), 0, "no password step at all");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), false);
		assert.equal(await page.inputValue("#vault-master-password"), "");
		await page.close();
	});

	await test("passkeys: passwordless sign-in is refused for a passkey the server does not know, and for one removed from the account", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		// A credential of another authenticator that the server never registered.
		await seedPasskey(mock, accountId, auth, { serverKnows: false });
		await page.goto(`${vault.origin}/`);
		await page.click("#passkey-signin-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /passkey was not accepted/);
		assert.equal(await page.isHidden("#account-panel"), true);
		assert.equal(mock.sessions.size, 0);
		assert.equal(await page.isDisabled("#login-submit"), false, "the password form is usable again");
		// A registered one, then removed from the account: refused too.
		await auth.cdp.send("WebAuthn.clearCredentials", { authenticatorId: auth.id });
		const pk = await seedPasskey(mock, accountId, auth);
		await page.click("#passkey-signin-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		mock.passkeys.set(accountId, mock.passkeys.get(accountId).filter((p) => p.id !== pk.id));
		const before = mock.sessions.size;
		await page.click("#passkey-signin-submit");
		await page.waitForSelector("#login-notice.err");
		assert.match(await page.textContent("#login-notice"), /removed from the account no longer signs in/);
		assert.equal(callsTo(mock, "/v1/auth/passkey"), 3);
		assert.equal(mock.sessions.size, before, "no new session");
		await page.close();
	});

	await test("passkeys: rename (POST .../rename, never PATCH), two-factor cannot be turned off while one exists, remove with password + code", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		const pk = await seedPasskey(mock, accountId, auth, { name: "Old name" });
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page, RECOVERY[0]);
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 1);
		assert.match(await page.textContent("#passkey-list"), /Old name Not synced/);
		assert.equal(await page.isVisible("#totp-passkeys-hint"), true, "the two-factor form says why it cannot be turned off");
		// Rename.
		await page.click(`button[data-passkey-rename="${pk.id}"]`);
		await page.waitForSelector("#passkey-rename-form:not([hidden])");
		assert.equal(await page.inputValue("#passkey-rename-name"), "Old name");
		await page.fill("#passkey-rename-name", "bad‮name");
		await page.click("#passkey-rename-submit");
		assert.match(await page.textContent("#passkey-notice"), /1–64 characters/);
		assert.equal(callsTo(mock, `/v1/account/passkeys/${pk.id}/rename`), 0);
		await page.fill("#passkey-rename-name", "  Phone  ");
		await page.click("#passkey-rename-submit");
		await page.waitForFunction(() => document.getElementById("passkey-notice").textContent === "Passkey renamed.");
		assert.match(await page.textContent("#passkey-list"), /^Phone Not synced/);
		assert.equal(await page.isHidden("#passkey-rename-form"), true);
		const rename = lastCall(mock, `/v1/account/passkeys/${pk.id}/rename`);
		assert.equal(rename.method, "POST");
		assert.deepEqual(rename.body, { name: "Phone" });
		assert.ok(mock.calls.every((c) => c.method !== "PATCH"));
		// Turning two-factor off is refused by the server while the passkey exists; nothing is used up.
		await page.fill("#totp-manage-password", PASSWORD);
		await page.fill("#totp-manage-code", RECOVERY[1]);
		await page.check("#totp-disable-ack");
		await page.click("#totp-disable");
		await page.waitForSelector("#totp-notice.err");
		assert.match(await page.textContent("#totp-notice"), /stays on: your account has passkeys.*Remove the passkeys below first; nothing was used up/);
		assert.equal(mock.totp.get(accountId).recoveryCodes.get(RECOVERY[1]), false, "the code was not used");
		assert.equal(await page.inputValue("#totp-manage-password"), "");
		// Remove: a wrong code changes nothing; the right one removes it.
		await page.click(`button[data-passkey-delete="${pk.id}"]`);
		await page.waitForSelector("#passkey-delete-form:not([hidden])");
		assert.equal(await page.textContent("#passkey-delete-current"), "Phone");
		await page.fill("#passkey-delete-password", PASSWORD);
		await page.fill("#passkey-delete-code", "000000");
		await page.click("#passkey-delete-submit");
		await page.waitForSelector("#passkey-notice.err");
		assert.match(await page.textContent("#passkey-notice"), /password or the code was not accepted. Nothing was changed/);
		assert.equal(mock.passkeys.get(accountId).length, 1);
		assert.equal(await page.inputValue("#passkey-delete-password"), "");
		assert.equal(await page.inputValue("#passkey-delete-code"), "");
		await page.fill("#passkey-delete-password", PASSWORD);
		await page.fill("#passkey-delete-code", RECOVERY[1]);
		await page.click("#passkey-delete-submit");
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 0);
		assert.match(await page.textContent("#passkey-notice"), /Passkey “Phone” removed/);
		assert.equal(await page.isHidden("#passkey-delete-form"), true);
		assert.equal(await page.isHidden("#totp-passkeys-hint"), true);
		assert.deepEqual(lastCall(mock, `/v1/account/passkeys/${pk.id}/delete`).body, { password: PASSWORD, code: RECOVERY[1] });
		assert.equal(mock.passkeys.get(accountId).length, 0);
		assert.equal(callsTo(mock, `/v1/account/passkeys/${pk.id}`), 0);
		await page.close();
	});

	await test("passkeys: a browser without WebAuthn shows no passkey button anywhere; the account page says so and can still rename and remove", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount({ beforeRoute: (p) => p.addInitScript(() => { delete window.PublicKeyCredential; }) });
		await seedPasskey(mock, accountId, auth);
		await page.goto(`${vault.origin}/`);
		assert.equal(await page.evaluate(() => typeof window.PublicKeyCredential), "undefined");
		assert.equal(await page.isHidden("#passkey-signin"), true);
		await passwordThenCode(page);
		assert.equal(await page.isHidden("#code-passkey"), true, "the server lists a passkey, the browser cannot use it");
		assert.doesNotMatch(await page.textContent("#login-notice"), /passkey/);
		await page.fill("#login-code", RECOVERY[0]);
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 1);
		assert.match(await passkeyStatus(page), /does not support passkeys, so none can be added or used here; you can still rename or remove them/);
		assert.equal(await page.isHidden("#passkey-add-form"), true);
		assert.equal(await page.locator("#passkey-list button[data-passkey-rename]").count(), 1);
		await page.close();
	});

	await test("passkeys: without the browser's JSON helpers the page converts the options and the credential itself; the server verifies both ceremonies", async () => {
		const { mock, accountId, page } = await passkeyAccount({ beforeRoute: (p) => p.addInitScript(() => {
			delete PublicKeyCredential.parseCreationOptionsFromJSON;
			delete PublicKeyCredential.parseRequestOptionsFromJSON;
			delete PublicKeyCredential.prototype.toJSON;
		}) });
		await page.goto(`${vault.origin}/`);
		assert.equal(await page.evaluate(() => typeof PublicKeyCredential.parseCreationOptionsFromJSON + typeof PublicKeyCredential.prototype.toJSON), "undefinedundefined");
		await passwordThenCode(page, RECOVERY[0]);
		await page.waitForSelector("#passkey-add-form:not([hidden])");
		await page.fill("#passkey-add-name", "Fallback key");
		await page.fill("#passkey-add-password", PASSWORD);
		await page.fill("#passkey-add-code", RECOVERY[1]);
		await page.click("#passkey-add-submit");
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 1);
		const reg = lastCall(mock, "/v1/account/passkeys/registration").body.credential;
		// The members toJSON() writes, in the same encoding.
		assert.deepEqual(Object.keys(reg).sort(), ["authenticatorAttachment", "clientExtensionResults", "id", "rawId", "response", "type"]);
		assert.deepEqual(Object.keys(reg.response).sort(), ["attestationObject", "authenticatorData", "clientDataJSON", "publicKey", "publicKeyAlgorithm", "transports"]);
		assert.equal(reg.rawId, reg.id);
		assert.deepEqual(reg.response.transports, ["internal"]);
		assert.equal(reg.response.publicKeyAlgorithm, -7);
		for (const k of ["attestationObject", "authenticatorData", "clientDataJSON", "publicKey"]) { assert.match(reg.response[k], /^[A-Za-z0-9_-]+$/, k); }
		assert.equal(JSON.parse(Buffer.from(reg.response.clientDataJSON, "base64url")).origin, vault.origin);
		// Passwordless with the fallback: the mock checks the ES256 signature over the converted bytes.
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		await page.click("#passkey-signin-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
		const assertion = lastCall(mock, "/v1/auth/passkey").body.credential;
		assert.deepEqual(Object.keys(assertion.response).sort(), ["authenticatorData", "clientDataJSON", "signature", "userHandle"]);
		assert.equal(assertion.response.userHandle, mock.userHandles.get(accountId));
		await page.close();
	});

	await test("passkeys: signing out while an add waits for the server cancels it: no browser prompt, nothing shown to the next session", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page, RECOVERY[0]);
		await page.waitForSelector("#passkey-add-form:not([hidden])");
		// The server answers (a valid ceremony), but the answer arrives after the sign-out.
		const h = holdOnce(mock, "POST", "/v1/account/passkeys/registration/options", true);
		await page.fill("#passkey-add-name", "Late");
		await page.fill("#passkey-add-password", PASSWORD);
		await page.fill("#passkey-add-code", RECOVERY[1]);
		await page.click("#passkey-add-submit");
		await h.held;
		assert.equal(await page.inputValue("#passkey-add-name"), "Late");
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.inputValue("#passkey-add-name"), "", "the add form is wiped with the account view");
		assert.equal(await page.inputValue("#passkey-add-password"), "");
		h.release();
		await until(() => callsTo(mock, "/v1/account/passkeys/registration/options") === 1, "the held request");
		await page.waitForTimeout(300);
		assert.equal((await auth.credentials()).length, 0, "no passkey was created after the session ended");
		assert.equal(callsTo(mock, "/v1/account/passkeys/registration"), 0);
		assert.equal(mock.passkeys.get(accountId), undefined);
		assert.equal(await page.textContent("#passkey-notice"), "");
		await page.close();
	});

	await test("passkeys: leaving the page (also into the back/forward cache) wipes the passkey forms", async () => {
		const { mock, accountId, page, auth } = await passkeyAccount();
		const pk = await seedPasskey(mock, accountId, auth);
		await page.goto(`${vault.origin}/`);
		await passwordThenCode(page, RECOVERY[0]);
		await page.waitForFunction(() => document.querySelectorAll("#passkey-list li").length === 1);
		await page.fill("#passkey-add-name", "Typed");
		await page.fill("#passkey-add-password", PASSWORD);
		await page.click(`button[data-passkey-delete="${pk.id}"]`);
		await page.fill("#passkey-delete-password", PASSWORD);
		await page.fill("#passkey-delete-code", RECOVERY[1]);
		await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
		for (const id of ["passkey-add-name", "passkey-add-password", "passkey-add-code", "passkey-delete-password", "passkey-delete-code", "passkey-rename-name"]) {
			assert.equal(await page.inputValue("#" + id), "", id);
		}
		assert.equal(await page.locator("#passkey-list li").count(), 0);
		assert.equal(await page.textContent("#passkey-delete-current"), "");
		assert.equal(await page.isHidden("#passkey-delete-form"), true);
		await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
		assert.match(await page.textContent("#login-notice"), /You left this page/);
		await page.close();
	});

	// ------------------------------------------- phase 11: import and export
	console.log("vault.bitosx.se — import and export");
	const conformance = require("./import-conformance.js");
	const ieNode = require("../vault/public/assets/js/import-export.js")(vcNode);
	const importFixture = (name) => fs.readFileSync(path.join(conformance.DIRECTORY, name));
	// A damaged XML file makes Chromium's XML parser build its error document, which carries inline
	// styles; the document inherits this page's policy, which refuses them and says so on the console.
	// Nothing of the file is in that message. A test that feeds the page a damaged XML file expects it.
	const STYLE_REFUSED = /^Refused to apply inline style because it violates the following Content Security Policy directive: "style-src 'self'"/;
	async function chooseImportFile(page, name, content) {
		await page.setInputFiles("#import-file", { name, mimeType: "application/octet-stream", buffer: Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8") });
	}
	async function previewOf(page, name, content) {
		await chooseImportFile(page, name, content);
		await page.waitForSelector("#import-preview:not([hidden])");
		return {
			count: await page.textContent("#import-count"),
			lines: await page.locator("#import-summary li").allTextContents(),
			button: await page.textContent("#import-confirm"),
			disabled: await page.isDisabled("#import-confirm")
		};
	}
	const vaultState = (page) => page.evaluate(() => ({
		items: document.querySelectorAll("#vault-items .vault-item").length,
		count: document.getElementById("vault-count").textContent,
		unsaved: window.bitosxVault.hasUnsavedChanges(),
		dirtyShown: !document.getElementById("vault-dirty").hidden,
		saveDisabled: document.getElementById("vault-save").disabled
	}));
	const UNTOUCHED = { items: 3, count: "3 items", unsaved: false, dirtyShown: false, saveDisabled: true };
	const csvFile = (rows, header) => (header || "name,url,username,password,note") + "\n" + rows.join("\n") + "\n";
	// Records what the page does with object URLs, so that a test can see a download's URL revoked.
	const watchObjectUrls = (page) => page.addInitScript(() => {
		window.__urls = { created: [], revoked: [] };
		const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
		URL.createObjectURL = (blob) => { const url = create(blob); window.__urls.created.push(url); return url; };
		URL.revokeObjectURL = (url) => { window.__urls.revoked.push(url); return revoke(url); };
	});

	await test("import: every conformance fixture gives in Chromium exactly what the desktop makes of it — all 44 files, KeePass XML through DOMParser", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		const refusedStyles = [];
		page.expectedConsole = STYLE_REFUSED;
		page.on("console", (m) => { if (m.type() === "error" && STYLE_REFUSED.test(m.text())) { refusedStyles.push(m.text()); } });
		const requests = [];
		await page.goto(`${vault.origin}/`);
		page.on("request", (r) => requests.push(r.url()));
		let files = 0, cases = 0, xmlFiles = 0, damagedXml = 0;
		const outcomes = {};
		for (const name of conformance.expectedFiles()) {
			const expected = conformance.readExpected(name);
			const out = await page.evaluate(conformance.runFixture, { input: conformance.inputForPage(expected.input), cases: expected.cases.map((c) => ({ vault: c.vault, options: c.options })) });
			assert.ok(!out.needsXmlParser, `${name}: the page has an XML parser`);
			assert.equal(out.results.length, expected.cases.length, name);
			expected.cases.forEach((c, i) => {
				assert.deepStrictEqual(out.results[i], c.result, `${name}, case "${c.name}"`);
				cases++;
				const outcome = c.result.refused || c.result.format;
				outcomes[outcome] = (outcomes[outcome] || 0) + 1;
				if (c.result.refused === "invalid_xml") { damagedXml++; }
			});
			files++;
			const start = (expected.input.file ? importFixture(expected.input.file).toString("latin1") : expected.input.parts[0].text).trimStart();
			if (start.startsWith("<")) { xmlFiles++; }
		}
		assert.equal(files, 44);
		assert.equal(cases, 55);
		assert.equal(xmlFiles, 11, "the XML fixtures: nine that reach the parser, two refused before it");
		assert.ok(outcomes.keepass_xml >= 3 && outcomes.nested_too_deeply >= 2 && outcomes.protected_values >= 1 && outcomes.doctype >= 2 && outcomes.too_many_entries >= 3, JSON.stringify(outcomes));
		// Exactly the two messages Chromium's error document causes for each damaged XML file, and no other.
		assert.equal(damagedXml, 1);
		assert.equal(refusedStyles.length, 2 * damagedXml, refusedStyles.join("\n"));
		// Reading a file fetches nothing: not an address of a file, not a document type, nothing.
		assert.deepEqual(requests, []);
		await page.close();
	});

	await test("import: what Chromium's own parser does with XML the fixtures do not hold — hostile markup runs nothing and fetches nothing; its limits are known", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		page.expectedConsole = STYLE_REFUSED;
		await page.goto(`${vault.origin}/`);
		const requests = [];
		page.on("request", (r) => requests.push(r.url()));
		const entry = "<Root><Group><Entry><String><Key>Title</Key><Value>fake</Value></String></Entry></Group></Root>";
		const deep = (n) => "<KeePassFile><Meta>" + "<a>".repeat(n - 2) + "</a>".repeat(n - 2) + "</Meta></KeePassFile>";
		const documents = {
			// Elements of a web page inside the file: nothing of them runs or loads.
			hostile: "<KeePassFile><script xmlns=\"http://www.w3.org/1999/xhtml\">window.__importRan = 1;</script><img xmlns=\"http://www.w3.org/1999/xhtml\" src=\"https://tracker.example/x.png\" onerror=\"window.__importRan = 2\"/>"
				+ "<link xmlns=\"http://www.w3.org/1999/xhtml\" rel=\"stylesheet\" href=\"https://tracker.example/x.css\"/><iframe xmlns=\"http://www.w3.org/1999/xhtml\" src=\"https://tracker.example/\"/>"
				+ "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"window.__importRan = 3\"><image href=\"https://tracker.example/y.png\"/></svg><?xml-stylesheet href=\"https://tracker.example/z.css\"?>" + entry + "</KeePassFile>",
			// An entity is never expanded: a declaration is refused on the text, a reference without one is damaged XML.
			doctype: "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><KeePassFile><Meta><x>&lol2;</x></Meta></KeePassFile>",
			external: "<!DOCTYPE KeePassFile SYSTEM \"https://tracker.example/evil.dtd\" [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><KeePassFile><Meta><x>&xxe;</x></Meta></KeePassFile>",
			entityWithoutDeclaration: "<KeePassFile><Meta><x>&xxe;</x></Meta></KeePassFile>",
			// The specification's limit is 100 levels; Chromium's parser has one of its own at 5,000.
			levels100: deep(100), levels101: deep(101), levels5000: deep(5000), levels5001: deep(5001),
			// Two faults: the desktop reads forward and reports the first; a parsed document can only be damaged.
			twoFaults: "<KeePassFile><Meta><Binary Protected=\"True\">AAAA</Binary></Meta><Root><Group>",
			protectedOnly: "<KeePassFile><Meta><Binary Protected=\"True\">AAAA</Binary></Meta><Root><Group/></Root></KeePassFile>",
			// What only looks like the parser's error report.
			errorLookalike: "<KeePassFile><parsererror/>" + entry + "</KeePassFile>",
			errorLookalikeXhtml: "<KeePassFile><parsererror xmlns=\"http://www.w3.org/1999/xhtml\"/>" + entry + "</KeePassFile>",
			version11: "<?xml version=\"1.1\"?><KeePassFile>" + entry + "</KeePassFile>"
		};
		const outcome = await page.evaluate((docs) => {
			const ie = window.bitosxImportExport;
			const out = {};
			for (const [name, xml] of Object.entries(docs)) {
				try { const p = ie.parseImport(new TextEncoder().encode(xml)); out[name] = "read " + p.records; }
				catch (e) { out[name] = e instanceof ie.ImportRefused ? e.code : "threw " + e.name; }
			}
			return out;
		}, documents);
		assert.deepEqual(outcome, {
			hostile: "read 1", doctype: "doctype", external: "doctype", entityWithoutDeclaration: "invalid_xml",
			levels100: "read 0", levels101: "nested_too_deeply", levels5000: "nested_too_deeply",
			levels5001: "invalid_xml",            // the desktop: nested_too_deeply
			twoFaults: "invalid_xml",             // the desktop: protected_values
			protectedOnly: "protected_values",
			errorLookalike: "read 1",
			errorLookalikeXhtml: "invalid_xml",   // the desktop reads it
			version11: "read 1"                   // the desktop: invalid_xml
		});
		await new Promise((r) => setTimeout(r, 300));
		assert.deepEqual(requests, [], "nothing of a file is fetched");
		assert.equal(await page.evaluate(() => window.__importRan), undefined, "nothing of a file runs");
		await page.close();
	});

	await test("import: this page's own exports of the fixture vault read back, in Chromium, to the candidates of the desktop's two exports", async () => {
		const mock = createMockApi();
		const page = await newPage(mock);
		await page.goto(`${vault.origin}/`);
		const exported = JSON.parse(importFixture("bitosx-export.json").toString("utf8"));
		const files = await page.evaluate((items) => {
			const ie = window.bitosxImportExport;
			// What the page holds after it opened a vault the desktop wrote with these items.
			const held = items.map((it, i) => ({
				id: "0b1705e0-0000-4000-8000-" + String(i + 1).padStart(12, "0"), type: "login", name: it.name, username: it.username || null, password: it.password || null,
				urls: it.urls, notes: it.notes || null, favorite: it.favorite, createdAt: new Date(it.createdAt), createdAtText: it.createdAt.replace(/Z$/, "+00:00"),
				updatedAt: new Date(it.updatedAt), updatedAtText: it.updatedAt.replace(/Z$/, "+00:00")
			}));
			const base64 = (bytes) => { let s = ""; bytes.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };
			return { csv: base64(ie.exportCsv(held)), json: base64(ie.exportJson(held, new Date("2026-11-10T12:00:00Z"))) };
		}, exported.items);
		for (const format of ["csv", "json"]) {
			const expected = conformance.readExpected(`bitosx-export.${format}.expected.json`);
			const out = await page.evaluate(conformance.runFixture, { input: { base64: files[format] }, cases: expected.cases.map((c) => ({ vault: c.vault, options: c.options })) });
			expected.cases.forEach((c, i) => assert.deepStrictEqual(out.results[i], c.result, `${format}, case "${c.name}"`));
		}
		assert.deepEqual(Buffer.from(files.csv, "base64"), importFixture("bitosx-export.csv"), "the CSV is the desktop's, byte for byte");
		assert.deepEqual(JSON.parse(Buffer.from(files.json, "base64").toString("utf8")), exported, "the JSON says what the desktop's says");
		await page.close();
	});

	await test("import: choose a file -> a preview, nothing added -> confirm -> unsaved items, like ones added by hand -> Save to server; the reminder to delete the file", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		// The words both clients use.
		assert.equal((await page.textContent("label:has(#import-copy-extras)")).trim(), ieNode.TEXTS.optionCopyExtrasToNotes);
		assert.equal((await page.textContent("label:has(#import-duplicates)")).trim(), ieNode.TEXTS.optionImportDuplicates);
		assert.equal(await page.isHidden("#vault-import-panel"), true);
		await page.click("#vault-import");
		await page.waitForSelector("#vault-import-panel:not([hidden])");
		assert.equal(await page.evaluate(() => document.activeElement.id), "import-file", "focus goes to the file field");
		assert.equal(await page.isHidden("#import-preview"), true);
		assert.equal(await page.isDisabled("#import-confirm"), true);
		assert.equal(await page.textContent("label[for=import-file]"), "File to import (at most 16 MiB)");

		const preview = await previewOf(page, "Chrome Passwords.csv", importFixture("chrome.csv"));
		assert.equal(preview.count, "6 logins would be added to the vault in this browser (it holds 3 now). Nothing is added until you press the button below, and nothing is on the server until you then press Save to server.");
		assert.deepEqual(preview.lines, [
			"Format: Chrome or Edge (CSV). The file holds 9 entries.",
			"1 duplicate is skipped: the vault, or an earlier entry of the file, already has the same name, username, password and web addresses.",
			"2 entries are not imported; they are listed below, each with its reason.",
			"Left out, because BitosX has no field for them: addresses that are not web addresses (1). Tick the first box below to copy them into each item's notes instead."
		]);
		assert.equal(preview.button, "Import 6 logins");
		assert.equal(preview.disabled, false);
		// Both choices are off unless chosen.
		assert.equal(await page.isChecked("#import-copy-extras"), false);
		assert.equal(await page.isChecked("#import-duplicates"), false);
		// The entries that are not imported, by name and reason — behind a disclosure, closed at first.
		assert.equal(await page.textContent("#import-not-imported-summary"), "2 entries that are not imported");
		assert.equal(await page.evaluate(() => document.getElementById("import-not-imported").open), false);
		await page.click("#import-not-imported-summary");
		assert.deepEqual(await page.locator("#import-not-imported-list li").allTextContents(), [
			"too-long.example (entry 8): The password is longer than 4096 characters.",
			"moved.example (entry 9): The row has more values than the file has columns."
		]);
		// A preview shows names, counts and reasons: no password, no notes, no username of the file.
		const shown = await page.content();
		for (const secret of ["FAKE-chrome-pw-1", "FAKE,pw", "FAKE-android-pw", "First line", "fake.shopper", "pppppppp", "Ünïcödé"]) { assert.ok(!shown.includes(secret), `the preview shows ${secret}`); }
		// Nothing was added, and nothing left the browser.
		assert.deepEqual(await vaultState(page), UNTOUCHED);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 0);
		const callsBefore = mock.calls.length;

		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.equal(await page.textContent("#vault-notice"), "Imported 6 logins into the vault in this browser (1 duplicate skipped, 2 entries not imported). Nothing is on the server until you press Save to server. " + ieNode.TEXTS.fileStillHoldsPasswords);
		assert.match(await page.textContent("#vault-notice"), /The file you imported still holds every password in plain text\. Delete it when you no longer need it\.$/);
		assert.deepEqual(await vaultState(page), { items: 9, count: "9 items", unsaved: true, dirtyShown: true, saveDisabled: false });
		assert.equal(await page.evaluate(() => document.activeElement.id), "vault-import", "focus returns to the button that opened the panel");
		assert.equal(mock.calls.length, callsBefore, "importing made no request");
		// The file field no longer holds the file, and the passwords of the file are not in the page: an imported item is like any other.
		assert.equal(await page.inputValue("#import-file"), "");
		const after = await page.content();
		for (const secret of ["FAKE-chrome-pw-1", "FAKE,pw", "FAKE-android-pw", "FAKE-lösenord-åäö"]) { assert.ok(!after.includes(secret), `the page shows ${secret}`); }
		assert.deepEqual((await page.locator(".vault-item__name").allTextContents()).map((n) => n.trim()).sort(),
			["Bank <script>alert(1)</script>", "GitHub ★", "Wi-Fi café", "bücher.example", "com.example.app", "empty-password.example", "example.com", "intranet.example", "shop.example"].sort());
		// Still nothing on the server.
		assert.equal((await serverItems(mock, accountId, meta.typedPassword)).length, 3);

		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 1);
		assert.deepEqual(await vaultState(page), { items: 9, count: "9 items", unsaved: false, dirtyShown: false, saveDisabled: true });
		// What the server holds opens with the master password and has the logins of the file, exactly.
		const stored = await serverItems(mock, accountId, meta.typedPassword);
		assert.equal(stored.length, 9);
		const expected = conformance.readExpected("chrome.csv.expected.json").cases[0].result.candidates.filter((c) => c.status === "add");
		assert.deepEqual(stored.slice(3).map((i) => [i.name, i.username || "", i.password || "", [...i.urls], i.notes || "", i.favorite]),
			expected.map((c) => [c.name, c.username, c.password, c.urls, c.notes, c.favorite]));
		const shop = stored.find((i) => i.name === "shop.example");
		assert.equal(shop.password, "FAKE,pw \"with\" quotes");
		assert.equal(shop.notes, "First line\nsecond line, with a comma\nthird line");
		assert.equal(stored.find((i) => i.name === "empty-password.example").password, null, "an empty value is stored as none");
		// New identifiers, and the time of the import — never anything from the file.
		const ids = new Set(stored.map((i) => i.id));
		assert.equal(ids.size, 9);
		for (const item of stored.slice(3)) {
			assert.match(item.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
			assert.equal(item.createdAt.getTime(), item.updatedAt.getTime());
			assert.ok(Math.abs(item.createdAt.getTime() - Date.now()) < 5 * 60 * 1000);
		}
		assert.equal(new Set(stored.slice(3).map((i) => i.createdAt.getTime())).size, 1, "one import, one time");
		await page.close();
	});

	await test("import: Cancel, another file, and locking each let go of the file and leave the vault untouched", async () => {
		const mock = createMockApi();
		const { page, meta } = await openedVault(mock);
		await page.click("#vault-import");
		await previewOf(page, "firefox.csv", importFixture("firefox.csv"));
		await page.check("#import-copy-extras");
		await page.check("#import-duplicates");
		await page.click("#import-cancel");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.equal(await page.evaluate(() => document.activeElement.id), "vault-import");
		assert.deepEqual(await vaultState(page), UNTOUCHED);
		// Opened again, nothing of the earlier file is left: no preview, no file, both choices off.
		await page.click("#vault-import");
		assert.equal(await page.isHidden("#import-preview"), true);
		assert.equal(await page.inputValue("#import-file"), "");
		assert.equal(await page.textContent("#import-count"), "");
		assert.equal(await page.locator("#import-summary li").count(), 0);
		assert.equal(await page.isChecked("#import-copy-extras"), false);
		assert.equal(await page.isChecked("#import-duplicates"), false);
		assert.equal(await page.isDisabled("#import-confirm"), true);
		// Another file replaces the one before it: the preview is of that file alone.
		assert.match((await previewOf(page, "a.csv", importFixture("keepassxc.csv"))).lines[0], /^Format: KeePassXC \(CSV\)/);
		assert.match((await previewOf(page, "b.json", importFixture("bitwarden.json"))).lines[0], /^Format: Bitwarden \(JSON\)/);
		// A file that is refused after one that was read takes the preview away.
		await chooseImportFile(page, "c.csv", "");
		await page.waitForSelector("#vault-import-notice.err");
		assert.equal(await page.isHidden("#import-preview"), true);
		assert.equal(await page.isDisabled("#import-confirm"), true);
		assert.equal(await page.textContent("#import-confirm"), "Import");
		// Export closes the import, and the other way round: one of the two at a time.
		await previewOf(page, "b.json", importFixture("bitwarden.json"));
		await page.click("#vault-export");
		assert.equal(await page.isHidden("#vault-import-panel"), true);
		assert.equal(await page.isHidden("#vault-export-panel"), false);
		await page.click("#vault-import");
		assert.equal(await page.isHidden("#vault-export-panel"), true);
		assert.equal(await page.isHidden("#import-preview"), true, "the file chosen before is gone");
		// Locking with a preview open: the panel is closed and the vault is as it was.
		await previewOf(page, "b.json", importFixture("bitwarden.json"));
		await page.click("#vault-lock");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.isHidden("#vault-import-panel"), true);
		assert.equal(await page.locator("#import-summary li").count(), 0);
		assert.ok(!(await page.content()).includes("Example Mail"), "no name of the file is left in the page");
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		assert.deepEqual(await vaultState(page), UNTOUCHED);
		assert.equal(await page.isHidden("#vault-import-panel"), true);
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 0);
		await page.close();
	});

	await test("import: duplicates are skipped by default and imported on opt-in; the preview follows the vault as it changes", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		// The vault's GitHub and Wi-Fi items, a third that differs in its password only, one twice in the file.
		const file = csvFile([
			"GitHub,https://github.com,octocat@example.com,P@ssw0rd-Strong-123,other notes do not matter",
			"Wi-Fi café,,,ñandú-Ωmega-🔐,",
			"GitHub,https://github.com,octocat@example.com,another-password,",
			"New,https://new.example/,fake.user,FAKE-new-pw,",
			"New,https://new.example/,fake.user,FAKE-new-pw,the same again"
		]);
		await page.click("#vault-import");
		let preview = await previewOf(page, "dupes.csv", file);
		assert.match(preview.count, /^2 logins would be added/);
		assert.equal(preview.lines[1], "3 duplicates are skipped: the vault, or an earlier entry of the file, already has the same name, username, password and web addresses.");
		assert.equal(preview.button, "Import 2 logins");
		await page.check("#import-duplicates");
		assert.match(await page.textContent("#import-count"), /^5 logins would be added/);
		assert.equal(await page.locator("#import-summary li").nth(1).textContent(), "3 duplicates are imported too.");
		assert.equal(await page.textContent("#import-confirm"), "Import 5 logins");
		await page.uncheck("#import-duplicates");
		assert.match(await page.textContent("#import-count"), /^2 logins would be added/);
		// The vault changes while the preview is open (an item is deleted by hand): the preview is of the vault as it is now.
		const wifi = page.locator('.vault-item[data-item-id="33333333-3333-4333-8333-333333333333"]');
		await wifi.locator("button[data-delete]").click();
		await wifi.locator("button[data-delete]").click();
		await page.waitForFunction(() => document.querySelectorAll("#vault-items .vault-item").length === 2);
		assert.match(await page.textContent("#import-count"), /^3 logins would be added to the vault in this browser \(it holds 2 now\)/);
		assert.equal(await page.locator("#import-summary li").nth(1).textContent(), "2 duplicates are skipped: the vault, or an earlier entry of the file, already has the same name, username, password and web addresses.");
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.match(await page.textContent("#vault-notice"), /^Imported 3 logins into the vault in this browser \(2 duplicates skipped\)\./);
		assert.equal((await vaultState(page)).items, 5);
		// With the box ticked the duplicates are added as well.
		await page.click("#vault-import");
		preview = await previewOf(page, "dupes.csv", file);
		assert.equal(preview.count, "Nothing would be added to the vault.");
		assert.equal(preview.button, "Nothing to import");
		assert.equal(preview.disabled, true);
		assert.equal(preview.lines[1], "5 duplicates are skipped: the vault, or an earlier entry of the file, already has the same name, username, password and web addresses.");
		await page.check("#import-duplicates");
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.match(await page.textContent("#vault-notice"), /^Imported 5 logins into the vault in this browser\. Nothing is on the server/);
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const stored = await serverItems(mock, accountId, meta.typedPassword);
		assert.deepEqual(stored.map((i) => i.name).sort(), ["Bank <script>alert(1)</script>", "GitHub", "GitHub", "GitHub", "GitHub", "New", "New", "New", "Wi-Fi café", "Wi-Fi café"].sort());
		assert.equal(new Set(stored.map((i) => i.id)).size, 10, "every item has an identifier of its own");
		await page.close();
	});

	await test("import: what BitosX has no field for is left out by default and copied into the notes on opt-in", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		await page.click("#vault-import");
		const preview = await previewOf(page, "bitwarden.json", importFixture("bitwarden.json"));
		const expected = conformance.readExpected("bitwarden.json.expected.json").cases[0].result;
		assert.match(preview.count, new RegExp("^" + expected.counts.toAdd + " logins would be added"));
		assert.deepEqual(Object.keys(expected.unsupported), Object.keys(ieNode.UNSUPPORTED_TEXTS), "the fixture has an item of every kind");
		assert.ok(preview.lines.includes("Not logins, and not imported: " + Object.keys(expected.unsupported).map((k) => ieNode.UNSUPPORTED_TEXTS[k] + " (" + expected.unsupported[k] + ")").join(", ") + "."), preview.lines.join("\n"));
		assert.ok(preview.lines.some((l) => l.startsWith("Not logins, and not imported: secure notes (1), cards (1), identities (1), SSH keys (1), bank accounts (1), driver's licences (1), passports (1), other items (")));
		assert.ok(preview.lines.includes("In the trash or the recycle bin of the file, and not imported: 1."));
		const leftOut = preview.lines.find((l) => l.startsWith("Left out, because BitosX has no field for them: "));
		assert.equal(leftOut, "Left out, because BitosX has no field for them: authenticator keys (TOTP) (" + expected.extras.totp + "), folder or group names (" + expected.extras.folder + "), addresses that are not web addresses ("
			+ expected.extras.other_address + "), custom fields (" + expected.extras.custom_field + "). Tick the first box below to copy them into each item's notes instead.");
		assert.ok(preview.lines.some((l) => /^https:\/\/ is put in front of \d+ address(es)? that ha(s|ve) no scheme\.$/.test(l)));
		assert.ok(preview.lines.some((l) => /^\d+ entr(y has|ies have) no name and (is|are) named after (its|their) address or username\.$/.test(l)));
		await page.check("#import-copy-extras");
		assert.ok((await page.locator("#import-summary li").allTextContents()).some((l) => l.startsWith("Copied into each item's notes, because BitosX has no field for them: authenticator keys (TOTP) (")));
		// Neither an authenticator key nor the value of a custom field is shown in the preview.
		const copied = conformance.readExpected("bitwarden.json.expected.json").cases.find((c) => c.options.copyExtrasToNotes && !c.options.importDuplicates && c.vault.length === 0);
		assert.ok(copied, "the fixture has a case that copies the extras");
		const withTotp = copied.result.candidates.find((c) => c.status === "add" && c.extras.totp.length > 0);
		assert.ok(!(await page.content()).includes(withTotp.extras.totp));
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const stored = (await serverItems(mock, accountId, meta.typedPassword)).slice(3);
		const added = copied.result.candidates.filter((c) => c.status === "add");
		assert.deepEqual(stored.map((i) => [i.name, i.notes || ""]), added.map((c) => [c.name, c.notes]));
		assert.match(stored.find((i) => i.name === withTotp.name).notes, /Authenticator key \(TOTP\): /);
		assert.ok(stored.some((i) => /(^|\n)Folder: /.test(i.notes || "")) && stored.some((i) => /(^|\n)Other address: /.test(i.notes || "")));
		// Left out by default: the same file again, without the box, into a vault without those items.
		const second = createMockApi();
		const other = await openedVault(second);
		await other.page.click("#vault-import");
		await previewOf(other.page, "bitwarden.json", importFixture("bitwarden.json"));
		await other.page.click("#import-confirm");
		await other.page.waitForSelector("#vault-import-panel", { state: "hidden" });
		await other.page.click("#vault-save");
		await other.page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const plain = (await serverItems(second, other.accountId, other.meta.typedPassword)).slice(3);
		assert.deepEqual(plain.map((i) => [i.name, i.notes || ""]), expected.candidates.filter((c) => c.status === "add").map((c) => [c.name, c.notes]));
		assert.ok(plain.every((i) => !/Authenticator key|Folder: |Other address: /.test(i.notes || "")));
		await other.page.close();
		await page.close();
	});

	await test("import: every kind of refusal shows its fixed text, and changes nothing", async () => {
		const mock = createMockApi();
		const { page } = await openedVault(mock);
		page.expectedConsole = STYLE_REFUSED;   // the damaged XML file among them
		await page.click("#vault-import");
		const seen = new Set();
		for (const name of conformance.expectedFiles()) {
			const expected = conformance.readExpected(name);
			const result = expected.cases[0].result;
			if (!result.refused) { continue; }
			await chooseImportFile(page, name.replace(/\.expected\.json$/, ""), Buffer.from(conformance.inputBytes(expected.input)));
			const text = ieNode.REFUSAL_TEXTS[result.refused] + (result.refused === "invalid_csv" ? " The fault is on line " + result.line + " of the file." : "");
			await page.waitForFunction((want) => document.getElementById("vault-import-notice").textContent === want, text, { timeout: 30000 }).catch(async () => {
				assert.equal(await page.textContent("#vault-import-notice"), text, name);
			});
			assert.match(await page.getAttribute("#vault-import-notice", "class"), /\berr\b/, name);
			assert.equal(await page.getAttribute("#vault-import-notice", "role"), "alert");
			assert.equal(await page.getAttribute("#import-file", "aria-invalid"), "true", name);
			assert.equal(await page.getAttribute("#import-file", "aria-describedby"), "vault-import-notice", name);
			assert.equal(await page.isHidden("#import-preview"), true, name);
			assert.equal(await page.isDisabled("#import-confirm"), true, name);
			assert.equal(await page.textContent("#import-count"), "", name);
			assert.equal(await page.inputValue("#import-file"), "", name);
			assert.deepEqual(await vaultState(page), UNTOUCHED, name);
			seen.add(result.refused);
		}
		// Every refusal of a file there is; the one about the vault is below.
		assert.deepEqual([...seen].sort(), Object.keys(ieNode.REFUSAL_TEXTS).filter((k) => k !== "vault_item_limit").sort());
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), 0);
		// A file the size limit refuses is never read: the page asks for its size, and for nothing else of it.
		const reads = await page.evaluate(async () => {
			let read = 0;
			const big = { size: 16 * 1024 * 1024 + 1, slice() { read++; return new Blob([]); } };
			try { await window.bitosxImportExport.readFileBytes(big); } catch (e) { return { read, code: e.code }; }
			return { read, code: null };
		});
		assert.deepEqual(reads, { read: 0, code: "too_large" });
		// After all that, a good file is still read.
		assert.equal((await previewOf(page, "ok.csv", importFixture("keepass1.csv"))).lines[0], "Format: KeePass 1.x (CSV). The file holds 3 entries.");
		assert.equal(await page.getAttribute("#import-file", "aria-invalid"), "false");
		assert.equal(await page.textContent("#vault-import-notice"), "");
		await page.close();
	});

	await test("import: a vault that would pass 10,000 items is refused as a whole, with the text of that refusal; one that just fits is imported", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		const env = vcNode.parseEnvelope(new Uint8Array(bytes));
		const o = await vcNode.unlock(env, meta.typedPassword);
		const at = new Date("2026-10-01T09:00:00Z");
		const items = [];
		for (let i = 0; i < 9998; i++) {
			items.push({ id: "00000000-0000-4000-8000-" + String(i).padStart(12, "0"), type: "login", name: "Item " + i, username: null, password: null, urls: [], notes: null, favorite: false, createdAt: at, updatedAt: at });
		}
		mock.seedEnvelope(accountId, Buffer.from(vcNode.serializeEnvelope(await vcNode.encryptContent(env, o.vaultKey, vcNode.serializeVault({ items })))));
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		await page.click("#vault-import");
		// Three new logins and one the vault has: 9,998 + 3 is one too many.
		const three = csvFile(["a,,,FAKE-1,", "b,,,FAKE-2,", "c,,,FAKE-3,", "Item 7,,,,"]);
		const preview = await previewOf(page, "three.csv", three);
		assert.match(preview.count, /^3 logins would be added to the vault in this browser \(it holds 9998 now\)/);
		assert.equal(preview.disabled, true);
		assert.equal(await page.textContent("#vault-import-notice"), ieNode.REFUSAL_TEXTS.vault_item_limit);
		assert.match(await page.getAttribute("#vault-import-notice", "class"), /\berr\b/);
		assert.equal(await page.textContent("#vault-count"), "9998 items");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		// With the duplicate imported too it is four too many; without the third login it fits exactly.
		await page.check("#import-duplicates");
		assert.equal(await page.isDisabled("#import-confirm"), true);
		await page.uncheck("#import-duplicates");
		const two = await previewOf(page, "two.csv", csvFile(["a,,,FAKE-1,", "b,,,FAKE-2,", "Item 7,,,,"]));
		assert.equal(two.disabled, false);
		assert.equal(await page.textContent("#vault-import-notice"), "");
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.equal(await page.textContent("#vault-count"), "10000 items");
		// Full: a file with one more login is refused, and so is one more by hand (as before).
		await page.click("#vault-import");
		assert.equal((await previewOf(page, "one.csv", csvFile(["z,,,FAKE-9,"]))).disabled, true);
		assert.equal(await page.textContent("#vault-import-notice"), ieNode.REFUSAL_TEXTS.vault_item_limit);
		await page.click("#import-cancel");
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent), null, { timeout: 60000 });
		assert.equal((await serverItems(mock, accountId, meta.typedPassword)).length, 10000);
		await page.close();
	});

	await test("import: text of a file is shown as text — markup in a name, a column or an address is never markup, and no address of a file is opened", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		const requests = [];
		page.on("request", (r) => { if (!r.url().startsWith(API_ORIGIN)) { requests.push(r.url()); } });
		const img = "<img src=https://tracker.example/x.png onerror=\"window.__xss=1\">";
		const script = "<script>window.__xss=2</script>";
		const file = "name,url,username,password,note,\"<b onmouseover=window.__xss=3>col</b>\",\"" + "c".repeat(300) + "\"\n"
			+ "\"" + img.replace(/"/g, "\"\"") + "\",https://tracker.example/login,fake.user,FAKE-markup-pw,\"<i>note</i> " + script + "\",,\n"
			+ "\"" + script + "\",\"javascript:window.__xss=4\",fake.user," + "p".repeat(4097) + ",,,\n"
			+ "\"" + "N".repeat(500) + "\",https://tracker.example/,fake.user,FAKE-pw,,,\n"
			+ "\"‮gnp.exe\",\"data:text/html,<script>window.__xss=5</script>\",fake.user,FAKE-rtl-pw,,,\n";
		await page.click("#vault-import");
		const preview = await previewOf(page, "<svg onload=window.__xss=6>.csv", file);
		assert.match(preview.count, /^2 logins would be added/);
		// The ignored columns are named as text, the long one cut short for the eye.
		assert.equal(preview.lines[preview.lines.length - 1], "Columns of the file that are not read: <b onmouseover=window.__xss=3>col</b>, " + "c".repeat(40) + "….");
		await page.click("#import-not-imported-summary");
		assert.deepEqual(await page.locator("#import-not-imported-list li").allTextContents(), [
			script + " (entry 2): The password is longer than 4096 characters.",
			"N".repeat(80) + "… (entry 3): The name is longer than 200 characters."
		]);
		assert.equal(await page.locator("#vault-import-panel img, #vault-import-panel script, #vault-import-panel b, #vault-import-panel i, #vault-import-panel svg").count(), 0);
		// A name of the file sits in an element of its own, so that its direction cannot reorder the page's words.
		assert.equal(await page.locator("#import-not-imported-list li bdi.import-name").count(), 2);
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		const names = (await page.locator(".vault-item__name").allTextContents()).map((n) => n.trim());
		assert.ok(names.includes(img) && names.includes("‮gnp.exe"), names.join(" | "));
		assert.equal(await page.locator("#vault-items img, #vault-items script, #vault-items i").count(), 0);
		assert.ok((await page.locator(".vault-notes").allTextContents()).includes("<i>note</i> " + script));
		// An address that is not http or https is no address of the item, so it is never a link.
		assert.equal(await page.locator("#vault-items a[href^='javascript:'], #vault-items a[href^='data:']").count(), 0);
		assert.equal(await page.locator("#vault-items a.vault-url[href='https://tracker.example/login']").count(), 1, "a web address is a link, as for any item");
		assert.equal(await page.evaluate(() => window.__xss), undefined);
		await new Promise((r) => setTimeout(r, 300));
		assert.deepEqual(requests, [], "no address of the file was opened or fetched");
		// Saved and read back, the text is what the file held.
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const stored = await serverItems(mock, accountId, meta.typedPassword);
		assert.deepEqual(stored.slice(3).map((i) => [i.name, [...i.urls], i.notes]), [[img, ["https://tracker.example/login"], "<i>note</i> " + script], ["‮gnp.exe", [], null]]);
		await page.close();
	});

	await test("import: KeePass 2 XML and a damaged XML file through the page, and a file whose name lies about what it is", async () => {
		const mock = createMockApi();
		const { page, accountId, meta } = await openedVault(mock);
		const styleMessages = [];
		page.on("console", (m) => { if (m.type() === "error" && STYLE_REFUSED.test(m.text())) { styleMessages.push(m.text()); } });
		await page.click("#vault-import");
		// The format is decided from the contents: a KeePass file named .csv is read as KeePass XML.
		const expected = conformance.readExpected("keepass.xml.expected.json").cases[0].result;
		const preview = await previewOf(page, "passwords.csv", importFixture("keepass.xml"));
		assert.equal(preview.lines[0], "Format: KeePass 2 (XML). The file holds " + expected.records + " entries.");
		assert.match(preview.count, new RegExp("^" + expected.counts.toAdd + " logins would be added"));
		assert.ok(preview.lines.includes("In the trash or the recycle bin of the file, and not imported: " + expected.inTrash + "."));
		assert.equal(styleMessages.length, 0, "a well-formed file causes no message");
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent));
		const stored = (await serverItems(mock, accountId, meta.typedPassword)).slice(3);
		assert.deepEqual(stored.map((i) => [i.name, i.username || "", i.password || "", [...i.urls], i.notes || ""]),
			expected.candidates.filter((c) => c.status === "add").map((c) => [c.name, c.username, c.password, c.urls, c.notes]));
		// A damaged file: refused with its text; Chromium's error document trips the style policy twice, and that is all.
		page.expectedConsole = STYLE_REFUSED;
		await page.click("#vault-import");
		await chooseImportFile(page, "damaged.xml", importFixture("refused-damaged.xml"));
		await page.waitForSelector("#vault-import-notice.err");
		assert.equal(await page.textContent("#vault-import-notice"), ieNode.REFUSAL_TEXTS.invalid_xml);
		assert.equal(styleMessages.length, 2);
		assert.ok(styleMessages.every((m) => !/FAKE|KeePass|Group/.test(m)), "nothing of the file is in the message");
		await page.close();
	});

	await test("import: a hidden tab does not lock the vault while the import is open (choosing a file can hide the page); it does once it is closed", async () => {
		const mock = createMockApi();
		const { page } = await openedVault(mock);
		const hide = () => page.evaluate(() => {
			Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
			document.dispatchEvent(new Event("visibilitychange"));
		});
		await page.click("#vault-import");
		await hide();
		assert.equal(await page.evaluate(() => window.bitosxVault.isUnlocked()), true);
		await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true }); document.dispatchEvent(new Event("visibilitychange")); });
		await previewOf(page, "chrome.csv", importFixture("chrome.csv"));
		await page.click("#import-cancel");
		await hide();
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.textContent("#vault-notice"), "Vault locked when the tab was hidden.");
		await page.close();
	});

	await test("import and save: an import that would make the vault too large to store is refused as a whole; a vault that grew too large by hand is not uploaded, says why, and loses nothing", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		const env = vcNode.parseEnvelope(new Uint8Array(bytes));
		const o = await vcNode.unlock(env, meta.typedPassword);
		const at = new Date("2026-10-01T09:00:00Z");
		const LIMIT = vcNode.MAX_ENVELOPE_BYTES;
		assert.equal(LIMIT, 16 * 1024 * 1024);
		// A vault whose envelope is expected to be 100 KiB under the limit: items with notes as long as notes may be.
		const items = [];
		const item = (i, notes) => ({ id: "00000000-0000-4000-8000-" + String(i).padStart(12, "0"), type: "login", name: "Large " + i, username: null, password: null, urls: [], notes, favorite: false, createdAt: at, updatedAt: at });
		const sizeWith = (list) => vcNode.estimateEnvelopeSize(env, vcNode.serializeVault({ items: list }).length);
		const full = "n".repeat(16384);
		while (sizeWith(items.concat([item(items.length, full)])) < LIMIT - 100 * 1024) { items.push(item(items.length, full)); }
		let last = 16384;
		while (sizeWith(items.concat([item(items.length, "n".repeat(last))])) >= LIMIT - 100 * 1024) { last -= 512; }
		items.push(item(items.length, "n".repeat(last)));
		const seeded = Buffer.from(vcNode.serializeEnvelope(await vcNode.encryptContent(env, o.vaultKey, vcNode.serializeVault({ items }))));
		assert.ok(seeded.length < LIMIT - 80 * 1024 && seeded.length > LIMIT - 130 * 1024, `the vault's envelope is ${seeded.length} bytes`);
		mock.seedEnvelope(accountId, seeded);
		const page = await newPage(mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])", { timeout: 60000 });
		const held = items.length;
		assert.equal(await page.textContent("#vault-count"), held + " items");

		// 1. An import of 12 logins with full notes (some 280 KiB more) is refused as a whole.
		const big = csvFile(Array.from({ length: 12 }, (_, i) => "Imported " + i + ",,,FAKE-pw," + full));
		await page.click("#vault-import");
		const preview = await previewOf(page, "big.csv", big);
		assert.match(preview.count, /^12 logins would be added/);
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-notice.err");
		assert.equal(await page.textContent("#vault-import-notice"), "The vault would be larger than 16 MiB after this import, which is the most BitosX can store. Nothing was imported.");
		assert.equal(await page.isHidden("#vault-import-panel"), false, "the preview stays, for another choice");
		assert.equal(await page.textContent("#vault-count"), held + " items");
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		// An import that fits is still taken: two small logins.
		await previewOf(page, "small.csv", csvFile(["Small 1,,,FAKE-1,", "Small 2,,,FAKE-2,"]));
		await page.click("#import-confirm");
		await page.waitForSelector("#vault-import-panel", { state: "hidden" });
		assert.equal(await page.textContent("#vault-count"), (held + 2) + " items");
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 2/.test(document.getElementById("vault-notice").textContent), null, { timeout: 60000 });
		assert.ok(mock.envelopes.get(accountId).bytes.length <= LIMIT);

		// 2. By hand there is no estimate to stop at: ten more items with full notes pass the limit.
		for (let i = 0; i < 10; i++) {
			await page.click("#vault-add");
			await page.fill("#edit-name", "By hand " + i);
			await page.fill("#edit-notes", full);
			await page.click("#edit-save");
			await page.waitForSelector("#vault-editor", { state: "hidden" });
		}
		const puts = callsTo(mock, "/v1/sync/envelope", "PUT");
		await page.click("#vault-save");
		await page.waitForSelector("#vault-notice.err", { timeout: 60000 });
		assert.equal(await page.textContent("#vault-notice"), "The vault would be larger than 16 MiB, which is the most BitosX can store. Delete items or shorten their notes, and save again: your changes are still in this browser. Nothing was uploaded.");
		assert.equal(callsTo(mock, "/v1/sync/envelope", "PUT"), puts, "nothing was sent");
		// Nothing is lost: the items are still here, still unsaved, and the page is not stuck.
		assert.equal(await page.textContent("#vault-count"), (held + 12) + " items");
		assert.deepEqual(await page.evaluate(() => [window.bitosxVault.hasUnsavedChanges(), document.getElementById("vault-dirty").hidden, document.getElementById("vault-save").disabled]), [true, false, false]);
		// With seven of them deleted again the vault fits, and is saved.
		await page.fill("#vault-search", "By hand");
		for (let i = 0; i < 7; i++) {
			const first = page.locator("#vault-items .vault-item").first();
			await first.locator("button[data-delete]").click();
			await first.locator("button[data-delete]").click();
			await page.waitForFunction((n) => document.querySelectorAll("#vault-items .vault-item").length === n, 9 - i);
		}
		await page.fill("#vault-search", "");
		await page.click("#vault-save");
		await page.waitForFunction(() => /Saved: the server now holds revision 3/.test(document.getElementById("vault-notice").textContent), null, { timeout: 60000 });
		const stored = mock.envelopes.get(accountId).bytes;
		assert.ok(stored.length <= LIMIT && stored.length > LIMIT - 60 * 1024, `the stored envelope is ${stored.length} bytes`);
		assert.equal((await serverItems(mock, accountId, meta.typedPassword)).length, held + 5);
		await page.close();
	});

	await test("export: the warning, the box and the master password come first; a wrong password writes nothing; CSV and JSON are downloaded under their dated names", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const context = await browser.newContext({ acceptDownloads: true });
		const page = await context.newPage();
		watchConsole(page, errors);
		await watchObjectUrls(page);
		await routeApi(page, mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		const downloads = [];
		page.on("download", (d) => downloads.push(d));
		const callsBefore = mock.calls.length;

		await page.click("#vault-export");
		await page.waitForSelector("#vault-export-panel:not([hidden])");
		assert.equal(await page.evaluate(() => document.activeElement.id), "export-format-csv");
		// The words both clients use, and the state the panel starts in.
		assert.equal(await page.textContent("#export-warning"), ieNode.TEXTS.exportWarning);
		assert.equal((await page.textContent("label:has(#export-ack)")).trim(), ieNode.TEXTS.exportAcknowledgement);
		assert.equal(await page.isChecked("#export-format-csv"), true);
		assert.equal(await page.isChecked("#export-ack"), false);
		assert.equal(await page.isDisabled("#export-submit"), true, "the box has to be ticked first");
		assert.equal(await page.getAttribute("#export-master-password", "type"), "password");
		assert.equal(await page.getAttribute("#export-master-password", "autocomplete"), "off");
		assert.equal(await page.getAttribute("#export-master-password", "data-lpignore"), "true");
		// One item of this vault has two addresses, which a CSV file cannot hold: said before choosing.
		assert.equal(await page.textContent("#export-several-urls"), "1 item has more than one address. A CSV file holds only the first of each; only JSON keeps them all.");
		assert.equal(await page.isHidden("#export-several-urls"), false);
		await page.check("#export-format-json");
		assert.equal(await page.isHidden("#export-several-urls"), true);
		await page.check("#export-format-csv");

		// The box alone is not enough: no password, no export.
		await page.fill("#export-master-password", meta.typedPassword);
		assert.equal(await page.isDisabled("#export-submit"), true);
		await page.press("#export-master-password", "Enter");
		await page.fill("#export-master-password", "");
		await page.check("#export-ack");
		assert.equal(await page.isDisabled("#export-submit"), false);
		await page.click("#export-submit");
		assert.equal(await page.textContent("#vault-export-notice"), "Enter the master password of your vault.");
		assert.equal(await page.getAttribute("#export-master-password", "aria-invalid"), "true");
		// A wrong master password: nothing is written, the field is cleared, and the panel stays for another try.
		await page.fill("#export-master-password", "definitely not it");
		await page.click("#export-submit");
		await page.waitForFunction(() => /incorrect/.test(document.getElementById("vault-export-notice").textContent));
		assert.equal(await page.textContent("#vault-export-notice"), "The master password is incorrect. Nothing was exported.");
		assert.equal(await page.getAttribute("#vault-export-notice", "role"), "alert");
		assert.equal(await page.inputValue("#export-master-password"), "", "what was typed is cleared");
		assert.equal(await page.getAttribute("#export-master-password", "aria-invalid"), "true");
		assert.equal(await page.isHidden("#vault-export-panel"), false);
		assert.equal(await page.isChecked("#export-ack"), true);
		assert.equal(await page.isDisabled("#export-submit"), false, "the form is not left busy");
		// The account password is not the master password either.
		await page.fill("#export-master-password", "another wrong one");
		await page.press("#export-master-password", "Enter");
		await page.waitForFunction(() => document.getElementById("export-master-password").value === "" && !document.getElementById("export-submit").disabled);
		await new Promise((r) => setTimeout(r, 300));
		assert.equal(downloads.length, 0, "a wrong password exports nothing");
		assert.deepEqual(await page.evaluate(() => window.__urls.created), [], "not even a Blob was made");

		// The right one: a CSV file, named for today.
		const today = await page.evaluate(() => { const d = new Date(); const two = (n) => (n < 10 ? "0" : "") + n; return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate()); });
		await page.fill("#export-master-password", meta.typedPassword);
		const [csv] = await Promise.all([page.waitForEvent("download"), page.click("#export-submit")]);
		assert.equal(csv.suggestedFilename(), "BitosX-export-" + today + ".csv");
		await page.waitForSelector("#vault-export-panel", { state: "hidden" });
		assert.equal(await page.textContent("#vault-notice"), "Exported 3 logins to BitosX-export-" + today + ".csv. That file is not encrypted: it holds every password in plain text. Keep it only as long as you need it, and delete it afterwards.");
		assert.match(await page.getAttribute("#vault-notice", "class"), /\bwarn\b/);
		assert.equal(await page.evaluate(() => document.activeElement.id), "vault-export");
		assert.equal(await page.inputValue("#export-master-password"), "", "the password does not stay in the field");
		assert.equal(await page.isChecked("#export-ack"), false, "the next export is asked about again");
		const items = await serverItems(mock, accountId, meta.typedPassword);
		const csvBytes = fs.readFileSync(await csv.path());
		assert.deepEqual(csvBytes, Buffer.from(ieNode.exportCsv(items)), "exactly the vault's items, in Chrome's layout");
		assert.equal(csvBytes.toString("utf8"),
			"name,url,username,password,note\r\n" +
			"\"GitHub\",\"https://github.com\",\"octocat@example.com\",\"P@ssw0rd-Strong-123\",\"\"\r\n" +
			"\"Bank <script>alert(1)</script>\",\"https://bank.example\",\"alice\",\"hunter2 & \"\"quotes\"\" <b>\",\"Security question: first pet.\nSecond line & <i>markup</i>\"\r\n" +
			"\"Wi-Fi café\",\"\",\"\",\"ñandú-Ωmega-🔐\",\"\"\r\n");

		// JSON: everything an item holds, with the times the desktop wrote.
		await page.click("#vault-export");
		assert.equal(await page.isChecked("#export-format-csv"), true, "the panel starts as it always does");
		await page.check("#export-format-json");
		await page.check("#export-ack");
		await page.fill("#export-master-password", meta.typedPassword);
		const [json] = await Promise.all([page.waitForEvent("download"), page.press("#export-master-password", "Enter")]);
		assert.equal(json.suggestedFilename(), "BitosX-export-" + today + ".json");
		const doc = JSON.parse(fs.readFileSync(await json.path(), "utf8"));
		assert.deepEqual(Object.keys(doc), ["format", "version", "exportedAt", "items"]);
		assert.equal(doc.format, "bitosx-export");
		assert.equal(doc.version, 1);
		assert.match(doc.exportedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
		assert.ok(Math.abs(new Date(doc.exportedAt).getTime() - Date.now()) < 5 * 60 * 1000);
		assert.deepEqual(doc.items, [
			{ type: "login", name: "GitHub", username: "octocat@example.com", password: "P@ssw0rd-Strong-123", urls: ["https://github.com"], notes: "", favorite: true, createdAt: "2026-10-01T09:00:00Z", updatedAt: "2026-10-02T09:00:00Z" },
			{ type: "login", name: "Bank <script>alert(1)</script>", username: "alice", password: "hunter2 & \"quotes\" <b>", urls: ["https://bank.example", "https://login.bank.example/portal"],
				notes: "Security question: first pet.\nSecond line & <i>markup</i>", favorite: false, createdAt: "2026-10-01T09:00:00Z", updatedAt: "2026-10-01T09:00:00Z" },
			{ type: "login", name: "Wi-Fi café", username: "", password: "ñandú-Ωmega-🔐", urls: [], notes: "", favorite: false, createdAt: "2026-10-03T09:00:00Z", updatedAt: "2026-10-03T09:00:00Z" }
		]);
		// Both files read back with this importer: into the vault they came from the JSON adds nothing, the CSV the item with two addresses.
		const held = items.map((i) => ({ name: i.name, username: i.username, password: i.password, urls: i.urls }));
		assert.deepEqual(ieNode.planImport(ieNode.parseImport(new Uint8Array(fs.readFileSync(await json.path()))), held, {}).counts.toAdd, 0);
		assert.deepEqual(ieNode.planImport(ieNode.parseImport(new Uint8Array(csvBytes)), held, {}).candidates.filter((c) => c.status === "add").map((c) => c.name), ["Bank <script>alert(1)</script>"]);
		// Nothing of an export goes to the server, and nothing is asked of it: the check is made in this browser.
		assert.equal(mock.calls.length, callsBefore, "an export makes no request");
		assert.ok(mock.calls.every((c) => !JSON.stringify(c.body || "").includes(meta.typedPassword)));
		// Passwords of the vault are still not in the page.
		await assertNoSecretInDom(page);
		// The object URLs: two made, none revoked yet; locking revokes both at once.
		assert.equal(await page.evaluate(() => window.__urls.created.length), 2);
		assert.deepEqual(await page.evaluate(() => window.__urls.revoked), []);
		await page.click("#vault-lock");
		assert.deepEqual(await page.evaluate(() => window.__urls.revoked.slice().sort()), await page.evaluate(() => window.__urls.created.slice().sort()));
		await context.close();
	});

	await test("export: the object URL is revoked a minute after the download; the downloaded file is complete even when the vault locks at once", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		mock.seedEnvelope(accountId, bytes);
		const context = await browser.newContext({ acceptDownloads: true });
		const page = await context.newPage();
		watchConsole(page, errors);
		await page.clock.install();
		await watchObjectUrls(page);
		await routeApi(page, mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		const exportOnce = async () => {
			await page.click("#vault-export");
			await page.check("#export-format-json");
			await page.check("#export-ack");
			await page.fill("#export-master-password", meta.typedPassword);
			const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export-submit")]);
			return download;
		};
		const first = await exportOnce();
		await page.waitForSelector("#vault-export-panel", { state: "hidden" });
		assert.equal(await page.evaluate(() => window.__urls.revoked.length), 0);
		await page.clock.fastForward("00:59");
		assert.equal(await page.evaluate(() => window.__urls.revoked.length), 0);
		await page.clock.fastForward("00:02");
		assert.deepEqual(await page.evaluate(() => window.__urls.revoked), await page.evaluate(() => window.__urls.created));
		assert.equal(JSON.parse(fs.readFileSync(await first.path(), "utf8")).items.length, 3);
		// Locked in the same breath as the download: the URL is revoked at once, and the file is whole all the same.
		await page.click("#vault-export");
		await page.check("#export-ack");
		await page.fill("#export-master-password", meta.typedPassword);
		const downloading = page.waitForEvent("download");
		await page.evaluate(() => {
			const panel = document.getElementById("vault-export-panel");
			new MutationObserver(() => { if (panel.hidden) { window.bitosxVault.lock(); } }).observe(panel, { attributes: true, attributeFilter: ["hidden"] });
		});
		await page.click("#export-submit");
		const second = await downloading;
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.evaluate(() => window.__urls.revoked.length), 2);
		assert.equal(fs.readFileSync(await second.path(), "utf8").split("\r\n").length, 5, "the header, three items, and the end of the last line");
		await context.close();
	});

	await test("export: an empty vault has nothing to export; locking and cancelling clear what was typed; a check that finishes after the lock writes nothing", async () => {
		const mock = createMockApi();
		const accountId = mock.seedAccount("user@example.com", PASSWORD);
		const { bytes, meta } = fixture("small");
		const env = vcNode.parseEnvelope(new Uint8Array(bytes));
		const o = await vcNode.unlock(env, meta.typedPassword);
		mock.seedEnvelope(accountId, Buffer.from(vcNode.serializeEnvelope(await vcNode.encryptContent(env, o.vaultKey, vcNode.serializeVault({ items: [] })))));
		const context = await browser.newContext({ acceptDownloads: true });
		const page = await context.newPage();
		watchConsole(page, errors);
		await watchObjectUrls(page);
		await routeApi(page, mock);
		await signedIn(mock, page);
		await unlockWith(page, meta.typedPassword);
		await page.waitForSelector("#vault-items-section:not([hidden])");
		const downloads = [];
		page.on("download", (d) => downloads.push(d));
		// Nothing to export: no file is made of an empty vault, and no password is asked for.
		await page.click("#vault-export");
		assert.equal(await page.textContent("#vault-export-notice"), "This vault has no items, so there is nothing to export.");
		assert.match(await page.getAttribute("#vault-export-notice", "class"), /\bwarn\b/);
		assert.deepEqual(await page.evaluate(() => ["export-ack", "export-master-password", "export-submit"].map((id) => document.getElementById(id).disabled)), [true, true, true]);
		assert.equal(await page.evaluate(() => document.activeElement.id), "export-cancel");
		await page.evaluate(() => document.getElementById("vault-export-panel").requestSubmit());
		await page.click("#export-cancel");
		assert.equal(await page.isHidden("#vault-export-panel"), true);
		// With one item there is something to export.
		await page.click("#vault-add");
		await page.fill("#edit-name", "Mine");
		await page.fill("#edit-password", "FAKE-mine-pw");
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await page.click("#vault-export");
		assert.equal(await page.textContent("#vault-export-notice"), "");
		// Cancel clears what was typed and ticked.
		await page.check("#export-ack");
		await page.fill("#export-master-password", "typed and then cancelled");
		await page.click("#export-cancel");
		assert.equal(await page.evaluate(() => document.activeElement.id), "vault-export");
		await page.click("#vault-export");
		assert.equal(await page.inputValue("#export-master-password"), "");
		assert.equal(await page.isChecked("#export-ack"), false);
		assert.equal(await page.isDisabled("#export-submit"), true);
		// The export of unsaved items is what the vault holds at that moment (the item added by hand).
		await page.check("#export-ack");
		await page.fill("#export-master-password", meta.typedPassword);
		const [download] = await Promise.all([page.waitForEvent("download"), page.click("#export-submit")]);
		assert.equal(fs.readFileSync(await download.path(), "utf8"), "name,url,username,password,note\r\n\"Mine\",\"\",\"\",\"FAKE-mine-pw\",\"\"\r\n");
		// Locking closes the panel and clears it; a check of the password that is still running then writes nothing.
		await page.click("#vault-export");
		await page.check("#export-ack");
		await page.fill("#export-master-password", meta.typedPassword);
		await page.evaluate(() => {
			// The key derivation of this check is held back until the test lets it go.
			const real = window.hashwasm.argon2id;
			window.__release = null;
			window.hashwasm.argon2id = (options) => new Promise((resolve) => { window.__release = () => resolve(real(options)); });
		});
		await page.click("#export-submit");
		await page.waitForFunction(() => typeof window.__release === "function");
		assert.equal(await page.isDisabled("#export-submit"), true, "busy while the password is checked");
		assert.match(await page.textContent("#export-progress"), /^Checking the master password: Argon2id with 1 MiB\./);
		await page.click("#vault-lock");
		await page.waitForSelector("#vault-unlock-form:not([hidden])");
		assert.equal(await page.isHidden("#vault-export-panel"), true);
		assert.equal(await page.inputValue("#export-master-password"), "");
		assert.equal(await page.isChecked("#export-ack"), false);
		await page.evaluate(() => { const release = window.__release; window.hashwasm.argon2id = undefined; release(); });
		await new Promise((r) => setTimeout(r, 500));
		assert.equal(downloads.length, 1, "only the export before the lock was written");
		assert.equal(await page.evaluate(() => window.__urls.created.length), 1);
		assert.equal(await page.textContent("#vault-notice"), "Vault locked.");
		await context.close();
	});

	// ------------------------------------------------------------- hygiene
	console.log("hygiene");
	await test("no console errors, page errors or CSP violations in any flow", async () => {
		assert.deepEqual(errors, [], errors.join("\n"));
	});
	await test("static CSP: no inline scripts/styles/handlers in any HTML", async () => {
		const files = [];
		for (const site of ["www", "vault"]) {
			for (const f of fs.readdirSync(path.join(ROOT, site, "public"))) {
				if (f.endsWith(".html")) { files.push(path.join(ROOT, site, "public", f)); }
			}
		}
		for (const f of files) {
			const html = fs.readFileSync(f, "utf8");
			assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>[\s\S]*?<\/script>/i.test(html), `inline <script> in ${f}`);
			assert.ok(!/\son[a-z]+\s*=/i.test(html), `inline event handler in ${f}`);
			assert.ok(!/\sstyle\s*=/i.test(html), `inline style attribute in ${f}`);
			assert.ok(!/<style[\s>]/i.test(html), `inline <style> in ${f}`);
			assert.ok(!/javascript:/i.test(html), `javascript: URL in ${f}`);
			assert.ok(/http-equiv="Content-Security-Policy"/.test(html), `missing CSP meta in ${f}`);
			// Only the page that runs the Argon2 WebAssembly may allow it, and nothing beyond that.
			const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)[1];
			if (f.endsWith(path.join("vault", "public", "index.html"))) {
				assert.ok(csp.includes("script-src 'self' 'wasm-unsafe-eval';"), `vault index needs wasm-unsafe-eval: ${f}`);
			} else {
				assert.ok(csp.includes("script-src 'self';"), `script-src must be 'self' only in ${f}`);
			}
			assert.ok(!/'unsafe-inline'|'unsafe-eval'|https?:\/\/(?!api\.bitosx\.se)/.test(csp), `CSP too wide in ${f}`);
		}
		const headers = fs.readFileSync(path.join(ROOT, "vault/public/_headers"), "utf8");
		assert.ok(headers.includes("script-src 'self' 'wasm-unsafe-eval';"), "_headers must carry the same script-src as the page");
		// Passkeys (WebAuthn L3 §5.9 "Permissions Policy integration": the feature tokens
		// publickey-credentials-create / publickey-credentials-get, default allowlist 'self') stay
		// with this origin only; every other powerful feature stays off.
		const pp = /^\s+Permissions-Policy:\s*(.+)$/m.exec(headers)[1].split(/,\s*/);
		assert.deepEqual(pp, ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()",
			"publickey-credentials-create=(self)", "publickey-credentials-get=(self)"]);
		// One web version everywhere: every footer and every stylesheet link.
		const WEB_VERSION = "0.7.0";
		for (const f of files) {
			const html = fs.readFileSync(f, "utf8");
			for (const m of html.matchAll(/bitosx\.css\?v=([0-9.]+)/g)) { assert.equal(m[1], WEB_VERSION, `stylesheet version in ${f}`); }
			for (const m of html.matchAll(/web v([0-9.]+)/g)) { assert.equal(m[1], WEB_VERSION, `footer version in ${f}`); }
			assert.ok(/bitosx\.css\?v=/.test(html), `stylesheet link without a version in ${f}`);
		}
		assert.ok(fs.readFileSync(path.join(ROOT, "README.md"), "utf8").includes("`web v" + WEB_VERSION + "`"), "README names the version");
		const a = fs.readFileSync(path.join(ROOT, "www/public/assets/css/bitosx.css"), "utf8");
		const b = fs.readFileSync(path.join(ROOT, "vault/public/assets/css/bitosx.css"), "utf8");
		assert.equal(a, b, "the two stylesheet copies must stay identical");
	});

	await browser.close();
	www.server.close();
	vault.server.close();

	const failed = results.filter(r => !r.ok).length;
	console.log(`\n${results.length - failed}/${results.length} passed`);
	process.exit(failed ? 1 : 0);
})().catch((err) => { console.error(err); process.exit(1); });
