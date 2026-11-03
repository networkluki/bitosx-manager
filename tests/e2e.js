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

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { createMockApi, totpCode, totpStep, base32Decode } = require("./mock-api.js");

const ROOT = path.resolve(__dirname, "..");
const API_ORIGIN = "https://api.bitosx.se";

const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml" };

// Minimal static server: "/" -> index.html, "/verify-email" -> verify-email.html, and so on.
function serveStatic(dir) {
	return new Promise((resolve) => {
		const server = http.createServer((req, res) => {
			let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
			if (p.includes("..")) { res.writeHead(400); return res.end(); }
			if (p.endsWith("/")) { p += "index.html"; }
			let file = path.join(dir, p);
			if (!path.extname(file) && fs.existsSync(file + ".html")) { file += ".html"; }
			if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
				res.writeHead(404, { "Content-Type": "text/html" });
				return res.end(fs.readFileSync(path.join(dir, "404.html")));
			}
			res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream" });
			res.end(fs.readFileSync(file));
		});
		server.listen(0, "127.0.0.1", () => resolve({ server, origin: `http://127.0.0.1:${server.address().port}` }));
	});
}

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

function watchConsole(page, bucket) {
	page.on("console", (msg) => {
		if (msg.type() !== "error") { return; }
		// Chromium logs every non-2xx response as an error; 400/401/403/413/429/503 from
		// the API are expected outcomes the app handles, so they are not failures here.
		if (/^Failed to load resource: the server responded with a status of (400|401|403|404|409|413|429|503)/.test(msg.text())) { return; }
		// A test that provokes a network failure on purpose says which messages it expects.
		if (page.expectedConsole && page.expectedConsole.test(msg.text())) { return; }
		bucket.push(`console.error: ${msg.text()}`);
	});
	page.on("pageerror", (err) => bucket.push(`pageerror: ${err.message}`));
}

const results = [];
async function test(name, fn) {
	// BITOSX_E2E_ONLY=<text> runs only the tests whose name contains it (plus the hygiene checks).
	if (process.env.BITOSX_E2E_ONLY && !name.includes(process.env.BITOSX_E2E_ONLY) && !name.startsWith("no console errors") && !name.startsWith("static CSP")) { return; }
	try { await fn(); results.push({ name, ok: true }); console.log(`  ok   ${name}`); }
	catch (err) { results.push({ name, ok: false, err }); console.log(`  FAIL ${name}\n       ${err.stack || err}`); }
}

(async () => {
	const www = await serveStatic(path.join(ROOT, "www", "public"));
	const vault = await serveStatic(path.join(ROOT, "vault", "public"));
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
		// One web version everywhere: every footer and every stylesheet link.
		const WEB_VERSION = "0.6.0";
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
