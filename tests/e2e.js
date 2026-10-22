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
const { createMockApi } = require("./mock-api.js");

const ROOT = path.resolve(__dirname, "..");
const API_ORIGIN = "https://api.bitosx.se";

const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml" };

// Minimal static server: "/" -> index.html, "/verify-email" -> verify-email.html.
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

// Route https://api.bitosx.se/** to the mock, including CORS preflight.
async function routeApi(page, mock) {
	await page.route(`${API_ORIGIN}/**`, async (route) => {
		const req = route.request();
		const origin = req.headers()["origin"] || "*";
		const cors = {
			"Access-Control-Allow-Origin": origin,
			"Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
			"Access-Control-Expose-Headers": "Retry-After, X-Correlation-ID",
			"Vary": "Origin"
		};
		if (req.method() === "OPTIONS") { return route.fulfill({ status: 204, headers: cors }); }
		const url = new URL(req.url());
		const r = mock.handle(req.method(), url.pathname, req.headers(), req.postData());
		const headers = Object.assign({}, cors, r.headers || {}, { "X-Correlation-ID": "test" });
		if (r.contentType) { headers["Content-Type"] = r.contentType; }
		return route.fulfill({ status: r.status, headers, body: r.body });
	});
}

function watchConsole(page, bucket) {
	page.on("console", (msg) => {
		if (msg.type() !== "error") { return; }
		// Chromium logs every non-2xx response as an error; 400/401/413/429/503 from
		// the API are expected outcomes the app handles, so they are not failures here.
		if (/^Failed to load resource: the server responded with a status of (400|401|404|409|413|429|503)/.test(msg.text())) { return; }
		bucket.push(`console.error: ${msg.text()}`);
	});
	page.on("pageerror", (err) => bucket.push(`pageerror: ${err.message}`));
}

const results = [];
async function test(name, fn) {
	try { await fn(); results.push({ name, ok: true }); console.log(`  ok   ${name}`); }
	catch (err) { results.push({ name, ok: false, err }); console.log(`  FAIL ${name}\n       ${err.stack || err}`); }
}

(async () => {
	const www = await serveStatic(path.join(ROOT, "www", "public"));
	const vault = await serveStatic(path.join(ROOT, "vault", "public"));
	const browser = await chromium.launch();
	const errors = [];

	async function newPage(mock) {
		const page = await browser.newPage();
		watchConsole(page, errors);
		await routeApi(page, mock);
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
		assert.equal(await page.evaluate(() => Object.keys(localStorage).filter(k => k !== "theme").length + sessionStorage.length), 0, "no token in web storage");
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
		assert.equal(generated.length, 24);
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
		assert.equal(await page.evaluate(() => window.bitosxVault.hasUnsavedChanges()), false);
		await page.click("#edit-cancel");
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
