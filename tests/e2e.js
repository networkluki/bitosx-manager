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
		if (/^Failed to load resource: the server responded with a status of (400|401|404|413|429|503)/.test(msg.text())) { return; }
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
		const refreshes = mock.calls.filter(c => c.path === "/v1/auth/refresh");
		assert.equal(refreshes.length, 1, "refresh must be single-flighted (reuse revokes the session server-side)");
		assert.equal(mock.calls.filter(c => c.path === "/v1/account/me").length, 1);
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

	// ------------------------------------------------------------- hygiene
	console.log("hygiene");
	await test("no console errors, page errors or CSP violations in any flow", async () => {
		assert.deepEqual(errors, []);
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
		}
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
