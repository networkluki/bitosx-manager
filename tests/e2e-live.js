// Live end-to-end test of the web vault (vault/public) in real Chromium against a REAL BitosX API
// and database — the local stack of networkluki/bitosx-api (`tools/devstack/up.sh`), or the same
// stack in CI. Opt-in: it needs exactly three environment variables, which the stack writes to
// `tools/devstack/.state/env`:
//
//   BITOSX_LIVE_API_URL     the API, e.g. http://127.0.0.1:5080
//   BITOSX_LIVE_WEB_ORIGIN  the one origin the API's CORS allows; the vault is served there
//   BITOSX_LIVE_MAIL_CMD    `<cmd> latest <verify|reset> <email>` prints the emailed token
//
// Without them it says so and exits with code 2: a live suite that did not run is never a pass.
//
// How the page reaches the live API without a single changed byte in the site:
//
//   The site hard-codes https://api.bitosx.se (config.js, and the CSP connect-src of every page and
//   of _headers). This suite does not touch any of that. It starts a loopback TLS relay with a
//   throw-away self-signed certificate for api.bitosx.se and launches its own Chromium with
//     --host-resolver-rules  "api.bitosx.se" resolves to the relay; every other name fails
//     --ignore-certificate-errors-spki-list  trusts exactly that one throw-away key
//   and without any proxy, so the request cannot go anywhere else. The browser therefore sends the
//   real CORS preflights and requests from BITOSX_LIVE_WEB_ORIGIN, the relay hands them to
//   BITOSX_LIVE_API_URL, and the API's own response headers (Access-Control-*, everything) come back
//   unchanged; only hop-by-hop framing headers (RFC 9110 §7.6.1) are re-framed. The browser applies
//   real CORS to the real answers. No Playwright route interception is used: Playwright answers the
//   preflight of an intercepted request itself, which would test nothing.
//   None of this can reach a visitor: it lives in this file only, needs a browser started with these
//   command-line switches, and the certificate's key exists only in a temporary directory for the
//   length of the run.
//
// Flows (one fresh account per run, e2e-<random>@example.test; the database is never assumed empty):
//   register -> verify (token via the mail command) and set the password -> sign in -> sessions list
//   (and revoke another session) -> enroll TOTP (codes computed here, RFC 6238) -> sign out -> sign in
//   with a code -> the vault (the page cannot create one: a desktop-written fixture envelope is uploaded
//   through the API) opens with the master password -> edit an item -> Save (real PUT, real CORS) ->
//   reload, sign in, re-open, the edit is there -> encrypted backup == GET /v1/sync/envelope ->
//   change the account password (other session revoked, this one kept) -> forgot + reset via the mail
//   token -> recovery-code sign-in -> delete the account with a code -> sign-in fails.
//
// Run:  set -a; . <bitosx-api>/tools/devstack/.state/env; set +a; node tests/e2e-live.js
// Needs the `playwright` package + Chromium, and `openssl` (for the throw-away certificate).
"use strict";

const https = require("node:https");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const { execFile, execFileSync } = require("node:child_process");

const REQUIRED = ["BITOSX_LIVE_API_URL", "BITOSX_LIVE_WEB_ORIGIN", "BITOSX_LIVE_MAIL_CMD"];
if (REQUIRED.some((k) => !process.env[k])) {
	console.error("live suite not configured: set BITOSX_LIVE_API_URL, BITOSX_LIVE_WEB_ORIGIN, BITOSX_LIVE_MAIL_CMD");
	process.exit(2);
}

const { chromium } = require("playwright");
const { totpCode, base32Decode } = require("./mock-api.js");
const { serveStatic, readHeadersFile, watchConsole } = require("./harness.js");

const ROOT = path.resolve(__dirname, "..");
const VAULT_DIR = path.join(ROOT, "vault", "public");
const PRODUCTION_API = "https://api.bitosx.se";
const API_URL = new URL(process.env.BITOSX_LIVE_API_URL);
const MAIL_CMD = process.env.BITOSX_LIVE_MAIL_CMD;

function die(message) { console.error(`e2e-live: ${message}`); process.exit(1); }

// The page is served over plain http on the stack's web origin; anything else is a misconfiguration.
const WEB = (() => {
	let u;
	try { u = new URL(process.env.BITOSX_LIVE_WEB_ORIGIN); } catch { die("BITOSX_LIVE_WEB_ORIGIN is not a URL"); }
	if (u.protocol !== "http:" || !u.port || u.pathname !== "/" || u.search || u.hash || u.username) {
		die("BITOSX_LIVE_WEB_ORIGIN must be an origin like http://127.0.0.1:8788");
	}
	return { origin: u.origin, host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port) };
})();
if (!["http:", "https:"].includes(API_URL.protocol)) { die("BITOSX_LIVE_API_URL must be an http(s) URL"); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = (n) => crypto.randomBytes(n).toString("hex");

// ---- the API, from Node (helpers only: what a desktop or a second device would do) ----
async function api(method, p, body, token) {
	const headers = { Accept: "application/json" };
	if (body !== undefined) { headers["Content-Type"] = "application/json"; }
	if (token) { headers.Authorization = `Bearer ${token}`; }
	const res = await fetch(new URL(p.replace(/^\//, ""), API_URL.href.replace(/\/?$/, "/")), {
		method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: "error"
	});
	const text = await res.text();
	let json = null;
	if (text && /json/.test(res.headers.get("content-type") || "")) { json = JSON.parse(text); }
	return { status: res.status, body: json, headers: res.headers };
}

// ---- the mail command: the token the emailed link would carry ----
function mailToken(kind, email) {
	return new Promise((resolve, reject) => {
		execFile(MAIL_CMD, ["latest", kind, email], { timeout: 120000 }, (err, stdout, stderr) => {
			if (err) { return reject(Object.assign(new Error(`mail command (${kind}) failed: exit ${err.code}: ${String(stderr).trim()}`), { exitCode: err.code })); }
			const token = String(stdout).trim();
			if (!/^[A-Za-z0-9_-]{20,}$/.test(token)) { return reject(new Error(`mail command (${kind}) printed something that is not a token`)); }
			resolve(token);
		});
	});
}
// The newest pending message for the address, waiting briefly (exit 1 = none yet). `previous`
// excludes a token already used: "latest pending" stays the old one until a newer message exists.
async function waitForMailToken(kind, email, previous) {
	const deadline = Date.now() + 20000;
	for (;;) {
		try {
			const token = await mailToken(kind, email);
			if (token !== previous) { return token; }
		} catch (err) {
			if (err.exitCode !== 1) { throw err; }
		}
		if (Date.now() > deadline) { throw new Error(`no new ${kind} message for ${email} in the outbox`); }
		await sleep(500);
	}
}

// ---- RFC 6238 codes, with the server's replay rule: every code must use a later step than the
// last one used (sign-in, confirmation, sensitive action), within ±1 step of the server's clock ----
const totp = { secret: null, digits: 6, period: 30, last: null };
async function nextTotp() {
	for (;;) {
		const nowS = Date.now() / 1000;
		const cur = Math.floor(nowS / totp.period);
		const left = totp.period - (nowS % totp.period);
		// The previous step is still inside the window, but only while the current one lasts.
		const earliest = left > 8 ? cur - 1 : cur;
		const step = Math.max(earliest, totp.last === null ? earliest : totp.last + 1);
		if (step <= cur + 1) {
			totp.last = step;
			return totpCode(totp.secret, step, totp.digits);
		}
		console.log(`       (waiting ${Math.ceil(left)} s for the next TOTP step)`);
		await sleep(Math.ceil(left * 1000) + 300);
	}
}

// ---- the loopback TLS relay standing in for api.bitosx.se ----
function makeCertificate(dir) {
	const key = path.join(dir, "key.pem"), cert = path.join(dir, "cert.pem");
	try {
		execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
			"-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=api.bitosx.se", "-addext", "subjectAltName=DNS:api.bitosx.se"],
		{ stdio: ["ignore", "ignore", "pipe"] });
	} catch (err) {
		die(`could not create the throw-away certificate with openssl: ${err.message}`);
	}
	const pem = fs.readFileSync(cert);
	const spki = new crypto.X509Certificate(pem).publicKey.export({ type: "spki", format: "der" });
	return { key: fs.readFileSync(key), cert: pem, spkiHash: crypto.createHash("sha256").update(spki).digest("base64") };
}

const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade"]);
function endToEnd(rawHeaders, skip) {
	const out = {};
	for (let i = 0; i < rawHeaders.length; i += 2) {
		const name = rawHeaders[i].toLowerCase();
		if (HOP_BY_HOP.has(name) || (skip && skip.has(name))) { continue; }
		if (name in out) { out[name] = [].concat(out[name], rawHeaders[i + 1]); } else { out[name] = rawHeaders[i + 1]; }
	}
	return out;
}

// Every exchange the browser had with "api.bitosx.se": { method, path, origin, status, headers }.
const relayed = [];
function startRelay(tls) {
	const transport = API_URL.protocol === "https:" ? https : http;
	const server = https.createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
		const headers = endToEnd(req.rawHeaders, new Set(["host"]));
		headers.host = API_URL.host;
		const entry = { method: req.method, path: req.url, origin: req.headers.origin || null, status: 0, headers: null };
		relayed.push(entry);
		const upstream = transport.request({ protocol: API_URL.protocol, hostname: API_URL.hostname, port: API_URL.port, method: req.method, path: req.url, headers }, (up) => {
			entry.status = up.statusCode;
			entry.headers = endToEnd(up.rawHeaders);
			res.writeHead(up.statusCode, entry.headers);
			up.pipe(res);
		});
		upstream.on("error", () => { entry.status = -1; res.destroy(); });
		req.pipe(upstream);
	});
	return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port })));
}

// ---- a tiny sequential runner: the flows build on each other, so after a failure the rest is
// reported as not run (never as passed) ----
const results = [];
let broken = false;
async function step(name, fn) {
	if (broken) { results.push({ name, ok: false, skipped: true }); console.log(`  skip ${name} (an earlier step failed)`); return; }
	const t0 = Date.now();
	try { await fn(); results.push({ name, ok: true }); console.log(`  ok   ${name} (${((Date.now() - t0) / 1000).toFixed(1)} s)`); }
	catch (err) { broken = true; results.push({ name, ok: false, err }); console.log(`  FAIL ${name}\n       ${err.stack || err}`); }
}
// Hygiene checks run even after a failure.
async function check(name, fn) {
	try { await fn(); results.push({ name, ok: true }); console.log(`  ok   ${name}`); }
	catch (err) { results.push({ name, ok: false, err }); console.log(`  FAIL ${name}\n       ${err.stack || err}`); }
}

(async () => {
	const health = await api("GET", "/health").catch((err) => ({ status: 0, err }));
	if (health.status !== 200) {
		die(`the live API at ${API_URL.href} is not healthy (GET /health -> ${health.status || health.err.message}); start it with tools/devstack/up.sh in bitosx-api`);
	}

	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bitosx-e2e-live-"));
	const cleanup = () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ } };
	process.on("exit", cleanup);
	const tls = makeCertificate(tmp);
	const relay = await startRelay(tls);

	// The site exactly as deployed: its files, and the headers of its _headers file (the CSP there
	// applies on top of each page's <meta> policy).
	const siteHeaders = readHeadersFile(path.join(VAULT_DIR, "_headers"));
	assert.match(siteHeaders["Content-Security-Policy"], /connect-src https:\/\/api\.bitosx\.se;/);
	const site = await serveStatic(VAULT_DIR, { host: WEB.host, port: WEB.port, headers: siteHeaders })
		.catch((err) => die(`cannot serve the vault on ${WEB.origin}: ${err.message}`));
	assert.equal(site.origin, WEB.origin);
	// A second origin the API does not allow, to show the browser's CORS check is the real one.
	const stranger = await serveStatic(VAULT_DIR, { host: "127.0.0.1", headers: siteHeaders });

	// No proxy for this browser (a proxy would resolve api.bitosx.se itself, i.e. reach production).
	const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/proxy/i.test(k)));
	const browser = await chromium.launch({
		env,
		args: [
			"--no-proxy-server",
			`--host-resolver-rules=MAP api.bitosx.se 127.0.0.1:${relay.port}, MAP * ~NOTFOUND, EXCLUDE ${WEB.host}`,
			`--ignore-certificate-errors-spki-list=${tls.spkiHash}`
		]
	});
	const errors = [];
	const context = await browser.newContext({ acceptDownloads: true });
	const page = await context.newPage();
	page.setDefaultTimeout(30000);
	watchConsole(page, errors);

	const email = `e2e-${rand(8)}@example.test`;
	const password = `live-${rand(10)}`;
	const newPassword = `live-new-${rand(10)}`;
	const resetPassword = `live-reset-${rand(10)}`;
	const FIX = path.join(__dirname, "fixtures");
	const fixtureBytes = fs.readFileSync(path.join(FIX, "small.vault.json"));
	const fixtureMeta = JSON.parse(fs.readFileSync(path.join(FIX, "small.meta.json"), "utf8"));
	const vcNode = require("../vault/public/assets/js/vault-crypto.js")(require("../vault/public/assets/vendor/hash-wasm/argon2.umd.min.js"), globalThis.crypto);
	const GITHUB_ID = "11111111-1111-4111-8111-111111111111";
	const editedName = `GitHub (edited live ${rand(3)})`;
	const editedUser = `live-${rand(3)}@example.test`;
	let recoveryCodes = [];
	let other = null; // a second session, as another device would hold it
	let revision = 0;
	let verifyToken = null;

	console.log(`live API ${API_URL.origin} via https://api.bitosx.se (relay 127.0.0.1:${relay.port}), vault on ${WEB.origin}`);
	console.log(`account ${email}`);

	async function passwordStep(pw) {
		await page.fill("#login-email", email);
		await page.fill("#login-password", pw);
		await page.click("#login-submit");
	}
	async function codeStep(code) {
		await page.waitForSelector("#code-form:not([hidden])");
		await page.fill("#login-code", code);
		await page.click("#code-submit");
		await page.waitForSelector("#account-panel:not([hidden])");
	}
	async function vaultStatusLoaded() {
		await page.waitForSelector("#vault-panel:not([hidden])");
		await page.waitForFunction(() => !document.getElementById("vault-status-text").textContent.startsWith("Checking"));
	}
	async function unlock() {
		await page.fill("#vault-master-password", fixtureMeta.typedPassword);
		await page.click("#vault-unlock-submit");
		await page.waitForSelector("#vault-items-section:not([hidden])");
	}
	async function serverEnvelope(token) {
		const r = await api("GET", "/v1/sync/envelope", undefined, token);
		assert.equal(r.status, 200, "GET /v1/sync/envelope");
		return { meta: r.body, bytes: Buffer.from(r.body.envelope, "base64") };
	}
	// A second session through the API, as a desktop would sign in (with a recovery code once TOTP is on).
	async function apiSignIn(pw, code) {
		const r = await api("POST", "/v1/auth/login", { email, password: pw });
		if (r.status === 200) { return r.body; }
		assert.equal(r.status, 202, `API login: ${r.status}`);
		const t = await api("POST", "/v1/auth/login/totp", { mfaToken: r.body.mfaToken, code });
		assert.equal(t.status, 200, `API second step: ${t.status}`);
		return t.body;
	}
	const sessionRows = () => page.locator("#sessions-body tr").count();

	console.log("browser CORS is the API's");
	await step("an origin the API does not allow gets no answer the page can read; the allowed one does", async () => {
		const p = await context.newPage();
		watchConsole(p, errors);
		p.expectedConsole = /blocked by CORS policy|net::ERR_FAILED/;
		await p.goto(`${stranger.origin}/`);
		const strangerResult = await p.evaluate(() => fetch("https://api.bitosx.se/health", { credentials: "omit", cache: "no-store" }).then((r) => `status ${r.status}`, (e) => `refused: ${e.name}`));
		assert.equal(strangerResult, "refused: TypeError");
		const seen = relayed.filter((e) => e.origin === stranger.origin);
		assert.ok(seen.length >= 1, "the request did reach the API");
		assert.ok(seen.every((e) => !("access-control-allow-origin" in e.headers)), "the API sent no Access-Control-Allow-Origin to it");
		await p.close();
		await page.goto(`${WEB.origin}/`);
		const ok = await page.evaluate(() => fetch("https://api.bitosx.se/health", { credentials: "omit", cache: "no-store" }).then((r) => r.status));
		assert.equal(ok, 200);
		const mine = relayed.filter((e) => e.origin === WEB.origin);
		assert.equal(mine[mine.length - 1].headers["access-control-allow-origin"], WEB.origin);
	});

	console.log("register and verify");
	await step("register: the page sends the address, the API queues a verification message", async () => {
		await page.goto(`${WEB.origin}/register`);
		await page.fill("#register-email", email);
		await page.click("#register-submit");
		await page.waitForSelector("#register-notice.ok");
		assert.match(await page.textContent("#register-notice"), /an email is on its way/);
		verifyToken = await waitForMailToken("verify", email);
	});
	await step("verify-email: the emailed link's token sets the account password; the token is single-use", async () => {
		await page.goto(`${WEB.origin}/verify-email#token=${verifyToken}`);
		await page.waitForFunction(() => !window.location.hash);
		await page.fill("#verify-password", password);
		await page.fill("#verify-password2", password);
		await page.click("#verify-submit");
		await page.waitForSelector("#verify-notice.ok");
		assert.match(await page.textContent("#verify-notice"), /verified/);
		assert.equal((await api("POST", "/v1/auth/verify-email", { token: verifyToken, password })).status, 400, "the token is spent");
	});

	console.log("sign in, sessions");
	await step("sign in with the password: account and the session list", async () => {
		await page.goto(`${WEB.origin}/`);
		await passwordStep(password);
		await page.waitForSelector("#account-panel:not([hidden])");
		assert.equal(await page.textContent("#acct-email"), email);
		assert.equal(await page.textContent("#acct-verified"), "Yes");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(await page.locator("#sessions-body .current").count(), 1);
		await vaultStatusLoaded();
		assert.match(await page.textContent("#vault-status-text"), /holds no vault for this account yet/);
	});
	await step("sessions: another device's session is listed and revoked from the page (DELETE through CORS)", async () => {
		const tokens = await apiSignIn(password);
		const list = await api("GET", "/v1/account/sessions", undefined, tokens.accessToken);
		const mine = list.body.find((s) => s.current);
		assert.ok(mine, "the API marks the calling session");
		await page.click("#refresh-sessions");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 2);
		assert.equal(await page.locator("#sessions-body .current").count(), 1);
		await page.click(`button[data-session-id="${mine.id}"]`);
		await page.waitForFunction(() => document.getElementById("account-notice").textContent === "Session revoked.");
		assert.equal(await sessionRows(), 1);
		assert.equal((await api("GET", "/v1/account/me", undefined, tokens.accessToken)).status, 401, "the revoked session is dead");
		assert.ok(relayed.some((e) => e.method === "OPTIONS" && e.path === `/v1/account/sessions/${mine.id}` && e.status === 204), "the browser sent a real preflight for the DELETE");
	});

	console.log("two-factor authentication");
	await step("enroll TOTP: the secret is shown, a code computed here confirms it, ten recovery codes", async () => {
		await page.waitForFunction(() => document.getElementById("totp-status").textContent === "Not enabled.");
		await page.fill("#totp-enroll-password", password);
		await page.click("#totp-enroll-submit");
		await page.waitForSelector("#totp-setup:not([hidden])");
		const uri = new URL(await page.textContent("#totp-setup-uri"));
		assert.equal(uri.protocol, "otpauth:");
		const algorithm = (uri.searchParams.get("algorithm") || "SHA1").toUpperCase();
		assert.equal(algorithm, "SHA1", "this suite computes SHA-1 codes only");
		totp.digits = Number(uri.searchParams.get("digits") || 6);
		totp.period = Number(uri.searchParams.get("period") || 30);
		const shown = (await page.textContent("#totp-setup-secret")).replace(/ /g, "");
		assert.equal(shown, uri.searchParams.get("secret"));
		totp.secret = base32Decode(shown);
		await page.fill("#totp-confirm-code", await nextTotp());
		await page.click("#totp-confirm-submit");
		await page.waitForSelector("#totp-codes:not([hidden])");
		recoveryCodes = (await page.textContent("#totp-codes-list")).trim().split("\n");
		assert.equal(recoveryCodes.length, 10);
		await page.waitForFunction(() => /Recovery codes left: 10/.test(document.getElementById("totp-status").textContent));
		await page.click("#totp-codes-done");
		assert.equal(await page.textContent("#totp-codes-list"), "");
	});
	await step("sign out", async () => {
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.equal(await page.textContent("#login-notice"), "You are signed out.");
	});
	await step("a desktop uploads its vault (the page cannot create one): a fixture envelope written by the desktop's code, through the API", async () => {
		other = await apiSignIn(password, recoveryCodes.shift());
		const put = await api("PUT", "/v1/sync/envelope", { baseRevision: 0, envelope: fixtureBytes.toString("base64") }, other.accessToken);
		assert.equal(put.status, 200, `PUT /v1/sync/envelope: ${put.status}`);
		assert.equal(put.body.fingerprint, fixtureMeta.fingerprint);
		revision = put.body.revision;
	});
	await step("sign in with the password and a TOTP code; the server's vault is listed", async () => {
		await passwordStep(password);
		await page.waitForSelector("#code-form:not([hidden])");
		assert.equal(await page.isHidden("#account-panel"), true, "no session before the code");
		await codeStep(await nextTotp());
		await page.waitForFunction(() => /Enabled/.test(document.getElementById("totp-status").textContent));
		assert.match(await page.textContent("#totp-status"), /Recovery codes left: 9/);
		await vaultStatusLoaded();
		assert.match(await page.textContent("#vault-status-text"), new RegExp(`revision ${revision}, 1\\.8 KiB`));
	});

	console.log("the web vault");
	await step("open the vault with the master password (Argon2id + AES-GCM in the browser)", async () => {
		await unlock();
		assert.equal(await page.locator("#vault-items .vault-item").count(), 3);
	});
	await step("edit an item and Save to server: a real PUT through real CORS; the server's copy opens with the master password", async () => {
		const item = page.locator(`.vault-item[data-item-id="${GITHUB_ID}"]`);
		await item.locator("button[data-edit]").click();
		await page.waitForSelector("#vault-editor:not([hidden])");
		await page.fill("#edit-name", editedName);
		await page.fill("#edit-username", editedUser);
		await page.click("#edit-save");
		await page.waitForSelector("#vault-editor", { state: "hidden" });
		await page.click("#vault-save");
		await page.waitForFunction((r) => document.getElementById("vault-notice").textContent.startsWith(`Saved: the server now holds revision ${r}.`), revision + 1);
		revision += 1;
		const preflight = relayed.filter((e) => e.method === "OPTIONS" && e.path === "/v1/sync/envelope").pop();
		assert.ok(preflight, "the browser sent a preflight for the PUT");
		assert.equal(preflight.headers["access-control-allow-origin"], WEB.origin);
		assert.match(preflight.headers["access-control-allow-methods"], /\bPUT\b/);
		const put = relayed.filter((e) => e.method === "PUT" && e.path === "/v1/sync/envelope").pop();
		assert.equal(put.status, 200);
		// The desktop's view: what the server holds now opens with the same master password.
		const { meta, bytes } = await serverEnvelope(other.accessToken);
		assert.equal(meta.revision, revision);
		const opened = await vcNode.unlock(vcNode.parseEnvelope(new Uint8Array(bytes)), fixtureMeta.typedPassword);
		const items = vcNode.parseVault(opened.plaintext).items;
		const edited = items.find((i) => i.id === GITHUB_ID);
		assert.equal(edited.name, editedName);
		assert.equal(edited.username, editedUser);
		assert.equal(items.length, 3);
		const before = JSON.parse(fixtureBytes.toString("utf8")), after = JSON.parse(bytes.toString("utf8"));
		for (const k of ["version", "kdf", "kdfParameters", "salt", "algorithm", "keyWrapNonce", "encryptedVaultKey"]) {
			assert.deepEqual(after[k], before[k], `the desktop's key-wrap header is untouched: ${k}`);
		}
	});
	await step("reload (memory-only tokens: signed out), sign in again, re-open: the edit is there", async () => {
		await page.reload();
		await page.waitForSelector("#login-panel:not([hidden])");
		await passwordStep(password);
		await codeStep(await nextTotp());
		await vaultStatusLoaded();
		assert.match(await page.textContent("#vault-status-text"), new RegExp(`revision ${revision},`));
		await unlock();
		const names = (await page.locator(".vault-item__name").allTextContents()).map((n) => n.trim());
		assert.ok(names.some((n) => n.startsWith(editedName)), `edited name listed: ${names.join(" | ")}`);
	});
	await step("download the encrypted backup: byte for byte what GET /v1/sync/envelope returns", async () => {
		const [download] = await Promise.all([page.waitForEvent("download"), page.click("#vault-backup")]);
		assert.match(download.suggestedFilename(), /^BitosX-backup-\d{4}-\d{2}-\d{2}\.bitosx-backup$/);
		const saved = fs.readFileSync(await download.path());
		const { bytes } = await serverEnvelope(other.accessToken);
		assert.ok(saved.equals(bytes), "the backup is the server's bytes");
		await page.click("#vault-lock");
	});

	console.log("account controls");
	await step("change the account password with a code: the other session is revoked, this one stays", async () => {
		assert.equal((await api("GET", "/v1/account/me", undefined, other.accessToken)).status, 200, "the other session works before");
		await page.fill("#pw-current", password);
		await page.fill("#pw-new", newPassword);
		await page.fill("#pw-new2", newPassword);
		await page.fill("#pw-code", await nextTotp());
		await page.click("#pw-submit");
		await page.waitForFunction(() => /password is changed/.test(document.getElementById("pw-notice").textContent));
		assert.equal((await api("GET", "/v1/account/me", undefined, other.accessToken)).status, 401, "the other session is signed out");
		assert.equal((await api("POST", "/v1/auth/refresh", { refreshToken: other.refreshToken })).status, 401, "and cannot refresh");
		await page.click("#refresh-sessions");
		await page.waitForFunction(() => document.querySelectorAll("#sessions-body tr").length === 1);
		assert.equal(await page.locator("#sessions-body .current").count(), 1);
		assert.equal(await page.isHidden("#account-panel"), false, "this session is still valid");
		assert.equal((await api("POST", "/v1/auth/login", { email, password })).status, 401, "the old password is refused");
	});
	await step("forgot password: the reset link's token from the mail command sets a new password", async () => {
		await page.click("#logout");
		await page.waitForSelector("#login-panel:not([hidden])");
		await page.click("a[href='/forgot-password']");
		await page.waitForSelector("#forgot-form");
		await page.fill("#forgot-email", email);
		await page.click("#forgot-submit");
		await page.waitForSelector("#forgot-notice.ok");
		const token = await waitForMailToken("reset", email);
		await page.goto(`${WEB.origin}/reset-password#token=${token}`);
		await page.waitForFunction(() => !window.location.hash);
		await page.fill("#reset-password", resetPassword);
		await page.fill("#reset-password2", resetPassword);
		await page.click("#reset-submit");
		await page.waitForSelector("#reset-notice.ok");
		assert.match(await page.textContent("#reset-notice"), /reset and every device is signed out/);
		assert.equal((await api("POST", "/v1/auth/login", { email, password: newPassword })).status, 401, "the previous password is refused");
	});
	await step("sign in with the reset password and a recovery code", async () => {
		await page.goto(`${WEB.origin}/`);
		await passwordStep(resetPassword);
		await codeStep(recoveryCodes.shift().toUpperCase().replace("-", " ")); // as a person might type it
		await page.waitForFunction(() => /Recovery codes left: 8/.test(document.getElementById("totp-status").textContent));
	});
	await step("delete the account with the password and a TOTP code; signing in fails afterwards", async () => {
		await page.fill("#delete-password", resetPassword);
		await page.fill("#delete-code", await nextTotp());
		await page.check("#delete-ack");
		await page.click("#delete-submit");
		await page.waitForSelector("#login-panel:not([hidden])");
		assert.match(await page.textContent("#login-notice"), /account and the vault stored on the server are deleted/);
		await passwordStep(resetPassword);
		await page.waitForSelector("#login-notice.err");
		assert.equal(await page.textContent("#login-notice"), "Invalid email or password.");
		assert.equal((await api("POST", "/v1/auth/login", { email, password: resetPassword })).status, 401);
	});

	console.log("hygiene");
	await check("every API request of the browser went through the relay to the live API, and every CORS answer was the API's", async () => {
		assert.ok(relayed.length > 20, `relayed ${relayed.length}`);
		assert.ok(relayed.every((e) => e.status > 0), "no relayed request failed");
		for (const e of relayed.filter((x) => x.origin === WEB.origin)) {
			assert.equal(e.headers["access-control-allow-origin"], WEB.origin, `${e.method} ${e.path}`);
		}
		assert.ok(relayed.some((e) => e.method === "OPTIONS"), "real preflights were sent");
	});
	await check("no console errors, page errors or CSP violations", async () => {
		assert.deepEqual(errors, [], errors.join("\n"));
	});

	await browser.close();
	site.server.close();
	stranger.server.close();
	relay.server.close();

	const failed = results.filter((r) => !r.ok).length;
	const skipped = results.filter((r) => r.skipped).length;
	console.log(`\n${results.length - failed}/${results.length} passed${skipped ? ` (${skipped} not run after a failure)` : ""} against ${PRODUCTION_API} -> ${API_URL.origin}`);
	process.exit(failed ? 1 : 0);
})().catch((err) => { console.error(err); process.exit(1); });
