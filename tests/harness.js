// Pieces shared by the browser suites: the mocked one (e2e.js) and the live one (e2e-live.js).
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".xml": "application/xml" };

// Minimal static server: "/" -> index.html, "/verify-email" -> verify-email.html, and so on, the
// extensionless-HTML resolution Cloudflare / GitHub Pages use.
// options.host / options.port: where to listen (default 127.0.0.1, a free port).
// options.headers: extra response headers sent with every answer (the site's `_headers`).
function serveStatic(dir, options = {}) {
	const host = options.host || "127.0.0.1";
	const extra = options.headers || {};
	return new Promise((resolve, reject) => {
		const server = http.createServer((req, res) => {
			let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
			if (p.includes("..")) { res.writeHead(400); return res.end(); }
			if (p.endsWith("/")) { p += "index.html"; }
			let file = path.join(dir, p);
			if (!path.extname(file) && fs.existsSync(file + ".html")) { file += ".html"; }
			if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
				res.writeHead(404, Object.assign({}, extra, { "Content-Type": "text/html" }));
				return res.end(fs.readFileSync(path.join(dir, "404.html")));
			}
			res.writeHead(200, Object.assign({}, extra, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream" }));
			res.end(fs.readFileSync(file));
		});
		server.once("error", reject);
		server.listen(options.port || 0, host, () => {
			const origin = `http://${host.includes(":") ? `[${host}]` : host}:${server.address().port}`;
			resolve({ server, origin });
		});
	});
}

// Reads a Cloudflare Pages `_headers` file and returns the headers of its `/*` rule. Any other rule
// is refused: this harness would not apply it, and a test must not pretend it did.
function readHeadersFile(file) {
	const headers = {};
	let rule = null;
	for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
		if (!raw.trim() || raw.trim().startsWith("#")) { continue; }
		if (!/^\s/.test(raw)) {
			rule = raw.trim();
			if (rule !== "/*") { throw new Error(`${file}: rule "${rule}" is not supported by the test server (only /*)`); }
			continue;
		}
		const m = /^\s+([A-Za-z0-9-]+):\s*(.*)$/.exec(raw);
		if (!rule || !m) { throw new Error(`${file}: cannot read line "${raw}"`); }
		headers[m[1]] = m[2].trim();
	}
	return headers;
}

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

module.exports = { MIME, serveStatic, readHeadersFile, watchConsole };
