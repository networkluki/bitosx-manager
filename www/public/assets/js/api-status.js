// Live status of api.bitosx.se, fetched from the visitor's browser.
// Reads only the two public, non-sensitive endpoints (/health and /version)
// and renders with textContent (never innerHTML). Any failure — network,
// CORS not yet enabled on the API, non-JSON body, unexpected shape — is shown
// as "unreachable from your browser" rather than guessed.
// External file so the strict CSP (script-src 'self') holds.
// Requires: connect-src https://api.bitosx.se
(function () {
	"use strict";

	var API_BASE = "https://api.bitosx.se";
	var TIMEOUT_MS = 6000;
	var MAX_BODY_BYTES = 4096;

	var badge = document.getElementById("api-badge");
	var desc = document.getElementById("api-desc");
	if (!badge || !window.fetch || !window.AbortController) { return; }

	function setBadge(cls, text) {
		badge.className = "badge " + cls;
		badge.textContent = text;
	}

	// Fetch a small JSON document with a hard timeout and a body-size cap.
	function getJson(path) {
		var controller = new AbortController();
		var timer = setTimeout(function () { controller.abort(); }, TIMEOUT_MS);
		return fetch(API_BASE + path, {
			method: "GET",
			headers: { "Accept": "application/json" },
			credentials: "omit",
			cache: "no-store",
			signal: controller.signal
		}).then(function (res) {
			if (!res.ok) { throw new Error("status " + res.status); }
			var type = res.headers.get("content-type") || "";
			if (type.indexOf("application/json") !== 0) { throw new Error("not json"); }
			return res.text();
		}).then(function (text) {
			if (text.length > MAX_BODY_BYTES) { throw new Error("body too large"); }
			return JSON.parse(text);
		}).finally(function () { clearTimeout(timer); });
	}

	// Accept only a short, printable version string before showing it.
	function safeVersion(v) {
		return (typeof v === "string" && /^[0-9A-Za-z.+-]{1,32}$/.test(v)) ? v : null;
	}

	Promise.all([getJson("/health"), getJson("/version")])
		.then(function (results) {
			var health = results[0] || {};
			var version = results[1] || {};
			if (health.status !== "healthy") { throw new Error("not healthy"); }
			var v = safeVersion(version.version);
			setBadge("ok", v ? "healthy · v" + v : "healthy");
		})
		.catch(function () {
			setBadge("warn", "unreachable from your browser");
			if (desc) {
				desc.textContent = "The API did not answer this page. It is either not publicly exposed yet or does not allow requests from this origin. Nothing about your account is affected.";
			}
		});
})();
