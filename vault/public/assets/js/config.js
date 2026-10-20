// Runtime configuration for the BitosX web account (phase 1).
// Plain constants: this is a static site with no build step. The API origin
// must also appear in the CSP connect-src (see _headers and the <meta> policy).
(function (global) {
	"use strict";
	global.BITOSX_CONFIG = Object.freeze({
		apiBase: "https://api.bitosx.se",
		requestTimeoutMs: 15000,
		// The API caps auth bodies at 4 KiB; keep the client-side cap tighter.
		maxResponseBytes: 64 * 1024,
		// Refresh the access token when it has less than this left to live.
		refreshSkewMs: 30 * 1000,
		// Drop tokens and sign out locally after this much inactivity.
		idleTimeoutMs: 15 * 60 * 1000,
		// Mirrors AccountPasswordPolicy on the server (12..128, used exactly as typed).
		passwordMinLength: 12,
		passwordMaxLength: 128,
		emailMaxLength: 254
	});
})(window);
