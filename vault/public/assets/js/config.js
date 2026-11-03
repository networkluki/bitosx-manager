// Runtime configuration for the BitosX web account and vault.
// Plain constants: this is a static site with no build step. The API origin
// must also appear in the CSP connect-src (see _headers and the <meta> policy).
(function (global) {
	"use strict";
	global.BITOSX_CONFIG = Object.freeze({
		apiBase: "https://api.bitosx.se",
		// Ordinary calls; the envelope transfers (up to 16 MiB each way) get envelopeTimeoutMs.
		requestTimeoutMs: 15000,
		envelopeTimeoutMs: 120000,
		// Most API answers are tiny; keep the client-side cap tight.
		maxResponseBytes: 64 * 1024,
		// The session list: the server returns at most 200 sessions, about 190 bytes each.
		maxSessionsResponseBytes: 256 * 1024,
		// Refresh the access token when it has less than this left to live.
		refreshSkewMs: 30 * 1000,
		// Drop tokens and sign out locally after this much inactivity.
		idleTimeoutMs: 15 * 60 * 1000,
		// Mirrors AccountPasswordPolicy on the server (12..128, used exactly as typed).
		passwordMinLength: 12,
		passwordMaxLength: 128,
		// The server's limit (EmailAddressValidator.MaxLength).
		emailMaxLength: 320,
		// The server's default for wrong codes per sign-in challenge (TotpOptions.MaxMfaAttempts).
		mfaMaxAttempts: 5,
		// The encrypted vault envelope may be 16 MiB (the desktop's own file limit); its Base64 plus
		// metadata fits in this. Only the envelope download may be this large.
		maxEnvelopeResponseBytes: 23 * 1024 * 1024,
		// Lock the unlocked vault after this much inactivity (shorter than the account sign-out),
		// with a warning this long before it when there are unsaved changes.
		vaultIdleTimeoutMs: 5 * 60 * 1000,
		idleWarningMs: 60 * 1000,
		// How often the idle timers are also checked against the wall clock (timers can stall in a
		// background tab or while the computer sleeps).
		idleCheckIntervalMs: 15 * 1000,
		// A secret copied to the clipboard is cleared again after this long, if the browser lets the
		// page check that it is still there.
		clipboardClearMs: 30 * 1000
	});
})(window);
