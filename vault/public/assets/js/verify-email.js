// Email verification + account password creation (vault.bitosx.se, phase 1).
//
// The verification email links to  https://vault.bitosx.se/verify-email#token=<base64url>
// The token travels in the URL *fragment*, which browsers never send to the
// server, so it stays out of web and proxy access logs. This page reads it
// once, removes it from the address bar and history, keeps it in memory, and
// sends it to the API only in a POST body together with the chosen password.
(function () {
	"use strict";

	var api = window.bitosxApi;
	var ui = window.bitosxUi;
	var $ = ui.$;

	var form = $("verify-form");
	var noticeEl = $("verify-notice");
	var passEl = $("verify-password");
	var pass2El = $("verify-password2");
	if (!form) { return; }

	// Base64URL, unpadded. The real token is 43 characters (256 bits); allow a
	// little slack so a future longer token still reaches the server, which is
	// the authority on validity.
	var TOKEN_RE = /^[A-Za-z0-9_-]{32,256}$/;

	function readTokenFromFragment() {
		var hash = window.location.hash || "";
		if (hash.charAt(0) === "#") { hash = hash.slice(1); }
		var token = null;
		hash.split("&").forEach(function (part) {
			var eq = part.indexOf("=");
			if (eq > 0 && part.slice(0, eq) === "token") {
				var raw = part.slice(eq + 1);
				try { raw = decodeURIComponent(raw); } catch (e) { raw = ""; }
				if (TOKEN_RE.test(raw)) { token = raw; }
			}
		});
		return token;
	}

	var token = readTokenFromFragment();
	// Scrub the fragment so the token does not linger in the address bar,
	// history, or a copied URL. The in-memory copy is all this page needs.
	if (window.location.hash) {
		try { window.history.replaceState(null, "", window.location.pathname + window.location.search); }
		catch (e) { /* history API blocked: the fragment stays, the flow still works */ }
	}

	if (!token) {
		ui.notice(noticeEl, "err", "This verification link is incomplete or malformed. Open the link from the email again, or request a new one.");
		ui.setBusy(form, true);
		return;
	}

	form.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var password = passEl.value;
		var password2 = pass2El.value;
		var okLen = ui.validPassword(password);
		passEl.setAttribute("aria-invalid", okLen ? "false" : "true");
		pass2El.setAttribute("aria-invalid", password === password2 ? "false" : "true");
		if (!okLen) {
			ui.notice(noticeEl, "err", "The account password must be 12–128 characters.");
			return;
		}
		if (password !== password2) {
			ui.notice(noticeEl, "err", "The two passwords do not match.");
			return;
		}
		ui.notice(noticeEl, "ok", "");
		ui.setBusy(form, true);
		api.verifyEmail(token, password)
			.then(function () {
				token = null;
				passEl.value = "";
				pass2El.value = "";
				ui.notice(noticeEl, "ok", "Your email is verified and your account password is set. You can sign in now.");
				// The token is single-use: keep the form disabled after success.
			})
			.catch(function (err) {
				ui.notice(noticeEl, "err", ui.describeError(err, "verify"));
				// 400 means the token is spent/expired; anything else may be retried.
				if (!(err && err.kind === api.KINDS.INVALID)) { ui.setBusy(form, false); }
			})
			.finally(function () { password = null; password2 = null; });
	});

	passEl.focus();
})();
