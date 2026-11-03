// Small DOM helpers shared by the vault app pages. Text only — nothing from
// the network or the URL is ever inserted as HTML.
(function (global) {
	"use strict";

	var cfg = global.BITOSX_CONFIG;
	var KINDS = global.bitosxApi.KINDS;

	function $(id) { return document.getElementById(id); }

	function el(tag, attrs, text) {
		var node = document.createElement(tag);
		if (attrs) {
			Object.keys(attrs).forEach(function (k) {
				if (k === "class") { node.className = attrs[k]; }
				else { node.setAttribute(k, attrs[k]); }
			});
		}
		if (text !== undefined && text !== null) { node.textContent = String(text); }
		return node;
	}

	function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

	// Show a notice. level: "ok" | "warn" | "err". Hidden when text is empty.
	function notice(node, level, text) {
		if (!node) { return; }
		node.className = "notice" + (text ? " is-visible " + level : "");
		node.textContent = text || "";
	}

	// Map an API failure to a fixed, non-sensitive user message.
	function describeError(err, context) {
		var kind = (err && err.kind) || KINDS.UNEXPECTED;
		switch (kind) {
			case KINDS.NETWORK:
				return "The API could not be reached from this browser. Check your connection and try again.";
			case KINDS.TIMEOUT:
				return "The API did not answer in time. Check your connection and try again.";
			case KINDS.RATE_LIMITED:
				return "Too many attempts. Try again " + (err.retryAfterSeconds ? "in about " + err.retryAfterSeconds + " seconds." : "in a few minutes.");
			case KINDS.UNAVAILABLE:
				// 503 has several causes: a busy server (always with Retry-After), email delivery
				// switched off, or the second factor being unavailable. Only the second sign-in step
				// and the two-factor settings name the second factor, and only without Retry-After.
				if (err && err.retryAfterSeconds) { return "The server is busy right now. Try again in a moment."; }
				if (context === "code" || context === "passkey-mfa") { return "Two-factor sign-in is temporarily unavailable on the server. Try again shortly."; }
				if (context === "totp") { return "Two-factor authentication is temporarily unavailable on the server. Try again shortly."; }
				return "The service is temporarily unavailable. Try again shortly.";
			case KINDS.TOO_LARGE:
				return "The request was too large.";
			case KINDS.UNAUTHENTICATED:
				if (context === "login") { return "Invalid email or password."; }
				if (context === "code") { return "The code was not accepted. Try the next code from your app, or a recovery code. After several wrong codes, or after a few minutes, start over with your password."; }
				if (context === "passkey-mfa") { return "The passkey was not accepted. Try again, or enter a code from your app or a recovery code. After several failed attempts, or after a few minutes, start over with your password."; }
				if (context === "passkey-login") { return "The passkey was not accepted. A passkey that was removed from the account no longer signs in; use your email and password instead."; }
				return "Your session has ended. Sign in again.";
			case KINDS.FORBIDDEN:
				// 403: the session is fine, the password (or the code) given to confirm was not.
				if (context === "delete") { return "The account password or the code was not accepted. Nothing was deleted."; }
				if (context === "password") { return "The current password or the code was not accepted. The password was not changed."; }
				return "The password or the code was not accepted. Nothing was changed.";
			case KINDS.INVALID:
				if (context === "verify") { return "This verification link is invalid, expired or already used. Request a new one."; }
				if (context === "reset") { return "This reset link is invalid, expired or already used. Request a new one."; }
				if (context === "totp") { return "The code is not valid. Check the time on your device and try the next code."; }
				if (context === "password") { return "The new password was refused: it must be 12–128 characters. The password was not changed."; }
				if (context === "passkey") { return "The passkey could not be verified by the server, so it was not added. If your device or password manager saved it anyway, remove it there."; }
				if (context === "passkey-name") { return "The name was refused: 1–64 characters, without control characters. Nothing was changed."; }
				return "The request was rejected. Check the fields and try again.";
			case KINDS.NOT_FOUND:
				if (context === "session") { return "That session no longer exists."; }
				if (context === "vault") { return "The server no longer holds a vault for this account."; }
				if (context === "passkey" || context === "passkey-name") { return "That passkey is no longer on the account. The list is reloaded."; }
				if (context === "passkey-login" || context === "passkey-mfa") { return "Passkey sign-in is not available on this server."; }
				return "This is not available on the server right now.";
			case KINDS.CONFLICT:
				if (context === "totp") { return "Two-factor authentication is already in that state. Reload the status and try again."; }
				if (context === "passkey") { return "No passkey was added: passkeys need two-factor authentication to be on, and an account can hold at most 10 of them."; }
				return "Another device changed the vault on the server first. Nothing was changed.";
			case KINDS.GONE:
				if (context === "passkey") { return "The passkey setup expired or was already used, so nothing was added. Start again."; }
				return "This step expired or was already used. Start again.";
			default:
				return "Something unexpected happened. Nothing was changed. Try again.";
		}
	}

	// ---- copying secrets, and clearing the clipboard again (honestly) ----
	// A page may write to the clipboard after a click. Clearing it later needs the browser's leave
	// to READ it back first (so that something the user copied afterwards is never erased), and
	// browsers give that only while this page is focused and, in some, only after asking the user.
	// So: try once the time is up and the page has focus; if it is not focused then, try again
	// when it is; and say so when it could not be done. A clipboard history kept by the operating
	// system is out of reach for any web page.
	var clip = { value: null, due: 0, timer: null, report: null };

	function canCopy() { return !!(navigator.clipboard && typeof navigator.clipboard.writeText === "function"); }
	function canCheck() { return !!(navigator.clipboard && typeof navigator.clipboard.readText === "function"); }
	function forgetClip() {
		if (clip.timer) { clearTimeout(clip.timer); }
		clip.value = null; clip.report = null; clip.timer = null; clip.due = 0;
	}
	function pageFocused() { return typeof document.hasFocus !== "function" || document.hasFocus(); }

	// Clears the clipboard if it still holds what this page copied. now = true: do not wait for the
	// timer (the vault was locked).
	function clearClipboard(now) {
		if (clip.value === null) { return Promise.resolve(false); }
		if (!now && Date.now() < clip.due) { return Promise.resolve(false); }
		if (!pageFocused()) { return Promise.resolve(false); } // refused anyway; tried again on focus
		var value = clip.value;
		var report = clip.report;
		if (clip.timer) { clearTimeout(clip.timer); clip.timer = null; }
		if (!canCheck()) { forgetClip(); return Promise.resolve(false); }
		return navigator.clipboard.readText()
			.then(function (current) {
				if (clip.value !== value) { return false; } // copied again meanwhile
				forgetClip();
				if (current !== value) { return false; }  // the user copied something else: leave it
				return navigator.clipboard.writeText("").then(function () { return true; });
			})
			.catch(function () {
				if (clip.value !== value && clip.value !== null) { return false; }
				forgetClip();
				if (report) { report("warn", "The clipboard could not be cleared: the browser did not let this page check it. It may still hold the copied value; copy something else to replace it."); }
				return false;
			});
	}

	function retryWhenBack() { if (clip.value !== null && Date.now() >= clip.due) { clearClipboard(false); } }
	global.addEventListener("focus", retryWhenBack);
	document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { retryWhenBack(); } });

	// Copies value and arranges the clear. report(level, text) shows the outcome in the caller's
	// notice. Resolves to true when the value was copied.
	function copySecret(value, report) {
		if (!canCopy()) {
			report("err", "This browser does not allow copying from the page.");
			return Promise.resolve(false);
		}
		return navigator.clipboard.writeText(value).then(function () {
			forgetClip();
			var secs = Math.round(cfg.clipboardClearMs / 1000);
			if (!canCheck()) {
				report("warn", "Copied. This browser does not let the page check the clipboard, so it cannot clear it again; copy something else when you are done.");
				return true;
			}
			clip.value = value;
			clip.report = report;
			clip.due = Date.now() + cfg.clipboardClearMs;
			clip.timer = setTimeout(function () { clip.timer = null; clearClipboard(false); }, cfg.clipboardClearMs);
			report("ok", "Copied. After " + secs + " seconds this page clears the clipboard if it still holds the copied value and the browser lets the page check it; you are told if that was not possible. A clipboard history kept by your system is not cleared.");
			return true;
		}, function () {
			report("err", "Copying was not allowed by the browser.");
			return false;
		});
	}

	function setBusy(form, busy) {
		var controls = form.querySelectorAll("input, button, select, textarea");
		controls.forEach(function (c) { c.disabled = !!busy; });
		form.setAttribute("aria-busy", busy ? "true" : "false");
	}

	// A form that can no longer be used (a spent single-use link): disabled, and not "busy" forever.
	function lockForm(form) {
		form.querySelectorAll("input, button, select, textarea").forEach(function (c) { c.disabled = true; });
		form.removeAttribute("aria-busy");
	}

	// Marks a field as wrong (or right) and points it at the notice that says why.
	function markField(field, invalid, noticeNode) {
		if (!field) { return; }
		field.setAttribute("aria-invalid", invalid ? "true" : "false");
		if (invalid && noticeNode && noticeNode.id) { field.setAttribute("aria-describedby", noticeNode.id); }
		else { field.removeAttribute("aria-describedby"); }
	}

	// Validation mirrors the server policy; the server stays authoritative.
	function validEmail(value) {
		return typeof value === "string" && value.length > 0 && value.length <= cfg.emailMaxLength &&
			value === value.trim() && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
	}
	function validPassword(value) {
		return typeof value === "string" && value.length >= cfg.passwordMinLength && value.length <= cfg.passwordMaxLength;
	}

	function formatDate(d) {
		try { return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }); }
		catch (e) { return d.toISOString(); }
	}

	global.bitosxUi = Object.freeze({
		$: $, el: el, clear: clear, notice: notice, describeError: describeError,
		setBusy: setBusy, lockForm: lockForm, markField: markField, validEmail: validEmail, validPassword: validPassword,
		formatDate: formatDate, copySecret: copySecret, clearClipboard: clearClipboard
	});
})(window);
