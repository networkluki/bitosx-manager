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
			case KINDS.RATE_LIMITED:
				return "Too many attempts. Try again " + (err.retryAfterSeconds ? "in about " + err.retryAfterSeconds + " seconds." : "in a few minutes.");
			case KINDS.UNAVAILABLE:
				if (context === "login" || context === "code" || context === "totp") { return "Two-factor authentication is temporarily unavailable on the server. Try again shortly."; }
				return "The service is temporarily unavailable. Try again shortly.";
			case KINDS.TOO_LARGE:
				return "The request was too large.";
			case KINDS.UNAUTHENTICATED:
				if (context === "login") { return "Invalid email or password."; }
				if (context === "code") { return "The code was not accepted. Try the next code from your app, or start over with your password."; }
				return "Your session has ended. Sign in again.";
			case KINDS.FORBIDDEN:
				if (context === "delete") { return "The account password is wrong. Nothing was deleted."; }
				if (context === "totp") { return "The password or the code was not accepted. Nothing was changed."; }
				return "The request was refused.";
			case KINDS.INVALID:
				if (context === "verify") { return "This verification link is invalid, expired or already used. Request a new one."; }
				if (context === "reset") { return "This reset link is invalid, expired or already used. Request a new one."; }
				if (context === "totp") { return "The code is not valid. Check the time on your device and try the next code."; }
				return "The request was rejected. Check the fields and try again.";
			case KINDS.NOT_FOUND:
				return "That item no longer exists.";
			case KINDS.CONFLICT:
				if (context === "totp") { return "Two-factor authentication is already in that state. Reload the status and try again."; }
				return "Another device changed the vault on the server first. Nothing was changed.";
			default:
				return "Something unexpected happened. Nothing was changed. Try again.";
		}
	}

	function setBusy(form, busy) {
		var controls = form.querySelectorAll("input, button");
		controls.forEach(function (c) { c.disabled = !!busy; });
		form.setAttribute("aria-busy", busy ? "true" : "false");
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
		setBusy: setBusy, validEmail: validEmail, validPassword: validPassword, formatDate: formatDate
	});
})(window);
