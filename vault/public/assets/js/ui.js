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
				return "The service is temporarily unavailable. Try again shortly.";
			case KINDS.TOO_LARGE:
				return "The request was too large.";
			case KINDS.UNAUTHENTICATED:
				return context === "login" ? "Invalid email or password." : "Your session has ended. Sign in again.";
			case KINDS.INVALID:
				return context === "verify" ? "This verification link is invalid, expired or already used. Request a new one." : "The request was rejected. Check the fields and try again.";
			case KINDS.NOT_FOUND:
				return "That item no longer exists.";
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
