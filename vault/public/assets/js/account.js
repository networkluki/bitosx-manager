// Sign-in page + account/session management (vault.bitosx.se, phase 1).
(function () {
	"use strict";

	var api = window.bitosxApi;
	var ui = window.bitosxUi;
	var cfg = window.BITOSX_CONFIG;
	var $ = ui.$;

	var loginPanel = $("login-panel");
	var accountPanel = $("account-panel");
	var loginForm = $("login-form");
	var loginNotice = $("login-notice");
	var accountNotice = $("account-notice");
	var sessionsBody = $("sessions-body");
	if (!loginForm || !accountPanel) { return; }

	var idleTimer = null;

	function showLogin(message, level) {
		accountPanel.hidden = true;
		loginPanel.hidden = false;
		ui.notice(loginNotice, level || "warn", message || "");
		$("login-password").value = "";
		$("login-email").focus();
	}

	function showAccount() {
		loginPanel.hidden = true;
		accountPanel.hidden = false;
		ui.notice(accountNotice, "ok", "");
	}

	// ---- idle sign-out: tokens are dropped locally and the session is revoked best-effort ----
	function armIdle() {
		if (idleTimer) { clearTimeout(idleTimer); }
		idleTimer = setTimeout(function () {
			if (!api.isSignedIn()) { return; }
			api.logout().catch(function () { /* already cleared locally */ });
			showLogin("Signed out after " + Math.round(cfg.idleTimeoutMs / 60000) + " minutes without activity.", "warn");
		}, cfg.idleTimeoutMs);
	}
	["pointerdown", "keydown", "scroll", "touchstart"].forEach(function (evt) {
		document.addEventListener(evt, function () { if (api.isSignedIn()) { armIdle(); } }, { passive: true });
	});
	// Tokens live in memory only, but be explicit when the page goes away.
	window.addEventListener("pagehide", function () { api.clearSession(); });

	// ---- rendering (textContent only) ----
	function renderAccount(me) {
		$("acct-email").textContent = me.email;
		$("acct-verified").textContent = me.emailVerified ? "Yes" : "No";
		$("acct-created").textContent = ui.formatDate(me.createdAt);
		$("acct-id").textContent = me.accountId;
	}

	function renderSessions(list) {
		ui.clear(sessionsBody);
		if (list.length === 0) {
			var tr0 = ui.el("tr");
			var td0 = ui.el("td", { colspan: "4" }, "No active sessions.");
			tr0.appendChild(td0);
			sessionsBody.appendChild(tr0);
			return;
		}
		list.forEach(function (s) {
			var tr = ui.el("tr");
			var started = ui.el("td", null, ui.formatDate(s.createdAt));
			if (s.current) {
				started.appendChild(document.createTextNode(" "));
				started.appendChild(ui.el("span", { class: "current" }, "this session"));
			}
			tr.appendChild(started);
			tr.appendChild(ui.el("td", null, ui.formatDate(s.lastSeenAt)));
			tr.appendChild(ui.el("td", null, ui.formatDate(s.expiresAt)));
			var actions = ui.el("td", { class: "actions" });
			var btn = ui.el("button", { type: "button", class: "btn danger small", "data-session-id": s.id }, s.current ? "Sign out" : "Revoke");
			actions.appendChild(btn);
			tr.appendChild(actions);
			sessionsBody.appendChild(tr);
		});
	}

	function loadAccount() {
		return Promise.all([api.me(), api.sessions()]).then(function (r) {
			renderAccount(r[0]);
			renderSessions(r[1]);
			showAccount();
			armIdle();
		});
	}

	function handleAuthFailure(err, fallbackContext) {
		if (err && err.kind === api.KINDS.UNAUTHENTICATED) {
			showLogin(ui.describeError(err, "session"), "warn");
			return true;
		}
		ui.notice(accountNotice, "err", ui.describeError(err, fallbackContext));
		return false;
	}

	// ---- sign in ----
	loginForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var emailEl = $("login-email");
		var passEl = $("login-password");
		var email = emailEl.value;
		var password = passEl.value;
		emailEl.setAttribute("aria-invalid", ui.validEmail(email) ? "false" : "true");
		passEl.setAttribute("aria-invalid", ui.validPassword(password) ? "false" : "true");
		if (!ui.validEmail(email) || !ui.validPassword(password)) {
			ui.notice(loginNotice, "err", "Enter your email and your account password (12–128 characters).");
			return;
		}
		ui.notice(loginNotice, "ok", "");
		ui.setBusy(loginForm, true);
		api.login(email, password)
			.then(function () {
				passEl.value = "";
				return loadAccount();
			})
			.catch(function (err) {
				api.clearSession();
				ui.notice(loginNotice, "err", ui.describeError(err, "login"));
			})
			.finally(function () {
				// Never leave a typed password sitting in the field, whatever the outcome.
				passEl.value = "";
				ui.setBusy(loginForm, false);
				password = null;
			});
	});

	// ---- session actions ----
	sessionsBody.addEventListener("click", function (ev) {
		var btn = ev.target.closest("button[data-session-id]");
		if (!btn) { return; }
		var id = btn.getAttribute("data-session-id");
		btn.disabled = true;
		api.revokeSession(id)
			.then(function () {
				if (!api.isSignedIn()) { return; }
				return api.sessions().then(renderSessions).then(function () {
					ui.notice(accountNotice, "ok", "Session revoked.");
				});
			})
			.catch(function (err) {
				// Revoking the current session ends ours too: the next call returns 401.
				if (!handleAuthFailure(err, "account")) { btn.disabled = false; }
			});
	});

	$("refresh-sessions").addEventListener("click", function () {
		api.sessions().then(function (list) {
			renderSessions(list);
			ui.notice(accountNotice, "ok", "");
		}).catch(function (err) { handleAuthFailure(err, "account"); });
	});

	$("logout").addEventListener("click", function () {
		api.logout()
			.then(function () { showLogin("You are signed out.", "ok"); })
			.catch(function () { showLogin("You are signed out.", "ok"); });
	});

	$("logout-all").addEventListener("click", function () {
		api.logoutAll()
			.then(function () { showLogin("Signed out everywhere. Every device must sign in again.", "ok"); })
			.catch(function (err) {
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { showLogin("You are signed out.", "ok"); }
				else { showLogin(ui.describeError(err, "account"), "err"); }
			});
	});

	// Fresh page load: nothing is persisted, so we always start signed out.
	showLogin("", "ok");
})();
