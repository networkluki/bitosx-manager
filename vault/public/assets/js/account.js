// Sign-in page (with the second-factor step) + account/session management, two-factor setup and account deletion (vault.bitosx.se).
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

	var codeForm = $("code-form");
	var codeEl = $("login-code");
	var mfaToken = null; // the one-step challenge token from the password step; memory only

	function showCodeStep() {
		loginForm.hidden = true;
		codeForm.hidden = false;
		codeEl.value = "";
		ui.setBusy(codeForm, false);
		ui.notice(loginNotice, "ok", "Enter the 6-digit code from your authenticator app, or one of your recovery codes.");
		codeEl.focus();
	}

	function leaveCodeStep() {
		mfaToken = null;
		codeEl.value = "";
		codeForm.hidden = true;
		loginForm.hidden = false;
	}

	function showLogin(message, level) {
		// The vault panel locks and hides itself on this; see vault.js.
		document.dispatchEvent(new CustomEvent("bitosx:signed-out"));
		leaveCodeStep();
		resetTotpSection();
		accountPanel.hidden = true;
		loginPanel.hidden = false;
		ui.notice(loginNotice, level || "warn", message || "");
		$("login-password").value = "";
		$("delete-password").value = "";
		$("delete-ack").checked = false;
		$("delete-submit").disabled = true;
		ui.notice($("delete-notice"), "ok", "");
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
			document.dispatchEvent(new CustomEvent("bitosx:signed-in"));
			return loadTotpStatus(); // separate call: its failure must not undo the sign-in
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
			.then(function (result) {
				passEl.value = "";
				if (!result.signedIn) {
					// Password accepted, second factor required: no session yet, only the challenge token.
					mfaToken = result.mfaToken;
					showCodeStep();
					return undefined;
				}
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

	// 6 digits, or a 10-character recovery code with an optional separator. The server decides; this saves a round trip.
	function looksLikeCode(code) {
		return /^[0-9]{6}$/.test(code) || /^[A-Za-z0-9]{5}[- ]?[A-Za-z0-9]{5}$/.test(code);
	}

	codeForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var code = codeEl.value.trim();
		codeEl.setAttribute("aria-invalid", looksLikeCode(code) ? "false" : "true");
		if (!looksLikeCode(code)) {
			ui.notice(loginNotice, "err", "Enter the 6-digit code from your authenticator app, or a recovery code (xxxxx-xxxxx).");
			return;
		}
		if (!mfaToken) { leaveCodeStep(); ui.notice(loginNotice, "warn", "Start over with your password."); return; }
		ui.notice(loginNotice, "ok", "");
		ui.setBusy(codeForm, true);
		api.loginTotp(mfaToken, code)
			.then(function () {
				leaveCodeStep();
				return loadAccount();
			})
			.catch(function (err) {
				api.clearSession();
				// A refused code keeps the challenge for another try (the server allows a few); anything else too.
				ui.notice(loginNotice, "err", ui.describeError(err, "code"));
				ui.setBusy(codeForm, false);
				codeEl.focus();
			})
			.finally(function () { codeEl.value = ""; code = null; });
	});

	$("code-cancel").addEventListener("click", function () {
		leaveCodeStep();
		ui.notice(loginNotice, "ok", "");
		$("login-password").focus();
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

	// ---- two-factor authentication (TOTP) ----
	var totpNotice = $("totp-notice");
	var totpStatusEl = $("totp-status");
	var enrollForm = $("totp-enroll-form");
	var setupEl = $("totp-setup");
	var confirmForm = $("totp-confirm-form");
	var codesEl = $("totp-codes");
	var codesList = $("totp-codes-list");
	var manageForm = $("totp-manage-form");
	var totpClipboardTimer = null;

	function resetTotpSection() {
		enrollForm.hidden = true;
		setupEl.hidden = true;
		codesEl.hidden = true;
		manageForm.hidden = true;
		$("totp-enroll-password").value = "";
		$("totp-manage-password").value = "";
		$("totp-manage-code").value = "";
		$("totp-confirm-code").value = "";
		$("totp-setup-secret").textContent = "";
		$("totp-setup-uri").textContent = "";
		$("totp-setup-label").textContent = "";
		$("totp-setup-params").textContent = "";
		ui.clear(codesList);
		totpStatusEl.textContent = "";
		ui.notice(totpNotice, "ok", "");
	}

	function renderTotpStatus(status) {
		setupEl.hidden = true;
		codesEl.hidden = true;
		if (status.enabled) {
			totpStatusEl.textContent = "Enabled" + (status.confirmedAt ? " since " + ui.formatDate(status.confirmedAt) : "") +
				". Recovery codes left: " + status.recoveryCodesRemaining + ".";
			enrollForm.hidden = true;
			manageForm.hidden = false;
		} else {
			totpStatusEl.textContent = status.pendingEnrollment
				? "Not enabled. A setup was started but never confirmed; starting again replaces it."
				: "Not enabled.";
			enrollForm.hidden = false;
			manageForm.hidden = true;
		}
	}

	function loadTotpStatus() {
		return api.totpStatus().then(renderTotpStatus).catch(function (err) {
			if (err && err.kind === api.KINDS.UNAVAILABLE) {
				totpStatusEl.textContent = "Two-factor authentication is not available on this server right now.";
				enrollForm.hidden = true;
				manageForm.hidden = true;
				return;
			}
			handleAuthFailure(err, "totp");
		});
	}

	function showRecoveryCodes(codes) {
		ui.clear(codesList);
		codesList.textContent = codes.join("\n");
		codesEl.hidden = false;
	}

	enrollForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var passEl = $("totp-enroll-password");
		var password = passEl.value;
		if (!ui.validPassword(password)) {
			ui.notice(totpNotice, "err", "Enter your account password (12–128 characters) to confirm.");
			return;
		}
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(enrollForm, true);
		api.totpEnroll(password)
			.then(function (enrollment) {
				$("totp-setup-label").textContent = enrollment.issuer + ": " + enrollment.label;
				$("totp-setup-secret").textContent = enrollment.secret;
				$("totp-setup-uri").textContent = enrollment.otpauthUri;
				$("totp-setup-params").textContent = "Time-based, SHA-1, " + enrollment.digits + " digits, every " + enrollment.periodSeconds + " seconds";
				enrollForm.hidden = true;
				setupEl.hidden = false;
				$("totp-confirm-code").value = "";
				$("totp-confirm-code").focus();
			})
			.catch(function (err) {
				if (!handleAuthFailure(err, "totp")) { ui.notice(totpNotice, "err", ui.describeError(err, "totp")); }
			})
			.finally(function () {
				passEl.value = "";
				ui.setBusy(enrollForm, false);
				password = null;
			});
	});

	$("totp-setup-cancel").addEventListener("click", function () {
		// The pending secret on the server is harmless (not a factor) and is replaced by the next setup.
		$("totp-setup-secret").textContent = "";
		$("totp-setup-uri").textContent = "";
		setupEl.hidden = true;
		loadTotpStatus();
	});

	confirmForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var codeInput = $("totp-confirm-code");
		var code = codeInput.value.trim();
		if (!/^[0-9]{6,8}$/.test(code)) {
			ui.notice(totpNotice, "err", "Enter the code your authenticator app shows (6 digits).");
			return;
		}
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(confirmForm, true);
		api.totpConfirm(code)
			.then(function (codes) {
				$("totp-setup-secret").textContent = "";
				$("totp-setup-uri").textContent = "";
				setupEl.hidden = true;
				ui.notice(totpNotice, "ok", "Two-factor authentication is enabled. From now on, signing in needs a code as well.");
				showRecoveryCodes(codes);
				return api.totpStatus().then(function (status) {
					renderTotpStatus(status);
					codesEl.hidden = false; // keep the codes on screen until acknowledged
				});
			})
			.catch(function (err) {
				if (!handleAuthFailure(err, "totp")) { ui.notice(totpNotice, "err", ui.describeError(err, "totp")); }
			})
			.finally(function () {
				codeInput.value = "";
				ui.setBusy(confirmForm, false);
			});
	});

	$("totp-codes-done").addEventListener("click", function () {
		ui.clear(codesList);
		codesEl.hidden = true;
	});

	$("totp-codes-copy").addEventListener("click", function () {
		var text = codesList.textContent;
		if (!text || !navigator.clipboard) { return; }
		navigator.clipboard.writeText(text).then(function () {
			ui.notice(totpNotice, "ok", "Recovery codes copied. The clipboard is cleared again after " + Math.round(cfg.clipboardClearMs / 1000) + " seconds.");
			if (totpClipboardTimer) { clearTimeout(totpClipboardTimer); }
			totpClipboardTimer = setTimeout(function () {
				navigator.clipboard.readText().then(function (current) {
					if (current === text) { return navigator.clipboard.writeText(""); }
				}).catch(function () { /* reading the clipboard may be refused; nothing to clear then */ });
			}, cfg.clipboardClearMs);
		}).catch(function () { ui.notice(totpNotice, "err", "The browser did not allow copying. Select the codes and copy them by hand."); });
	});

	function manage(action, successMessage) {
		var passEl = $("totp-manage-password");
		var codeInput = $("totp-manage-code");
		var password = passEl.value;
		var code = codeInput.value.trim();
		if (!ui.validPassword(password) || !looksLikeCode(code)) {
			ui.notice(totpNotice, "err", "Enter your account password and a current code (6 digits from the app, or a recovery code).");
			return;
		}
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(manageForm, true);
		action(password, code)
			.then(function (result) {
				ui.notice(totpNotice, "ok", successMessage);
				if (Array.isArray(result)) { showRecoveryCodes(result); }
				return api.totpStatus().then(function (status) {
					renderTotpStatus(status);
					if (Array.isArray(result)) { codesEl.hidden = false; }
				});
			})
			.catch(function (err) {
				if (!handleAuthFailure(err, "totp")) { ui.notice(totpNotice, "err", ui.describeError(err, "totp")); }
			})
			.finally(function () {
				passEl.value = "";
				codeInput.value = "";
				ui.setBusy(manageForm, false);
				password = null;
			});
	}

	manageForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		manage(api.totpRecoveryCodes, "New recovery codes issued. The old ones no longer work.");
	});

	$("totp-disable").addEventListener("click", function () {
		manage(api.totpDisable, "Two-factor authentication is turned off. Signing in needs only the account password again.");
	});

	// ---- delete account (password-confirmed; the server re-checks it) ----
	var deleteForm = $("delete-form");
	var deleteNotice = $("delete-notice");
	var deletePass = $("delete-password");
	var deleteAck = $("delete-ack");
	var deleteSubmit = $("delete-submit");
	deleteAck.addEventListener("change", function () { deleteSubmit.disabled = !deleteAck.checked; });
	deleteForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var password = deletePass.value;
		if (!deleteAck.checked) { return; }
		deletePass.setAttribute("aria-invalid", ui.validPassword(password) ? "false" : "true");
		if (!ui.validPassword(password)) {
			ui.notice(deleteNotice, "err", "Enter your account password (12–128 characters) to confirm.");
			return;
		}
		ui.notice(deleteNotice, "ok", "");
		ui.setBusy(deleteForm, true);
		api.deleteAccount(password)
			.then(function () {
				deletePass.value = "";
				deleteAck.checked = false;
				showLogin("Your account and the vault stored on the server are deleted. Any vault file on your own devices is untouched.", "ok");
			})
			.catch(function (err) {
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { showLogin(ui.describeError(err, "session"), "warn"); return; }
				ui.notice(deleteNotice, "err", ui.describeError(err, "delete"));
			})
			.finally(function () {
				deletePass.value = "";
				ui.setBusy(deleteForm, false);
				deleteSubmit.disabled = !deleteAck.checked;
				password = null;
			});
	});

	// Fresh page load: nothing is persisted, so we always start signed out.
	showLogin("", "ok");
})();
