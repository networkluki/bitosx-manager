// Sign-in page (with the second-factor step) + account/session management, account password change,
// two-factor setup and account deletion (vault.bitosx.se).
//
// Every asynchronous step remembers the session generation it started in (api.generation()) and
// drops its result if the session ended or another one started meanwhile, so a late answer never
// writes one person's data into the next person's session on a shared screen.
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

	var codeForm = $("code-form");
	var codeEl = $("login-code");
	var emailEl = $("login-email");
	var passEl = $("login-password");

	// The one-step challenge from the password step; memory only. { token, deadline, failures, timer }
	var challenge = null;
	// While these run, the flow itself reports a session that ended; the global handler stays quiet.
	var signingIn = false;
	var signingOut = false;
	// What the server said about two-factor: "on", "off", or "unknown" (not loaded, or unavailable).
	var totpState = "unknown";

	function generation() { return api.generation(); }
	function signedInOnScreen() { return !accountPanel.hidden; }

	// ---- unsaved vault changes (vault.js) ----
	function vaultUnsaved() {
		return !!(window.bitosxVault && typeof window.bitosxVault.hasUnsavedChanges === "function" && window.bitosxVault.hasUnsavedChanges());
	}
	function confirmDiscard(action) {
		if (!vaultUnsaved()) { return true; }
		return window.confirm("The vault has unsaved changes in this browser. " + action + " discards them. Continue?");
	}
	function discardedNote(hadUnsaved) { return hadUnsaved ? " Unsaved vault changes in this browser were discarded." : ""; }

	// ---- the site navigation: Sign in / Register lead away (and so sign out) while signed in ----
	function setNavSignedIn(signedIn) {
		["nav-signin", "nav-register"].forEach(function (id) { var a = $(id); if (a) { a.hidden = signedIn; } });
	}

	// ---- the second-factor step ----
	function showCodeStep(result) {
		var ttl = result.mfaTokenExpiresAt.getTime() - Date.now();
		// The server's clock decides; a client clock that disagrees must not end the step at once or never.
		ttl = Math.min(Math.max(ttl, 60 * 1000), 10 * 60 * 1000);
		challenge = { token: result.mfaToken, deadline: Date.now() + ttl, failures: 0, timer: setTimeout(expireChallenge, ttl) };
		loginForm.hidden = true;
		codeForm.hidden = false;
		codeEl.value = "";
		ui.markField(codeEl, false);
		ui.setBusy(codeForm, false);
		ui.notice(loginNotice, "ok", "Enter the code from your authenticator app, or one of your recovery codes.");
		codeEl.focus();
	}

	function leaveCodeStep() {
		if (challenge && challenge.timer) { clearTimeout(challenge.timer); }
		challenge = null;
		codeEl.value = "";
		codeForm.hidden = true;
		loginForm.hidden = false;
		ui.setBusy(codeForm, false);
	}

	function backToPassword(message) {
		leaveCodeStep();
		ui.notice(loginNotice, "warn", message);
		passEl.focus();
	}

	function expireChallenge() {
		if (!challenge) { return; }
		backToPassword("The sign-in step timed out. Enter your password again.");
	}

	// ---- signed in / signed out ----
	function showLogin(message, level) {
		// The vault panel locks and hides itself on this; see vault.js.
		document.dispatchEvent(new CustomEvent("bitosx:signed-out"));
		leaveCodeStep();
		wipeAccountView();
		loginPanel.hidden = false;
		ui.notice(loginNotice, level || "warn", message || "");
		passEl.value = "";
		emailEl.focus();
	}

	// Everything the account panel showed goes, not just the tokens: account details, the session
	// list, a pending two-factor secret, recovery codes, and every typed field.
	function wipeAccountView() {
		resetTotpSection();
		accountPanel.hidden = true;
		setNavSignedIn(false);
		["acct-email", "acct-verified", "acct-created", "acct-id"].forEach(function (id) { $(id).textContent = ""; });
		ui.clear(sessionsBody);
		ui.notice(accountNotice, "ok", "");
		["delete-password", "delete-code", "pw-current", "pw-new", "pw-new2", "pw-code"].forEach(function (id) { $(id).value = ""; });
		$("delete-ack").checked = false;
		$("delete-submit").disabled = true;
		ui.notice($("delete-notice"), "ok", "");
		ui.notice($("pw-notice"), "ok", "");
		totpState = "unknown";
		renderCodeFields();
		setAccountButtonsBusy(false);
	}

	function showAccount() {
		loginPanel.hidden = true;
		accountPanel.hidden = false;
		setNavSignedIn(true);
		ui.notice(accountNotice, "ok", "");
		$("account-title").focus();
	}

	function sessionEndedMessage() { return "Your session has ended. Sign in again." + discardedNote(vaultUnsaved()); }

	// A 401 that one refresh could not cure, from any call on this page (vault.js included).
	document.addEventListener("bitosx:session-ended", function () {
		if (signingIn || signingOut || !signedInOnScreen()) { return; }
		showLogin(sessionEndedMessage(), "warn");
	});

	// Reports a failure in one place: a dead session goes back to the sign-in, anything else is
	// shown in the notice of the section that asked.
	function reportError(err, context, target) {
		if (err && err.kind === api.KINDS.UNAUTHENTICATED) {
			if (signedInOnScreen()) { showLogin(sessionEndedMessage(), "warn"); }
			return;
		}
		ui.notice(target || accountNotice, "err", ui.describeError(err, context));
	}

	// ---- idle sign-out: a timer, and the wall clock (timers stall while the computer sleeps) ----
	var idleTimer = null;
	var lastActivity = Date.now();
	function armIdle() {
		if (idleTimer) { clearTimeout(idleTimer); }
		idleTimer = setTimeout(checkIdle, Math.max(cfg.idleTimeoutMs - (Date.now() - lastActivity), 0));
	}
	function checkIdle() {
		if (!signedInOnScreen()) { return; }
		if (Date.now() - lastActivity >= cfg.idleTimeoutMs) { idleSignOut(); }
		else { armIdle(); }
	}
	function idleSignOut() {
		var hadUnsaved = vaultUnsaved();
		signingOut = true;
		if (api.isSignedIn()) { api.logout().catch(function () { /* cleared locally either way */ }).finally(function () { signingOut = false; }); }
		else { signingOut = false; }
		showLogin("Signed out after " + Math.round(cfg.idleTimeoutMs / 60000) + " minutes without activity." + discardedNote(hadUnsaved), "warn");
	}
	// User input only: "scroll" also fires when the layout changes (an editor closing), which is not activity.
	["pointerdown", "keydown", "wheel", "touchstart"].forEach(function (evt) {
		document.addEventListener(evt, function () {
			if (!signedInOnScreen()) { return; }
			// Time that already ran out is not given back by touching the page.
			if (Date.now() - lastActivity >= cfg.idleTimeoutMs) { idleSignOut(); return; }
			lastActivity = Date.now();
			armIdle();
		}, { passive: true, capture: true });
	});
	setInterval(checkIdle, cfg.idleCheckIntervalMs);
	document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { checkIdle(); } });
	window.addEventListener("focus", checkIdle);

	// Leaving the page signs out: the tokens are dropped and, best effort, the session is revoked on
	// the server. The screen is wiped too, because a page kept in the back/forward cache comes back
	// exactly as it was left.
	window.addEventListener("pagehide", function () {
		api.revokeOnUnload();
		leaveCodeStep();
		wipeAccountView();
		loginPanel.hidden = false;
	});
	window.addEventListener("pageshow", function (ev) {
		if (ev.persisted) {
			api.clearSession();
			showLogin("You left this page, so you were signed out. Sign in again.", "warn");
		}
	});

	// ---- rendering (textContent only) ----
	function renderAccount(me) {
		$("acct-email").textContent = me.email;
		$("acct-verified").textContent = me.emailVerified ? "Yes" : "No";
		$("acct-created").textContent = ui.formatDate(me.createdAt);
		$("acct-id").textContent = me.accountId;
	}

	function renderSessions(list) {
		var hadFocus = sessionsBody.contains(document.activeElement);
		ui.clear(sessionsBody);
		if (list.length === 0) {
			var tr0 = ui.el("tr");
			tr0.appendChild(ui.el("td", { colspan: "4" }, "No active sessions."));
			sessionsBody.appendChild(tr0);
		}
		list.forEach(function (s) {
			var tr = ui.el("tr");
			var startedText = ui.formatDate(s.createdAt);
			var started = ui.el("td", null, startedText);
			if (s.current) {
				started.appendChild(document.createTextNode(" "));
				started.appendChild(ui.el("span", { class: "current" }, "this session"));
			}
			tr.appendChild(started);
			tr.appendChild(ui.el("td", null, ui.formatDate(s.lastSeenAt)));
			tr.appendChild(ui.el("td", null, ui.formatDate(s.expiresAt)));
			var actions = ui.el("td", { class: "actions" });
			var attrs = { type: "button", class: "btn danger small", "data-session-id": s.id,
				"aria-label": s.current ? "Sign out this session (started " + startedText + ")" : "Revoke the session started " + startedText };
			if (s.current) { attrs["data-current"] = "1"; }
			actions.appendChild(ui.el("button", attrs, s.current ? "Sign out" : "Revoke"));
			tr.appendChild(actions);
			sessionsBody.appendChild(tr);
		});
		if (hadFocus) { $("sessions-title").focus(); }
	}

	function loadAccount() {
		var g = generation();
		resetTotpSection();
		return Promise.all([api.me(), api.sessions()]).then(function (r) {
			if (g !== generation()) { return; }
			renderAccount(r[0]);
			renderSessions(r[1]);
			showAccount();
			lastActivity = Date.now();
			armIdle();
			document.dispatchEvent(new CustomEvent("bitosx:signed-in"));
			loadTotpStatus(); // separate call: its failure must not undo the sign-in
		});
	}

	// The password (and code) were accepted, but loading the account failed: that is not a
	// credential failure. The half-made session is revoked best effort and the user starts again.
	function afterSignIn() {
		return loadAccount().catch(function (err) {
			var text = err && err.kind === api.KINDS.UNAUTHENTICATED
				? "You were signed in, but the session ended straight away. Sign in again."
				: "You were signed in, but the account could not be loaded: " + ui.describeError(err, "account") + " Sign in again.";
			if (api.isSignedIn()) { api.logout().catch(function () { /* local state is gone either way */ }); }
			else { api.clearSession(); }
			showLogin(text, "err");
		});
	}

	// ---- sign in ----
	loginForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var email = emailEl.value;
		var password = passEl.value;
		var badEmail = !ui.validEmail(email);
		var badPassword = !ui.validPassword(password);
		ui.markField(emailEl, badEmail, loginNotice);
		ui.markField(passEl, badPassword, loginNotice);
		if (badEmail || badPassword) {
			ui.notice(loginNotice, "err", "Enter your email and your account password (12–128 characters).");
			(badEmail ? emailEl : passEl).focus();
			return;
		}
		ui.notice(loginNotice, "ok", "");
		ui.setBusy(loginForm, true);
		signingIn = true;
		api.login(email, password)
			.then(function (result) {
				passEl.value = "";
				if (!result.signedIn) {
					// Password accepted, second factor required: no session yet, only the challenge token.
					showCodeStep(result);
					return undefined;
				}
				return afterSignIn();
			}, function (err) {
				ui.notice(loginNotice, "err", ui.describeError(err, "login"));
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) { ui.markField(passEl, true, loginNotice); }
				passEl.value = "";
				ui.setBusy(loginForm, false);
				passEl.focus();
			})
			.finally(function () {
				// Never leave a typed password sitting in the field, whatever the outcome.
				passEl.value = "";
				ui.setBusy(loginForm, false);
				password = null;
				signingIn = false;
			});
	});

	// The server's digit count (6, 7 or 8), or a 10-character recovery code with an optional separator.
	// The server decides; this saves a round trip.
	function looksLikeCode(code) {
		return /^[0-9]{6,8}$/.test(code) || /^[A-Za-z0-9]{5}[- ]?[A-Za-z0-9]{5}$/.test(code);
	}

	codeForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		if (!challenge) { backToPassword("Start over with your password."); return; }
		if (Date.now() >= challenge.deadline) { expireChallenge(); return; }
		var code = codeEl.value.trim();
		ui.markField(codeEl, !looksLikeCode(code), loginNotice);
		if (!looksLikeCode(code)) {
			ui.notice(loginNotice, "err", "Enter the code from your authenticator app (6 to 8 digits), or a recovery code (xxxxx-xxxxx).");
			codeEl.focus();
			return;
		}
		var current = challenge;
		ui.notice(loginNotice, "ok", "");
		ui.setBusy(codeForm, true);
		signingIn = true;
		api.loginTotp(current.token, code)
			.then(function () {
				leaveCodeStep();
				return afterSignIn();
			}, function (err) {
				if (challenge !== current) { return; } // started over meanwhile
				ui.setBusy(codeForm, false);
				if (err && err.kind === api.KINDS.UNAUTHENTICATED) {
					current.failures++;
					if (current.failures >= cfg.mfaMaxAttempts || Date.now() >= current.deadline) {
						backToPassword("Too many wrong codes, or the sign-in step expired. Enter your password again.");
						return;
					}
				}
				// A refused code keeps the challenge for another try (the server allows a few).
				ui.notice(loginNotice, "err", ui.describeError(err, "code"));
				ui.markField(codeEl, true, loginNotice);
				codeEl.focus();
			})
			.finally(function () { codeEl.value = ""; code = null; signingIn = false; });
	});

	$("code-cancel").addEventListener("click", function () {
		leaveCodeStep();
		ui.notice(loginNotice, "ok", "");
		passEl.focus();
	});

	// ---- session actions ----
	var logoutBtn = $("logout");
	var logoutAllBtn = $("logout-all");
	function setAccountButtonsBusy(busy) {
		logoutBtn.disabled = busy;
		logoutAllBtn.disabled = busy;
		sessionsBody.querySelectorAll("button").forEach(function (b) { b.disabled = busy; });
	}

	function refreshSessionList(message) {
		var g = generation();
		return api.sessions().then(function (list) {
			if (g !== generation()) { return; }
			renderSessions(list);
			ui.notice(accountNotice, "ok", message || "");
		}).catch(function (err) { if (g === generation()) { reportError(err, "account"); } });
	}

	sessionsBody.addEventListener("click", function (ev) {
		var btn = ev.target.closest("button[data-session-id]");
		if (!btn) { return; }
		if (btn.getAttribute("data-current") === "1") { signOut(); return; } // this session: that is signing out
		var id = btn.getAttribute("data-session-id");
		var g = generation();
		btn.disabled = true;
		api.revokeSession(id)
			.then(function () { if (g === generation()) { return refreshSessionList("Session revoked."); } })
			.catch(function (err) {
				if (g !== generation()) { return; }
				if (err && err.kind === api.KINDS.NOT_FOUND) { return refreshSessionList("That session had already ended."); }
				btn.disabled = false;
				reportError(err, "account");
			});
	});

	$("refresh-sessions").addEventListener("click", function () { refreshSessionList(""); });

	function signOut() {
		if (!confirmDiscard("Signing out")) { return; }
		var hadUnsaved = vaultUnsaved();
		setAccountButtonsBusy(true);
		signingOut = true;
		api.logout()
			.then(function () { showLogin("You are signed out." + discardedNote(hadUnsaved), "ok"); },
				function (err) {
					if (err && err.kind === api.KINDS.UNAUTHENTICATED) { showLogin("You are signed out." + discardedNote(hadUnsaved), "ok"); return; }
					showLogin("You are signed out in this browser, but the server could not be told (" + ui.describeError(err, "account") +
						") This session stays listed until it expires; you can revoke it from another device." + discardedNote(hadUnsaved), "warn");
				})
			.finally(function () { signingOut = false; setAccountButtonsBusy(false); });
	}
	logoutBtn.addEventListener("click", signOut);

	logoutAllBtn.addEventListener("click", function () {
		if (!confirmDiscard("Signing out everywhere")) { return; }
		var hadUnsaved = vaultUnsaved();
		var g = generation();
		setAccountButtonsBusy(true);
		signingOut = true;
		ui.notice(accountNotice, "ok", "");
		api.logoutAll()
			.then(function () { showLogin("Signed out everywhere. Every device must sign in again." + discardedNote(hadUnsaved), "ok"); },
				function (err) {
					if (err && err.kind === api.KINDS.UNAUTHENTICATED) {
						showLogin("Your session had already ended, so the other devices were not signed out from here. Sign in and try again." + discardedNote(hadUnsaved), "warn");
						return;
					}
					if (g !== generation()) { return; }
					// The server was not told: every other device is still signed in, and so is this one.
					ui.notice(accountNotice, "err", "Signing out everywhere failed: " + ui.describeError(err, "account") +
						" Other devices are still signed in, and so is this browser. Try again.");
				})
			.finally(function () { signingOut = false; setAccountButtonsBusy(false); });
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
	var setupLink = $("totp-setup-link");
	var disableAck = $("totp-disable-ack");
	var disableBtn = $("totp-disable");
	// The pending secret and link, for the copy buttons only; dropped with the setup view.
	var setup = null; // { secret, uri, digits }
	var shownCodes = null;

	function clearSetup() {
		setup = null;
		$("totp-setup-secret").textContent = "";
		$("totp-setup-uri").textContent = "";
		$("totp-setup-label").textContent = "";
		$("totp-setup-params").textContent = "";
		setupLink.removeAttribute("href");
		setupLink.hidden = true;
		setupEl.hidden = true;
	}

	function clearCodes() {
		shownCodes = null;
		ui.clear(codesList);
		codesEl.hidden = true;
	}

	function resetTotpSection() {
		enrollForm.hidden = true;
		manageForm.hidden = true;
		clearSetup();
		clearCodes();
		["totp-enroll-password", "totp-manage-password", "totp-manage-code", "totp-confirm-code"].forEach(function (id) { $(id).value = ""; });
		disableAck.checked = false;
		disableBtn.disabled = true;
		totpStatusEl.textContent = "";
		ui.notice(totpNotice, "ok", "");
	}

	// The code fields of the password change and the deletion: required with two-factor, shown (as
	// optional) when the state is unknown, hidden without it.
	function renderCodeFields() {
		["pw", "delete"].forEach(function (prefix) {
			var field = $(prefix + "-code-field");
			var hint = $(prefix + "-code-hint");
			field.hidden = totpState === "off";
			hint.textContent = totpState === "on"
				? "Two-factor authentication is on: a code from your app, or a recovery code."
				: "Needed only if two-factor authentication is on: a code from your app, or a recovery code.";
		});
	}

	function renderTotpStatus(status) {
		if (status.enabled) {
			totpState = "on";
			totpStatusEl.textContent = "Enabled" + (status.confirmedAt ? " since " + ui.formatDate(status.confirmedAt) : "") +
				". Recovery codes left: " + status.recoveryCodesRemaining + ".";
			enrollForm.hidden = true;
			manageForm.hidden = false;
		} else {
			totpState = "off";
			totpStatusEl.textContent = status.pendingEnrollment
				? "Not enabled. A setup was started but never confirmed; starting again replaces it."
				: "Not enabled.";
			enrollForm.hidden = false;
			manageForm.hidden = true;
		}
		renderCodeFields();
	}

	function loadTotpStatus() {
		var g = generation();
		return api.totpStatus().then(function (status) {
			if (g !== generation()) { return; }
			renderTotpStatus(status);
		}).catch(function (err) {
			if (g !== generation()) { return; }
			if (err && err.kind === api.KINDS.UNAVAILABLE) {
				totpState = "unknown";
				totpStatusEl.textContent = "Two-factor authentication is not available on this server right now.";
				enrollForm.hidden = true;
				manageForm.hidden = true;
				clearSetup();
				renderCodeFields();
				return;
			}
			reportError(err, "totp", totpNotice);
		});
	}

	function showRecoveryCodes(codes) {
		shownCodes = codes.slice();
		ui.clear(codesList);
		codesList.textContent = codes.join("\n");
		codesEl.hidden = false;
	}

	// While fresh recovery codes are on screen nothing else is asked of the server: a failing
	// follow-up call must not take the only copy away. The status is rendered from what is known.
	function renderEnabledWith(codes) {
		renderTotpStatus({ enabled: true, confirmedAt: new Date(), recoveryCodesRemaining: codes.length, pendingEnrollment: false });
	}

	function groupSecret(secret) { return secret.replace(/(.{4})(?=.)/g, "$1 "); }

	enrollForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var passInput = $("totp-enroll-password");
		var password = passInput.value;
		ui.markField(passInput, !ui.validPassword(password), totpNotice);
		if (!ui.validPassword(password)) {
			ui.notice(totpNotice, "err", "Enter your account password (12–128 characters) to confirm.");
			passInput.focus();
			return;
		}
		var g = generation();
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(enrollForm, true);
		api.totpEnroll(password)
			.then(function (enrollment) {
				if (g !== generation()) { return; } // signed out meanwhile: the secret is not shown to anyone
				setup = { secret: enrollment.secret, uri: enrollment.otpauthUri, digits: enrollment.digits };
				$("totp-setup-label").textContent = enrollment.issuer + ": " + enrollment.label;
				$("totp-setup-secret").textContent = groupSecret(enrollment.secret);
				$("totp-setup-uri").textContent = enrollment.otpauthUri;
				setupLink.setAttribute("href", enrollment.otpauthUri);
				setupLink.hidden = false;
				$("totp-setup-params").textContent = "Time-based, SHA-1, " + enrollment.digits + " digits, every " + enrollment.periodSeconds + " seconds";
				$("totp-confirm-code").setAttribute("maxlength", String(enrollment.digits));
				enrollForm.hidden = true;
				setupEl.hidden = false;
				$("totp-confirm-code").value = "";
				$("totp-confirm-code").focus();
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				reportError(err, "totp", totpNotice);
				if (err && err.kind === api.KINDS.FORBIDDEN) { ui.markField(passInput, true, totpNotice); passInput.focus(); }
			})
			.finally(function () {
				passInput.value = "";
				ui.setBusy(enrollForm, false);
				password = null;
			});
	});

	function copyReporter(node) { return function (level, text) { ui.notice(node, level, text); }; }

	$("totp-secret-copy").addEventListener("click", function () {
		if (setup) { ui.copySecret(setup.secret, copyReporter(totpNotice)); }
	});
	$("totp-uri-copy").addEventListener("click", function () {
		if (setup) { ui.copySecret(setup.uri, copyReporter(totpNotice)); }
	});

	$("totp-setup-cancel").addEventListener("click", function () {
		// The pending secret on the server is harmless (not a factor) and is replaced by the next setup.
		clearSetup();
		ui.notice(totpNotice, "ok", "");
		loadTotpStatus();
	});

	confirmForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var codeInput = $("totp-confirm-code");
		var code = codeInput.value.trim();
		var digits = setup ? setup.digits : 6;
		var ok = new RegExp("^[0-9]{" + digits + "}$").test(code);
		ui.markField(codeInput, !ok, totpNotice);
		if (!ok) {
			ui.notice(totpNotice, "err", "Enter the " + digits + "-digit code your authenticator app shows.");
			codeInput.focus();
			return;
		}
		var g = generation();
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(confirmForm, true);
		api.totpConfirm(code)
			.then(function (codes) {
				if (g !== generation()) { return; }
				clearSetup();
				ui.notice(totpNotice, "ok", "Two-factor authentication is enabled. From now on, signing in needs a code as well.");
				renderEnabledWith(codes);
				showRecoveryCodes(codes);
				$("totp-codes-copy").focus();
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				reportError(err, "totp", totpNotice);
				if (err && err.kind === api.KINDS.INVALID) { ui.markField(codeInput, true, totpNotice); codeInput.focus(); }
			})
			.finally(function () {
				codeInput.value = "";
				ui.setBusy(confirmForm, false);
			});
	});

	$("totp-codes-done").addEventListener("click", function () {
		clearCodes();
		loadTotpStatus();
	});

	$("totp-codes-copy").addEventListener("click", function () {
		if (shownCodes) { ui.copySecret(shownCodes.join("\n"), copyReporter(totpNotice)); }
	});

	function manage(action, successMessage, isDisable) {
		var passInput = $("totp-manage-password");
		var codeInput = $("totp-manage-code");
		var password = passInput.value;
		var code = codeInput.value.trim();
		var badPassword = !ui.validPassword(password);
		var badCode = !looksLikeCode(code);
		ui.markField(passInput, badPassword, totpNotice);
		ui.markField(codeInput, badCode, totpNotice);
		if (badPassword || badCode) {
			ui.notice(totpNotice, "err", "Enter your account password and a current code (from the app, or a recovery code).");
			(badPassword ? passInput : codeInput).focus();
			return;
		}
		var g = generation();
		ui.notice(totpNotice, "ok", "");
		ui.setBusy(manageForm, true);
		action(password, code)
			.then(function (result) {
				if (g !== generation()) { return; }
				ui.notice(totpNotice, "ok", successMessage);
				if (isDisable) {
					clearCodes();
					renderTotpStatus({ enabled: false, confirmedAt: null, recoveryCodesRemaining: 0, pendingEnrollment: false });
				} else if (Array.isArray(result)) {
					renderEnabledWith(result);
					showRecoveryCodes(result);
					$("totp-codes-copy").focus();
				}
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				reportError(err, "totp", totpNotice);
				if (err && err.kind === api.KINDS.FORBIDDEN) { passInput.focus(); }
			})
			.finally(function () {
				passInput.value = "";
				codeInput.value = "";
				ui.setBusy(manageForm, false);
				disableAck.checked = false;
				disableBtn.disabled = true;
				password = null;
			});
	}

	// Enter in this form chooses nothing: both actions are explicit buttons.
	manageForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		ui.notice(totpNotice, "warn", "Choose New recovery codes or Turn off.");
	});
	$("totp-regenerate").addEventListener("click", function () {
		manage(api.totpRecoveryCodes, "New recovery codes issued. The old ones no longer work.", false);
	});
	disableAck.addEventListener("change", function () { disableBtn.disabled = !disableAck.checked; });
	disableBtn.addEventListener("click", function () {
		if (!disableAck.checked) { return; }
		manage(api.totpDisable, "Two-factor authentication is turned off. Signing in needs only the account password again.", true);
	});

	// ---- the second factor where a password confirmation asks for it ----
	function readCode(input, notice) {
		var code = input.value.trim();
		if (code === "") {
			if (totpState === "on") { return { error: "Enter a current code from your authenticator app, or a recovery code." }; }
			return { code: null };
		}
		if (!looksLikeCode(code)) { return { error: "That does not look like a code: 6 to 8 digits from the app, or a recovery code (xxxxx-xxxxx)." }; }
		return { code: code };
	}

	// ---- change the account password (the vault master password is not involved) ----
	var pwForm = $("pw-form");
	var pwNotice = $("pw-notice");
	pwForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var cur = $("pw-current"), next = $("pw-new"), next2 = $("pw-new2"), codeInput = $("pw-code");
		var badCur = !ui.validPassword(cur.value);
		var badNew = !ui.validPassword(next.value);
		var mismatch = !badNew && next.value !== next2.value;
		var code = readCode(codeInput);
		ui.markField(cur, badCur, pwNotice);
		ui.markField(next, badNew, pwNotice);
		ui.markField(next2, mismatch, pwNotice);
		ui.markField(codeInput, !!code.error, pwNotice);
		var problem = badCur ? [cur, "Enter your current account password (12–128 characters)."]
			: badNew ? [next, "The new account password must be 12–128 characters."]
			: mismatch ? [next2, "The two new passwords do not match."]
			: code.error ? [codeInput, code.error] : null;
		if (problem) {
			ui.notice(pwNotice, "err", problem[1]);
			problem[0].focus();
			return;
		}
		var g = generation();
		ui.notice(pwNotice, "ok", "");
		ui.setBusy(pwForm, true);
		api.changePassword(cur.value, next.value, code.code)
			.then(function () {
				if (g !== generation()) { return; }
				ui.notice(pwNotice, "ok", "Your account password is changed. Every other device and browser was signed out; this one stays signed in. " +
					"Your vault master password is unchanged: it was never on the server.");
				return refreshSessionList("");
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				reportError(err, "password", pwNotice);
				if (err && err.kind === api.KINDS.FORBIDDEN) { cur.focus(); }
				else if (err && err.kind === api.KINDS.INVALID) { ui.markField(next, true, pwNotice); next.focus(); }
			})
			.finally(function () {
				[cur, next, next2, codeInput].forEach(function (f) { f.value = ""; });
				ui.setBusy(pwForm, false);
			});
	});

	// ---- delete account (password-confirmed, and code-confirmed with two-factor; the server re-checks) ----
	var deleteForm = $("delete-form");
	var deleteNotice = $("delete-notice");
	var deletePass = $("delete-password");
	var deleteCode = $("delete-code");
	var deleteAck = $("delete-ack");
	var deleteSubmit = $("delete-submit");
	deleteAck.addEventListener("change", function () { deleteSubmit.disabled = !deleteAck.checked; });
	deleteForm.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var password = deletePass.value;
		if (!deleteAck.checked) { return; }
		var code = readCode(deleteCode);
		ui.markField(deletePass, !ui.validPassword(password), deleteNotice);
		ui.markField(deleteCode, !!code.error, deleteNotice);
		if (!ui.validPassword(password)) {
			ui.notice(deleteNotice, "err", "Enter your account password (12–128 characters) to confirm.");
			deletePass.focus();
			return;
		}
		if (code.error) { ui.notice(deleteNotice, "err", code.error); deleteCode.focus(); return; }
		if (!confirmDiscard("Deleting the account")) { return; }
		var hadUnsaved = vaultUnsaved();
		var g = generation();
		ui.notice(deleteNotice, "ok", "");
		ui.setBusy(deleteForm, true);
		api.deleteAccount(password, code.code)
			.then(function () {
				if (g !== generation()) { return; }
				api.clearSession();
				showLogin("Your account and the vault stored on the server are deleted. Any vault file on your own devices is untouched." + discardedNote(hadUnsaved), "ok");
			})
			.catch(function (err) {
				if (g !== generation()) { return; }
				reportError(err, "delete", deleteNotice);
				if (err && err.kind === api.KINDS.FORBIDDEN) { deletePass.focus(); }
			})
			.finally(function () {
				deletePass.value = "";
				deleteCode.value = "";
				ui.setBusy(deleteForm, false);
				deleteSubmit.disabled = !deleteAck.checked;
				password = null;
			});
	});

	// Fresh page load: nothing is persisted, so we always start signed out.
	$("note-idle-minutes").textContent = String(Math.round(cfg.idleTimeoutMs / 60000));
	renderCodeFields();
	showLogin("", "ok");
})();
