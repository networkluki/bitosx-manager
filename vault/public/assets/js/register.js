// Email-first registration and resend-verification (vault.bitosx.se, phase 1).
// Both endpoints answer with the same generic 202 whether or not the address
// exists, so the page shows the same generic text too.
(function () {
	"use strict";

	var api = window.bitosxApi;
	var ui = window.bitosxUi;
	var $ = ui.$;

	var GENERIC_OK = "If the address can be registered or needs verification, an email is on its way. Open the link within 30 minutes to choose your account password.";

	function wire(formId, emailId, noticeId, action) {
		var form = $(formId);
		var emailEl = $(emailId);
		var noticeEl = $(noticeId);
		if (!form || !emailEl) { return; }
		form.addEventListener("submit", function (ev) {
			ev.preventDefault();
			var email = emailEl.value;
			var ok = ui.validEmail(email);
			emailEl.setAttribute("aria-invalid", ok ? "false" : "true");
			if (!ok) {
				ui.notice(noticeEl, "err", "Enter a valid email address.");
				return;
			}
			ui.notice(noticeEl, "ok", "");
			ui.setBusy(form, true);
			action(email)
				.then(function () {
					emailEl.value = "";
					ui.notice(noticeEl, "ok", GENERIC_OK);
				})
				.catch(function (err) {
					var msg = (err && err.kind === api.KINDS.UNAVAILABLE)
						? "Email delivery is not available right now. Nothing was created; try again later."
						: ui.describeError(err, "register");
					ui.notice(noticeEl, "err", msg);
				})
				.finally(function () { ui.setBusy(form, false); });
		});
	}

	wire("register-form", "register-email", "register-notice", api.register);
	wire("resend-form", "resend-email", "resend-notice", api.resendVerification);

	// Deep link from the sign-in page: /register#resend focuses the resend form.
	if (window.location.hash === "#resend") {
		var resendEmail = $("resend-email");
		if (resendEmail) { resendEmail.focus(); }
	}
})();
