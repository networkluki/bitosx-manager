// Forgot-password request (vault.bitosx.se, phase 6). The endpoint answers with
// the same generic 202 whether or not an account exists, so the page shows the
// same generic text too. It resets the ACCOUNT password only; the vault master
// password is never involved.
(function () {
	"use strict";

	var api = window.bitosxApi;
	var ui = window.bitosxUi;
	var $ = ui.$;

	var GENERIC_OK = "If an account exists for this address, an email with a reset link is on its way. Open it within 30 minutes to choose a new account password.";

	var form = $("forgot-form");
	var emailEl = $("forgot-email");
	var noticeEl = $("forgot-notice");
	if (!form || !emailEl) { return; }

	form.addEventListener("submit", function (ev) {
		ev.preventDefault();
		var email = emailEl.value;
		var ok = ui.validEmail(email);
		ui.markField(emailEl, !ok, noticeEl);
		if (!ok) {
			ui.notice(noticeEl, "err", "Enter a valid email address.");
			return;
		}
		ui.notice(noticeEl, "ok", "");
		ui.setBusy(form, true);
		api.forgotPassword(email)
			.then(function () {
				emailEl.value = "";
				ui.notice(noticeEl, "ok", GENERIC_OK);
			})
			.catch(function (err) {
				var msg = (err && err.kind === api.KINDS.UNAVAILABLE)
					? "Email delivery is not available right now. Nothing was sent; try again later."
					: ui.describeError(err, "forgot");
				ui.notice(noticeEl, "err", msg);
			})
			.finally(function () { ui.setBusy(form, false); });
	});

	emailEl.focus();
})();
