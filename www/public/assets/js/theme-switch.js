// iOS-style light/dark theme switch.
// Loaded as an external file so it complies with a strict
// Content-Security-Policy (script-src 'self'; no inline scripts).
// Note: the knob is positioned at runtime via element.style (CSSOM), which is
// NOT restricted by the style-src directive, so dragging works under the CSP.
(function () {
	"use strict";

	var STORAGE_KEY = "theme";
	var root = document.documentElement;
	var btn = document.getElementById("themeSwitch");
	if (!btn) { return; }

	var knob = btn.querySelector(".theme-switch__knob");
	// Horizontal travel of the knob: track width - knob width - 2*gap.
	var TRAVEL = 32;

	// localStorage can throw (private mode, blocked cookies); fail safe to null.
	function readStored() {
		try {
			var v = localStorage.getItem(STORAGE_KEY);
			return (v === "light" || v === "dark") ? v : null;
		} catch (e) { return null; }
	}

	function store(value) {
		try { localStorage.setItem(STORAGE_KEY, value); } catch (e) { /* ignore */ }
	}

	function prefersDark() {
		return window.matchMedia &&
			window.matchMedia("(prefers-color-scheme: dark)").matches;
	}

	// Current effective theme: explicit attribute wins, else OS preference.
	function isDark() {
		var attr = root.getAttribute("data-theme");
		if (attr === "dark") { return true; }
		if (attr === "light") { return false; }
		return prefersDark();
	}

	function apply(theme) {
		root.setAttribute("data-theme", theme);
		btn.setAttribute("aria-checked", theme === "dark" ? "true" : "false");
		store(theme);
	}

	// Sync aria-checked with the real starting state (may come from OS preference).
	btn.setAttribute("aria-checked", isDark() ? "true" : "false");

	// --- Click / keyboard toggle (button handles Enter and Space natively) ---
	btn.addEventListener("click", function () {
		if (suppressClick) { suppressClick = false; return; }
		apply(isDark() ? "light" : "dark");
	});

	// --- Drag like an iOS switch ---
	// Capture the pointer only once a real drag starts, NOT on pointerdown:
	// capturing on pointerdown makes the browser swallow the following "click",
	// which would break a plain tap/click on the switch.
	var dragging = false;
	var captured = false;
	var pointerId = null;
	var startX = 0;
	var moved = false;
	var suppressClick = false; // prevents the click firing after a real drag

	function knobOffset() { return isDark() ? TRAVEL : 0; }

	btn.addEventListener("pointerdown", function (ev) {
		dragging = true;
		captured = false;
		moved = false;
		pointerId = ev.pointerId;
		startX = ev.clientX;
	});

	btn.addEventListener("pointermove", function (ev) {
		if (!dragging) { return; }
		var delta = ev.clientX - startX;
		if (!moved && Math.abs(delta) > 3) {
			// A drag has begun: now take capture so it tracks outside the button.
			moved = true;
			btn.classList.add("is-dragging");
			try { btn.setPointerCapture(pointerId); captured = true; } catch (e) { /* ignore */ }
		}
		if (!moved) { return; }
		// Follow the finger, clamped to the track.
		var pos = Math.max(0, Math.min(TRAVEL, knobOffset() + delta));
		knob.style.transform = "translateX(" + pos + "px)";
	});

	function endDrag(ev) {
		if (!dragging) { return; }
		dragging = false;
		if (captured) {
			try { btn.releasePointerCapture(pointerId); } catch (e) { /* ignore */ }
			captured = false;
		}
		btn.classList.remove("is-dragging");
		knob.style.transform = ""; // hand control back to the CSS rules
		if (moved) {
			suppressClick = true; // a drag happened; don't also toggle on the click
			var pos = knobOffset() + (ev.clientX - startX);
			apply(pos > TRAVEL / 2 ? "dark" : "light");
		}
		// A plain tap (moved === false) falls through to the click handler.
	}

	btn.addEventListener("pointerup", endDrag);
	btn.addEventListener("pointercancel", endDrag);
})();
