// Apply a previously saved theme before first paint (avoids a flash of the
// wrong theme). No saved choice -> CSS falls back to the OS preference.
// Loaded from the <head> as an external file so it complies with a strict
// Content-Security-Policy (script-src 'self'; no inline scripts).
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) { /* storage blocked (private mode): keep OS-preference default */ }
})();
