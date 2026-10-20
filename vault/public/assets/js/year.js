// Dynamic copyright year without document.write().
(function () {
  "use strict";
  var el = document.getElementById("current-year");
  if (el) { el.textContent = String(new Date().getFullYear()); }
})();
