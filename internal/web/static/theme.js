// Theme: Auto (follow the OS), Light or Dark. Loaded from <head> so the right
// theme is set before first paint; an external file because the CSP forbids
// inline scripts. The choice is kept in localStorage; nothing is sent anywhere.
(function () {
  var KEY = "tracefall-theme";
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  function choice() {
    try { var v = localStorage.getItem(KEY); if (v === "light" || v === "dark") return v; } catch (e) {}
    return "auto";
  }
  function resolved(c) { return c === "auto" ? (mq && mq.matches ? "light" : "dark") : c; }
  function apply() { document.documentElement.setAttribute("data-theme", resolved(choice())); }
  apply();
  if (mq && mq.addEventListener) mq.addEventListener("change", apply);
  var LABEL = { auto: "Theme: Auto", light: "Theme: Light", dark: "Theme: Dark" };
  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    function paint() { b.textContent = LABEL[choice()]; }
    paint();
    b.addEventListener("click", function () {
      var next = { auto: "light", light: "dark", dark: "auto" }[choice()];
      try { if (next === "auto") localStorage.removeItem(KEY); else localStorage.setItem(KEY, next); } catch (e) {}
      apply(); paint();
      // The Photo Map basemap is painted on a canvas that reads the theme colours when it draws.
      if (location.hash.indexOf("/geomap") !== -1) location.reload();
    });
  });
})();
