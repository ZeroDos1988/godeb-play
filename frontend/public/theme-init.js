// Applies the stored theme colors before the app loads, so the page does not
// flash in the default palette. Kept as a file because the CSP forbids inline scripts.
try {
  var stored = JSON.parse(localStorage.getItem("godeb-theme") || "null");
  var light = { primary: "#b8304f", bg: "#eef2f7", accent: "#0b86ad", text: "#14243a" };
  var dark = { primary: "#d9466a", bg: "#0d1828", accent: "#14afdd", text: "#e6edf5" };
  var mode = stored && stored.mode;
  var colors = mode === "custom" && stored.colors ? stored.colors : mode === "dark" || (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches) ? dark : light;
  var root = document.documentElement;
  root.style.setProperty("--color-primary", colors.primary);
  root.style.setProperty("--color-bg", colors.bg);
  root.style.setProperty("--color-accent", colors.accent);
  root.style.setProperty("--color-text", colors.text);
} catch (e) {}
