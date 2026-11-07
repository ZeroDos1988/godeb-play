import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@/i18n.ts";
import App from "@/App.tsx";
import { applyTheme, readStoredTheme } from "@/context/theme.ts";
import "@/index.css";

applyTheme(readStoredTheme());

const root = document.getElementById("root");
if (!root) {
  throw new Error("root element missing");
}

// Only over real HTTPS (app access in the tunnel); the worker caches nothing.
if ("serviceWorker" in navigator && window.location.protocol === "https:") {
  navigator.serviceWorker.register("/sw.js").catch(() => undefined);
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
