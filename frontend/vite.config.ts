import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    dedupe: ["react", "react-dom", "i18next", "react-i18next"],
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      react: fileURLToPath(new URL("./node_modules/react", import.meta.url)),
      "react-dom": fileURLToPath(new URL("./node_modules/react-dom", import.meta.url)),
      i18next: fileURLToPath(new URL("./node_modules/i18next", import.meta.url)),
      "react-i18next": fileURLToPath(new URL("./node_modules/react-i18next", import.meta.url)),
    },
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
