// GoDeb service worker. It exists so the interface can be installed as an
// app; it caches nothing and has no fetch handler, so every request
// (/api included) goes to the network exactly as without it.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
