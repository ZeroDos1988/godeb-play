import { expect, test, type Page } from "@playwright/test";

const plugins = [
  {
    id: "wireguard",
    name: "WireGuard",
    icon: "shield",
    group: "network",
    description: "VPN",
    ready: true,
  },
  {
    id: "ufw",
    name: "Firewall",
    icon: "firewall",
    group: "network",
    description: "UFW",
    ready: true,
  },
];

async function mockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      });

    if (path === "/api/setup/status") {
      return json({ required: false, hasAdmin: true });
    }
    if (path === "/api/auth/me") {
      return json({ username: "admin" });
    }
    if (path === "/api/health") {
      return json({ version: "0.0.0-e2e", ok: true });
    }
    if (path === "/api/plugins") {
      return json({ plugins });
    }
    if (path === "/api/plugin-manager") {
      return json({ plugins: plugins.map((p) => ({ ...p, enabled: true, installed: true })) });
    }
    if (path === "/api/system") {
      return json({
        hostname: "godeb-e2e",
        os: "Debian GNU/Linux 13",
        kernel: "6.12.0",
        uptime: "1h",
        mocked: true,
      });
    }
    if (path === "/api/doctor") {
      return json({ ok: true, findings: [] });
    }
    if (path === "/api/plugins/monitor/summary") {
      return json({ status: "ok", findings: [], mocked: true });
    }
    if (path === "/api/plugins/fail2ban/status") {
      return json({ jails: [], mocked: true });
    }
    if (path === "/api/plugins/wireguard/peers") {
      return json({
        path: "/etc/wireguard/wg0.conf",
        clientsDir: "/etc/wireguard/clients",
        interface: {
          name: "wg0",
          up: true,
          publicKey: "serverPublicKey=",
          listenPort: 51820,
          addresses: ["10.8.0.1/24"],
          dns: ["10.8.0.1"],
        },
        peers: [
          {
            id: "phone",
            name: "phone",
            publicKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCD=",
            allowedIPs: ["10.8.0.2/32"],
            endpoint: "",
            latestHandshake: 0,
            rxBytes: 0,
            txBytes: 0,
            inConfig: true,
            live: false,
            hasClient: false,
          },
        ],
        configured: true,
        role: { role: "hub" },
        mocked: true,
      });
    }
    if (path === "/api/plugins/wireguard/android") {
      return json({
        available: false,
        filename: "godeb-tunnel.apk",
        downloadPath: "/api/plugins/wireguard/android/apk",
      });
    }
    if (path === "/api/plugins/wireguard/trust") {
      return json({
        config: { enabled: false, address: "", port: 0, iface: "", prefix: "" },
        running: false,
        candidates: [],
        mocked: true,
      });
    }
    if (path === "/api/plugins/ufw/status") {
      return json({
        active: true,
        default: "deny (incoming)",
        rules: [{ to: "22/tcp", action: "ALLOW IN", from: "Anywhere" }],
        mocked: true,
      });
    }
    return json({ ok: true, mocked: true });
  });
}

const routes = ["#/", "#/plugin-manager", "#/wireguard", "#/ufw"];

for (const hash of routes) {
  test(`no horizontal overflow on ${hash}`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/${hash}`);
    await expect(page.getByRole("navigation").first()).toBeVisible();
    // Wait for shell / panel content.
    await page.waitForTimeout(300);
    const overflow = await page.evaluate(() => {
      const doc = document.documentElement;
      return {
        scrollWidth: doc.scrollWidth,
        innerWidth: window.innerWidth,
      };
    });
    expect(
      overflow.scrollWidth,
      `scrollWidth ${overflow.scrollWidth} > innerWidth ${overflow.innerWidth} on ${hash}`,
    ).toBeLessThanOrEqual(overflow.innerWidth + 1);
  });
}

test("tabs lead to the plugins of a group", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/");
  await page.getByRole("link", { name: /^(Netzwerk|Network)$/ }).click();
  await expect(page).toHaveURL(/#\/wireguard/);
  const sub = page.getByRole("navigation", { name: /^(Netzwerk|Network)$/ });
  await sub.getByText("Firewall").click();
  await expect(page).toHaveURL(/#\/ufw/);
});

// Regression: the 2FA dialog focused the password field after every render,
// so each digit typed into the code field pulled the cursor back.
test("step-up dialog keeps the cursor in the code field", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/plugin-manager", (route) =>
    route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        plugins: plugins.map((p) => ({ ...p, enabled: true, installed: true, supported: true, dependenciesReady: true, services: [], aptDependencies: [], architectures: [] })),
      }),
    }),
  );
  await page.route("**/api/plugin-manager/ufw/disable", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: "2FA nötig", step_up_required: true, critical: true }),
    }),
  );
  await page.goto("/#/plugin-manager");
  await page.getByRole("switch", { name: "Firewall" }).click();
  const password = page.locator("#stepup-password");
  const code = page.locator("#stepup-code");
  await expect(password).toBeFocused();
  await password.fill("geheim");
  await code.click();
  await code.pressSequentially("123456");
  await expect(code).toBeFocused();
  await expect(code).toHaveValue("123456");
  await expect(password).toHaveValue("geheim");
});
