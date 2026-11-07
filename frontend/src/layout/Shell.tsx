import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useGet } from "@/lib/useAsync.ts";
import { PluginIcon } from "@/components/Icons.tsx";
import { SessionsDialog } from "@/components/SessionsDialog.tsx";
import { ThemeSettings } from "@/components/ThemeSettings.tsx";
import { Shield, Wordmark } from "@/components/Brand.tsx";
import { UserMenu } from "@/components/UserMenu.tsx";
import type { PluginMeta } from "@/lib/types.ts";

type ShellProps = {
  plugins: PluginMeta[];
  pluginsError: string;
  route: string;
  username: string;
  onLogout: () => void;
  children: ReactNode;
};

type Health = { status: "ok" | "info" | "warning" | "critical" };
type Doctor = { fails: number; warns: number };

const rank: Health["status"][] = ["ok", "info", "warning", "critical"];

// The tabs below the header, like the tab row of a GitHub repository.
// Every plugin names its group in manifest.json; settings sit at the end.
const groups = ["system", "network", "apps"] as const;
type Tab = "overview" | (typeof groups)[number] | "settings";

const tabIcons: Record<Tab, string> = {
  overview: "dashboard",
  system: "server",
  network: "network",
  apps: "grid",
  settings: "sliders",
};

type SubLink = { href: string; route: string; icon: string; label: string };

const healthDot: Record<Health["status"], string> = {
  ok: "bg-[#0ca30c]",
  info: "bg-[#0ca30c]",
  warning: "bg-[#fab219]",
  critical: "bg-[#d03b3b] animate-pulse",
};

export function Shell({ plugins, pluginsError, route, username, onLogout, children }: ShellProps) {
  const { t } = useTranslation();
  const [themeOpen, setThemeOpen] = useState(false);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const health = useGet<{ version?: string }>("/api/health");
  // The host name tells VPS and home VM apart at a glance.
  const host = useGet<{ hostname?: string }>("/api/system").data?.hostname ?? "";
  // Missing when the monitor plugin is off; the dot then hides.
  const state = useGet<Health>("/api/plugins/monitor/summary");
  // Doctor is slower; it loads once per page load and only darkens the dot.
  const doctor = useGet<Doctor>("/api/doctor").data;
  const doctorStatus: Health["status"] = doctor?.fails ? "critical" : doctor?.warns ? "warning" : "ok";
  const status = state.data
    ? rank[Math.max(rank.indexOf(state.data.status), rank.indexOf(doctorStatus))]
    : undefined;
  const reloadState = state.reload;
  useEffect(() => {
    reloadState();
  }, [route, reloadState]);

  const settingsLinks: SubLink[] = [
    { href: "#/plugin-manager", route: "/plugin-manager", icon: "cogs", label: t("nav.plugins") },
    { href: "#/setup-summary", route: "/setup-summary", icon: "log", label: t("nav.setupSummary") },
  ];
  const linksFor = (tab: Tab): SubLink[] => {
    if (tab === "settings") return settingsLinks;
    return plugins
      .filter((plugin) => (plugin.group ?? "apps") === tab)
      .map((plugin) => ({ href: `#/${plugin.id}`, route: `/${plugin.id}`, icon: plugin.icon, label: plugin.name }));
  };

  const current = plugins.find((plugin) => `/${plugin.id}` === route);
  const tab: Tab = current
    ? (current.group ?? "apps")
    : settingsLinks.some((link) => link.route === route)
      ? "settings"
      : "overview";
  const subLinks = tab === "overview" ? [] : linksFor(tab);

  const tabs: { id: Tab; href: string; label: string }[] = [
    { id: "overview", href: "#/", label: t("nav.overview") },
    ...groups
      .map((id) => ({ id, links: linksFor(id) }))
      .filter((g) => g.links.length > 0)
      .map((g) => ({ id: g.id, href: g.links[0].href, label: t(`nav.groups.${g.id}`) })),
  ];

  return (
    <div className="min-h-screen bg-paper text-ink">
      {/* Top bar in the dark of the theme (the navy of the logo's shield),
          like the main menu bar of HestiaCP. */}
      <div className="sticky top-0 z-30 bg-sidebar text-sidebar-fg shadow-lg shadow-black/10">
        <header className="mx-auto flex max-w-[1280px] items-center gap-3 px-3 pt-3 pb-2 md:px-6">
          <a href="#/" className="flex min-w-0 items-center gap-2" aria-label={t("nav.overview")}>
            <Shield className="h-8 w-auto" />
            <Wordmark className="hidden h-4 w-auto sm:block" />
          </a>
          {host ? (
            <>
              <span aria-hidden className="text-sidebar-fg/35">
                /
              </span>
              <span className="min-w-0 truncate font-mono text-sm font-semibold">{host}</span>
            </>
          ) : null}
          <div className="ms-auto flex items-center gap-2">
            {status ? (
              <a
                href="#/"
                title={t(`monitor.status.${status}`)}
                className="flex min-h-9 items-center gap-2 rounded-full border border-sidebar-fg/20 px-3 text-xs text-sidebar-fg/85 transition-all duration-200 ease-in-out hover:bg-sidebar-fg/10"
              >
                <span className={`h-2 w-2 rounded-full ${healthDot[status]}`} aria-hidden />
                <span className="hidden sm:inline">{t(`monitor.status.${status}`)}</span>
              </a>
            ) : null}
            <UserMenu
              username={username}
              version={health.data?.version}
              onAppearance={() => setThemeOpen(true)}
              onSessions={() => setSessionsOpen(true)}
              onLogout={onLogout}
            />
          </div>
        </header>
        <nav
          aria-label={t("nav.menu")}
          className="mx-auto flex max-w-[1280px] gap-1 overflow-x-auto px-1 [scrollbar-width:none] md:px-4"
        >
          {tabs.map((item) => (
            <TabLink key={item.id} href={item.href} active={tab === item.id} icon={tabIcons[item.id]} label={item.label} />
          ))}
          <span className="ms-auto" />
          <TabLink
            href="#/plugin-manager"
            active={tab === "settings"}
            icon={tabIcons.settings}
            label={t("nav.groups.settings")}
          />
        </nav>
      </div>

      <div className="mx-auto max-w-[1280px] px-3 py-5 md:px-6 md:py-6">
        {pluginsError ? <p className="mb-4 text-sm text-debian">{pluginsError}</p> : null}
        {subLinks.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-[13rem_minmax(0,1fr)] md:gap-6">
            <nav
              aria-label={t(`nav.groups.${tab}`)}
              className="-mx-3 flex gap-1 overflow-x-auto px-3 [scrollbar-width:none] md:sticky md:top-28 md:mx-0 md:flex-col md:self-start md:overflow-visible md:px-0"
            >
              {subLinks.map((link) => (
                <SubNavLink key={link.route} link={link} active={route === link.route} />
              ))}
            </nav>
            <main className="min-w-0">{children}</main>
          </div>
        ) : (
          <main className="min-w-0">{children}</main>
        )}
      </div>

      {themeOpen ? <ThemeSettings onClose={() => setThemeOpen(false)} /> : null}
      {sessionsOpen ? <SessionsDialog onClose={() => setSessionsOpen(false)} onSignedOut={onLogout} /> : null}
    </div>
  );
}

// TabLink is one entry of the tab row; the active tab gets the cyan line.
function TabLink({ href, active, icon, label }: { href: string; active: boolean; icon: string; label: string }) {
  return (
    <a
      href={href}
      aria-current={active ? "page" : undefined}
      className={`relative flex min-h-11 shrink-0 items-center gap-2 rounded-t-lg px-3 text-sm whitespace-nowrap transition-all duration-200 ease-in-out ${
        active ? "font-semibold text-sidebar-fg" : "text-sidebar-fg/65 hover:text-sidebar-fg"
      }`}
    >
      <PluginIcon name={icon} />
      {label}
      <span
        aria-hidden
        className={`absolute inset-x-2 bottom-0 h-[3px] rounded-full ${active ? "bg-brand-cyan" : "bg-transparent"}`}
      />
    </a>
  );
}

// SubNavLink is the left list inside a tab (a row of chips on phones),
// like the sidebar of GitHub's settings pages.
function SubNavLink({ link, active }: { link: SubLink; active: boolean }) {
  return (
    <a
      href={link.href}
      aria-current={active ? "page" : undefined}
      className={`flex min-h-11 shrink-0 items-center gap-2 rounded-2xl px-3 text-sm whitespace-nowrap transition-all duration-200 ease-in-out md:min-h-9 ${
        active
          ? "bg-slate-900/60 font-medium text-white shadow-sm md:border-s-[3px] md:border-brand-cyan"
          : "text-muted hover:bg-slate-900/30 hover:text-ink"
      }`}
    >
      <PluginIcon name={link.icon} />
      <span>{link.label}</span>
    </a>
  );
}
