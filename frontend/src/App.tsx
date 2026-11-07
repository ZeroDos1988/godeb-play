import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Login2FA } from "@/components/Login2FA.tsx";
import { StepUpDialog } from "@/components/StepUpDialog.tsx";
import { ThemeProvider } from "@/context/ThemeContext.tsx";
import { Shell } from "@/layout/Shell.tsx";
import { UNAUTHORIZED_EVENT } from "@/lib/api.ts";
import { authApi } from "@/lib/auth.ts";
import { useGet } from "@/lib/useAsync.ts";
import type { PluginMeta } from "@/lib/types.ts";
import { Overview } from "@/pages/Overview.tsx";
import { PluginManager } from "@/pages/PluginManager.tsx";
import { SetupSummaryPage } from "@/pages/SetupSummaryPage.tsx";
import { ErrorBoundary } from "@/components/ErrorBoundary.tsx";
import { SetupAdmin, SetupWizard, type SetupStatus } from "@/pages/Setup.tsx";
import { api } from "@/lib/api.ts";
import { panelFor } from "@/plugins/registry.ts";

type PluginList = {
  plugins: PluginMeta[];
};

type AuthState = { status: "checking" } | { status: "anonymous" } | { status: "signed-in"; username: string };

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ status: "checking" });
  const [setup, setSetup] = useState<SetupStatus | null>(null);

  useEffect(() => {
    api<SetupStatus>("/api/setup/status")
      .then(setSetup)
      .catch(() => setSetup({ required: false, hasAdmin: true }));
  }, []);

  useEffect(() => {
    let cancelled = false;
    authApi
      .me()
      .then((me) => !cancelled && setAuth({ status: "signed-in", username: me.username }))
      .catch(() => !cancelled && setAuth({ status: "anonymous" }));
    const onUnauthorized = () => setAuth({ status: "anonymous" });
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => {
      cancelled = true;
      window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    };
  }, []);

  if (auth.status === "checking" || setup === null) {
    return (
      <ThemeProvider signedIn={false}>
        <SessionCheck />
      </ThemeProvider>
    );
  }
  // First-run setup: admin (with the one-time token), then the normal login
  // with 2FA enrollment, then role and access.
  if (setup.required && !setup.hasAdmin) {
    return (
      <ThemeProvider signedIn={false}>
        <SetupAdmin onCreated={() => setSetup({ required: true, hasAdmin: true })} />
      </ThemeProvider>
    );
  }
  if (auth.status === "anonymous") {
    return (
      <ThemeProvider signedIn={false}>
        <Login2FA onAuthenticated={(username) => setAuth({ status: "signed-in", username })} />
      </ThemeProvider>
    );
  }
  if (setup.required) {
    return (
      <ThemeProvider signedIn>
        <SetupWizard onDone={() => setSetup({ required: false, hasAdmin: true })} />
        <StepUpDialog />
      </ThemeProvider>
    );
  }

  async function logout() {
    try {
      await authApi.logout();
    } finally {
      setAuth({ status: "anonymous" });
    }
  }

  return (
    <ThemeProvider signedIn>
      <Dashboard username={auth.username} onLogout={() => void logout()} />
      <StepUpDialog />
    </ThemeProvider>
  );
}

function SessionCheck() {
  const { t } = useTranslation();
  return <div className="grid min-h-screen place-items-center bg-paper text-sm text-muted">{t("login.session")}</div>;
}

function Dashboard({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { t } = useTranslation();
  const route = useHashRoute();
  const pluginsQuery = useGet<PluginList>("/api/plugins");
  const plugins = pluginsQuery.data?.plugins ?? [];
  const pluginId = route === "/" ? "" : route.slice(1);
  const active = plugins.find((plugin) => plugin.id === pluginId);

  useEffect(() => {
    document.title = active ? `${active.name} · GoDeb` : "GoDeb";
  }, [active]);

  let content = <Overview />;
  if (route === "/plugin-manager") {
    content = <PluginManager onChanged={pluginsQuery.reload} />;
  } else if (route === "/setup-summary") {
    content = <SetupSummaryPage />;
  } else if (pluginId && !pluginsQuery.loading && !active) {
    content = (
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">{t("app.unknown")}</h1>
        <p className="mt-2 text-sm text-muted">{t("app.unknownBody", { id: pluginId })}</p>
      </section>
    );
  } else if (active) {
    content = <PluginView plugin={active} />;
  }

  return (
    <Shell
      plugins={plugins}
      pluginsError={pluginsQuery.error}
      route={route}
      username={username}
      onLogout={onLogout}
    >
      <ErrorBoundary resetKey={route}>{content}</ErrorBoundary>
    </Shell>
  );
}

function PluginView({ plugin }: { plugin: PluginMeta }) {
  const { t } = useTranslation();
  const Panel = panelFor(plugin.id);
  if (!plugin.ready) {
    return (
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">{plugin.name}</h1>
        <p className="mt-2 max-w-xl text-sm text-muted">{t("app.notReady")}</p>
      </section>
    );
  }
  if (!Panel) {
    return (
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">{plugin.name}</h1>
        <p className="mt-2 max-w-xl text-sm text-muted">
          {plugin.description} {t("app.noView")}
        </p>
      </section>
    );
  }
  return <Panel />;
}

function useHashRoute() {
  const read = () => normalize(window.location.hash);
  const [route, setRoute] = useState(read);

  useEffect(() => {
    const onChange = () => setRoute(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  return route;
}

function normalize(hash: string) {
  const path = hash.replace(/^#/, "").replace(/\/+$/, "");
  if (path === "" || path === "/") {
    return "/";
  }
  return path.startsWith("/") ? path : `/${path}`;
}
