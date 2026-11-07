import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";
import { Help } from "@/components/Help.tsx";
import { DataTable } from "@/components/PanelFrame.tsx";
import { SectionHeader, StatGrid } from "@/components/Section.tsx";

type ServiceStatus = {
  unit: string;
  enabled: string;
  active: string;
};

type ManagedPlugin = {
  id: string;
  name: string;
  description?: string;
  aptDependencies: string[];
  systemdServices: string[];
  supported: boolean;
  architectures: string[];
  dependenciesReady: boolean;
  installed: boolean;
  enabled: boolean;
  services: ServiceStatus[];
};

type PluginList = {
  plugins: ManagedPlugin[];
};

// order puts active plugins first, then the ones that can be switched on,
// then those that need packages, then those this machine cannot run.
function order(p: ManagedPlugin): number {
  if (p.enabled) return 0;
  if (!p.supported) return 3;
  return p.dependenciesReady ? 1 : 2;
}

export function PluginManager({ onChanged }: { onChanged?: () => void }) {
  const { t } = useTranslation();
  const query = useGet<PluginList>("/api/plugin-manager");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const plugins = [...(query.data?.plugins ?? [])].sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name));
  const active = plugins.filter((p) => p.enabled);
  const inactive = plugins.filter((p) => !p.enabled);

  async function run(id: string, action: "install" | "enable" | "disable") {
    setBusy(`${id}:${action}`);
    setError("");
    try {
      await api(`/api/plugin-manager/${id}/${action}`, { method: "POST" });
      query.reload();
      // Switching a plugin on or off changes the sidebar.
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unbekannter Fehler");
    } finally {
      setBusy("");
    }
  }

  function table(list: ManagedPlugin[]) {
    return (
      <DataTable head={[t("pluginManager.colPlugin"), t("pluginManager.colState"), t("pluginManager.colServices"), ""]} mobileCards>
        {list.map((plugin) => {
          const working = busy.startsWith(`${plugin.id}:`);
          return (
            <tr key={plugin.id}>
              <td className="px-3 py-3 align-top sm:w-1/2">
                <div className="min-w-0">
                  <span className="block font-medium">{plugin.name}</span>
                  {plugin.description ? <span className="mt-0.5 block text-xs text-white/55">{plugin.description}</span> : null}
                  {!plugin.supported ? (
                    <span className="mt-1 block text-xs text-amber-200">{t("pluginManager.unsupported", { archs: plugin.architectures.join(", ") })}</span>
                  ) : plugin.aptDependencies.length > 0 && !plugin.dependenciesReady ? (
                    <span className="mt-1 block text-xs text-white/55">
                      {t("pluginManager.deps")}: {plugin.aptDependencies.join(", ")}
                    </span>
                  ) : null}
                </div>
              </td>
              <td className="px-3 py-3 align-top sm:w-1/6">
                <div className="flex flex-wrap gap-1.5">
                  <Badge tone={plugin.enabled ? "ok" : "idle"}>{plugin.enabled ? t("pluginManager.enabled") : t("pluginManager.disabled")}</Badge>
                  {!plugin.installed ? <Badge tone="bad">{t("pluginManager.missing")}</Badge> : null}
                </div>
              </td>
              <td className="px-3 py-3 align-top">
                {/* Service state only means something once the packages are there. */}
                {plugin.installed && plugin.services.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {plugin.services.map((service) => (
                      <Badge key={service.unit} tone={service.active === "active" ? "ok" : "idle"}>
                        {`${service.unit.replace(/\.service$/, "")} · ${service.active}`}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <span className="text-white/40">–</span>
                )}
              </td>
              <td className="px-3 py-3 align-top">
                <div className="flex items-center justify-end gap-2">
                  {plugin.supported && !plugin.dependenciesReady ? (
                    <button type="button" disabled={working} onClick={() => void run(plugin.id, "install")} className={ui.primary}>
                      {working ? t("pluginManager.working") : t("pluginManager.install")}
                    </button>
                  ) : null}
                  <Toggle
                    checked={plugin.enabled}
                    disabled={working || (!plugin.enabled && (!plugin.dependenciesReady || !plugin.supported))}
                    label={plugin.name}
                    onChange={(next) => void run(plugin.id, next ? "enable" : "disable")}
                  />
                </div>
              </td>
            </tr>
          );
        })}
      </DataTable>
    );
  }

  return (
    <section>
      <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
        {t("pluginManager.title")}
        <Help>{t("pluginManager.lead")}</Help>
      </h1>
      {query.loading && !query.data ? <p className="mt-6 text-sm text-muted">{t("pluginManager.loading")}</p> : null}
      {query.error || error ? (
        <p className="mt-6 max-w-xl rounded-2xl border border-white/10 bg-rose-950/40 px-4 py-3 text-sm text-rose-100 backdrop-blur-xl">
          {error || query.error}
        </p>
      ) : null}
      {!query.loading && plugins.length === 0 ? <p className="mt-6 text-sm text-muted">{t("pluginManager.empty")}</p> : null}
      {plugins.length > 0 ? (
        <div className="mt-6">
          <StatGrid
            items={[
              { label: t("pluginManager.statActive"), value: active.length, tone: "text-emerald-300" },
              { label: t("pluginManager.statInactive"), value: inactive.length },
              { label: t("pluginManager.statMissing"), value: plugins.filter((p) => p.supported && !p.dependenciesReady).length },
              { label: t("pluginManager.statTotal"), value: plugins.length },
            ]}
          />
        </div>
      ) : null}
      {active.length > 0 ? (
        <div className="mt-2">
          <SectionHeader title={t("pluginManager.sectionActive", { count: active.length })} />
          {table(active)}
        </div>
      ) : null}
      {inactive.length > 0 ? (
        <div className="mt-8">
          <SectionHeader title={t("pluginManager.sectionInactive", { count: inactive.length })} hint={t("pluginManager.sectionInactiveHint")} />
          {table(inactive)}
        </div>
      ) : null}
    </section>
  );
}

function Badge({ tone, children }: { tone: "ok" | "bad" | "idle"; children: string }) {
  const toneClass =
    tone === "ok" ? "bg-emerald-400/15 text-emerald-200" : tone === "bad" ? "bg-rose-400/15 text-rose-200" : "bg-white/10 text-white/70";
  return <span className={`rounded-full px-2.5 py-1 text-[11px] tracking-wide uppercase ${toneClass}`}>{children}</span>;
}

function Toggle({
  checked,
  disabled,
  label,
  onChange,
}: {
  checked: boolean;
  disabled: boolean;
  label: string;
  onChange: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-7 w-12 shrink-0 rounded-full transition-all duration-200 ease-in-out disabled:opacity-40 ${
        checked ? "bg-emerald-500" : "bg-white/20"
      }`}
    >
      <span
        className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white transition-all duration-200 ease-in-out ${
          checked ? "translate-x-5" : ""
        }`}
      />
    </button>
  );
}
