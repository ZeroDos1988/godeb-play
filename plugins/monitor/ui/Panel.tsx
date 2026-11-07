import { useState } from "react";
import { useTranslation } from "react-i18next";
import { PanelFrame } from "@/components/PanelFrame.tsx";
import { useGet } from "@/lib/useAsync.ts";
import { AccessTab } from "./AccessTab.tsx";
import { AlertsTab } from "./AlertsTab.tsx";
import { NetworkTab } from "./NetworkTab.tsx";
import { SitesTab, useSites } from "./SitesTab.tsx";
import { SystemTab } from "./SystemTab.tsx";
import { usePolling, type RangeName, type Summary, RangePicker } from "./shared.tsx";

const TABS = ["system", "network", "access", "sites", "alerts"] as const;
type Tab = (typeof TABS)[number];

export default function Panel() {
  const { t } = useTranslation();
  const summary = useGet<Summary>("/api/plugins/monitor/summary");
  usePolling(summary.reload, 10_000);
  const [tab, setTab] = useState<Tab>("system");
  const [range, setRange] = useState<RangeName>("24h");
  const sites = useSites();
  // Sites only exist on a hub.
  const tabs = TABS.filter((id) => id !== "sites" || sites.data?.hub || (sites.data?.sites.length ?? 0) > 0);

  return (
    <PanelFrame
      title={t("monitor.title")}
      description={t("monitor.description")}
      loading={summary.loading && !summary.data}
      error={summary.error}
      onRefresh={summary.reload}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-1" role="tablist">
          {tabs.map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={`rounded-2xl border px-3 py-1.5 text-sm transition-all duration-200 ${
                tab === id ? "border-white/20 bg-white/10 text-white" : "border-transparent text-white/60 hover:bg-white/5"
              }`}
            >
              {t(`monitor.tabs.${id}`)}
            </button>
          ))}
        </div>
        <RangePicker value={range} onChange={setRange} />
      </div>
      <div className="mt-4">
        {tab === "system" ? <SystemTab summary={summary.data} range={range} /> : null}
        {tab === "network" ? <NetworkTab summary={summary.data} range={range} /> : null}
        {tab === "access" ? <AccessTab range={range} /> : null}
        {tab === "sites" ? <SitesTab data={sites.data} range={range} /> : null}
        {tab === "alerts" ? <AlertsTab /> : null}
      </div>
    </PanelFrame>
  );
}
