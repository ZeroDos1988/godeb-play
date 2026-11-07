import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { PanelFrame } from "@/components/PanelFrame.tsx";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

type Field = { key: string; value: string };

type Entry = {
  time: number;
  priority: number;
  unit: string;
  message: string;
  fields: Field[];
  /** Set when the web UI's and the agent's line of one request were merged. */
  sources?: string[];
};

type LogResponse = CommandEnvelope & { entries: Entry[] };

type Filter = { source: string; level: string; since: string; q: string };

const input = ui.input;

const button = ui.button;

// Journal priorities: 3 error, 4 warning, 6 info, 7 debug.
function levelStyle(priority: number): { key: string; className: string } {
  if (priority <= 3) return { key: "error", className: "border-rose-400/30 bg-rose-950/40 text-rose-200" };
  if (priority === 4) return { key: "warning", className: "border-amber-300/30 bg-amber-950/30 text-amber-100" };
  if (priority >= 7) return { key: "debug", className: "border-white/10 bg-white/5 text-white/50" };
  return { key: "info", className: "border-sky-300/20 bg-sky-950/30 text-sky-100" };
}

export default function Panel() {
  const { t, i18n } = useTranslation();
  const [filter, setFilter] = useState<Filter>({ source: "all", level: "info", since: "24h", q: "" });
  const [text, setText] = useState("");
  const [live, setLive] = useState(false);

  const params = new URLSearchParams({ source: filter.source, level: filter.level, since: filter.since, lines: "300" });
  if (filter.q) params.set("q", filter.q);
  const query = useGet<LogResponse>(`/api/plugins/logs/entries?${params.toString()}`);
  const { reload } = query;

  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(reload, 5000);
    return () => window.clearInterval(id);
  }, [live, reload]);

  const entries = query.data?.entries ?? [];
  const timeFormat = new Intl.DateTimeFormat(i18n.language, {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  function search(e: FormEvent) {
    e.preventDefault();
    setFilter((f) => ({ ...f, q: text.trim() }));
  }

  return (
    <PanelFrame
      title={t("logs.title")}
      description={t("logs.description")}
      command={query.data?.command}
      mocked={query.data?.mocked}
      detail={query.data?.detail}
      loading={query.loading}
      error={query.error}
      onRefresh={reload}
    >
      <form onSubmit={search} className="grid gap-3 md:grid-cols-5">
        <Labeled label={t("logs.source")}>
          <select className={input} value={filter.source} onChange={(e) => setFilter({ ...filter, source: e.target.value })}>
            <option value="all">{t("logs.sourceAll")}</option>
            <option value="web">{t("logs.sourceWeb")}</option>
            <option value="agent">{t("logs.sourceAgent")}</option>
          </select>
        </Labeled>
        <Labeled label={t("logs.level")}>
          <select className={input} value={filter.level} onChange={(e) => setFilter({ ...filter, level: e.target.value })}>
            <option value="error">{t("logs.levelError")}</option>
            <option value="warning">{t("logs.levelWarning")}</option>
            <option value="info">{t("logs.levelInfo")}</option>
            <option value="debug">{t("logs.levelDebug")}</option>
          </select>
        </Labeled>
        <Labeled label={t("logs.since")}>
          <select className={input} value={filter.since} onChange={(e) => setFilter({ ...filter, since: e.target.value })}>
            <option value="15m">{t("logs.since15m")}</option>
            <option value="1h">{t("logs.since1h")}</option>
            <option value="24h">{t("logs.since24h")}</option>
            <option value="7d">{t("logs.since7d")}</option>
            <option value="all">{t("logs.sinceAll")}</option>
          </select>
        </Labeled>
        <Labeled label={t("logs.search")}>
          <input
            className={input}
            value={text}
            maxLength={100}
            placeholder={t("logs.searchHint")}
            onChange={(e) => setText(e.target.value)}
          />
        </Labeled>
        <div className="flex items-end gap-3">
          <button type="submit" className={button}>
            {t("logs.apply")}
          </button>
          <label className="flex items-center gap-2 pb-2 text-sm text-muted">
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
            {t("logs.live")}
          </label>
        </div>
      </form>

      {query.data ? (
        entries.length === 0 ? (
          <p className="mt-6 text-sm text-muted">{t("logs.empty")}</p>
        ) : (
          <ul className="mt-6 space-y-2">
            {entries.map((entry, i) => {
              const level = levelStyle(entry.priority);
              return (
                <li
                  key={`${entry.time}-${i}`}
                  className="rounded-2xl border border-white/10 bg-slate-900/60 px-3 py-2 text-sm backdrop-blur-xl"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-xl border px-2 py-0.5 text-[11px] uppercase ${level.className}`}>
                      {t(`logs.badge.${level.key}`)}
                    </span>
                    <span className="font-mono text-xs text-white/50">{entry.time ? timeFormat.format(entry.time) : ""}</span>
                    <span className="text-xs text-white/50">
                      {entry.sources?.length
                        ? `${t("logs.sourceWeb")} → ${t("logs.sourceAgent")}`
                        : entry.unit === "godeb-play-agent.service"
                          ? t("logs.sourceAgent")
                          : t("logs.sourceWeb")}
                    </span>
                  </div>
                  <p className="mt-1 font-medium break-words text-white">{entry.message}</p>
                  {entry.fields?.length ? (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {entry.fields.map((f, j) => (
                        <span key={j} className="max-w-full rounded-xl bg-white/5 px-2 py-0.5 font-mono text-[11px] break-all text-white/70">
                          <span className="text-white/40">{f.key}=</span>
                          {f.value}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )
      ) : null}
    </PanelFrame>
  );
}

function Labeled({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block min-w-0 text-xs text-muted">
      <span className="mb-1 block">{label}</span>
      {children}
    </label>
  );
}
