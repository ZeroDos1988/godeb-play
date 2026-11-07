import { useState } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, PanelFrame } from "@/components/PanelFrame.tsx";
import { api } from "@/lib/api.ts";
import type { CommandEnvelope } from "@/lib/types.ts";
import { useGet } from "@/lib/useAsync.ts";
import * as ui from "@/components/ui.ts";

type UfwRule = {
  to: string;
  action: string;
  from: string;
};

type UfwStatus = CommandEnvelope & {
  active: boolean;
  rules: UfwRule[];
};

const actionButton =
  "rounded-2xl border border-white/10 bg-slate-900/60 px-3 py-1.5 text-sm text-white backdrop-blur-xl transition-all duration-200 ease-in-out enabled:hover:bg-white/10 disabled:opacity-50";

export default function Panel() {
  const { t } = useTranslation();
  const query = useGet<UfwStatus>("/api/plugins/ufw/status");
  const [rule, setRule] = useState("22/tcp");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");

  async function submit(action: "allow" | "deny" | "delete", value: string, policy = "allow") {
    setBusy(true);
    setActionError("");
    try {
      await api("/api/plugins/ufw/rules", {
        method: "POST",
        body: JSON.stringify({ action, rule: value, policy }),
      });
      query.reload();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : t("ufw.failed"));
    } finally {
      setBusy(false);
    }
  }

  const rules = query.data?.rules ?? [];

  return (
    <PanelFrame
      title={t("ufw.title")}
      description={t("ufw.description")}
      command={query.data?.command}
      mocked={query.data?.mocked}
      detail={query.data?.detail}
      loading={query.loading}
      error={query.error}
      onRefresh={query.reload}
    >
      {query.data ? (
        <p className="mb-4 text-sm">
          {t("ufw.status")}:{" "}
          <span className={query.data.active ? "text-emerald-400" : "text-debian"}>
            {query.data.active ? t("common.active") : t("common.inactive")}
          </span>
        </p>
      ) : null}

      <RemoteCard />

      <form
        className="mb-4 flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          void submit("allow", rule);
        }}
      >
        <label className="text-sm">
          <span className="mb-1 block text-xs tracking-wide text-muted uppercase">{t("ufw.rule")}</span>
          <input
            value={rule}
            onChange={(event) => setRule(event.target.value)}
            className={`${ui.input} font-mono`}
            placeholder="22/tcp"
          />
        </label>
        <button type="submit" disabled={busy} className={actionButton}>
          {t("ufw.allow")}
        </button>
        <button type="button" disabled={busy} onClick={() => void submit("deny", rule)} className={actionButton}>
          {t("ufw.deny")}
        </button>
      </form>
      {actionError ? <p className="mb-4 text-sm text-debian">{actionError}</p> : null}

      {query.data ? (
        rules.length === 0 ? (
          <p className="text-sm text-muted">{t("ufw.empty")}</p>
        ) : (
          <DataTable mobileCards head={[t("ufw.to"), t("ufw.action"), t("ufw.from"), ""]}>
            {rules.map((entry) => (
              <tr key={`${entry.to}-${entry.action}-${entry.from}`}>
                <td className="px-3 py-2 font-mono text-xs">{entry.to}</td>
                <td className="px-3 py-2">{entry.action}</td>
                <td className="px-3 py-2">{entry.from}</td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void submit("delete", entry.to.replace(/ \(v6\)$/, ""), entry.action.split(" ")[0].toLowerCase())}
                    className="text-xs text-rose-300 transition-all duration-200 ease-in-out enabled:hover:underline disabled:opacity-50"
                  >
                    {t("ufw.remove")}
                  </button>
                </td>
              </tr>
            ))}
          </DataTable>
        )
      ) : null}
    </PanelFrame>
  );
}

type Remote = { open: boolean; address?: string; port: number; until?: string; url?: string; publicIp?: string };

const durations = [30, 60, 120, 240, 480, 1440];

// RemoteCard switches the temporary HTTPS access on the public address.
function RemoteCard() {
  const { t } = useTranslation();
  const query = useGet<Remote>("/api/plugins/ufw/remote");
  const [current, setCurrent] = useState<Remote | null>(null);
  const [minutes, setMinutes] = useState(120);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const view = current ?? query.data;

  async function post(path: string, body?: object) {
    setBusy(path);
    setError("");
    try {
      setCurrent(await api<Remote>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("ufw.failed"));
    } finally {
      setBusy("");
    }
  }

  if (!view) {
    return null;
  }
  const until = view.until ? new Date(view.until).toLocaleString([], { dateStyle: "short", timeStyle: "short" }) : "";
  return (
    <div className={`${ui.card} mb-4 ${view.open ? "border-amber-400/40" : ""}`}>
      <h3 className={ui.cardTitle}>{t("ufw.remote.title")}</h3>
      {view.open ? (
        <>
          <p className="mt-2 text-sm text-amber-200">{t("ufw.remote.openUntil", { until })}</p>
          <p className="mt-1 font-mono text-sm break-all">{view.url}</p>
        </>
      ) : (
        <p className={ui.hint}>{t("ufw.remote.hint", { ip: view.publicIp || "—", port: view.port })}</p>
      )}
      <div className="mt-4 flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <span className={ui.label}>{t("ufw.remote.duration")}</span>
          <select className={ui.input} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
            {durations.map((m) => (
              <option key={m} value={m}>
                {m < 60 ? t("ufw.remote.minutes", { count: m }) : t("ufw.remote.hours", { count: m / 60 })}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          className={view.open ? ui.button : ui.primary}
          disabled={busy !== ""}
          onClick={() => void post("/api/plugins/ufw/remote", { minutes })}
        >
          {view.open ? t("ufw.remote.extend") : t("ufw.remote.open")}
        </button>
        {view.open ? (
          <button type="button" className={ui.danger} disabled={busy !== ""} onClick={() => void post("/api/plugins/ufw/remote/close")}>
            {t("ufw.remote.close")}
          </button>
        ) : null}
      </div>
      <p className={ui.hint}>{t("ufw.remote.safety")}</p>
      {error ? <p className="mt-2 text-sm break-words text-debian">{error}</p> : null}
    </div>
  );
}
