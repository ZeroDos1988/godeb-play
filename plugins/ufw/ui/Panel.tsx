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

