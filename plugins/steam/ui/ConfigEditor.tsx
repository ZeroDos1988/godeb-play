import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import { useGet } from "@/lib/useAsync.ts";
import type { ConfigForm, GameConfig } from "./games/types.ts";
import { button, card, input, primary } from "./parts.tsx";

type ConfigFile = {
  path: string;
  content: string;
  exists: boolean;
};

// ConfigEditor shows a game's configuration as a form (if the game has one)
// or as the raw file. Both views edit the same object, so switching never
// drops keys the form does not know.
export function ConfigEditor({
  base,
  Form,
  onSaved,
  serverActive,
}: {
  base: string;
  Form?: ConfigForm;
  onSaved: () => void;
  serverActive: boolean;
}) {
  const { t } = useTranslation();
  const file = useGet<ConfigFile>(`${base}/config`);
  const [mode, setMode] = useState<"form" | "raw">(Form ? "form" : "raw");
  const [raw, setRaw] = useState("");
  const [cfg, setCfg] = useState<GameConfig>({});
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!file.data) {
      return;
    }
    setRaw(file.data.content);
    try {
      setCfg(JSON.parse(file.data.content) as GameConfig);
      setMode(Form ? "form" : "raw");
    } catch {
      setMode("raw");
    }
  }, [file.data, Form]);

  const rawError = useMemo(() => {
    if (mode !== "raw") {
      return "";
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? "" : t("steam.notObject");
    } catch (err: unknown) {
      return err instanceof Error ? err.message : t("steam.invalidJson");
    }
  }, [mode, raw, t]);

  function switchTo(next: "form" | "raw") {
    setError("");
    if (next === mode) {
      return;
    }
    if (next === "raw") {
      setRaw(JSON.stringify(cfg, null, 2));
      setMode("raw");
      return;
    }
    try {
      setCfg(JSON.parse(raw) as GameConfig);
      setMode("form");
    } catch {
      setError(t("steam.fixJsonFirst"));
    }
  }

  async function save(restart: boolean) {
    const content = mode === "raw" ? raw : JSON.stringify(cfg, null, 2);
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const res = await api<{ restarted?: boolean; detail?: string }>(`${base}/config`, {
        method: "PUT",
        body: JSON.stringify({ content, restart }),
      });
      setNotice(res.detail ?? (res.restarted ? t("steam.savedRestarted") : t("steam.saved")));
      file.reload();
      onSaved();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t("steam.failed"));
    } finally {
      setSaving(false);
    }
  }

  const update = (patch: GameConfig) => setCfg((current) => ({ ...current, ...patch }));

  return (
    <div className={card}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{t("steam.config")}</h2>
          <p className="truncate font-mono text-xs text-white/50">{file.data?.path}</p>
        </div>
        {Form ? (
          <div role="tablist" className="flex rounded-2xl border border-white/10 p-0.5 text-sm">
            {(["form", "raw"] as const).map((id) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={mode === id}
                onClick={() => switchTo(id)}
                className={`rounded-xl px-3 py-1.5 transition-all duration-200 ease-in-out ${mode === id ? "bg-white/15 text-white" : "text-white/60 hover:text-white"}`}
              >
                {id === "form" ? t("steam.modeForm") : t("steam.modeRaw")}
              </button>
            ))}
          </div>
        ) : null}
      </div>
      {file.data && !file.data.exists ? <p className="mt-3 text-xs text-amber-200">{t("steam.defaultShown")}</p> : null}
      {file.error ? <p className="mt-3 text-sm text-debian">{file.error}</p> : null}

      {mode === "form" && Form ? (
        <Form cfg={cfg} update={update} />
      ) : (
        <div className="mt-4">
          <textarea
            className={`${input} h-[55vh] min-h-64 resize-y font-mono text-xs leading-relaxed`}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            aria-label={t("steam.modeRaw")}
          />
          <p className={`mt-2 text-xs ${rawError ? "text-rose-300" : "text-emerald-400"}`}>{rawError || t("steam.jsonOk")}</p>
        </div>
      )}

      {error ? <p className="mt-3 text-sm text-debian">{error}</p> : null}
      {notice ? <p className="mt-3 text-sm text-moss">{notice}</p> : null}
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" className={primary} disabled={saving || Boolean(rawError)} onClick={() => void save(false)}>
          {t("steam.save")}
        </button>
        {serverActive ? (
          <button type="button" className={button} disabled={saving || Boolean(rawError)} onClick={() => void save(true)}>
            {t("steam.saveRestart")}
          </button>
        ) : null}
      </div>
    </div>
  );
}
