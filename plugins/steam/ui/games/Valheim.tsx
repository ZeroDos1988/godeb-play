import { useTranslation } from "react-i18next";
import { button, Field, input, randomPassword, Toggle } from "../parts.tsx";
import type { ConfigFormProps } from "./types.ts";

type ServerConfig = {
  name?: string;
  world?: string;
  password?: string;
  public?: boolean;
  port?: number;
  [key: string]: unknown;
};

// ValheimForm edits godeb-valheim.json: server name, world, password,
// listing in the server browser and the port. The agent passes the values
// to the server through a root-only settings file.
export function ValheimForm({ cfg: raw, update }: ConfigFormProps) {
  const { t } = useTranslation();
  const cfg = raw as ServerConfig;
  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-3 md:grid-cols-2">
        <Field label={t("valheim.name")}>
          <input className={input} value={cfg.name ?? ""} maxLength={32} onChange={(e) => update({ name: e.target.value })} />
        </Field>
        <Field label={t("valheim.world")}>
          <input className={`${input} font-mono`} value={cfg.world ?? ""} maxLength={32} onChange={(e) => update({ world: e.target.value })} />
        </Field>
        <Field label={t("valheim.password")}>
          <div className="flex gap-2">
            <input className={`${input} font-mono`} value={cfg.password ?? ""} maxLength={32} onChange={(e) => update({ password: e.target.value })} />
            <button type="button" className={button} onClick={() => update({ password: randomPassword() })}>
              {t("ens.generate")}
            </button>
          </div>
        </Field>
        <Field label={t("valheim.port")}>
          <input className={input} type="number" min={1024} max={65534} value={cfg.port ?? 2456} onChange={(e) => update({ port: Number(e.target.value) })} />
        </Field>
      </div>
      <Toggle label={t("valheim.public")} checked={Boolean(cfg.public)} onChange={(v) => update({ public: v })} />
      <p className="text-xs text-white/60">{t("valheim.hint")}</p>
    </div>
  );
}
