import { useTranslation } from "react-i18next";
import { button, Field, input, randomPassword, Toggle } from "../parts.tsx";
import type { ConfigFormProps } from "./types.ts";

type Group = {
  name: string;
  password?: string;
  canKickBan?: boolean;
  canAccessInventories?: boolean;
  canEditBase?: boolean;
  canExtendBase?: boolean;
  reservedSlots?: number;
  [key: string]: unknown;
};

type ServerConfig = {
  name?: string;
  slotCount?: number;
  queryPort?: number;
  gamePort?: number;
  gameSettingsPreset?: string;
  enableVoiceChat?: boolean;
  enableTextChat?: boolean;
  voiceChatMode?: string;
  userGroups?: Group[];
  [key: string]: unknown;
};

const presets = ["Default", "Relaxed", "Hard", "Survival", "Custom"];
const permissions = ["canKickBan", "canAccessInventories", "canEditBase", "canExtendBase"] as const;

const customFactors: { key: string; min: number; max: number; step: number; def: number }[] = [
  { key: "playerHealthFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "playerManaFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "playerStaminaFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "playerBodyHeatFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "foodBuffDurationFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "hungerTimeFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "playerDamageFromEnemiesFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "enemyDamageFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "enemyHealthFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "miningDamageFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "plantGrowthSpeedFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
  { key: "resourceDropAmountFactor", min: 0.25, max: 4, step: 0.05, def: 1 },
];

function CustomSettings({
  settings,
  onChange,
}: {
  settings: Record<string, number>;
  onChange: (next: Record<string, number>) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3 rounded-2xl border border-white/10 bg-white/5 p-3">
      <p className="text-xs text-white/60">{t("ens.customHint")}</p>
      <div className="grid gap-3 md:grid-cols-2">
        {customFactors.map((f) => {
          const value = typeof settings[f.key] === "number" ? settings[f.key] : f.def;
          return (
            <label key={f.key} className="block text-xs text-white/70">
              <span className="flex justify-between gap-2">
                <span>{t(`ens.factor.${f.key}`, { defaultValue: f.key })}</span>
                <span className="font-mono text-white/90">{value.toFixed(2)}</span>
              </span>
              <input
                type="range"
                min={f.min}
                max={f.max}
                step={f.step}
                value={value}
                className="mt-1 w-full"
                onChange={(e) =>
                  onChange({ ...settings, [f.key]: Number(e.target.value) })
                }
              />
            </label>
          );
        })}
      </div>
    </div>
  );
}

// EnshroudedForm edits enshrouded_server.json: name, slots, preset, ports,
// chat and the user groups with their passwords.
export function EnshroudedForm({ cfg: raw, update }: ConfigFormProps) {
  const { t } = useTranslation();
  const cfg = raw as ServerConfig;
  const groups = cfg.userGroups ?? [];
  const setGroup = (index: number, patch: Partial<Group>) =>
    update({ userGroups: groups.map((group, i) => (i === index ? { ...group, ...patch } : group)) });

  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-3 md:grid-cols-2">
        <Field label={t("ens.name")}>
          <input className={input} value={cfg.name ?? ""} maxLength={64} onChange={(e) => update({ name: e.target.value })} />
        </Field>
        <Field label={t("ens.slots")}>
          <input className={input} type="number" min={1} max={16} value={cfg.slotCount ?? 16} onChange={(e) => update({ slotCount: Number(e.target.value) })} />
        </Field>
        <Field label={t("ens.preset")}>
          <select className={input} value={cfg.gameSettingsPreset ?? "Default"} onChange={(e) => update({ gameSettingsPreset: e.target.value })}>
            {presets.map((preset) => (
              <option key={preset} value={preset}>
                {t(`ens.preset${preset}`)}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("ens.queryPort")}>
          <input className={input} type="number" min={1024} max={65535} value={cfg.queryPort ?? 15637} onChange={(e) => update({ queryPort: Number(e.target.value) })} />
        </Field>
        {cfg.gamePort !== undefined ? (
          <Field label={t("ens.gamePort")}>
            <input className={input} type="number" min={1024} max={65535} value={cfg.gamePort} onChange={(e) => update({ gamePort: Number(e.target.value) })} />
          </Field>
        ) : null}
      </div>
      {cfg.gameSettingsPreset === "Custom" ? (
        <CustomSettings
          settings={(cfg.gameSettings as Record<string, number> | undefined) ?? {}}
          onChange={(gameSettings) => update({ gameSettings })}
        />
      ) : null}

      <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
        <Toggle label={t("ens.voiceChat")} checked={cfg.enableVoiceChat ?? false} onChange={(v) => update({ enableVoiceChat: v })} />
        <Toggle label={t("ens.textChat")} checked={cfg.enableTextChat ?? false} onChange={(v) => update({ enableTextChat: v })} />
      </div>

      <div>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-xs tracking-wide text-white/60 uppercase">{t("ens.groups")}</h3>
          <button
            type="button"
            className="text-xs text-white/70 hover:text-white"
            onClick={() => update({ userGroups: [...groups, { name: `Gruppe${groups.length + 1}`, password: randomPassword(), canEditBase: true, reservedSlots: 0 }] })}
          >
            + {t("ens.addGroup")}
          </button>
        </div>
        <div className="space-y-3">
          {groups.map((group, index) => (
            <div key={index} className="rounded-2xl border border-white/10 p-3">
              <div className="grid gap-3 sm:grid-cols-[1fr_1fr_6rem]">
                <Field label={t("ens.groupName")}>
                  <input className={input} value={group.name} maxLength={32} onChange={(e) => setGroup(index, { name: e.target.value })} />
                </Field>
                <Field label={t("ens.password")}>
                  <div className="flex gap-2">
                    <input className={`${input} font-mono`} value={group.password ?? ""} maxLength={64} onChange={(e) => setGroup(index, { password: e.target.value })} />
                    <button type="button" className={button} title={t("ens.generate")} onClick={() => setGroup(index, { password: randomPassword() })}>
                      ↻
                    </button>
                  </div>
                </Field>
                <Field label={t("ens.reserved")}>
                  <input className={input} type="number" min={0} max={16} value={group.reservedSlots ?? 0} onChange={(e) => setGroup(index, { reservedSlots: Number(e.target.value) })} />
                </Field>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
                {permissions.map((perm) => (
                  <Toggle key={perm} label={t(`ens.${perm}`)} checked={group[perm] ?? false} onChange={(v) => setGroup(index, { [perm]: v })} />
                ))}
                <button type="button" className="ml-auto text-xs text-rose-300 hover:underline" onClick={() => update({ userGroups: groups.filter((_, i) => i !== index) })}>
                  {t("ens.removeGroup")}
                </button>
              </div>
            </div>
          ))}
          {groups.length === 0 ? <p className="text-xs text-white/60">{t("ens.noGroups")}</p> : null}
        </div>
      </div>
    </div>
  );
}
