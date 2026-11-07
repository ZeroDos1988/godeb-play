import { useTranslation } from "react-i18next";
import { useTheme } from "@/context/ThemeContext.tsx";
import { applyTheme, darkColors, lightColors, type ThemeColors, type ThemeMode } from "@/context/theme.ts";

export function ThemeSettings({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const { settings, setMode, setColors } = useTheme();
  const modes: { id: ThemeMode; label: string; hint: string }[] = [
    { id: "light", label: t("theme.light"), hint: t("theme.lightHint") },
    { id: "dark", label: t("theme.dark"), hint: t("theme.darkHint") },
    { id: "system", label: t("theme.system"), hint: t("theme.systemHint") },
    { id: "custom", label: t("theme.custom"), hint: t("theme.customHint") },
  ];
  const fields: { key: keyof ThemeColors; label: string }[] = [
    { key: "primary", label: t("theme.primary") },
    { key: "bg", label: t("theme.bg") },
    { key: "accent", label: t("theme.accent") },
    { key: "text", label: t("theme.text") },
  ];
  const preview = {
    light: lightColors,
    dark: darkColors,
    system: lightColors,
    custom: settings.colors,
  };

  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-slate-950/50 p-4 backdrop-blur-sm" role="presentation" onClick={onClose}>
      <div
        role="dialog"
        aria-labelledby="theme-title"
        className="w-full max-w-xl rounded-3xl border border-white/10 bg-slate-900/60 p-5 text-white shadow-xl backdrop-blur-xl transition-all duration-200 ease-in-out"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 id="theme-title" className="text-lg font-semibold">
              {t("theme.title")}
            </h2>
            <p className="mt-1 text-sm text-white/70">{t("theme.hint")}</p>
          </div>
          <button type="button" onClick={onClose} className="text-sm text-white/70 transition-all duration-200 ease-in-out hover:text-white">
            {t("common.close")}
          </button>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {modes.map((mode) => {
            const colors = mode.id === "system" ? lightColors : preview[mode.id];
            const active = settings.mode === mode.id;
            return (
              <button
                key={mode.id}
                type="button"
                onClick={() => setMode(mode.id)}
                onMouseEnter={() => applyTheme({ mode: mode.id, colors: mode.id === "custom" ? settings.colors : colors })}
                onMouseLeave={() => applyTheme(settings)}
                className={`rounded-2xl border p-3 text-start transition-all duration-200 ease-in-out ${
                  active ? "border-white/40 bg-white/10" : "border-white/10 hover:bg-white/5"
                }`}
              >
                <span className="mb-2 grid grid-cols-4 overflow-hidden rounded-xl">
                  <span className="h-8" style={{ background: colors.bg }} />
                  <span className="h-8" style={{ background: colors.text }} />
                  <span className="h-8" style={{ background: colors.primary }} />
                  <span className="h-8" style={{ background: colors.accent }} />
                </span>
                <span className="block text-sm font-medium">{mode.label}</span>
                <span className="block text-xs text-white/60">{mode.hint}</span>
              </button>
            );
          })}
        </div>

        {settings.mode === "custom" ? (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {fields.map((field) => (
              <label key={field.key} className="text-sm">
                <span className="mb-1 block text-xs tracking-wide text-white/50 uppercase">{field.label}</span>
                <span className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-2 py-1.5">
                  <input
                    type="color"
                    aria-label={field.label}
                    value={settings.colors[field.key]}
                    onChange={(event) => setColors({ ...settings.colors, [field.key]: event.target.value })}
                    className="h-8 w-10 cursor-pointer border-0 bg-transparent p-0"
                  />
                  <span className="font-mono text-xs">{settings.colors[field.key]}</span>
                </span>
              </label>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
