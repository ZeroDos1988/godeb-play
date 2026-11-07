import { useState } from "react";
import { useTranslation } from "react-i18next";
import { applyLanguage, browserLanguage, languagePreference, languages, persistLanguage } from "@/i18n.ts";

// LanguageSelect picks the UI language. "Automatic" (the default) follows
// the browser; persist stores the choice with the account as well.
export function LanguageSelect({ persist, className = "" }: { persist: boolean; className?: string }) {
  const { t } = useTranslation();
  const [choice, setChoice] = useState<string>(languagePreference());
  const auto = languages.find((l) => l.id === browserLanguage())?.label ?? "English";

  return (
    <select
      aria-label={t("common.language")}
      value={choice}
      onChange={(event) => {
        const next = event.target.value;
        setChoice(next);
        if (!persist) {
          applyLanguage(next);
          return;
        }
        void persistLanguage(next).catch(() => undefined);
      }}
      className={`rounded-2xl border border-white/10 bg-slate-900/60 px-3 py-1.5 text-sm text-white backdrop-blur-xl transition-all duration-200 ease-in-out outline-none hover:border-white/30 ${className}`}
    >
      <option value="">{t("common.languageAuto", { language: auto })}</option>
      {languages.map((language) => (
        <option key={language.id} value={language.id}>
          {language.label}
        </option>
      ))}
    </select>
  );
}
