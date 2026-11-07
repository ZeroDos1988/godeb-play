import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { api } from "@/lib/api.ts";
import { readStoredTheme } from "@/context/theme.ts";
import ar from "@/locales/ar.json";
import de from "@/locales/de.json";
import en from "@/locales/en.json";
import es from "@/locales/es.json";
import fr from "@/locales/fr.json";
import pt from "@/locales/pt.json";
import zh from "@/locales/zh.json";

export const languageStorageKey = "godeb-lang";

export const languages = [
  { id: "de", label: "Deutsch" },
  { id: "en", label: "English" },
  { id: "es", label: "Español" },
  { id: "fr", label: "Français" },
  { id: "pt", label: "Português" },
  { id: "zh", label: "中文" },
  { id: "ar", label: "العربية", dir: "rtl" },
] as const;

export type LanguageCode = (typeof languages)[number]["id"];

const supported = new Set<string>(languages.map((language) => language.id));

export function isLanguage(value: string): value is LanguageCode {
  return supported.has(value);
}

// languagePreference is the language the user picked, or "" for "follow
// the browser" (the default until someone picks one).
export function languagePreference(): LanguageCode | "" {
  try {
    const stored = localStorage.getItem(languageStorageKey);
    if (stored && isLanguage(stored)) {
      return stored;
    }
  } catch {
    /* private mode */
  }
  return "";
}

// browserLanguage is the first supported language from the browser's list.
export function browserLanguage(): LanguageCode {
  const list = navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const tag of list) {
    const base = tag.toLowerCase().split("-")[0] ?? "";
    if (isLanguage(base)) {
      return base;
    }
  }
  return "en";
}

export function detectLanguage(): LanguageCode {
  return languagePreference() || browserLanguage();
}

// applyLanguage switches the UI; "" follows the browser again.
export function applyLanguage(code: string) {
  const choice = isLanguage(code) ? code : "";
  const language = choice || browserLanguage();
  document.documentElement.lang = language;
  document.documentElement.dir = language === "ar" ? "rtl" : "ltr";
  try {
    if (choice) {
      localStorage.setItem(languageStorageKey, choice);
    } else {
      localStorage.removeItem(languageStorageKey);
    }
  } catch {
    /* ignore */
  }
  void i18n.changeLanguage(language);
}

export async function persistLanguage(code: string) {
  applyLanguage(code);
  const theme = readStoredTheme();
  await api("/api/user/settings", {
    method: "POST",
    body: JSON.stringify({
      themeMode: theme.mode,
      colorPrimary: theme.colors.primary,
      colorBg: theme.colors.bg,
      colorAccent: theme.colors.accent,
      colorText: theme.colors.text,
      language: isLanguage(code) ? code : "",
    }),
  });
}

void i18n.use(initReactI18next).init({
  resources: {
    de: { translation: de },
    en: { translation: en },
    es: { translation: es },
    fr: { translation: fr },
    pt: { translation: pt },
    zh: { translation: zh },
    ar: { translation: ar },
  },
  lng: detectLanguage(),
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

applyLanguage(languagePreference());

export default i18n;
