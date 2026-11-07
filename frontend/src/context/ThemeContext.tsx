import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { applyLanguage, languagePreference } from "@/i18n.ts";
import { ApiError, api } from "@/lib/api.ts";
import {
  applyTheme,
  defaultSettings,
  readStoredTheme,
  storeTheme,
  systemIsDark,
  type ThemeColors,
  type ThemeMode,
  type ThemeSettings,
} from "@/context/theme.ts";

type ThemeContextValue = {
  settings: ThemeSettings;
  setMode: (mode: ThemeMode) => void;
  setColors: (colors: ThemeColors) => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

type RemoteSettings = {
  themeMode: ThemeMode;
  colorPrimary: string;
  colorBg: string;
  colorAccent: string;
  colorText: string;
  language?: string;
};

function toRemote(settings: ThemeSettings): RemoteSettings {
  return {
    themeMode: settings.mode,
    colorPrimary: settings.colors.primary,
    colorBg: settings.colors.bg,
    colorAccent: settings.colors.accent,
    colorText: settings.colors.text,
    language: languagePreference(),
  };
}

function fromRemote(remote: RemoteSettings): ThemeSettings {
  return {
    mode: remote.themeMode,
    colors: {
      primary: remote.colorPrimary,
      bg: remote.colorBg,
      accent: remote.colorAccent,
      text: remote.colorText,
    },
  };
}

export function ThemeProvider({
  signedIn,
  children,
}: {
  signedIn: boolean;
  children: ReactNode;
}) {
  const [settings, setSettings] = useState<ThemeSettings>(() => readStoredTheme());
  const [prefersDark, setPrefersDark] = useState(systemIsDark);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setPrefersDark(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    applyTheme(settings, prefersDark);
    storeTheme(settings);
  }, [settings, prefersDark]);

  useEffect(() => {
    if (!signedIn) {
      return;
    }
    let cancelled = false;
    api<RemoteSettings>("/api/user/settings")
      .then((remote) => {
        if (cancelled) {
          return;
        }
        if (remote.language) {
          applyLanguage(remote.language);
        }
        setSettings(fromRemote(remote));
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 401) {
          return;
        }
      });
    return () => {
      cancelled = true;
    };
  }, [signedIn]);

  const value = useMemo<ThemeContextValue>(() => {
    function commit(next: ThemeSettings) {
      setSettings(next);
      storeTheme(next);
      applyTheme(next, prefersDark);
      if (signedIn) {
        void api("/api/user/settings", { method: "POST", body: JSON.stringify(toRemote(next)) }).catch(() => undefined);
      }
    }
    return {
      settings,
      setMode: (mode) => commit({ ...settings, mode }),
      setColors: (colors) => commit({ mode: "custom", colors }),
    };
  }, [prefersDark, settings, signedIn]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) {
    return {
      settings: defaultSettings,
      setMode: () => undefined,
      setColors: () => undefined,
    };
  }
  return value;
}
