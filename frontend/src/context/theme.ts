export type ThemeMode = "light" | "dark" | "system" | "custom";

export type ThemeColors = {
  primary: string;
  bg: string;
  accent: string;
  text: string;
};

export type ThemeSettings = {
  mode: ThemeMode;
  colors: ThemeColors;
};

export const themeStorageKey = "godeb-theme";

// Colours of the logo (docs/brand/README.md): red "Deb", cyan "Go", the
// navy of the shield. Light mode darkens red and cyan a little so text in
// these colours stays readable on white.
export const lightColors: ThemeColors = {
  primary: "#b8304f",
  bg: "#eef2f7",
  accent: "#0b86ad",
  text: "#14243a",
};

export const darkColors: ThemeColors = {
  primary: "#d9466a",
  bg: "#0d1828",
  accent: "#14afdd",
  text: "#e6edf5",
};

export const defaultSettings: ThemeSettings = {
  mode: "system",
  colors: { ...lightColors },
};

const hex = /^#[0-9a-fA-F]{6}$/;

export function isThemeMode(value: string): value is ThemeMode {
  return value === "light" || value === "dark" || value === "system" || value === "custom";
}

export function sanitizeColors(input: Partial<ThemeColors> | undefined, fallback: ThemeColors): ThemeColors {
  return {
    primary: validHex(input?.primary, fallback.primary),
    bg: validHex(input?.bg, fallback.bg),
    accent: validHex(input?.accent, fallback.accent),
    text: validHex(input?.text, fallback.text),
  };
}

function validHex(value: string | undefined, fallback: string) {
  return value && hex.test(value) ? value : fallback;
}

export function systemIsDark() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function resolvedColors(settings: ThemeSettings, prefersDark: boolean): ThemeColors {
  if (settings.mode === "custom") {
    return settings.colors;
  }
  if (settings.mode === "dark" || (settings.mode === "system" && prefersDark)) {
    return darkColors;
  }
  return lightColors;
}

function channel(color: string, offset: number) {
  return Number.parseInt(color.slice(offset, offset + 2), 16);
}

function luminance(color: string) {
  const r = channel(color, 1) / 255;
  const g = channel(color, 3) / 255;
  const b = channel(color, 5) / 255;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function mix(base: string, target: string, amount: number) {
  const value = [1, 3, 5]
    .map((offset) => {
      const from = channel(base, offset);
      const to = channel(target, offset);
      return Math.round(from + (to - from) * amount)
        .toString(16)
        .padStart(2, "0");
    })
    .join("");
  return `#${value}`;
}

export function themeVars(colors: ThemeColors, dark: boolean): Record<string, string> {
  const surface = dark ? mix(colors.bg, "#ffffff", 0.06) : mix(colors.bg, "#ffffff", 0.85);
  const border = dark ? mix(colors.bg, "#ffffff", 0.18) : mix(colors.bg, colors.text, 0.14);
  const muted = dark ? mix(colors.text, colors.bg, 0.28) : mix(colors.text, colors.bg, 0.38);
  return {
    "--color-primary": colors.primary,
    "--color-bg": colors.bg,
    "--color-text": colors.text,
    "--color-accent": colors.accent,
    "--color-surface": surface,
    "--color-border": border,
    "--color-muted-fg": muted,
    // Top bar: the dark of the theme (navy like the shield in light mode).
    "--color-sidebar-bg": luminance(colors.text) > 0.6 ? mix(colors.bg, "#000000", 0.25) : colors.text,
    "--gd-sidebar-fg": luminance(colors.text) > 0.6 ? colors.text : colors.bg,
  };
}

export function applyTheme(settings: ThemeSettings, prefersDark = systemIsDark()) {
  const colors = resolvedColors(settings, prefersDark);
  const dark = settings.mode === "dark" || (settings.mode === "system" && prefersDark) || (settings.mode === "custom" && luminance(colors.bg) < 0.45);
  const vars = themeVars(colors, dark);
  for (const [name, value] of Object.entries(vars)) {
    document.documentElement.style.setProperty(name, value);
  }
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
  return vars;
}

export function readStoredTheme(): ThemeSettings {
  try {
    const raw = localStorage.getItem(themeStorageKey);
    if (!raw) {
      return defaultSettings;
    }
    const parsed = JSON.parse(raw) as Partial<ThemeSettings>;
    const mode = typeof parsed.mode === "string" && isThemeMode(parsed.mode) ? parsed.mode : "system";
    return { mode, colors: sanitizeColors(parsed.colors, lightColors) };
  } catch {
    return defaultSettings;
  }
}

export function storeTheme(settings: ThemeSettings) {
  localStorage.setItem(themeStorageKey, JSON.stringify(settings));
}
