import { EnshroudedForm } from "./Enshrouded.tsx";
import { ValheimForm } from "./Valheim.tsx";
import type { ConfigForm } from "./types.ts";

// Forms per game ID. Games without an entry get the file view only.
export const forms: Record<string, ConfigForm> = {
  enshrouded: EnshroudedForm,
  valheim: ValheimForm,
};
