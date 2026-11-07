import { EnshroudedForm } from "./Enshrouded.tsx";
import type { ConfigForm } from "./types.ts";

// Forms per game ID. Games without an entry get the file view only.
export const forms: Record<string, ConfigForm> = {
  enshrouded: EnshroudedForm,
};
