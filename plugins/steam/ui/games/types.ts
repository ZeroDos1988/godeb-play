import type { ComponentType } from "react";

export type GameConfig = Record<string, unknown>;

// A game form edits the parsed configuration. It must keep every key it does
// not show, because the file view and later server versions rely on them.
export type ConfigFormProps = {
  cfg: GameConfig;
  update: (patch: GameConfig) => void;
};

export type ConfigForm = ComponentType<ConfigFormProps>;
