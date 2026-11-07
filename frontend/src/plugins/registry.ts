import type { ComponentType } from "react";

type PanelModule = {
  default: ComponentType;
};

const modules = import.meta.glob("../../../plugins/*/ui/Panel.tsx", {
  eager: true,
}) as Record<string, PanelModule>;

export function panelFor(id: string): ComponentType | undefined {
  const suffix = `/plugins/${id}/ui/Panel.tsx`;
  const key = Object.keys(modules).find((entry) => entry.endsWith(suffix));
  return key ? modules[key].default : undefined;
}
