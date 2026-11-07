export type PluginMeta = {
  id: string;
  name: string;
  description: string;
  icon: string;
  group: "system" | "network" | "apps";
  order: number;
  ready: boolean;
};

export type SystemInfo = {
  hostname: string;
  os: string;
  kernel: string;
  cpu: number;
  memUsed: number;
  memTotal: number;
  diskUsed: number;
  diskTotal: number;
  mocked: boolean;
  detail?: string;
};

export type CommandEnvelope = {
  command: string[];
  mocked: boolean;
  detail?: string;
};
