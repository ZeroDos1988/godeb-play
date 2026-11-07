type IconProps = {
  name: string;
};

export function PluginIcon({ name }: IconProps) {
  const path = paths[name] ?? paths.server;
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="h-4 w-4">
      <path
        d={path}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

const paths: Record<string, string> = {
  server:
    "M4 6.5h16v4.5H4zM4 13h16v4.5H4zM7 8.5h.01M7 15h.01",
  upgrade:
    "M12 19V6M7 10l5-5 5 5M5 19h14",
  shield: "M12 3.5 19 6.5v6.2c0 4.2-2.9 6.7-7 8.3-4.1-1.6-7-4.1-7-8.3V6.5z",
  cogs: "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zM12 3.5v2.2M12 18.3V20.5M4.8 7.2l1.9 1.1M17.3 15.7l1.9 1.1M4.8 16.8l1.9-1.1M17.3 8.3l1.9-1.1",
  certificate:
    "M7 4.5h10v15l-5-2.5-5 2.5zM9.5 8.5h5M9.5 12h5",
  lock: "M6.5 10.5h11v9h-11zM8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5M12 14v2.5",
  network:
    "M12 12h.01M7 8.5a7 7 0 0 1 10 0M4.5 6a11 11 0 0 1 15 0M8.5 15.5h7v4h-7z",
  mail: "M4 6.5h16v11H4zM4 7l8 6 8-6",
  globe:
    "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17zM3.5 12h17M12 3.5c2.3 2.4 3.4 5.2 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.2-3.4-8.5s1.1-6.1 3.4-8.5z",
  pulse: "M3.5 12h4l2.5-6 4 12 2.5-6h4",
  dashboard: "M4 13a8 8 0 0 1 16 0M12 13l3.5-3.5M6.5 17.5h11",
  grid: "M4.5 4.5h6v6h-6zM13.5 4.5h6v6h-6zM4.5 13.5h6v6h-6zM13.5 13.5h6v6h-6z",
  sliders: "M5 7h9M18 7h1M5 17h3M12 17h7M16 5v4M10 15v4",
  log: "M6.5 4.5h11v15h-11zM9 8.5h6M9 12h6M9 15.5h3.5",
  forward: "M4 12h12M12 7.5l4.5 4.5-4.5 4.5M19.5 6v12",
  game: "M7.5 8h9a4 4 0 0 1 3.9 4.9l-.8 3.4a2 2 0 0 1-3.4.9L14 15h-4l-2.2 2.2a2 2 0 0 1-3.4-.9l-.8-3.4A4 4 0 0 1 7.5 8zM8 10.5v3M6.5 12h3M15.5 11.5h.01M17 13h.01",
};
