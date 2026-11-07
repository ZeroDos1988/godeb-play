// GoDeb Play logo: the GoDeb shield (public/logo.png) and the "GoDeb"
// lettering (public/wordmark.png) with "Play" behind it, until Play has a
// logo of its own. Sources and sizes: docs/brand/README.md.

export function Shield({ className = "h-10 w-auto" }: { className?: string }) {
  return <img src="/logo.png" alt="" aria-hidden="true" className={`${className} shrink-0 select-none`} draggable={false} />;
}

export function Wordmark({ className = "h-5 w-auto" }: { className?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 select-none" aria-label="GoDeb Play">
      <img src="/wordmark.png" alt="" aria-hidden="true" className={className} draggable={false} />
      <span aria-hidden="true" className="rounded-md bg-debian px-1.5 text-[0.7em] leading-tight font-bold tracking-wide text-on-solid uppercase">
        Play
      </span>
    </span>
  );
}
