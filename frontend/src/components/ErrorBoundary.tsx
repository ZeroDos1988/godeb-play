import { Component, type ErrorInfo, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import * as ui from "@/components/ui.ts";

type Props = { children: ReactNode; resetKey: string };
type State = { error: Error | null };

// ErrorBoundary keeps a crashing view from taking the whole interface with
// it: without it React unmounts everything and the page turns blank. It
// resets when resetKey (the route) changes.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("GoDeb-Ansicht abgestürzt", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return <Crashed error={this.state.error} onRetry={() => this.setState({ error: null })} />;
    }
    return this.props.children;
  }
}

function Crashed({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-3xl border border-rose-300/30 bg-rose-950/50 p-5 text-white backdrop-blur-xl">
      <h1 className="text-lg font-semibold">{t("app.crashTitle")}</h1>
      <p className="mt-1 text-sm text-white/70">{t("app.crashText")}</p>
      <pre className="mt-3 overflow-x-auto rounded-2xl bg-black/30 p-3 font-mono text-xs whitespace-pre-wrap text-rose-100">{error.message}</pre>
      <button
        type="button"
        onClick={onRetry}
        className={`${ui.button} mt-3`}
      >
        {t("app.crashRetry")}
      </button>
    </section>
  );
}
