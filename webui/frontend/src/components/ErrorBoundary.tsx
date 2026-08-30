import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * React error boundaries must be class components - hooks can't implement
 * getDerivedStateFromError/componentDidCatch. A product/AppSec review found none existed
 * anywhere: any unhandled render-time exception (malformed API data, a bug in a chart library, a
 * null reference in a new feature) unmounted the entire React app, leaving a blank white page
 * with zero indication of what happened or how to recover - a genuinely bad failure mode for a
 * security tool people may be relying on mid-incident.
 *
 * Wraps the whole app (see main.tsx), above the router - not individual routes, and deliberately
 * doesn't reuse Shell or any other app chrome for its fallback UI. If whatever crashed is itself
 * part of that chrome (or the router), reusing it here risks the fallback crashing too; this
 * renders from nothing but plain HTML/Tailwind classes.
 *
 * Both recovery actions are plain <a>/full navigations, not React Router - once tripped, nothing
 * below this boundary (including the router) is still mounted, so anything depending on React
 * state or context being intact is exactly what shouldn't be trusted here.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // eslint-disable-next-line no-console
    console.error("Unhandled error caught by ErrorBoundary:", error, info.componentStack);
  }

  render() {
    if (!this.state.error) {
      return this.props.children;
    }
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-void px-6 text-center">
        <p className="font-display text-2xl font-bold text-severity-critical">Something went wrong</p>
        <p className="max-w-md font-mono text-sm text-slate-400">
          An unexpected error occurred and this page couldn't continue. Your session should still be intact -
          reloading usually fixes it.
        </p>
        <div className="flex gap-3">
          <a
            href={window.location.pathname}
            className="rounded bg-neon-magenta/90 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta"
          >
            Reload this page
          </a>
          <a
            href="/dashboard"
            className="rounded border border-neon-cyan/40 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-neon-cyan transition hover:bg-neon-cyan/10"
          >
            Go to Dashboard
          </a>
        </div>
      </div>
    );
  }
}
