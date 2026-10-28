import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { BloodhoundMascot } from "../components/BloodhoundMascot";
import { CenteredState } from "../components/CenteredState";
import { Shell } from "../components/Shell";
import { forgotPassword } from "../lib/authClient";
import { usePageTitle } from "../lib/usePageTitle";

/**
 * Always ends in the same "check your email" state regardless of whether the address actually
 * matched an account - see authClient#forgotPassword's own comment for why the frontend must not
 * undo that enumeration protection by branching on the outcome itself. The only thing that can
 * actually surface as an error here is rate-limiting (a real signal: "slow down", not "this
 * account does or doesn't exist").
 */
export function ForgotPasswordPage() {
  usePageTitle("Forgot Password");
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Shell>
      <CenteredState>
        <div className="flex flex-col items-center">
          <BloodhoundMascot title="Bloodhound" variant="full" className="mb-2 h-44 w-auto" />
          <div className="w-full max-w-sm rounded-lg border border-neon-cyan/20 bg-panel/80 p-8 text-left shadow-glow-cyan backdrop-blur">
            {sent ? (
              <>
                <h1 className="mb-4 text-center font-display text-xl font-bold tracking-widest text-neon-cyan">
                  CHECK YOUR EMAIL
                </h1>
                <p className="mb-6 font-mono text-xs text-slate-300">
                  If an account exists for <span className="text-slate-100">{email}</span>, a reset link is on its
                  way. It expires in an hour.
                </p>
              </>
            ) : (
              <>
                <h1 className="mb-6 text-center font-display text-xl font-bold tracking-widest text-neon-cyan">
                  FORGOT PASSWORD
                </h1>
                <form onSubmit={handleSubmit}>
                  <label
                    htmlFor="forgot-email"
                    className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400"
                  >
                    Email
                  </label>
                  <input
                    id="forgot-email"
                    type="email"
                    required
                    autoComplete="email"
                    autoFocus
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
                  />
                  {error && <p className="mb-4 font-mono text-xs text-severity-critical">{error}</p>}
                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
                  >
                    {submitting ? "Sending…" : "Send reset link"}
                  </button>
                </form>
              </>
            )}
            <p className="mt-4 text-center font-mono text-[11px] text-slate-500">
              <Link to="/login" className="text-neon-cyan hover:underline">
                Back to sign in
              </Link>
            </p>
          </div>
        </div>
      </CenteredState>
    </Shell>
  );
}
