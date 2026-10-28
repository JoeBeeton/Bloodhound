import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { BloodhoundMascot } from "../components/BloodhoundMascot";
import { CenteredState } from "../components/CenteredState";
import { PasswordInput } from "../components/PasswordInput";
import { Shell } from "../components/Shell";
import { resetPassword } from "../lib/authClient";
import { usePageTitle } from "../lib/usePageTitle";

const MIN_PASSWORD_LENGTH = 8;

/** Reached only via the link emailed by ForgotPasswordPage's own request - the token lives in the URL, not any app state, since this page can be opened cold in a fresh tab/browser. */
export function ResetPasswordPage() {
  usePageTitle("Reset Password");
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const newPasswordLongEnough = newPassword.length >= MIN_PASSWORD_LENGTH;
  const passwordsMatch = confirmPassword.length > 0 && newPassword === confirmPassword;
  const canSubmit = Boolean(token) && newPasswordLongEnough && passwordsMatch;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!newPasswordLongEnough) {
      setError(`New password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (!passwordsMatch) {
      setError("Passwords don't match.");
      return;
    }
    if (!token) {
      setError("This reset link is missing its token - use the link from your email.");
      return;
    }
    setSubmitting(true);
    try {
      await resetPassword(token, newPassword);
      setDone(true);
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
            {!token ? (
              <>
                <h1 className="mb-4 text-center font-display text-xl font-bold tracking-widest text-severity-critical">
                  INVALID LINK
                </h1>
                <p className="mb-6 font-mono text-xs text-slate-300">
                  This reset link is missing its token. Request a new one from the forgot-password page.
                </p>
              </>
            ) : done ? (
              <>
                <h1 className="mb-4 text-center font-display text-xl font-bold tracking-widest text-neon-cyan">
                  PASSWORD RESET
                </h1>
                <p className="mb-6 font-mono text-xs text-slate-300">
                  Your password has been changed. Sign in with your new password.
                </p>
              </>
            ) : (
              <>
                <h1 className="mb-6 text-center font-display text-xl font-bold tracking-widest text-neon-cyan">
                  SET NEW PASSWORD
                </h1>
                <form onSubmit={handleSubmit} className="flex flex-col gap-3">
                  <div>
                    <PasswordInput
                      id="reset-new-password"
                      label="New password"
                      required
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={setNewPassword}
                    />
                    {newPassword.length > 0 && (
                      <p
                        className={`mt-1 font-mono text-[11px] ${newPasswordLongEnough ? "text-neon-cyan" : "text-slate-500"}`}
                      >
                        {newPasswordLongEnough ? "✓" : "○"} At least {MIN_PASSWORD_LENGTH} characters
                      </p>
                    )}
                  </div>
                  <div>
                    <PasswordInput
                      id="reset-confirm-password"
                      label="Confirm new password"
                      required
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={setConfirmPassword}
                    />
                    {confirmPassword.length > 0 && (
                      <p
                        className={`mt-1 font-mono text-[11px] ${passwordsMatch ? "text-neon-cyan" : "text-severity-high"}`}
                      >
                        {passwordsMatch ? "✓ Passwords match" : "✕ Passwords don't match"}
                      </p>
                    )}
                  </div>
                  {error && <p className="font-mono text-xs text-severity-critical">{error}</p>}
                  <button
                    type="submit"
                    disabled={submitting || !canSubmit}
                    className="mt-1 w-full rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
                  >
                    {submitting ? "Resetting…" : "Reset password"}
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
