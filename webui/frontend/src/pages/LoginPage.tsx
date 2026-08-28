import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { BloodhoundMascot } from "../components/BloodhoundMascot";
import { CenteredState } from "../components/CenteredState";
import { Shell } from "../components/Shell";
import { useAuth } from "../lib/useAuth";

export function LoginPage() {
  const { login, status } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [ssoSlug, setSsoSlug] = useState("");
  const [ssoError, setSsoError] = useState<string | null>(null);
  const [ssoChecking, setSsoChecking] = useState(false);

  useEffect(() => {
    if (status === "authenticated") {
      navigate("/dashboard", { replace: true });
    }
  }, [status, navigate]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSso(e: FormEvent) {
    e.preventDefault();
    setSsoError(null);
    const slug = ssoSlug.trim().toLowerCase();
    if (!slug) return;
    setSsoChecking(true);
    try {
      const res = await fetch(`/api/v1/public/sso/${encodeURIComponent(slug)}`);
      if (!res.ok) throw new Error("Unknown organization.");
      const data: { enabled: boolean; ssoLoginUrl: string } = await res.json();
      if (!data.enabled) throw new Error("This organization hasn't enabled SSO.");
      // Full navigation, not a fetch - SAML is a browser redirect flow that
      // central-server drives end to end (see SecurityConfig's saml2Login chain).
      window.location.href = data.ssoLoginUrl;
    } catch (err) {
      setSsoError(err instanceof Error ? err.message : "Couldn't start SSO sign-in.");
      setSsoChecking(false);
    }
  }

  return (
    <Shell>
      <CenteredState>
        <div className="flex flex-col items-center">
          <BloodhoundMascot
            title="Bloodhound"
            variant="full"
            className="mb-2 h-44 w-auto"
            style={{ filter: "drop-shadow(0 0 16px rgba(0,240,255,0.45)) drop-shadow(0 0 30px rgba(255,46,151,0.3))" }}
          />
          <form
            onSubmit={handleSubmit}
            className="w-full max-w-sm rounded-lg border border-neon-cyan/20 bg-panel/80 p-8 text-left shadow-glow-cyan backdrop-blur"
          >
            <h1 className="mb-6 text-center font-display text-xl font-bold tracking-widest text-neon-cyan">SIGN IN</h1>

            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Email</label>
            <input
              type="email"
              required
              autoComplete="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mb-4 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
            />

            <label className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">Password</label>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mb-6 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
            />

            {error && <p className="mb-4 font-mono text-xs text-severity-critical">{error}</p>}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
            >
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <form
            onSubmit={handleSso}
            className="mt-4 w-full max-w-sm rounded-lg border border-neon-magenta/20 bg-panel/60 p-6 text-left backdrop-blur"
          >
            <p className="mb-3 font-mono text-xs uppercase tracking-widest text-slate-400">
              Or sign in with your organization's SSO
            </p>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="org-slug"
                value={ssoSlug}
                onChange={(e) => setSsoSlug(e.target.value)}
                className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-neon-magenta"
              />
              <button
                type="submit"
                disabled={ssoChecking || !ssoSlug.trim()}
                className="shrink-0 rounded border border-neon-magenta/60 px-4 py-2 font-mono text-xs font-bold uppercase tracking-widest text-neon-magenta transition hover:bg-neon-magenta/10 disabled:opacity-50"
              >
                {ssoChecking ? "…" : "Continue"}
              </button>
            </div>
            {ssoError && <p className="mt-2 font-mono text-xs text-severity-critical">{ssoError}</p>}
          </form>
        </div>
      </CenteredState>
    </Shell>
  );
}
