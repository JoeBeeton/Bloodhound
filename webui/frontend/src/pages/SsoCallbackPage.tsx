import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { CenteredState } from "../components/CenteredState";
import { Shell } from "../components/Shell";
import { useAuth } from "../lib/useAuth";

/**
 * Lands here after a SAML login redirect from central-server, carrying a
 * one-time handoff code (?code=...) - never the real tokens themselves. See
 * SamlAuthenticationSuccessHandler / SsoHandoffCodeRepository for why.
 */
export function SsoCallbackPage() {
  const [searchParams] = useSearchParams();
  const { completeSsoLogin } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const ranOnce = useRef(false);

  useEffect(() => {
    if (ranOnce.current) return;
    ranOnce.current = true;
    const code = searchParams.get("code");
    if (!code) {
      setError("No SSO code was present in the callback URL.");
      return;
    }
    completeSsoLogin(code)
      .then(() => navigate("/dashboard", { replace: true }))
      .catch((err) => setError(err instanceof Error ? err.message : "SSO sign-in failed."));
  }, [searchParams, completeSsoLogin, navigate]);

  return (
    <Shell>
      <CenteredState>
        <div className="max-w-sm text-center">
          {error ? (
            <>
              <p className="mb-4 font-mono text-sm text-severity-critical">{error}</p>
              <a href="/login" className="font-mono text-xs uppercase tracking-widest text-neon-cyan hover:underline">
                Back to sign in
              </a>
            </>
          ) : (
            <p className="font-mono text-sm text-slate-400">Completing sign-in…</p>
          )}
        </div>
      </CenteredState>
    </Shell>
  );
}
