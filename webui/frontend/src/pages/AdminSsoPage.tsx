import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminSubNav } from "../components/AdminSubNav";
import { ErrorState } from "../components/ErrorState";
import { Shell } from "../components/Shell";
import { apiFetch } from "../lib/apiClient";
import { useAuth } from "../lib/useAuth";
import { usePageTitle } from "../lib/usePageTitle";
import { useUnsavedChangesWarning } from "../lib/useUnsavedChangesWarning";

interface SsoConfig {
  registrationId: string;
  idpEntityId: string;
  idpSsoUrl: string;
  idpX509Cert: string;
  emailAttributeName: string;
  displayNameAttributeName: string | null;
  enabled: boolean;
  spEntityId: string;
  spAcsUrl: string;
  ssoLoginUrl: string;
}

async function fetchConfig(orgId: string): Promise<SsoConfig> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/sso`);
  if (!res.ok) throw new Error("Failed to load SSO configuration.");
  return res.json();
}

async function saveConfig(orgId: string, body: Omit<SsoConfig, "registrationId" | "spEntityId" | "spAcsUrl" | "ssoLoginUrl">): Promise<SsoConfig> {
  const res = await apiFetch(`/api/v1/orgs/${orgId}/sso`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error("Failed to save SSO configuration.");
  return res.json();
}

/** Read-only field with a copy affordance - the SP metadata an admin pastes into their IdP. */
function MetadataField({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-3">
      <p className="mb-1 font-mono text-[11px] uppercase tracking-widest text-slate-400">{label}</p>
      <code className="block break-all rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-neon-cyan">{value}</code>
    </div>
  );
}

export function AdminSsoPage() {
  usePageTitle("SSO");
  const { user } = useAuth();
  const orgId = user?.organizationId ?? "";
  const queryClient = useQueryClient();

  const configQuery = useQuery({ queryKey: ["admin-sso", orgId], queryFn: () => fetchConfig(orgId), enabled: !!orgId });

  const [idpEntityId, setIdpEntityId] = useState("");
  const [idpSsoUrl, setIdpSsoUrl] = useState("");
  const [idpX509Cert, setIdpX509Cert] = useState("");
  const [emailAttributeName, setEmailAttributeName] = useState("email");
  const [displayNameAttributeName, setDisplayNameAttributeName] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [saved, setSaved] = useState(false);
  // Which configQuery.data snapshot the fields above were last synced from - see
  // hasUnsavedChanges's own comment for why this matters (same fix as AdminSlackPage's identical
  // gap - a real, if very narrow, production race, not just test flakiness).
  const [hydratedFrom, setHydratedFrom] = useState<SsoConfig | undefined>(undefined);

  useEffect(() => {
    if (configQuery.data) {
      setIdpEntityId(configQuery.data.idpEntityId);
      setIdpSsoUrl(configQuery.data.idpSsoUrl);
      setIdpX509Cert(configQuery.data.idpX509Cert);
      setEmailAttributeName(configQuery.data.emailAttributeName || "email");
      setDisplayNameAttributeName(configQuery.data.displayNameAttributeName ?? "");
      setEnabled(configQuery.data.enabled);
    }
    setHydratedFrom(configQuery.data);
  }, [configQuery.data]);

  // Compares against the last-loaded/last-saved config, not a separate "dirty" flag to keep in
  // sync by hand - the moment a save succeeds, configQuery.data itself updates (see the
  // mutation's own onSuccess) and this naturally re-syncs to false along with it.
  //
  // hydratedFrom === configQuery.data gates this - without it, the render where configQuery.data
  // first resolves (or changes again after a save) sees the new data while idpEntityId etc. above
  // still hold their pre-sync defaults (the useEffect that copies them across hasn't run yet, since
  // effects fire after the render that scheduled them). Every field here defaults to "" - a real
  // loaded config's own values essentially never match that - so that window reliably evaluated
  // this to a false "unsaved changes" for one frame, the same bug AdminSlackPage.tsx had.
  const hasUnsavedChanges =
    hydratedFrom === configQuery.data &&
    !!configQuery.data &&
    (idpEntityId !== configQuery.data.idpEntityId ||
      idpSsoUrl !== configQuery.data.idpSsoUrl ||
      idpX509Cert !== configQuery.data.idpX509Cert ||
      emailAttributeName !== (configQuery.data.emailAttributeName || "email") ||
      displayNameAttributeName !== (configQuery.data.displayNameAttributeName ?? "") ||
      enabled !== configQuery.data.enabled);
  useUnsavedChangesWarning(hasUnsavedChanges);

  const mutation = useMutation({
    mutationFn: () =>
      saveConfig(orgId, {
        idpEntityId,
        idpSsoUrl,
        idpX509Cert,
        emailAttributeName,
        displayNameAttributeName: displayNameAttributeName || null,
        enabled,
      }),
    onSuccess: (data) => {
      queryClient.setQueryData(["admin-sso", orgId], data);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    },
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    mutation.mutate();
  }

  return (
    <Shell>
      <div className="mx-auto w-full max-w-4xl px-6 py-10">
        <div className="mb-2">
          <p className="font-mono text-sm uppercase tracking-[0.3em] text-neon-magenta">Administration</p>
          <h1 className="font-display text-2xl font-bold text-neon-cyan">SSO (SAML)</h1>
        </div>
        <AdminSubNav />

        {configQuery.isLoading && <p className="font-mono text-sm text-slate-400">Loading…</p>}
        {configQuery.isError && <ErrorState message="Failed to load SSO configuration." onRetry={() => configQuery.refetch()} />}

        {configQuery.data && (
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <div className="rounded-lg border border-neon-cyan/20 bg-panel/60 p-5">
              <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-cyan">
                1. Give this to your identity provider
              </h2>
              <p className="mb-4 font-mono text-xs text-slate-400">
                SAML setup is a two-sided exchange - your IT admin needs Bloodhound's own SP metadata to register us
                as a service provider in your IdP.
              </p>
              <MetadataField label="SP Entity ID" value={configQuery.data.spEntityId} />
              <MetadataField label="ACS URL (assertion consumer)" value={configQuery.data.spAcsUrl} />
              <MetadataField label="Sign-in URL (for your login page)" value={configQuery.data.ssoLoginUrl} />
              <p className="mt-4 font-mono text-xs text-slate-400">
                Your users sign in at <code className="text-neon-cyan">/login</code> and enter{" "}
                <code className="text-neon-cyan">{configQuery.data.registrationId}</code> under "Sign in with SSO".
              </p>
            </div>

            <form onSubmit={handleSubmit} className="rounded-lg border border-neon-magenta/20 bg-panel/60 p-5">
              <h2 className="mb-3 font-mono text-sm uppercase tracking-widest text-neon-magenta">
                2. Configure your identity provider here
              </h2>

              <label htmlFor="sso-idp-entity-id" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                IdP Entity ID
              </label>
              <input
                id="sso-idp-entity-id"
                value={idpEntityId}
                onChange={(e) => setIdpEntityId(e.target.value)}
                required
                className="mb-3 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
              />

              <label htmlFor="sso-idp-sso-url" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                IdP SSO URL
              </label>
              <input
                id="sso-idp-sso-url"
                value={idpSsoUrl}
                onChange={(e) => setIdpSsoUrl(e.target.value)}
                required
                className="mb-3 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
              />

              <label htmlFor="sso-idp-cert" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                IdP signing certificate (X.509, PEM or base64)
              </label>
              <textarea
                id="sso-idp-cert"
                value={idpX509Cert}
                onChange={(e) => setIdpX509Cert(e.target.value)}
                required
                rows={5}
                className="mb-3 w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-[10px] text-slate-200 outline-none focus:border-neon-magenta"
              />

              <div className="mb-3 grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="sso-email-attr" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                    Email attribute
                  </label>
                  <input
                    id="sso-email-attr"
                    value={emailAttributeName}
                    onChange={(e) => setEmailAttributeName(e.target.value)}
                    required
                    className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
                  />
                </div>
                <div>
                  <label htmlFor="sso-display-name-attr" className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
                    Display name attribute (optional)
                  </label>
                  <input
                    id="sso-display-name-attr"
                    value={displayNameAttributeName}
                    onChange={(e) => setDisplayNameAttributeName(e.target.value)}
                    className="w-full rounded border border-slate-700 bg-void px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-neon-magenta"
                  />
                </div>
              </div>

              <label className="mb-4 flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-slate-300">
                <input className="checkbox-cyber" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                Enabled
              </label>

              <button
                type="submit"
                disabled={mutation.isPending}
                className="w-full rounded bg-neon-magenta/90 px-4 py-2 font-mono text-sm font-bold uppercase tracking-widest text-void transition hover:bg-neon-magenta disabled:opacity-50"
              >
                {mutation.isPending ? "Saving…" : saved ? "Saved ✓" : "Save"}
              </button>
              {/* In-app echo of the same beforeunload warning below - a visible reminder while
                  still on the page, not just a surprise prompt at the moment of navigating away. */}
              {hasUnsavedChanges && !mutation.isPending && (
                <p className="mt-2 font-mono text-xs text-neon-amber">Unsaved changes.</p>
              )}
              {mutation.isError && <p className="mt-2 font-mono text-xs text-severity-critical">Failed to save.</p>}
            </form>
          </div>
        )}
      </div>
    </Shell>
  );
}
