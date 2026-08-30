import { NavLink } from "react-router-dom";

/**
 * Shared cross-links for the admin screens (Users/Rules catalog/SSO/SCIM/Slack/MCP/Audit log) - each
 * used to hand-roll its own subset of these links, in a different order, with two of them
 * carrying a copy-pasted indentation bug. That drift meant e.g. Slack's page couldn't link
 * straight to Users, and Rules catalog couldn't reach SCIM/Slack at all. One shared nav fixes
 * both problems and gives every admin screen the same aria-current-highlighted active state
 * Shell's own top nav already uses.
 */
const ADMIN_LINKS: { to: string; label: string }[] = [
  { to: "/admin/users", label: "Users" },
  { to: "/admin/rules-catalog", label: "Rules catalog" },
  { to: "/admin/sso", label: "SSO" },
  { to: "/admin/scim", label: "SCIM" },
  { to: "/admin/slack", label: "Slack" },
  { to: "/admin/mcp", label: "MCP" },
  { to: "/admin/audit-log", label: "Audit log" },
];

const LINK_CLASS =
  "font-mono text-xs uppercase tracking-widest text-slate-400 transition hover:text-neon-cyan aria-[current=page]:text-neon-cyan";

export function AdminSubNav() {
  return (
    <nav className="mb-6 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-neon-cyan/10 pb-3">
      {ADMIN_LINKS.map((l) => (
        <NavLink key={l.to} to={l.to} className={LINK_CLASS}>
          {l.label}
        </NavLink>
      ))}
      <NavLink to="/dashboard" className={`ml-auto ${LINK_CLASS}`}>
        ← Dashboard
      </NavLink>
    </nav>
  );
}
