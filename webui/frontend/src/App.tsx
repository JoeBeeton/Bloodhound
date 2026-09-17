import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { CenteredState } from "./components/CenteredState";
import { RequireAdmin } from "./components/RequireAdmin";
import { RequireAuth } from "./components/RequireAuth";
import { Shell } from "./components/Shell";

// Every page used to be bundled into one ~850KB chunk, loaded in full before anything - including
// a first-time visitor who's never seen anything past /login - could render at all. A performance
// review found this was purely accidental: nothing about the app actually needs every admin page,
// every detail view, and the login screen in the same download. React.lazy + route-level code
// splitting means Vite ships each page as its own chunk, fetched only once its route is actually
// visited - LoginPage (what every unauthenticated visitor waits on) now ships alone, and a user
// who never opens /admin/scim never downloads its code at all. .then(m => ({ default: m.X }))
// because every page here is a named export, not a default one (React.lazy requires a default).
const LoginPage = lazy(() => import("./pages/LoginPage").then((m) => ({ default: m.LoginPage })));
const SsoCallbackPage = lazy(() => import("./pages/SsoCallbackPage").then((m) => ({ default: m.SsoCallbackPage })));
const DashboardPage = lazy(() => import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const TargetsPage = lazy(() => import("./pages/TargetsPage").then((m) => ({ default: m.TargetsPage })));
const PortfoliosPage = lazy(() => import("./pages/PortfoliosPage").then((m) => ({ default: m.PortfoliosPage })));
const PortfolioDetailPage = lazy(() =>
  import("./pages/PortfolioDetailPage").then((m) => ({ default: m.PortfolioDetailPage })),
);
const FindingsPage = lazy(() => import("./pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const FindingsFeedPage = lazy(() => import("./pages/FindingsFeedPage").then((m) => ({ default: m.FindingsFeedPage })));
const TargetDetailPage = lazy(() => import("./pages/TargetDetailPage").then((m) => ({ default: m.TargetDetailPage })));
const SubdomainsPage = lazy(() => import("./pages/SubdomainsPage").then((m) => ({ default: m.SubdomainsPage })));
const SubdomainDetailPage = lazy(() =>
  import("./pages/SubdomainDetailPage").then((m) => ({ default: m.SubdomainDetailPage })),
);
const ApiKeysPage = lazy(() => import("./pages/ApiKeysPage").then((m) => ({ default: m.ApiKeysPage })));
const SessionsPage = lazy(() => import("./pages/SessionsPage").then((m) => ({ default: m.SessionsPage })));
const AttackSurfaceMapPage = lazy(() =>
  import("./pages/AttackSurfaceMapPage").then((m) => ({ default: m.AttackSurfaceMapPage })),
);
const ComparePage = lazy(() => import("./pages/ComparePage").then((m) => ({ default: m.ComparePage })));
const ScansPage = lazy(() => import("./pages/ScansPage").then((m) => ({ default: m.ScansPage })));
const ScanDetailPage = lazy(() => import("./pages/ScanDetailPage").then((m) => ({ default: m.ScanDetailPage })));
const AdminUsersPage = lazy(() => import("./pages/AdminUsersPage").then((m) => ({ default: m.AdminUsersPage })));
const AdminRulesCatalogPage = lazy(() =>
  import("./pages/AdminRulesCatalogPage").then((m) => ({ default: m.AdminRulesCatalogPage })),
);
const AdminSsoPage = lazy(() => import("./pages/AdminSsoPage").then((m) => ({ default: m.AdminSsoPage })));
const AdminScimPage = lazy(() => import("./pages/AdminScimPage").then((m) => ({ default: m.AdminScimPage })));
const AdminSlackPage = lazy(() => import("./pages/AdminSlackPage").then((m) => ({ default: m.AdminSlackPage })));
const AdminMcpPage = lazy(() => import("./pages/AdminMcpPage").then((m) => ({ default: m.AdminMcpPage })));
const AdminAuditLogPage = lazy(() =>
  import("./pages/AdminAuditLogPage").then((m) => ({ default: m.AdminAuditLogPage })),
);

/** Matches RequireAuth's own "Checking session…" loading style - shown for the brief moment a
 * route's chunk is still being fetched, same visual language as every other transient loading
 * state in the app rather than a generic spinner. */
function RouteLoadingFallback() {
  return (
    <Shell>
      <CenteredState>
        <p className="font-mono text-sm uppercase tracking-widest text-slate-400">Loading…</p>
      </CenteredState>
    </Shell>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<RouteLoadingFallback />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/sso/callback" element={<SsoCallbackPage />} />
          <Route
            path="/dashboard"
            element={
              <RequireAuth>
                <DashboardPage />
              </RequireAuth>
            }
          />
          <Route
            path="/targets"
            element={
              <RequireAuth>
                <TargetsPage />
              </RequireAuth>
            }
          />
          <Route
            path="/portfolios"
            element={
              <RequireAuth>
                <PortfoliosPage />
              </RequireAuth>
            }
          />
          <Route
            path="/portfolios/:id"
            element={
              <RequireAuth>
                <PortfolioDetailPage />
              </RequireAuth>
            }
          />
          <Route
            path="/findings"
            element={
              <RequireAuth>
                <FindingsPage />
              </RequireAuth>
            }
          />
          <Route
            path="/findings/feed"
            element={
              <RequireAuth>
                <FindingsFeedPage />
              </RequireAuth>
            }
          />
          <Route
            path="/targets/:id"
            element={
              <RequireAuth>
                <TargetDetailPage />
              </RequireAuth>
            }
          />
          <Route
            path="/targets/:id/subdomains"
            element={
              <RequireAuth>
                <SubdomainsPage />
              </RequireAuth>
            }
          />
          <Route
            path="/targets/:id/subdomains/:hostname"
            element={
              <RequireAuth>
                <SubdomainDetailPage />
              </RequireAuth>
            }
          />
          <Route
            path="/settings/api-keys"
            element={
              <RequireAuth>
                <ApiKeysPage />
              </RequireAuth>
            }
          />
          <Route
            path="/settings/sessions"
            element={
              <RequireAuth>
                <SessionsPage />
              </RequireAuth>
            }
          />
          <Route
            path="/map"
            element={
              <RequireAuth>
                <AttackSurfaceMapPage />
              </RequireAuth>
            }
          />
          <Route
            path="/compare"
            element={
              <RequireAuth>
                <ComparePage />
              </RequireAuth>
            }
          />
          <Route
            path="/scans"
            element={
              <RequireAuth>
                <ScansPage />
              </RequireAuth>
            }
          />
          <Route
            path="/scans/:id"
            element={
              <RequireAuth>
                <ScanDetailPage />
              </RequireAuth>
            }
          />
          <Route
            path="/admin/users"
            element={
              <RequireAdmin>
                <AdminUsersPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/rules-catalog"
            element={
              <RequireAdmin>
                <AdminRulesCatalogPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/sso"
            element={
              <RequireAdmin>
                <AdminSsoPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/scim"
            element={
              <RequireAdmin>
                <AdminScimPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/slack"
            element={
              <RequireAdmin>
                <AdminSlackPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/mcp"
            element={
              <RequireAdmin>
                <AdminMcpPage />
              </RequireAdmin>
            }
          />
          <Route
            path="/admin/audit-log"
            element={
              <RequireAdmin>
                <AdminAuditLogPage />
              </RequireAdmin>
            }
          />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
