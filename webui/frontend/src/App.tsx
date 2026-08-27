import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { RequireAdmin } from "./components/RequireAdmin";
import { RequireAuth } from "./components/RequireAuth";
import { AdminRulesCatalogPage } from "./pages/AdminRulesCatalogPage";
import { AdminScimPage } from "./pages/AdminScimPage";
import { AdminSlackPage } from "./pages/AdminSlackPage";
import { AdminUsersPage } from "./pages/AdminUsersPage";
import { ApiKeysPage } from "./pages/ApiKeysPage";
import { AttackSurfaceMapPage } from "./pages/AttackSurfaceMapPage";
import { ComparePage } from "./pages/ComparePage";
import { DashboardPage } from "./pages/DashboardPage";
import { AdminSsoPage } from "./pages/AdminSsoPage";
import { LoginPage } from "./pages/LoginPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ScansPage } from "./pages/ScansPage";
import { SsoCallbackPage } from "./pages/SsoCallbackPage";
import { SubdomainDetailPage } from "./pages/SubdomainDetailPage";
import { SubdomainsPage } from "./pages/SubdomainsPage";
import { TargetDetailPage } from "./pages/TargetDetailPage";
import { TargetsPage } from "./pages/TargetsPage";

export default function App() {
  return (
    <BrowserRouter>
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
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
