import { Routes, Route } from "react-router-dom";
import IdeShell from "./components/IdeShell";
import DashboardPage from "./pages/DashboardPage";
import SessionsPage from "./pages/SessionsPage";
import AuditPage from "./pages/AuditPage";
import ThreatsPage from "./pages/ThreatsPage";
import PosturePage from "./pages/PosturePage";
import ScansPage from "./pages/ScansPage";
import IntegrationsPage from "./pages/IntegrationsPage";
import AgentsPage from "./pages/AgentsPage";
import AttackPathsPage from "./pages/AttackPathsPage";
import AssetsPage from "./pages/AssetsPage";
import CompliancePage from "./pages/CompliancePage";
import AlertsPage from "./pages/AlertsPage";
import Soc2Page from "./pages/Soc2Page";
import RbacPage from "./pages/RbacPage";
import FrameworksPage from "./pages/FrameworksPage";
import CryptoPoliciesPage from "./pages/CryptoPoliciesPage";
import RemediationsPage from "./pages/RemediationsPage";

export default function App() {
  return (
    <IdeShell>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/posture" element={<PosturePage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/attack-paths" element={<AttackPathsPage />} />
        <Route path="/remediations" element={<RemediationsPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/compliance" element={<CompliancePage />} />
        <Route path="/soc2" element={<Soc2Page />} />
        <Route path="/frameworks" element={<FrameworksPage />} />
        <Route path="/crypto-policies" element={<CryptoPoliciesPage />} />
        <Route path="/rbac" element={<RbacPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/integrations" element={<IntegrationsPage />} />
      </Routes>
    </IdeShell>
  );
}
