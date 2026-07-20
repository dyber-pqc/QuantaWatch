import { Routes, Route } from "react-router-dom";
import { AppShell, Box } from "@mantine/core";
import Sidebar from "./components/Sidebar";
import TopBar from "./components/TopBar";
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

export default function App() {
  return (
    <AppShell
      layout="alt"
      navbar={{ width: 236, breakpoint: "sm" }}
      header={{ height: 52 }}
      padding="lg"
    >
      <AppShell.Navbar bg="dark.9" style={{ borderColor: "var(--mantine-color-dark-5)" }}>
        <Sidebar />
      </AppShell.Navbar>
      <AppShell.Header bg="dark.9" style={{ borderColor: "var(--mantine-color-dark-5)" }}>
        <TopBar />
      </AppShell.Header>
      <AppShell.Main bg="dark.8">
        <Box maw={1200} mx="auto">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/posture" element={<PosturePage />} />
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/attack-paths" element={<AttackPathsPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/compliance" element={<CompliancePage />} />
            <Route path="/soc2" element={<Soc2Page />} />
            <Route path="/frameworks" element={<FrameworksPage />} />
            <Route path="/rbac" element={<RbacPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/integrations" element={<IntegrationsPage />} />
          </Routes>
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}
