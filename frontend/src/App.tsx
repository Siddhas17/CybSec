import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./hooks/useAuth";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AdminRoute } from "./components/AdminRoute";
import { DashboardLayout } from "./layouts/DashboardLayout";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { LiveThreats } from "./pages/LiveThreats";
import { ThreatDetails } from "./pages/ThreatDetails";
import { AttackGraph } from "./pages/AttackGraph";
import { Analytics } from "./pages/Analytics";
import { ModelInfo } from "./pages/ModelInfo";
import { ModelEvaluation } from "./pages/ModelEvaluation";
import { Reports } from "./pages/Reports";
import { DatasetManagement } from "./pages/DatasetManagement";
import { Victims } from "./pages/Victims";
import { SystemHealth } from "./pages/SystemHealth";
import { Prevention } from "./pages/Prevention";

function Protected({ children }: { children: React.ReactNode }) {
  return (
    <ProtectedRoute>
      <DashboardLayout>{children}</DashboardLayout>
    </ProtectedRoute>
  );
}

function AdminProtected({ children }: { children: React.ReactNode }) {
  return (
    <AdminRoute>
      <DashboardLayout>{children}</DashboardLayout>
    </AdminRoute>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Protected><Overview /></Protected>} />
        <Route path="/threats" element={<Protected><LiveThreats /></Protected>} />
        <Route path="/threats/:eventId" element={<Protected><ThreatDetails /></Protected>} />
        <Route path="/attack-graph" element={<Protected><AttackGraph /></Protected>} />
        <Route path="/analytics" element={<Protected><Analytics /></Protected>} />
        <Route path="/victims" element={<Protected><Victims /></Protected>} />
        <Route path="/model-info" element={<Protected><ModelInfo /></Protected>} />
        <Route path="/model-evaluation" element={<AdminProtected><ModelEvaluation /></AdminProtected>} />
        <Route path="/datasets" element={<AdminProtected><DatasetManagement /></AdminProtected>} />
        <Route path="/reports" element={<AdminProtected><Reports /></AdminProtected>} />
        <Route path="/prevention" element={<Protected><Prevention /></Protected>} />
        <Route path="/system-health" element={<Protected><SystemHealth /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
