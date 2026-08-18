import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./hooks/useAuth";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { DashboardLayout } from "./layouts/DashboardLayout";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { LiveThreats } from "./pages/LiveThreats";
import { ThreatDetails } from "./pages/ThreatDetails";
import { AttackGraph } from "./pages/AttackGraph";
import { Analytics } from "./pages/Analytics";
import { ModelInfo } from "./pages/ModelInfo";
import { SystemHealth } from "./pages/SystemHealth";

function Protected({ children }: { children: React.ReactNode }) {
  return (
    <ProtectedRoute>
      <DashboardLayout>{children}</DashboardLayout>
    </ProtectedRoute>
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
        <Route path="/model-info" element={<Protected><ModelInfo /></Protected>} />
        <Route path="/system-health" element={<Protected><SystemHealth /></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
