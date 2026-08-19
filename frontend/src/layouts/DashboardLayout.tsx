import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { useWebSocket } from "../hooks/useWebSocket";

const NAV_ITEMS = [
  { to: "/", label: "Overview" },
  { to: "/threats", label: "Live Threats" },
  { to: "/attack-graph", label: "Attack Graph" },
  { to: "/analytics", label: "Analytics" },
  { to: "/model-info", label: "Model Information" },
  { to: "/prevention", label: "Prevention & Response" },
  { to: "/system-health", label: "System Health" },
];

export function DashboardLayout({ children }: { children: ReactNode }) {
  const { username, logout } = useAuth();
  const { status } = useWebSocket();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          Attack Graph &amp; Anomaly
          <br />
          Detection System
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="pill" style={{ marginBottom: 6 }}>
            <span className={`dot ${status === "connected" ? "ok" : status === "connecting" ? "warn" : "bad"}`} />
            Live feed: {status}
          </div>
          <div>{username}</div>
          <button className="secondary" style={{ marginTop: 8, width: "100%" }} onClick={logout}>
            Log out
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
