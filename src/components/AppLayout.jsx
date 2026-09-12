import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  Smartphone,
  Megaphone,
  GitBranch,
  Search,
  BarChart3,
  Bell,
  History,
  Settings,
  LogOut,
  Download,
} from "lucide-react";
import Logo from "./Logo";
import ThemeToggle from "./ThemeToggle";
import { useAuth } from "../context/AuthContext";
import { stats, recentApks, campaigns } from "../data/mockData";
import { exportIntelligencePdf } from "../utils/exportPdf";
import "./AppLayout.css";

const nav = [
  { to: "/app/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/app/apk-analysis", label: "APK Analysis", icon: Smartphone },
  { to: "/app/campaigns", label: "Campaigns", icon: Megaphone },
  { to: "/app/graph", label: "Graph Explorer", icon: GitBranch },
  { to: "/app/search", label: "Search", icon: Search },
  { to: "/app/analytics", label: "Threat Analytics", icon: BarChart3 },
  { to: "/app/alerts", label: "Alerts", icon: Bell },
  { to: "/app/history", label: "History", icon: History },
  { to: "/app/settings", label: "Settings", icon: Settings },
];

export default function AppLayout() {
  const { user, logout, showToast } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/");
  };

  const handleExport = () => {
    exportIntelligencePdf({ stats, recentApks, campaigns });
    showToast("Intelligence report exported as PDF");
  };

  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <Logo size={32} textSize={20} />
          <p className="sidebar-tagline">Fraud Intelligence</p>
        </div>
        <nav className="sidebar-nav">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => (isActive ? "nav-item active" : "nav-item")}>
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-avatar">{user?.name?.[0]?.toUpperCase() || "A"}</div>
            <div>
              <div className="user-name">{user?.name}</div>
              <div className="user-role">{user?.role}</div>
            </div>
          </div>
          <button type="button" className="logout-btn" onClick={handleLogout}>
            <LogOut size={16} /> Logout
          </button>
        </div>
      </aside>
      <div className="app-main">
        <header className="app-topbar">
          <div className="topbar-search">
            <Search size={16} />
            <input
              placeholder="Search APK, SHA-256, certificate, campaign..."
              onKeyDown={(e) => {
                if (e.key === "Enter") navigate(`/app/search?q=${encodeURIComponent(e.target.value)}`);
              }}
            />
          </div>
          <div className="topbar-actions">
            <ThemeToggle />
            <button type="button" className="btn-ghost" onClick={handleExport}>
              <Download size={16} /> Export Report
            </button>
          </div>
        </header>
        <main className="app-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
