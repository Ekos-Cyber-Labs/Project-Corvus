import { LayoutDashboard, ScrollText, Settings, Shield } from "lucide-react";
import { Link, useLocation } from "react-router";
import sidebarStyles from "./Sidebar.module.css";
export function Sidebar({ theme, onToggleTheme }: { theme: string; onToggleTheme: () => void }) {
  const location = useLocation();
  const path = location.pathname;
  const isDashboard = path === "/dashboard";
  const isIncidents = path === "/" || path === "/incidents" || path.startsWith("/incidents/");
  const isRules = path === "/rules" || path.startsWith("/rules/");
  const isSettings = path === "/settings";
  return (
    <div className={sidebarStyles.sidebarRoot}>
      <div className="sidebar-brand"><Shield size={22} /><div><h1>Corvus</h1><p className="muted tagline">Every claim is verifiable: severity, timeline, trace, and cost cite stored evidence.</p></div></div>
      <nav aria-label="Sections" className="sidebar-nav">
        <Link to="/dashboard" aria-current={isDashboard ? "page" : undefined}><LayoutDashboard size={18} /> Dashboard</Link>
        <Link to="/incidents" aria-current={isIncidents ? "page" : undefined}><Shield size={18} /> Incidents</Link>
        <Link to="/rules" aria-current={isRules ? "page" : undefined}><ScrollText size={18} /> Rules</Link>
        <Link to="/settings" aria-current={isSettings ? "page" : undefined}><Settings size={18} /> Settings</Link>
      </nav>
      <button type="button" aria-label="Toggle color theme" onClick={onToggleTheme}>{theme === "dark" ? "Light theme" : "Dark theme"}</button>
    </div>
  );
}
