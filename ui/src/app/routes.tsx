import { Link, Route, Routes } from "react-router";
import { IncidentsPage } from "../features/incidents/pages/IncidentsPage";
import { IncidentDetailPage } from "../features/incidents/pages/IncidentDetailPage";
import { RulesPage } from "../features/rules/pages/RulesPage";
import { RuleDetailPage } from "../features/rules/pages/RuleDetailPage";
import { EmptyState } from "../components/ui/EmptyState";
export function NotFoundPage() {
  const lastListHash = (() => { try { return sessionStorage.getItem("corvus-last-list-hash") || "#/"; } catch { return "#/"; } })();
  return (
    <main>
      <p><Link to={lastListHash.slice(1)}>Back to incidents</Link></p>
      <p role="alert">Page not found. <a href={lastListHash}>Back to incidents</a></p>
    </main>
  );
}
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<IncidentsPage />} />
      <Route path="/incidents" element={<IncidentsPage />} />
      <Route path="/incidents/:id" element={<IncidentDetailPage />} />
      <Route path="/rules" element={<RulesPage />} />
      <Route path="/rules/:id" element={<RuleDetailPage />} />
      <Route path="/dashboard" element={<main><EmptyState title="Dashboard" message="Coming next" /></main>} />
      <Route path="/settings" element={<main><EmptyState title="Settings" message="Coming next" /></main>} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
