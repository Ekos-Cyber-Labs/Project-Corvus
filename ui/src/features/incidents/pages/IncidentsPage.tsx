import { useCallback, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { buildDetailHash, buildListHash, parseHash, type ListFilters } from "../../../lib/hash";
import { useIncidents } from "../hooks/useIncidents";
import { IncidentFilterBar } from "../components/IncidentFilterBar";
import { IncidentList } from "../components/IncidentList";
import { Skeleton } from "../../../components/ui/Skeleton";
import { PageHeader } from "../../../components/layout/PageHeader";
import { Spinner } from "../../../components/ui/Spinner";
import { ErrorState } from "../../../components/ui/ErrorState";
import pageStyles from "./IncidentsPage.module.css";
export function IncidentsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [retryNonce, setRetryNonce] = useState(0);
  const filters = useMemo<ListFilters>(() => {
    const route = parseHash(`#${location.pathname}${location.search}`);
    return route.view === "list" ? route : { page: 0, minFloor: null, verdict: null, analyzed: null };
  }, [location.pathname, location.search]);
  const listHash = buildListHash(filters);
  try { sessionStorage.setItem("corvus-last-list-hash", listHash); } catch { }
  const pageSize = 20;
  const { items, total, state } = useIncidents(filters, pageSize, retryNonce);
  const go = useCallback((hash: string) => { navigate(hash.slice(1)); }, [navigate]);
  const setFilters = useCallback((next: ListFilters) => { go(buildListHash(next)); }, [go]);
  const open = useCallback((id: number) => { go(buildDetailHash(id)); }, [go]);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const filterDesc = [
    filters.minFloor !== null ? `floor at least ${filters.minFloor}` : null,
    filters.verdict ? `verdict ${filters.verdict}` : null,
    filters.analyzed !== null ? (filters.analyzed ? "analyzed only" : "not analyzed only") : null,
  ].filter(Boolean).join(", ");
  return (
    <main className={pageStyles.pageRoot}><PageHeader title="Incidents" />
      <IncidentFilterBar filters={filters} onChange={setFilters} />
      {state === "loading" ? <div aria-live="polite"><p>Loading incidents…</p><Spinner label="Loading incidents" /><Skeleton /></div>
        : state === "error" ? <ErrorState message="Could not load incidents. Check that the API and database are running, then reload." onRetry={retry} /> : (
        <IncidentList items={items} total={total} page={filters.page} setPage={(n) => setFilters({ ...filters, page: n })} pageSize={pageSize} onSelect={open}
          onStripFilter={(patch) => setFilters({ ...filters, ...patch, page: 0 })}
          emptyMessage={filterDesc ? `No incidents found matching ${filterDesc}.` : "No incidents found."} />
      )}
    </main>
  );
}
