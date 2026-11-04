import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { buildDetailHash, buildListHash, parseHash, type ListFilters } from "../../../lib/hash";
import { listQuarantined } from "../utils/incidents";
import { useIncidents } from "../hooks/useIncidents";
import { IncidentFilterBar } from "../components/IncidentFilterBar";
import { IncidentList } from "../components/IncidentList";
import { IncidentPreview } from "../components/IncidentPreview";
import { Skeleton } from "../../../components/ui/Skeleton";
import { PageHeader } from "../../../components/layout/PageHeader";
import { Spinner } from "../../../components/ui/Spinner";
import { ErrorState } from "../../../components/ui/ErrorState";
import pageStyles from "./IncidentsPage.module.css";
function matchesQuery(title: string, id: number, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return title.toLowerCase().includes(needle) || String(id).includes(needle);
}
export function IncidentsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [retryNonce, setRetryNonce] = useState(0);
  const filters = useMemo<ListFilters>(() => {
    const route = parseHash(`#${location.pathname}${location.search}`);
    return route.view === "list" ? route : { page: 0, minFloor: null, verdict: null, analyzed: null, q: null, quarantined: null };
  }, [location.pathname, location.search]);
  const listHash = buildListHash(filters);
  try { sessionStorage.setItem("corvus-last-list-hash", listHash); } catch { }
  const pageSize = 20;
  const { items, total, state } = useIncidents(filters, pageSize, retryNonce);
  const shown = useMemo(() => items.filter((it) => {
    if (filters.quarantined === true && !listQuarantined(it)) return false;
    if (!matchesQuery(it.title, it.id, filters.q ?? "")) return false;
    return true;
  }), [items, filters.q, filters.quarantined]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  useEffect(() => {
    if (shown.length && (selectedId === null || !shown.some((it) => it.id === selectedId))) setSelectedId(shown[0].id);
    if (!shown.length) setSelectedId(null);
  }, [shown, selectedId]);
  const go = useCallback((hash: string) => { navigate(hash.slice(1)); }, [navigate]);
  const setFilters = useCallback((next: ListFilters) => { go(buildListHash(next)); }, [go]);
  const open = useCallback((id: number) => {
    setSelectedId(id);
    try {
      if (typeof window.matchMedia === "function" && !window.matchMedia("(max-width: 1100px)").matches) return;
    } catch { }
    go(buildDetailHash(id));
  }, [go]);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const countLine = `${total} correlated · ${shown.length} shown`;
  const filterDesc = [
    filters.minFloor !== null ? `floor at least ${filters.minFloor}` : null,
    filters.verdict ? `verdict ${filters.verdict}` : null,
    filters.analyzed !== null ? (filters.analyzed ? "analyzed only" : "not analyzed only") : null,
    filters.quarantined ? "quarantined (injection) only" : null,
    filters.q ? `search ${filters.q}` : null,
  ].filter(Boolean).join(", ");
  return (
    <main className={pageStyles.pageRoot}>
      <PageHeader title="Incidents" subtitle={countLine} />
      <IncidentFilterBar filters={filters} onChange={setFilters} />
      {state === "loading" ? <div aria-live="polite"><p>Loading incidents…</p><Spinner label="Loading incidents" /><Skeleton /></div>
        : state === "error" ? <ErrorState message="Could not load incidents. Check that the API and database are running, then reload." onRetry={retry} /> : (
        <div className={pageStyles.columns}>
          <div className={pageStyles.listCard}>
            <IncidentList items={shown} total={total} page={filters.page} setPage={(n) => setFilters({ ...filters, page: n })} pageSize={pageSize} onSelect={open}
              onStripFilter={(patch) => setFilters({ ...filters, ...patch, page: 0 })}
              emptyMessage={filterDesc ? `No incidents found matching ${filterDesc}.` : "No incidents found."}
              selectedId={selectedId} />
          </div>
          {selectedId !== null ? <IncidentPreview id={selectedId} /> : null}
        </div>
      )}
    </main>
  );
}
