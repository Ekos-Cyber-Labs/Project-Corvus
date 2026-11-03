import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { buildRuleHash, buildRulesHash, parseHash, type RuleFilters } from "../../../lib/hash";
import { useRules } from "../hooks/useRules";
import { useRuleDetail } from "../hooks/useRuleDetail";
import { LifecycleBar } from "../components/LifecycleBar";
import { RuleFilterBar } from "../components/RuleFilterBar";
import { RulesBanner } from "../components/RulesBanner";
import { RulesList } from "../components/RulesList";
import { RuleDetailView } from "../components/RuleDetail";
import { Skeleton } from "../../../components/ui/Skeleton";
import { PageHeader } from "../../../components/layout/PageHeader";
import { Spinner } from "../../../components/ui/Spinner";
import pageStyles from "./RulesPage.module.css";
export function RulesPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [retryNonce, setRetryNonce] = useState(0);
  const filters = useMemo<RuleFilters>(() => {
    const route = parseHash(`#${location.pathname}${location.search}`);
    return route.view === "rules" ? route : { page: 0, status: null, mode: null };
  }, [location.pathname, location.search]);
  try { sessionStorage.setItem("corvus-last-rules-hash", buildRulesHash(filters)); } catch { }
  const pageSize = 20;
  const { items, total, state } = useRules(filters, pageSize, retryNonce);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  useEffect(() => {
    if (items.length && (selectedId === null || !items.some((it) => it.id === selectedId))) setSelectedId(items[0].id);
    if (!items.length) setSelectedId(null);
  }, [items, selectedId]);
  const go = useCallback((hash: string) => { navigate(hash.slice(1)); }, [navigate]);
  const setRuleFilters = useCallback((next: RuleFilters) => { go(buildRulesHash(next)); }, [go]);
  const openRule = useCallback((id: number) => {
    setSelectedId(id);
    try {
      if (typeof window.matchMedia === "function" && !window.matchMedia("(max-width: 1100px)").matches) return;
    } catch { }
    go(buildRuleHash(id));
  }, [go]);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const { detail, state: detailState } = useRuleDetail(selectedId === null ? "" : String(selectedId), retryNonce);
  return (
    <main className={pageStyles.pageRoot}>
      <PageHeader title="Rules" subtitle="Sigma rules learned from confirmed incidents. A human approves every step." />
      <LifecycleBar nonce={retryNonce} sideStatus={detail?.status ?? null} />
      <RulesBanner />
      <RuleFilterBar filters={filters} onChange={setRuleFilters} />
      {state === "loading" ? <div aria-live="polite" className="reserve"><p>Loading rules…</p><Skeleton /></div> : state === "error" ? <p role="alert">Could not load rules. Check that the API and database are running, then reload. <button type="button" onClick={retry}>Retry</button></p> : (
        <div className={pageStyles.columns}>
          <div className={pageStyles.listCard}>
            <RulesList items={items} total={total} page={filters.page} setPage={(n) => setRuleFilters({ ...filters, page: n })} pageSize={pageSize} onSelect={openRule} selectedId={selectedId} />
          </div>
          <div className={pageStyles.detailCol}>
            {selectedId === null ? <p>No rule selected.</p>
              : detailState === "loading" ? <div aria-live="polite"><p>Loading rule…</p><Spinner label="Loading rule" /><Skeleton /></div>
              : detailState === "error" ? <p role="alert">Could not load this rule. <button type="button" onClick={retry}>Retry</button></p>
              : detail ? <RuleDetailView detail={detail} /> : null}
          </div>
        </div>
      )}
    </main>
  );
}
