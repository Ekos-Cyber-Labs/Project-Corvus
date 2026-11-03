import { useCallback, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { buildRuleHash, buildRulesHash, parseHash, type RuleFilters } from "../../../lib/hash";
import { useRules } from "../hooks/useRules";
import { RulesBanner } from "../components/RulesBanner";
import { RuleFilterBar } from "../components/RuleFilterBar";
import { RulesList } from "../components/RulesList";
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
  const go = useCallback((hash: string) => { navigate(hash.slice(1)); }, [navigate]);
  const setRuleFilters = useCallback((next: RuleFilters) => { go(buildRulesHash(next)); }, [go]);
  const openRule = useCallback((id: number) => { go(buildRuleHash(id)); }, [go]);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  return (
    <main className={pageStyles.pageRoot}><PageHeader title="Learned rules" />
      <RulesBanner />
      <RuleFilterBar filters={filters} onChange={setRuleFilters} />
      {state === "loading" ? <div aria-live="polite" className="reserve"><p>Loading rules…</p><Skeleton /></div> : state === "error" ? <p role="alert">Could not load rules. Check that the API and database are running, then reload. <button type="button" onClick={retry}>Retry</button></p> : (
        <RulesList items={items} total={total} page={filters.page} setPage={(n) => setRuleFilters({ ...filters, page: n })} pageSize={pageSize} onSelect={openRule} />
      )}
    </main>
  );
}
