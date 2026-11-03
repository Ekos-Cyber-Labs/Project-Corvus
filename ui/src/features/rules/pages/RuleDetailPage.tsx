import { useCallback, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { useRuleDetail } from "../hooks/useRuleDetail";
import { RuleDetailView } from "../components/RuleDetail";
import { Skeleton } from "../../../components/ui/Skeleton";
import { Button } from "../../../components/ui/Button";
import pageStyles from "./RuleDetailPage.module.css";
export function RuleDetailPage() {
  const params = useParams();
  const navigate = useNavigate();
  const [retryNonce, setRetryNonce] = useState(0);
  const id = params.id ?? "";
  const { detail, state } = useRuleDetail(id, retryNonce);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const lastRulesHash = (() => { try { return sessionStorage.getItem("corvus-last-rules-hash") || "#/rules"; } catch { return "#/rules"; } })();
  return (
    <main className={pageStyles.pageRoot}>
      <Button onClick={() => navigate(lastRulesHash.slice(1))}>Back to rules</Button>
      {state === "loading" ? <div aria-live="polite" className="reserve"><p>Loading rule…</p><Skeleton /></div>
        : state === "invalid" ? <p role="alert">Invalid rule id: the URL must be #/rules/&lt;number&gt;.</p>
        : state === "error" ? <p role="alert">Could not load this rule. It may not exist. <button type="button" onClick={retry}>Retry</button></p>
        : detail ? <RuleDetailView detail={detail} /> : null}
    </main>
  );
}
