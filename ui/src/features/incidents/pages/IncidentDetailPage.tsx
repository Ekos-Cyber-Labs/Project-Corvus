import { useCallback, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { useIncidentDetail } from "../hooks/useIncidentDetail";
import { IncidentDetailView } from "../components/IncidentDetail";
import { Skeleton } from "../../../components/ui/Skeleton";
import { Button } from "../../../components/ui/Button";
import pageStyles from "./IncidentDetailPage.module.css";
export function IncidentDetailPage() {
  const params = useParams();
  const navigate = useNavigate();
  const [retryNonce, setRetryNonce] = useState(0);
  const id = params.id ?? "";
  const { detail, state } = useIncidentDetail(id, retryNonce);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const lastListHash = (() => { try { return sessionStorage.getItem("corvus-last-list-hash") || "#/"; } catch { return "#/"; } })();
  const goBack = () => navigate(lastListHash.slice(1));
  return (
    <main className={pageStyles.pageRoot}>
      <Button onClick={goBack}>Back to incidents</Button>
      {state === "loading" ? <div aria-live="polite"><p>Loading incident…</p><Skeleton /></div>
        : state === "invalid" ? <p role="alert">Invalid incident id: the URL must be #/incidents/&lt;number&gt;.</p>
        : state === "error" || state === "missing" ? <p role="alert">Could not load this incident. It may not exist. <button type="button" onClick={retry}>Retry</button></p>
        : detail ? <IncidentDetailView detail={detail} /> : null}
    </main>
  );
}
