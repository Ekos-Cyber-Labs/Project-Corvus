import { useEffect, useState } from "react";
import { fetchIncident } from "../../../api/incidents";
import type { IncidentDetail } from "../../../api/types";
import { isNumericId } from "../../../lib/hash";
export function useIncidentDetail(id: string, retryNonce: number) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error" | "invalid" | "missing">("idle");
  useEffect(() => {
    if (!isNumericId(id)) { setDetail(null); setState("invalid"); return; }
    const controller = new AbortController();
    setState("loading"); setDetail(null);
    fetchIncident(id, controller.signal)
      .then((d) => { if (!controller.signal.aborted) { setDetail(d); setState("ready"); } })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [id, retryNonce]);
  return { detail, state };
}
