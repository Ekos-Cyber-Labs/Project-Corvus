import { useEffect, useState } from "react";
import { getJson } from "../../../api/client";
export function useRuleStageCounts(retryNonce: number) {
  const [counts, setCounts] = useState<{ proposed: number; backtested: number; shadow: number; active: number } | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    const one = (status: string) => getJson<{ total: number }>(`/api/rules?status=${status}&limit=1`, controller.signal);
    Promise.all([one("candidate"), one("shadow"), one("active")])
      .then(([candidate, shadow, active]) => {
        if (controller.signal.aborted) return;
        setCounts({ proposed: candidate.total, backtested: 0, shadow: shadow.total, active: active.total });
        setState("ready");
      })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [retryNonce]);
  return { counts, state };
}
