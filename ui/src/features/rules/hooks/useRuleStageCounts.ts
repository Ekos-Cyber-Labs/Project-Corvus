import { useEffect, useState } from "react";
import { getJson } from "../../../api/client";
export function useRuleStageCounts(retryNonce: number) {
  const [counts, setCounts] = useState<{ proposed: number; backtested: number; shadow: number; active: number } | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    const one = (status: string | null) => {
      const query = status ? `?status=${status}&limit=1` : "?limit=1";
      return getJson<{ total: number }>(`/api/rules${query}`, controller.signal);
    };
    Promise.all([one("candidate"), one(null), one("shadow"), one("active")])
      .then(([candidate, all, shadow, active]) => {
        if (controller.signal.aborted) return;
        setCounts({ proposed: candidate.total, backtested: all.total, shadow: shadow.total, active: active.total });
        setState("ready");
      })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [retryNonce]);
  return { counts, state };
}
