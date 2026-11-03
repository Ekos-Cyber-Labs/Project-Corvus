import { useEffect, useState } from "react";
import { fetchDashboard, fetchSweepStatus } from "../../../api/console";
import type { Dashboard, SweepStatus } from "../../../api/types";
export function useConsole() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [sweep, setSweep] = useState<SweepStatus | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [retryNonce, setRetryNonce] = useState(0);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    Promise.all([fetchDashboard(controller.signal), fetchSweepStatus(controller.signal)])
      .then(([d, s]) => {
        if (controller.signal.aborted) return;
        setDashboard(d);
        setSweep(s);
        setUpdatedAt(new Date());
        setState("ready");
      })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [retryNonce]);
  return { dashboard, sweep, state, updatedAt, retry: () => setRetryNonce((n) => n + 1) };
}
