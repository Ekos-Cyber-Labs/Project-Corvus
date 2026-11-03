import { useEffect, useState } from "react";
import { fetchSettings, fetchSweepStatus } from "../../../api/console";
import type { SettingsView, SweepStatus } from "../../../api/types";
export function useSettingsPage() {
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [sweep, setSweep] = useState<SweepStatus | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [retryNonce, setRetryNonce] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    Promise.all([fetchSettings(controller.signal), fetchSweepStatus(controller.signal)])
      .then(([s, sw]) => {
        if (controller.signal.aborted) return;
        setSettings(s);
        setSweep(sw);
        setState("ready");
      })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [retryNonce]);
  return { settings, sweep, state, retry: () => setRetryNonce((n) => n + 1) };
}
