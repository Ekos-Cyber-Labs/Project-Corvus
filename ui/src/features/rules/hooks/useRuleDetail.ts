import { useEffect, useState } from "react";
import { fetchRule } from "../../../api/rules";
import type { RuleDetail } from "../../../api/types";
import { isNumericId } from "../../../lib/hash";
export function useRuleDetail(id: string, retryNonce: number) {
  const [detail, setDetail] = useState<RuleDetail | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error" | "invalid">("idle");
  useEffect(() => {
    if (!isNumericId(id)) { setDetail(null); setState("invalid"); return; }
    const controller = new AbortController();
    setState("loading"); setDetail(null);
    fetchRule(id, controller.signal)
      .then((d) => { if (!controller.signal.aborted) { setDetail(d); setState("ready"); } })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [id, retryNonce]);
  return { detail, state };
}
