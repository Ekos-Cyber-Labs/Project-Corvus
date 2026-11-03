import { useEffect, useState } from "react";
import { fetchRules } from "../../../api/rules";
import type { RuleListItem } from "../../../api/types";
import type { RuleFilters } from "../../../lib/hash";
export function useRules(filters: RuleFilters, pageSize: number, retryNonce: number) {
  const [items, setItems] = useState<RuleListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    fetchRules(filters, pageSize, controller.signal)
      .then((d) => { if (!controller.signal.aborted) { setItems(d.items); setTotal(d.total); setState("ready"); } })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [filters, pageSize, retryNonce]);
  return { items, total, state };
}
