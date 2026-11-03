import { useEffect, useState } from "react";
import { fetchIncidents } from "../../../api/incidents";
import type { IncidentListItem } from "../../../api/types";
import type { ListFilters } from "../../../lib/hash";
export function useIncidents(filters: ListFilters, pageSize: number, retryNonce: number) {
  const [items, setItems] = useState<IncidentListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    setState("loading");
    fetchIncidents(filters, pageSize, controller.signal)
      .then((d) => { if (!controller.signal.aborted) { setItems(d.items); setTotal(d.total); setState("ready"); } })
      .catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [filters, pageSize, retryNonce]);
  return { items, total, state };
}
