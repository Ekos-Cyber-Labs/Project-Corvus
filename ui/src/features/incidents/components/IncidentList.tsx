import { useCallback } from "react";
import type { IncidentListItem } from "../../../api/types";
import type { ListFilters } from "../../../lib/hash";
import { buildDetailHash } from "../../../lib/hash";
import { Pagination } from "../../../components/ui/Pagination";
import { Table } from "../../../components/ui/Table";
import { VerdictBadge } from "./VerdictBadge";
import { verdictKind } from "../utils/incidents";
import listStyles from "./IncidentList.module.css";
const SEV_NAMES: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal" };
function sevName(id: number, fallback: string | null | undefined): string {
  return fallback ?? SEV_NAMES[id] ?? "Unknown";
}
export function IncidentList({ items, total, page, setPage, pageSize, onSelect, onStripFilter, emptyMessage, selectedId }: {
  items: IncidentListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
  onStripFilter?: (patch: Partial<ListFilters>) => void; emptyMessage?: string; selectedId?: number | null;
}) {
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  if (!items.length) return <p>{emptyMessage ?? "No incidents found."}</p>;
  const analyzedCount = items.filter((it) => {
    const k = verdictKind(it.verdict, it.ai_status);
    return (k === "verdict" || k === "triaged") && it.analyzed !== false;
  }).length;
  const injectionCount = items.filter((it) => it.has_injection).length;
  void onStripFilter;
  return (
    <div className={listStyles.listRoot}>
      <p className="summary-count">{total} incidents, {analyzedCount} analyzed, {injectionCount} with injection signals</p>
      <Table className="incidents" label="Incidents">
          <thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Status</th><th>Events</th></tr></thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.id} className={`rowlink${selectedId === it.id ? " selected" : ""}`} tabIndex={0} onClick={() => open(it.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(it.id); } }}>
                <td className="mono cell-id">{it.id}</td>
                <td>
                  <a className="title-link" href={buildDetailHash(it.id)}>{it.title || `Incident ${it.id}`}</a>
                  <p className={listStyles.second}>{it.event_count} events · {it.ai_status}{it.has_injection ? " · injection" : ""}</p>
                </td>
                <td className="cell-sev"><span className={`sev-dot sev-dot-${it.severity_floor}`} aria-hidden="true" />{sevName(it.severity_floor, it.severity_floor_name)} <span aria-hidden="true">→</span><span className="sr-only">floor to final</span> <span className={`sev-dot sev-dot-${it.severity_id}`} aria-hidden="true" />{sevName(it.severity_id, it.severity_name)}</td>
                <td className="cell-verdict"><VerdictBadge verdict={it.verdict} aiStatus={it.ai_status} /></td>
                <td className={`mono ${listStyles.events}`}><span className="num">{it.event_count}</span></td>
              </tr>
            ))}
          </tbody>
      </Table>
      <Pagination page={page} total={total} pageSize={pageSize} setPage={setPage} />
    </div>
  );
}
