import { useCallback } from "react";
import type { IncidentListItem } from "../../../api/types";
import type { ListFilters } from "../../../lib/hash";
import { buildDetailHash } from "../../../lib/hash";
import { SeverityChip } from "../../../components/charts/SeverityChip";
import { SeverityBars } from "../../../components/charts/SeverityBars";
import { Pagination } from "../../../components/ui/Pagination";
import { Table } from "../../../components/ui/Table";
import { VerdictBadge } from "./VerdictBadge";
import { verdictKind } from "../utils/incidents";
import listStyles from "./IncidentList.module.css";
export function IncidentList({ items, total, page, setPage, pageSize, onSelect, onStripFilter, emptyMessage }: {
  items: IncidentListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
  onStripFilter?: (patch: Partial<ListFilters>) => void; emptyMessage?: string;
}) {
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  if (!items.length) return <p>{emptyMessage ?? "No incidents found."}</p>;
  const analyzedCount = items.filter((it) => {
    const k = verdictKind(it.verdict, it.ai_status);
    return (k === "verdict" || k === "triaged") && it.analyzed !== false;
  }).length;
  const injectionCount = items.filter((it) => it.has_injection).length;
  const maxEvents = Math.max(1, ...items.map((it) => it.event_count));
  return (
    <div className={listStyles.listRoot}>
      <p className="summary-count">{total} incidents, {analyzedCount} analyzed, {injectionCount} with injection signals</p>
      <SeverityBars items={items} onStripFilter={onStripFilter} />
      <Table className="incidents" label="Incidents">
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Verdict</th><th>Events</th><th className="col-inj">Injection</th></tr></thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.id} className="rowlink" tabIndex={0} onClick={() => open(it.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(it.id); } }}>
                <td className="mono cell-id"><span className={`rail sev-bg-${it.severity_id}`} aria-hidden="true" />{it.id}</td>
                <td><a className="title-link" href={buildDetailHash(it.id)}>{it.title || `Incident ${it.id}`}</a></td>
                <td className="cell-sev"><SeverityChip floor={it.severity_floor} final={it.severity_id} /></td>
                <td className="cell-verdict"><VerdictBadge verdict={it.verdict} aiStatus={it.ai_status} /></td>
                <td className="cell-events"><span className="num">{it.event_count}</span><span className="event-bar" aria-hidden="true"><span className="event-fill grow" style={{ width: `${(it.event_count / maxEvents) * 100}%` }} /></span><span className="sr-only">{it.event_count} events</span></td>
                <td className="cell-inj">{it.has_injection ? <span className="badge injection">injection</span> : "—"}</td>
              </tr>
            ))}
          </tbody>
      </Table>
      <Pagination page={page} total={total} pageSize={pageSize} setPage={setPage} />
    </div>
  );
}
