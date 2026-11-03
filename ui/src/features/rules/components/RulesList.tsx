import { useCallback } from "react";
import type { RuleListItem } from "../../../api/types";
import { buildRuleHash, RULE_STATUSES } from "../../../lib/hash";
import { Pagination } from "../../../components/ui/Pagination";
import { Table } from "../../../components/ui/Table";
import { ruleCountLine } from "../utils/rules";
import { RuleStatusBadge } from "./RuleStatusBadge";
import { RuleModeBadge } from "./RuleModeBadge";
import listStyles from "./RulesList.module.css";
export function RulesList({ items, total, page, setPage, pageSize, onSelect }: {
  items: RuleListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
}) {
  if (!items.length) return <p>No learned rules found.</p>;
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  return (
    <div className={listStyles.listRoot}>
      <p className="summary-count">{ruleCountLine(items, total)}</p>
    <Table className="rules" label="Learned rules">
        <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Mode</th><th>Version</th><th>Level</th><th>Techniques</th><th>Hits</th><th>FP</th></tr></thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.id} className="rowlink" tabIndex={0} onClick={() => open(it.id)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(it.id); } }}>
              <td className="mono cell-id"><span className={`rail rule-rail-${RULE_STATUSES.has(it.status) ? it.status : "unknown"}`} aria-hidden="true" />{it.id}</td>
              <td className="cell-title"><a className="title-link" href={buildRuleHash(it.id)}>{it.title || `Rule ${it.id}`}</a></td>
              <td><RuleStatusBadge status={it.status} /></td>
              <td><RuleModeBadge mode={it.mode} /></td>
              <td className="mono">v{it.version}</td>
              <td>{it.level ?? "—"}</td>
              <td className="mono">{it.techniques?.length ? it.techniques.join(", ") : "—"}</td>
              <td className="num">{it.hits}</td>
              <td className="num">{it.false_positives}</td>
            </tr>
          ))}
        </tbody>
    </Table>
      <Pagination page={page} total={total} pageSize={pageSize} setPage={setPage} />
    </div>
  );
}
