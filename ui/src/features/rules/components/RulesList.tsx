import type { RuleListItem } from "../../../api/types";
import { buildRuleHash } from "../../../lib/hash";
import { Pagination } from "../../../components/ui/Pagination";
import { ruleCountLine } from "../utils/rules";
import { RuleStatusBadge } from "./RuleStatusBadge";
import cardsStyles from "./RulesList.module.css";
export function RulesList({ items, total, page, setPage, pageSize, onSelect, selectedId }: {
  items: RuleListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void; selectedId?: number | null;
}) {
  if (!items.length) return <p>No learned rules found.</p>;
  return (
    <div className={cardsStyles.cardsRoot}>
      <p className="summary-count">{ruleCountLine(items, total)}</p>
      <ul className={cardsStyles.list}>
        {items.map((it) => (
          <li key={it.id} className={selectedId === it.id ? `${cardsStyles.card} ${cardsStyles.selected}` : cardsStyles.card}>
            <a
              className={cardsStyles.anchor}
              href={buildRuleHash(it.id)}
              aria-current={selectedId === it.id ? "true" : undefined}
              onClick={(e) => { e.preventDefault(); onSelect(it.id); }}
              onKeyDown={(e) => { if (e.key === " ") { e.preventDefault(); onSelect(it.id); } }}
            >
              <span className={`mono ${cardsStyles.id}`}>{it.id}</span>
              <span className={cardsStyles.name}>{it.title || `Rule ${it.id}`}</span>
              <span className={cardsStyles.meta}><RuleStatusBadge status={it.status} /></span>
              <span className={cardsStyles.sub}>From incident {it.source_incident_id ?? "unknown"}{it.techniques?.length ? ` · ${it.techniques[0]}` : ""}</span>
            </a>
          </li>
        ))}
      </ul>
      <Pagination page={page} total={total} pageSize={pageSize} setPage={setPage} />
    </div>
  );
}
