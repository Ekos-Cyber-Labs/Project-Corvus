import type { IncidentListItem } from "../../api/types";
import type { ListFilters } from "../../lib/hash";
import { verdictKind } from "../../features/incidents/utils/incidents";
import barsStyles from "./SeverityBars.module.css";
export function SeverityBars({ items, onStripFilter }: { items: IncidentListItem[]; onStripFilter?: (patch: Partial<ListFilters>) => void }) {
  const sevCounts = [1, 2, 3, 4, 5, 6].map((n) => ({ n, c: items.filter((it) => it.severity_id === n).length }));
  const verdictCats: { key: string; label: string; c: number; patch: Partial<ListFilters> }[] = [
    { key: "true_positive", label: "true_positive", c: items.filter((it) => it.verdict === "true_positive").length, patch: { verdict: "true_positive", analyzed: null } },
    { key: "needs_human", label: "needs_human", c: items.filter((it) => it.verdict === "needs_human").length, patch: { verdict: "needs_human", analyzed: null } },
    { key: "false_positive", label: "false_positive", c: items.filter((it) => it.verdict === "false_positive").length, patch: { verdict: "false_positive", analyzed: null } },
    { key: "benign_authorized", label: "benign_authorized", c: items.filter((it) => it.verdict === "benign_authorized").length, patch: { verdict: "benign_authorized", analyzed: null } },
    { key: "not_analyzed", label: "not analyzed", c: items.filter((it) => !it.verdict && verdictKind(it.verdict, it.ai_status) === "pending").length, patch: { verdict: null, analyzed: false } },
  ];
  const sevTotal = Math.max(1, sevCounts.reduce((a, b) => a + b.c, 0));
  const verdTotal = Math.max(1, verdictCats.reduce((a, b) => a + b.c, 0));
  return (
    <div className={barsStyles.barsRoot}>
      <div className="dist" aria-label="Severity distribution">
        <p className="dist-title">Severity distribution (this page, by final severity)</p>
        <div className="dist-bar" role="group" aria-label="Severity distribution bar">
          {sevCounts.filter((s) => s.c > 0).map((s) => onStripFilter ? (
            <button key={s.n} type="button" className={`dist-seg sev-bg-${s.n} grow`} style={{ width: `${(s.c / sevTotal) * 100}%` }}
              aria-label={`Severity ${s.n}: ${s.c} incidents. Filter to floor at least ${s.n}`}
              title={`Severity ${s.n}: ${s.c}`} onClick={() => onStripFilter({ minFloor: s.n, page: 0 })}>{s.c}</button>
          ) : (<span key={s.n} className={`dist-seg sev-bg-${s.n} grow`} style={{ width: `${(s.c / sevTotal) * 100}%` }} title={`Severity ${s.n}: ${s.c}`}>{s.c}</span>))}
        </div>
        <ul className="dist-legend">{sevCounts.map((s) => <li key={s.n}>Severity {s.n}: {s.c}</li>)}</ul>
      </div>
      <div className="dist" aria-label="Verdict distribution">
        <p className="dist-title">Verdicts (this page)</p>
        <div className="dist-bar verdict-bar" role="group" aria-label="Verdict strip">
          {verdictCats.filter((v) => v.c > 0).map((v) => onStripFilter ? (
            <button key={v.key} type="button" className={`dist-seg verdict-bg-${v.key} grow`} style={{ width: `${(v.c / verdTotal) * 100}%` }}
              aria-label={`${v.label}: ${v.c} incidents. Apply this filter`} title={`${v.label}: ${v.c}`}
              onClick={() => onStripFilter({ ...v.patch, page: 0 })}>{v.c}</button>
          ) : (<span key={v.key} className={`dist-seg verdict-bg-${v.key} grow`} style={{ width: `${(v.c / verdTotal) * 100}%` }} title={`${v.label}: ${v.c}`}>{v.c}</span>))}
        </div>
        <ul className="dist-legend">{verdictCats.map((v) => <li key={v.key}>{v.label}: {v.c}</li>)}</ul>
      </div>
    </div>
  );
}
