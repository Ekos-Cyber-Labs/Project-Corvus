import type { Dashboard } from "../../../api/types";
import chartStyles from "./SeverityDist.module.css";
const ROWS = ["Critical", "High", "Medium", "Low", "Informational"] as const;
const KEY: Record<(typeof ROWS)[number], string> = { Critical: "critical", High: "high", Medium: "medium", Low: "low", Informational: "informational" };
const FILL: Record<(typeof ROWS)[number], string> = { Critical: "critical", High: "high", Medium: "medium", Low: "low", Informational: "low" };
export function SeverityDist({ dashboard }: { dashboard: Dashboard }) {
  const by = dashboard.totals.by_severity ?? {};
  const verdict = dashboard.totals.by_verdict ?? {};
  const max = Math.max(1, ...ROWS.map((r) => by[KEY[r]] ?? 0));
  const split: [string, string, number][] = [
    ["True positive", "true_positive", verdict.true_positive ?? 0],
    ["Benign", "benign", (verdict.benign_authorized ?? 0) + (verdict.false_positive ?? 0)],
    ["Needs human", "needs_human", verdict.needs_human ?? 0],
    ["Quarantined", "quarantined", dashboard.totals.quarantined ?? 0],
    ["Failed", "failed", dashboard.totals.failed ?? 0],
    ["Pending", "pending", dashboard.totals.pending ?? 0],
  ];
  return (
    <section className={`panel ${chartStyles.card}`} aria-label="Incidents by final severity">
      <h2>Incidents by final severity</h2>
      <div className={chartStyles.body}>
        <ul className={chartStyles.rows}>
          {ROWS.map((name) => {
            const n = by[KEY[name]] ?? 0;
            return (
              <li key={name}>
                <span className={chartStyles.name}>{name}</span>
                <span className={chartStyles.track} aria-hidden="true"><span className={`${chartStyles.fill} ${chartStyles[FILL[name]]}`} style={{ width: `${(n / max) * 100}%` }} /></span>
                <span className={`mono ${chartStyles.count}`}>{n}</span>
                <span className="sr-only">{name}: {n} incidents</span>
              </li>
            );
          })}
        </ul>
        <p className={`muted ${chartStyles.footnote}`}>Critical includes Fatal.</p>
        <ul className={chartStyles.split} aria-label="Verdict split">
          {split.map(([label, raw, n]) => (
            <li key={label} title={raw}><span>{label}</span><span className={`mono ${chartStyles.splitCount}`}>{n}</span></li>
          ))}
        </ul>
      </div>
    </section>
  );
}
