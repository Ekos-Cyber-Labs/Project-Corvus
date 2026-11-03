import type { Dashboard } from "../../../api/types";
import chartStyles from "./SeverityDist.module.css";
const ROWS = ["Critical", "High", "Medium", "Low"] as const;
const KEY: Record<(typeof ROWS)[number], string> = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
export function SeverityDist({ dashboard }: { dashboard: Dashboard }) {
  const by = dashboard.totals.by_severity ?? {};
  const verdict = dashboard.totals.by_verdict ?? {};
  const max = Math.max(1, ...ROWS.map((r) => by[KEY[r]] ?? 0));
  const split: [string, number][] = [
    ["true positive", verdict.true_positive ?? 0],
    ["benign", (verdict.benign_authorized ?? 0) + (verdict.false_positive ?? 0)],
    ["needs human", verdict.needs_human ?? 0],
    ["quarantined", dashboard.totals.quarantined ?? 0],
    ["failed", dashboard.totals.failed ?? 0],
    ["pending", dashboard.totals.pending ?? 0],
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
                <span className={chartStyles.track} aria-hidden="true"><span className={`${chartStyles.fill} ${chartStyles[name.toLowerCase()]}`} style={{ width: `${(n / max) * 100}%` }} /></span>
                <span className={`mono ${chartStyles.count}`}>{n}</span>
                <span className="sr-only">{name}: {n} incidents</span>
              </li>
            );
          })}
        </ul>
        <ul className={chartStyles.split} aria-label="Verdict split">
          {split.map(([label, n]) => (
            <li key={label}><span>{label}</span><span className={`mono ${chartStyles.count}`}>{n}</span></li>
          ))}
        </ul>
      </div>
    </section>
  );
}
