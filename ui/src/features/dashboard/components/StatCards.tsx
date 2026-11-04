import type { Dashboard, SweepStatus } from "../../../api/types";
import { formatMoney } from "../utils/dashboard";
import dashStyles from "./StatCards.module.css";
export function StatCards({ dashboard, sweep }: { dashboard: Dashboard; sweep: SweepStatus | null }) {
  const t = dashboard.totals;
  const open = t.pending;
  const lastNew = sweep?.last?.new_incidents;
  const openLine = lastNew === null || lastNew === undefined ? "no sweep recorded yet" : `${lastNew} new in the last sweep`;
  const analyzedPct = t.incidents > 0 ? Math.round((t.analyzed / t.incidents) * 100) : 0;
  const spendTotal = dashboard.spend.total_usd ?? 0;
  const spendCap = dashboard.spend.cap_usd;
  const spendPct = spendCap && spendCap > 0 ? Math.min(100, Math.round((spendTotal / spendCap) * 100)) : 0;
  return (
    <div className={dashStyles.grid}>
      <section className="panel" aria-label="Open incidents">
        <p className={dashStyles.label}>Open incidents</p>
        <p className={dashStyles.big}>{open}</p>
        <p className={dashStyles.sub}>{openLine}</p>
      </section>
      <section className="panel" aria-label="Analyzed with a verdict">
        <p className={dashStyles.label}>Analyzed with a verdict</p>
        <p className={dashStyles.big}>{t.analyzed} <span className={dashStyles.of}>/ {t.incidents}</span></p>
        <p className={dashStyles.bar} aria-hidden="true"><span style={{ width: `${analyzedPct}%` }} /></p>
        <p className="sr-only">{analyzedPct} percent analyzed</p>
      </section>
      <section className="panel" aria-label="Injection quarantined">
        <p className={dashStyles.label}>Injection quarantined</p>
        <p className={`${dashStyles.big} ${dashStyles.amber}`}>{t.quarantined}</p>
        <p className={dashStyles.sub}>Model never obeyed</p>
      </section>
      <section className="panel" aria-label="Model spend">
        <p className={dashStyles.label}>Model spend</p>
        <p className={dashStyles.big}>{formatMoney(spendTotal)} <span className={dashStyles.of}>/ {formatMoney(spendCap)}</span></p>
        <p className={`${dashStyles.bar} ${dashStyles.blue}`} aria-hidden="true"><span style={{ width: `${spendPct}%` }} /></p>
        <p className="sr-only">{spendPct} percent of spend cap used</p>
      </section>
    </div>
  );
}
