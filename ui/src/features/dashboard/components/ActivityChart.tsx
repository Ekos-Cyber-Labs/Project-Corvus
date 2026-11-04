import type { Dashboard } from "../../../api/types";
import { useMaskFn } from "../../../lib/presentation";
import activityStyles from "./ActivityChart.module.css";
function hourLabel(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCHours())}:00`;
}
export function ActivityChart({ dashboard }: { dashboard: Dashboard }) {
  const mask = useMaskFn();
  const activity = dashboard.activity ?? [];
  const markers = dashboard.sweep_runs ?? [];
  const max = Math.max(1, ...activity.map((a) => a.incidents));
  const markerHours = new Set(markers.map((m) => (m.started_at ?? "").slice(0, 13)));
  const ticks = [0, 6, 12, 18].map((i) => activity[i]).filter(Boolean);
  const last = activity[activity.length - 1];
  const described = activity.map((a) => `${hourLabel(a.hour)}: ${a.incidents}`).join(", ");
  return (
    <section className="panel" aria-label="Alert activity">
      <h2>Alert activity</h2>
      <svg viewBox="0 0 480 160" role="img" aria-label={mask(`Hourly incidents over 24 hours: ${described}`)} className={activityStyles.svg}>
        {activity.map((a, i) => {
          const x = 20 + i * 18;
          const h = Math.round((a.incidents / max) * 100);
          const recent = i >= activity.length - 6;
          return (
            <g key={a.hour}>
              <title>{mask(`${hourLabel(a.hour)}: ${a.incidents} incidents`)}</title>
              <rect x={x} y={120 - h} width={12} height={h} rx={3} className={recent ? activityStyles.recent : activityStyles.older} />
              {markerHours.has(a.hour.slice(0, 13)) ? <line x1={x + 6} y1={8} x2={x + 6} y2={120} className={activityStyles.marker} strokeDasharray="4 3" /> : null}
            </g>
          );
        })}
        <line x1={20} y1={120} x2={472} y2={120} className={activityStyles.axis} />
        {ticks.map((t) => {
          const i = activity.indexOf(t);
          return <text key={t.hour} x={20 + i * 18} y={136} className={activityStyles.tick}>{hourLabel(t.hour)}</text>;
        })}
        {last ? <text x={20 + (activity.length - 1) * 18} y={150} className={activityStyles.tick}>now</text> : null}
      </svg>
      <ul className={activityStyles.legend}>
        <li><span className={activityStyles.swRecent} aria-hidden="true" /> recent hours</li>
        <li><span className={activityStyles.swOlder} aria-hidden="true" /> older hours</li>
        <li><span className={activityStyles.swSweep} aria-hidden="true" /> sweep run</li>
      </ul>
    </section>
  );
}
