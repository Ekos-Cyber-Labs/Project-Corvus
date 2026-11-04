import type { DashboardRecent } from "../../../api/types";
import { formatDateTime } from "../../../lib/formatDateTime";
import { useMaskFn } from "../../../lib/presentation";
import { recentChip, severityName } from "../utils/dashboard";
import recentStyles from "./RecentVerdicts.module.css";
export function RecentVerdicts({ recent }: { recent: DashboardRecent[] }) {
  const mask = useMaskFn();
  return (
    <section className="panel" aria-label="Latest verdicts from the sweep">
      <h2>Latest verdicts from the sweep</h2>
      {recent.length === 0 ? <p className="muted">No analyzed incidents yet.</p> : (
        <div className="table-wrap">
          <table aria-label="Latest verdicts from the sweep" className={recentStyles.table}>
            <thead><tr><th>ID</th><th>Incident</th><th>Severity</th><th>Verdict</th><th>Time</th></tr></thead>
            <tbody>
              {recent.map((r) => {
                const chip = recentChip(r);
                const iso = r.analyzed_at ?? "not recorded";
                return (
                  <tr key={r.id}>
                    <td className={`mono ${recentStyles.id}`}>{r.id}</td>
                    <td className={recentStyles.title}><a href={`#/incidents/${r.id}`}>{mask(r.title || `Incident ${r.id}`)}</a></td>
                    <td className={recentStyles.sev}><span className={recentStyles.sevCell}><span className={`sev-dot sev-dot-${r.final_severity}`} aria-hidden="true" />{severityName(r.final_severity)}</span></td>
                    <td className={recentStyles.verdict}><span className={chip.className} title={mask(r.verdict ?? r.verdict_kind)}>{chip.text}</span></td>
                    <td className={`mono ${recentStyles.time}`} title={mask(iso)}>{mask(formatDateTime(r.analyzed_at))}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p><a href="#/incidents">View all</a></p>
    </section>
  );
}
