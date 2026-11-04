import type { Dashboard, SweepStatus } from "../../../api/types";
import { formatAgo, formatTime } from "../../../lib/formatDateTime";
import { useMaskFn } from "../../../lib/presentation";
import { policySentence } from "../utils/dashboard";
export function SweepStatusCard({ sweep, dashboard }: { sweep: SweepStatus | null; dashboard: Dashboard }) {
  const last = sweep?.last ?? null;
  const policy = (sweep?.policy ?? null) as Record<string, unknown> | null;
  const mask = useMaskFn();
  const interval = typeof policy?.interval_seconds === "number" ? policy.interval_seconds : last?.interval_seconds ?? 300;
  const analyzed = last?.analyzed ?? 0;
  const failed = last?.failed_analyses ?? 0;
  const skipped = last?.skipped_policy ?? 0;
  const lastIso = last?.started_at ?? null;
  const lastText = lastIso ? `${mask(formatTime(lastIso))} · ${mask(formatAgo(lastIso))}` : "never";
  return (
    <section className="panel" aria-label="Sweep status">
      <h2>Sweep status</h2>
      <dl className="args">
        <div><dt className="nowrap">Interval</dt><dd className="mono nowrap">{interval}s</dd></div>
        <div><dt className="nowrap">Last sweep</dt><dd className="mono nowrap" title={mask(lastIso ?? "never")}>{lastText}</dd></div>
        <div><dt className="nowrap">New incidents</dt><dd className="mono nowrap">{last?.new_incidents ?? "not recorded"}</dd></div>
        <div><dt className="nowrap">Analyzed</dt><dd className="mono nowrap">{analyzed} of {analyzed + failed + skipped}</dd></div>
        <div><dt className="nowrap">Skipped by policy</dt><dd className="mono nowrap">{skipped}</dd></div>
        <div><dt className="nowrap">Skipped by budget</dt><dd className="mono nowrap">{last?.skipped_budget ?? 0}</dd></div>
      </dl>
      <hr />
      <p className="muted">{mask(policySentence(policy, dashboard.spend.cap_usd))}</p>
      <p><a href="#/settings">View sweep policy</a></p>
    </section>
  );
}
