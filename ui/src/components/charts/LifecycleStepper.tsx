import lifecycleStyles from "./LifecycleStepper.module.css";
export type RuleTransition = { from?: string | null; to?: string | null; approver?: string | null; reason?: string | null; at?: string | null };
export const LIFECYCLE_MAIN = ["candidate", "shadow", "active"] as const;
export const LIFECYCLE_SIDE = ["rolled_back", "archived"] as const;
export function lifecycleDates(transitions: RuleTransition[]): Record<string, string> {
  const dates: Record<string, string> = {};
  for (const t of transitions) if (t.to && t.at) dates[t.to] = t.at;
  return dates;
}
export function LifecycleStepper({ status, transitions }: { status: string; transitions: RuleTransition[] }) {
  const dates = lifecycleDates(transitions);
  const known = (LIFECYCLE_MAIN as readonly string[]).includes(status) || (LIFECYCLE_SIDE as readonly string[]).includes(status);
  const step = (s: string, side = false) => (
    <li key={s} className={`lc-step ${side ? "lc-side" : ""} ${status === s ? "lc-current" : ""}`} aria-current={status === s ? "step" : undefined}>
      <span className="lc-dot" aria-hidden="true" />
      <span className="lc-name">{s}</span>
      <span className="lc-date mono">{dates[s] ?? "no date recorded"}</span>
      {status === s ? <span className="lc-here">current</span> : null}
    </li>
  );
  return (
    <div className={`lifecycle ${lifecycleStyles.lifecycleRoot}`}>
      <p className="sr-only">Rule lifecycle: candidate, then shadow, then active. Rolled back and archived are side states. Current status is {known ? status : `${status} (unknown)`}{dates[status] ? ` since ${dates[status]}` : ""}.</p>
      <ol className="lc-main" aria-hidden="true">{LIFECYCLE_MAIN.map((s) => step(s))}</ol>
      <ul className="lc-sides" aria-hidden="true">{LIFECYCLE_SIDE.map((s) => step(s, true))}</ul>
      {!known ? <p className="muted">Current status: <span className="mono">{status || "unknown"}</span> (not a known lifecycle state)</p> : null}
    </div>
  );
}
