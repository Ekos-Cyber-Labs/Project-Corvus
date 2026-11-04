import { useRuleStageCounts } from "../hooks/useRuleStageCounts";
import barStyles from "./LifecycleBar.module.css";
const CURRENT_STAGE: Record<string, string> = { candidate: "Proposed", shadow: "Shadow", active: "Active" };
export function LifecycleBar({ nonce, sideStatus }: { nonce: number; sideStatus?: string | null }) {
  const { counts, state } = useRuleStageCounts(nonce);
  if (state === "loading") return <p aria-live="polite">Loading lifecycle…</p>;
  if (state === "error" || !counts) return <p role="alert">Could not load lifecycle counts.</p>;
  const stages = [
    { name: "Proposed", n: counts.proposed },
    { name: "Backtested", n: counts.backtested },
    { name: "Shadow", n: counts.shadow },
    { name: "Active", n: counts.active },
  ];
  const current = sideStatus ? CURRENT_STAGE[sideStatus] ?? null : null;
  const side = sideStatus === "rolled_back" || sideStatus === "archived" ? sideStatus : null;
  const shownSide = side ?? (sideStatus && !CURRENT_STAGE[sideStatus] ? sideStatus : null);
  return (
    <section className="panel" aria-label="Rule lifecycle">
      <ul className={barStyles.stages}>
        {stages.map((s, i) => (
          <li key={s.name} className={s.n > 0 ? barStyles.hot : undefined} aria-current={current === s.name ? "step" : undefined}>
            <span>{s.name} {s.n}{current === s.name ? " (current)" : ""}</span>
            {i < stages.length - 1 ? <span aria-hidden="true"> → </span> : null}
            <span className="sr-only">{s.name}: {s.n} {s.n === 1 ? "rule" : "rules"}{current === s.name ? ", current stage of the selected rule" : ""}</span>
          </li>
        ))}
        {shownSide ? <li className={barStyles.side} aria-current={sideStatus === shownSide ? "step" : undefined}>{shownSide === sideStatus ? `${shownSide} (current)` : shownSide}</li> : null}
      </ul>
    </section>
  );
}
