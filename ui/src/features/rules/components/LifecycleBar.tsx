import { useRuleStageCounts } from "../hooks/useRuleStageCounts";
import barStyles from "./LifecycleBar.module.css";
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
  const side = sideStatus === "rolled_back" || sideStatus === "archived" ? sideStatus : null;
  return (
    <section className="panel" aria-label="Rule lifecycle">
      <ul className={barStyles.stages}>
        {stages.map((s, i) => (
          <li key={s.name} className={s.n > 0 ? barStyles.hot : undefined}>
            <span>{s.name} {s.n}</span>
            {i < stages.length - 1 ? <span aria-hidden="true"> → </span> : null}
            <span className="sr-only">{s.name}: {s.n} rules</span>
          </li>
        ))}
        {side ? <li className={barStyles.side}>{side}</li> : null}
      </ul>
    </section>
  );
}
