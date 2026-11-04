import type { LearnedRuleRef } from "../../../api/types";
import { buildRuleHash } from "../../../lib/hash";
import { useMaskFn } from "../../../lib/presentation";
function knownRuleId(ref: LearnedRuleRef): number | null {
  if (ref.unknown || ref.rule_db_id === null || ref.rule_db_id === undefined) return null;
  const id = Number(ref.rule_db_id);
  return Number.isInteger(id) ? id : null;
}
export function LearnedRuleRefs({ refs }: { refs: LearnedRuleRef[] }) {
  const mask = useMaskFn();
  if (!refs.length) return null;
  const known = refs.filter((r) => knownRuleId(r) !== null);
  if (!known.length) {
    return (
      <section className="panel" aria-label="Learned-rule findings">
        <h3>Learned-rule findings</h3>
        <p className="muted">No learned rule matched this incident.</p>
      </section>
    );
  }
  return (
    <section className="panel" aria-label="Learned-rule findings">
      <h3>Learned-rule findings</h3>
      <ul className="plain">
        {known.map((r, i) => {
          const id = knownRuleId(r) as number;
          const mode = typeof r.mode === "string" && r.mode ? r.mode : "unknown mode";
          const modeClass = mode === "shadow" ? "learned-shadow" : mode === "active" ? "learned-active" : "learned-other";
          return (
            <li key={i}>
              <a className={`badge learned-rule ${modeClass}`} href={buildRuleHash(id)} title={mask(`rule ${id}, mode ${mode}`)}>learned rule v{r.version ?? "?"} ({mask(mode)})</a>
              {typeof r.findings === "number" ? <> · {r.findings} finding{r.findings === 1 ? "" : "s"}</> : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
