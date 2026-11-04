import type { LearnedRuleRef } from "../../../api/types";
import { buildRuleHash } from "../../../lib/hash";
import { useMaskFn } from "../../../lib/presentation";
export function LearnedRuleRefs({ refs }: { refs: LearnedRuleRef[] }) {
  const mask = useMaskFn();
  if (!refs.length) return null;
  return (
    <section className="panel" aria-label="Learned-rule findings">
      <h3>Learned-rule findings</h3>
      <ul className="plain">
        {refs.map((r, i) => {
          if (r.unknown || r.rule_db_id === null || r.rule_db_id === undefined) {
            return <li key={i}><span className="badge learned-unknown">unknown learned rule (unresolved)</span></li>;
          }
          const id = Number(r.rule_db_id);
          if (!Number.isInteger(id)) return <li key={i}><span className="badge learned-unknown">unknown learned rule (unresolved)</span></li>;
          const mode = typeof r.mode === "string" && r.mode ? r.mode : "unknown mode";
          const modeClass = mode === "shadow" ? "learned-shadow" : mode === "active" ? "learned-active" : "learned-other";
          return (
            <li key={i}>
              <a className={`badge learned-rule ${modeClass}`} href={buildRuleHash(id)}>learned rule v{r.version ?? "?"} ({mask(mode)})</a>
              {typeof r.findings === "number" ? <> · {r.findings} finding{r.findings === 1 ? "" : "s"}</> : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
