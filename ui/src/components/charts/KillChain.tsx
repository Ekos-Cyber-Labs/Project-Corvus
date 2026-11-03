import { TACTIC_NAMES, TACTIC_ORDER } from "../../lib/attackMap";
import killStyles from "./KillChain.module.css";
export function KillChainStrip({ counts, selected, onSelect }: { counts: Record<string, number>; selected: string | null; onSelect: (t: string | null) => void }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className={`killchain ${killStyles.chainRoot}`} role="group" aria-label="Kill chain tactics">
      {TACTIC_ORDER.map((short) => {
        const c = counts[short] ?? 0;
        const name = TACTIC_NAMES[short] ?? short;
        return (
          <button key={short} type="button" className={`kc-seg ${c ? "filled" : "empty"} ${selected === short ? "selected" : ""}`}
            aria-pressed={selected === short} aria-label={`${name}: ${c} technique${c === 1 ? "" : "s"}${selected === short ? ", filtering" : ""}`}
            title={`${name}: ${c}`}
            onClick={() => onSelect(selected === short ? null : short)}>
            <span className="kc-bar grow" style={{ width: c ? `${Math.max(18, (c / max) * 100)}%` : "0%" }} aria-hidden="true" />
            <span className="kc-label">{name}</span><span className="kc-count">{c || ""}</span>
          </button>
        );
      })}
      {(counts.other ?? 0) > 0 ? <span className="kc-other">Other: {counts.other}</span> : null}
    </div>
  );
}

export { KillChainStrip as KillChain };
