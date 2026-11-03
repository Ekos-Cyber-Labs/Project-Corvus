import scaleStyles from "./SeverityScale.module.css";
export function SeverityScale({ floor, final }: { floor: number; final: number }) {
  return (
    <div className={`sev-scale-wrap ${scaleStyles.scaleRoot}`}>
      <p className="sr-only">Severity scale from 1 to 6: floor {floor}, final {final}.</p>
      <div className="sev-scale" aria-hidden="true">
        {[1, 2, 3, 4, 5, 6].map((n) => (
          <span key={n} className={`sev-scale-cell sev-bg-${n} ${n === floor ? "mark-floor" : ""} ${n === final ? "mark-final" : ""}`}>
            {n}{n === floor ? <em>floor</em> : null}{n === final ? <em>final</em> : null}
          </span>
        ))}
      </div>
    </div>
  );
}
