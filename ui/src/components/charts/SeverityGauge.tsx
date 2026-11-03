import gaugeStyles from "./SeverityGauge.module.css";
export function SeverityGauge({ floor, final }: { floor: number; final: number }) {
  return (
    <div className={`gauge ${gaugeStyles.gaugeRoot}`} role="img" aria-label={`Severity floor ${floor}, final ${final} on a scale of 1 to 6${final > floor ? `, raised from floor ${floor} to ${final}` : ""}`}>
      <div className="sev-scale" aria-hidden="true">
        {[1, 2, 3, 4, 5, 6].map((n) => (
          <span key={n} className={`sev-scale-cell sev-bg-${n} ${n === floor ? "mark-floor" : ""} ${n === final ? "mark-final" : ""}`}>
            {n}{n === floor ? <em>floor</em> : null}{n === final ? <em>final</em> : null}
          </span>
        ))}
      </div>
      <p className="gauge-caption">
        Floor {floor} {final > floor ? (<><span aria-hidden="true">→</span><span className="sr-only">raised to</span> Final {final}</>) : (<>· Final {final}</>)}
      </p>
      <p className="sr-only">Severity scale 1 to 6. Floor marker at {floor}, final marker at {final}.</p>
    </div>
  );
}
