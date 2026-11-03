import meterStyles from "./ConfidenceMeter.module.css";
export function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, Math.round(value <= 1 ? value * 100 : value)));
  return (
    <div className={`meter ${meterStyles.meterRoot}`}>
      <span>Confidence {pct}%</span>
      <span className="meter-track" role="img" aria-label={`Confidence ${pct} percent`}><span className="meter-fill grow" style={{ width: `${pct}%` }} /></span>
    </div>
  );
}
