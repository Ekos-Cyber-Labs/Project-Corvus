import backtestStyles from "./BacktestBars.module.css";
export type BacktestFigures = { matched: number | null; targetTotal: number | null; baselineCount: number | null; baselineTotal: number | null };
export function backtestFigures(backtest: Record<string, unknown> | null | undefined): BacktestFigures {
  if (!backtest) return { matched: null, targetTotal: null, baselineCount: null, baselineTotal: null };
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  return {
    matched: Array.isArray(backtest.target_matched) ? backtest.target_matched.length : null,
    targetTotal: num(backtest.target_total),
    baselineCount: num(backtest.baseline_count),
    baselineTotal: num(backtest.baseline_total),
  };
}
export function BacktestBars({ backtest }: { backtest: Record<string, unknown> | null | undefined }) {
  const f = backtestFigures(backtest);
  if (f.matched === null && f.baselineCount === null) return null;
  const max = Math.max(1, f.matched ?? 0, f.baselineCount ?? 0);
  const row = (label: string, value: number | null, n: number | null, missingN: string) => (
    <div className="bt-row">
      <span className="bt-label">{label}</span>
      <span className="bt-track" role="img" aria-label={`${label}: ${value ?? "not recorded"} matches${n !== null ? ` of n=${n}` : `, ${missingN}`}`}><span className="bt-fill grow" style={{ width: `${((value ?? 0) / max) * 100}%` }} /></span>
      <span className="bt-value num">{value ?? "not recorded"} ({n !== null ? `n=${n}` : missingN})</span>
    </div>
  );
  return (
    <div className={`backtest-bars ${backtestStyles.backtestRoot}`}>
      {row("Target events matched", f.matched, f.targetTotal, "n not recorded")}
      {row("Benign baseline matches", f.baselineCount, f.baselineTotal, "baseline size not recorded")}
      <p className="sr-only">Backtest bars: target events matched {f.matched ?? "not recorded"} of {f.targetTotal ?? "not recorded"}; benign baseline matches {f.baselineCount ?? "not recorded"}{f.baselineTotal !== null ? ` of ${f.baselineTotal}` : " (baseline size not recorded)"}.</p>
    </div>
  );
}
