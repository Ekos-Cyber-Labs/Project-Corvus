import { TACTIC_NAMES, TACTIC_ORDER, tacticForTechnique } from "./attackMap";

export const SEV_NAMES: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Critical+" };
export function sevLabel(n: number): string { return `${n} ${SEV_NAMES[n] ?? ""}`.trim(); }

export function SeverityChip({ floor, final }: { floor: number; final: number }) {
  if (floor === final) return <span className={`badge sev-${final}`}>{sevLabel(final)}</span>;
  return <span className={`badge sev-${final}`}>{sevLabel(floor)} <span aria-hidden="true">→</span><span className="sr-only">to</span> {sevLabel(final)}</span>;
}

export function SeverityGauge({ floor, final }: { floor: number; final: number }) {
  return (
    <div className="gauge" role="img" aria-label={`Severity floor ${floor}, final ${final} on a scale of 1 to 6${final > floor ? `, raised from floor ${floor} to ${final}` : ""}`}>
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

export function SeverityScale({ floor, final }: { floor: number; final: number }) {
  return (
    <div className="sev-scale-wrap">
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

export function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, Math.round(value <= 1 ? value * 100 : value)));
  return (
    <div className="meter">
      <span>Confidence {pct}%</span>
      <span className="meter-track" role="img" aria-label={`Confidence ${pct} percent`}><span className="meter-fill grow" style={{ width: `${pct}%` }} /></span>
    </div>
  );
}

export type TimelineEntry = { time: string; event_uid: string; description: string };

function parseMs(t: string): number { const n = Date.parse(t); return Number.isFinite(n) ? n : NaN; }
function median(xs: number[]): number { if (!xs.length) return 0; const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; }
function fmtDur(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s gap`;
  if (s < 3600) return `${Math.round(s / 60)}m gap`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h gap`;
  return `${(s / 86400).toFixed(1)}d gap`;
}

export function eventTactic(uid: string, evidence: { event_uid: string; event?: unknown }[] | undefined, techniques: { id: string }[] | undefined): string {
  const ev = evidence?.find((e) => e.event_uid === uid);
  if (!ev?.event) return "other";
  let text = "";
  try { text = JSON.stringify(ev.event); } catch { return "other"; }
  const known = new Set((techniques ?? []).map((t) => t.id));
  const m = text.match(/T\d{4}(?:\.\d{3})?/);
  if (m && (known.size === 0 || known.has(m[0]))) return tacticForTechnique(m[0]);
  return "other";
}

export const TACTIC_FILL: Record<string, string> = {
  reconnaissance: "#7a8a99", "resource-development": "#7a8a99", "initial-access": "#bd7f27", execution: "#b8862e",
  persistence: "#b07a2a", "privilege-escalation": "#c05a3a", stealth: "#9a6a9a", "defense-impairment": "#9a6a9a",
  "credential-access": "#c05a3a", discovery: "#5a8a7a", "lateral-movement": "#4a7ab5", collection: "#5a8ab5",
  "command-and-control": "#4a7aa5", exfiltration: "#9c5f7d", impact: "#c04545", other: "#7d8894",
};

function fmtTick(ms: number): string {
  const d = new Date(ms);
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 19).replace("T", " ") : "";
}
export type ActivityCluster = { indices: number[]; x: number };
export function clusterIndices(xs: number[], threshold = 6): ActivityCluster[] {
  const clusters: ActivityCluster[] = [];
  xs.forEach((x, i) => {
    const last = clusters[clusters.length - 1];
    if (last && x - last.x <= threshold) last.indices.push(i);
    else clusters.push({ indices: [i], x });
  });
  return clusters;
}
export function ActivityStrip({ timeline, firstSeen, lastSeen, techniques, evidence, highlighted, onHighlight, onJump }: {
  timeline: TimelineEntry[]; firstSeen?: string | null; lastSeen?: string | null;
  techniques?: { id: string }[]; evidence?: { event_uid: string; event?: unknown }[];
  highlighted: number | null; onHighlight: (i: number | null) => void; onJump?: (i: number) => void;
}) {
  if (!timeline.length) return null;
  const times = timeline.map((e) => parseMs(e.time));
  const valid = times.filter(Number.isFinite);
  const start = Math.min(...(firstSeen && Number.isFinite(parseMs(firstSeen)) ? [parseMs(firstSeen)] : []), ...valid);
  const end = Math.max(...(lastSeen && Number.isFinite(parseMs(lastSeen)) ? [parseMs(lastSeen)] : []), ...valid);
  const span = Math.max(1, end - start);
  const gaps: number[] = [];
  for (let i = 1; i < times.length; i++) if (Number.isFinite(times[i]) && Number.isFinite(times[i - 1])) gaps.push(times[i] - times[i - 1]);
  const med = median(gaps.filter((g) => g > 0));
  const W = 720; const H = 84;
  const xFor = (t: number) => 8 + ((t - start) / span) * (W - 16);
  const xs = times.map((t) => (Number.isFinite(t) ? xFor(t) : NaN));
  const finiteIdx = xs.map((x, i) => ({ x, i })).filter((p) => Number.isFinite(p.x));
  const clusters = clusterIndices(finiteIdx.map((p) => p.x)).map((c) => ({ x: c.x, indices: c.indices.map((k) => finiteIdx[k].i) }));
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ ms: start + span * f, x: 8 + f * (W - 16) }));
  const presentTactics = Array.from(new Set(timeline.map((e) => eventTactic(e.event_uid, evidence, techniques))));
  return (
    <figure className="activity">
      <figcaption className="sr-only">Activity from {firstSeen ?? timeline[0].time} to {lastSeen ?? timeline[timeline.length - 1].time} with {timeline.length} timeline claims.</figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Activity strip: ${timeline.length} claims between ${timeline[0].time} and ${timeline[timeline.length - 1].time}`} className="activity-svg">
        <line x1="8" y1="30" x2={W - 8} y2="30" stroke="currentColor" opacity="0.35" />
        {ticks.map((tick, i) => (
          <g key={i}>
            <line x1={tick.x} y1="24" x2={tick.x} y2="36" stroke="currentColor" opacity="0.5" />
            <text x={tick.x} y="50" textAnchor={i === 0 ? "start" : i === ticks.length - 1 ? "end" : "middle"} className="svg-tick">{fmtTick(tick.ms)}</text>
          </g>
        ))}
        {clusters.map((cluster) => {
          const first = cluster.indices[0];
          const e = timeline[first];
          const t = times[first];
          const tac = eventTactic(e.event_uid, evidence, techniques);
          const isBreak = first > 0 && med > 0 && Number.isFinite(times[first - 1]) && (t - times[first - 1]) > med * 5;
          const isCluster = cluster.indices.length > 1;
          return (
            <g key={first}>
              {isBreak ? (<><line x1={cluster.x - 6} y1="14" x2={cluster.x - 2} y2="46" stroke="currentColor" opacity="0.6" /><line x1={cluster.x - 2} y1="14" x2={cluster.x + 2} y2="46" stroke="currentColor" opacity="0.6" /><text x={cluster.x} y="64" textAnchor="middle" className="svg-gap">{fmtDur(t - times[first - 1])}</text></>) : null}
              {isCluster ? (
                <g tabIndex={0} role="button" aria-label={`${cluster.indices.length} claims clustered at ${e.time}. Jump to the first of them: claim ${first + 1}, ${e.description}, event ${e.event_uid}`}
                  onMouseEnter={() => onHighlight(first)} onMouseLeave={() => onHighlight(null)}
                  onFocus={() => onHighlight(first)} onBlur={() => onHighlight(null)}
                  onClick={() => onJump?.(first)}
                  onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onJump?.(first); } }}>
                  <circle cx={cluster.x} cy="30" r="10" fill={TACTIC_FILL[tac] ?? TACTIC_FILL.other} stroke={highlighted !== null && cluster.indices.includes(highlighted) ? "currentColor" : "none"} strokeWidth="2" />
                  <text x={cluster.x} y="34" textAnchor="middle" className="svg-count">{cluster.indices.length}</text>
                </g>
              ) : (
                <circle cx={cluster.x} cy="30" r={highlighted === first ? 7 : 5} fill={TACTIC_FILL[tac] ?? TACTIC_FILL.other} stroke={highlighted === first ? "currentColor" : "none"} strokeWidth="2"
                  tabIndex={0} role="button" aria-label={`Claim ${first + 1}: ${e.description} at ${e.time}, event ${e.event_uid}${tac !== "other" ? `, tactic ${TACTIC_NAMES[tac] ?? tac}` : ", neutral: no technique tied"}`}
                  onMouseEnter={() => onHighlight(first)} onMouseLeave={() => onHighlight(null)}
                  onFocus={() => onHighlight(first)} onBlur={() => onHighlight(null)} />
              )}
            </g>
          );
        })}
      </svg>
      <ul className="activity-legend">
        <li><span className="legend-dot" aria-hidden="true" /> A dot is one timeline claim at its timestamp; a numbered badge is several claims within 6 px, and activating it jumps to the first of them.</li>
        <li><span aria-hidden="true">// </span>The break symbol means a gap longer than five times the median gap between claims; its duration is printed under it.</li>
        <li>Color means the ATT&amp;CK tactic of the technique tied to that claim&apos;s event; <span className="legend-dot legend-neutral" aria-hidden="true" /> neutral: no technique tied.</li>
        {presentTactics.filter((t) => t !== "other").map((t) => (
          <li key={t}><span className="legend-dot" style={{ background: TACTIC_FILL[t] }} aria-hidden="true" /> {TACTIC_NAMES[t] ?? t}</li>
        ))}
      </ul>
      <ul className="sr-only">{timeline.map((e, i) => <li key={i}>{e.time}: {e.description} (event {e.event_uid})</li>)}</ul>
    </figure>
  );
}

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
    <div className="lifecycle">
      <p className="sr-only">Rule lifecycle: candidate, then shadow, then active. Rolled back and archived are side states. Current status is {known ? status : `${status} (unknown)`}{dates[status] ? ` since ${dates[status]}` : ""}.</p>
      <ol className="lc-main" aria-hidden="true">{LIFECYCLE_MAIN.map((s) => step(s))}</ol>
      <ul className="lc-sides" aria-hidden="true">{LIFECYCLE_SIDE.map((s) => step(s, true))}</ul>
      {!known ? <p className="muted">Current status: <span className="mono">{status || "unknown"}</span> (not a known lifecycle state)</p> : null}
    </div>
  );
}

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
  const row = (label: string, value: number | null, n: number | null) => (
    <div className="bt-row">
      <span className="bt-label">{label}</span>
      <span className="bt-track" role="img" aria-label={`${label}: ${value ?? "not recorded"} matches${n !== null ? ` of n=${n}` : ", n not recorded"}`}><span className="bt-fill grow" style={{ width: `${((value ?? 0) / max) * 100}%` }} /></span>
      <span className="bt-value num">{value ?? "not recorded"} (n={n !== null ? n : "not recorded"})</span>
    </div>
  );
  return (
    <div className="backtest-bars">
      {row("Target events matched", f.matched, f.targetTotal)}
      {row("Benign baseline matches", f.baselineCount, f.baselineTotal)}
      <p className="sr-only">Backtest bars: target events matched {f.matched ?? "not recorded"} of {f.targetTotal ?? "not recorded"}; benign baseline matches {f.baselineCount ?? "not recorded"}{f.baselineTotal !== null ? ` of ${f.baselineTotal}` : " (baseline n not recorded in the payload)"}.</p>
    </div>
  );
}

export function KillChainStrip({ counts, selected, onSelect }: { counts: Record<string, number>; selected: string | null; onSelect: (t: string | null) => void }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="killchain" role="group" aria-label="Kill chain tactics">
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
