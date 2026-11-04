import { TACTIC_NAMES, tacticForTechnique } from "../../lib/attackMap";
import { formatDate, formatTime } from "../../lib/formatDateTime";
import { useMaskFn } from "../../lib/presentation";
import { useContainerWidth } from "../../lib/useContainerWidth";
import activityStyles from "./ActivityStrip.module.css";
import { layoutTimeline } from "./timelineLayout";
import { clusterPositions } from "./timelineLayout";

export type TimelineEntry = { time: string; event_uid: string; description: string };
export function localStamp(value: string): string {
  return `${formatDate(value)}, ${formatTime(value, { seconds: true })}`;
}
export function localZoneLabel(now = new Date()): string {
  const off = -now.getTimezoneOffset();
  if (off === 0) return "UTC";
  const sign = off < 0 ? "−" : "+";
  const abs = Math.abs(off);
  const h = Math.floor(abs / 60);
  const m = abs % 60;
  return m ? `UTC${sign}${h}:${String(m).padStart(2, "0")}` : `UTC${sign}${h}`;
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
  reconnaissance: "var(--tactic-reconnaissance)", "resource-development": "var(--tactic-resource-development)", "initial-access": "var(--tactic-initial-access)", execution: "var(--tactic-execution)",
  persistence: "var(--tactic-persistence)", "privilege-escalation": "var(--tactic-privilege-escalation)", stealth: "var(--tactic-stealth)", "defense-impairment": "var(--tactic-defense-impairment)",
  "credential-access": "var(--tactic-credential-access)", discovery: "var(--tactic-discovery)", "lateral-movement": "var(--tactic-lateral-movement)", collection: "var(--tactic-collection)",
  "command-and-control": "var(--tactic-command-and-control)", exfiltration: "var(--tactic-exfiltration)", impact: "var(--tactic-impact)", other: "var(--tactic-other)",
};

export type ActivityCluster = { indices: number[]; x: number };
export function clusterIndices(xs: number[], threshold = 24): ActivityCluster[] {
  return clusterPositions(xs, threshold);
}

export function ActivityStrip({ timeline, firstSeen, lastSeen, techniques, evidence, highlighted, onHighlight, onJump }: {
  timeline: TimelineEntry[]; firstSeen?: string | null; lastSeen?: string | null;
  techniques?: { id: string }[]; evidence?: { event_uid: string; event?: unknown }[];
  highlighted: number | null; onHighlight: (i: number | null) => void; onJump?: (i: number) => void;
}) {
  const [figureRef, containerWidth] = useContainerWidth<HTMLElement>(720);
  const mask = useMaskFn();
  if (!timeline.length) return null;
  const width = Math.max(320, containerWidth);
  const layout = layoutTimeline(timeline, width, firstSeen, lastSeen);
  const presentTactics = Array.from(new Set(timeline.map((e) => eventTactic(e.event_uid, evidence, techniques))));
  const zone = localZoneLabel();
  const captionParts: string[] = [];
  if (layout.dateLabel) captionParts.push(`Activity on ${layout.dateLabel}`);
  captionParts.push(`Times in your local time zone (${zone})`);
  captionParts.push(`${timeline.length} timeline claims`);
  if (layout.marks.length) captionParts.push(`from ${localStamp(timeline[layout.validIndices[0]].time)} to ${localStamp(timeline[layout.validIndices[layout.validIndices.length - 1]].time)}`);
  if (layout.outsideFirstSeen && firstSeen) captionParts.push(`incident first_seen ${firstSeen} lies outside the displayed axis range`);
  if (layout.outsideLastSeen && lastSeen) captionParts.push(`incident last_seen ${lastSeen} lies outside the displayed axis range`);
  if (layout.skippedIndices.length) captionParts.push(`${layout.skippedIndices.length} claims with invalid timestamps were skipped`);
  const caption = mask(`${captionParts.join(", ")}.`);
  return (
    <figure ref={figureRef} className={`activity ${activityStyles.activityRoot}`}>
      <figcaption className="sr-only">{caption}</figcaption>
      <svg viewBox={`0 0 ${layout.width} ${layout.height}`} width={layout.width} height={layout.height} role="img" aria-label={mask(`Activity strip: ${timeline.length} claims between ${timeline[0].time} and ${timeline[timeline.length - 1].time}`)} className={`activity-svg ${activityStyles.svg}`}>
        <line x1="14" y1={layout.axisY} x2={layout.width - 14} y2={layout.axisY} stroke="currentColor" opacity="0.35" />
        {layout.ticks.map((tick, i) => (
          <g key={i}>
            <line x1={tick.x} y1={layout.axisY - 6} x2={tick.x} y2={layout.axisY + 6} stroke="currentColor" opacity="0.5" />
            <text x={tick.x} y="70" textAnchor={tick.anchor} className={`svg-tick ${activityStyles.tick}`}>{tick.label}</text>
          </g>
        ))}
        {layout.breaks.map((brk, i) => (
          <g key={`break-${i}`}>
            {brk.showSymbol ? (<><line x1={brk.x - 5} y1={brk.y2} x2={brk.x - 1} y2={brk.y1} stroke="currentColor" opacity="0.6" /><line x1={brk.x + 1} y1={brk.y2} x2={brk.x + 5} y2={brk.y1} stroke="currentColor" opacity="0.6" /></>) : null}
            <text x={brk.labelX} y={brk.labelY} textAnchor="middle" className={`svg-gap ${activityStyles.gap}`}>{brk.label}</text>
          </g>
        ))}
        {layout.marks.map((mark) => {
          const first = mark.indices[0];
          const e = timeline[first];
          const tac = eventTactic(e.event_uid, evidence, techniques);
          const isCluster = mark.kind === "cluster";
          return (
            <g key={first}>
              {isCluster ? (
                <g tabIndex={0} role="button" aria-label={mask(`${mark.indices.length} claims clustered at ${e.time}. Jump to the first of them: claim ${first + 1}, ${e.description}, event ${e.event_uid}`)}
                  onMouseEnter={() => onHighlight(first)} onMouseLeave={() => onHighlight(null)}
                  onFocus={() => onHighlight(first)} onBlur={() => onHighlight(null)}
                  onClick={() => onJump?.(first)}
                  onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onJump?.(first); } }}>
                  <circle cx={mark.x} cy={mark.y} r={mark.r} style={{ fill: TACTIC_FILL[tac] ?? TACTIC_FILL.other }} stroke={highlighted !== null && mark.indices.includes(highlighted) ? "currentColor" : "none"} strokeWidth="2" />
                  <text x={mark.x} y={mark.y + 3} textAnchor="middle" className={`svg-count ${activityStyles.count}`}>{mark.indices.length}</text>
                </g>
              ) : (
                <circle cx={mark.x} cy={mark.y} r={mark.r} style={{ fill: TACTIC_FILL[tac] ?? TACTIC_FILL.other }} stroke={highlighted === first ? "currentColor" : "none"} strokeWidth="2"
                  tabIndex={0} role="button" aria-label={mask(`Claim ${first + 1}: ${e.description} at ${e.time}, event ${e.event_uid}${tac !== "other" ? `, tactic ${TACTIC_NAMES[tac] ?? tac}` : ", neutral: no technique tied"}`)}
                  onMouseEnter={() => onHighlight(first)} onMouseLeave={() => onHighlight(null)}
                  onFocus={() => onHighlight(first)} onBlur={() => onHighlight(null)} />
              )}
            </g>
          );
        })}
      </svg>
      <p className={`muted ${activityStyles.tz}`}>Times in your local time zone ({zone}).</p>
      <ul className={`activity-legend ${activityStyles.legend}`}>
        <li><span className="legend-dot" aria-hidden="true" /> A dot is one timeline claim at its timestamp; claims closer than 24 px are grouped into a numbered badge; activate it to jump to the first of them.</li>
        <li><svg className={activityStyles.breakIcon} width="18" height="16" viewBox="0 0 18 16" aria-hidden="true" focusable="false"><line x1="4" y1="15" x2="8" y2="1" stroke="currentColor" strokeWidth="1.5" /><line x1="10" y1="15" x2="14" y2="1" stroke="currentColor" strokeWidth="1.5" /></svg> The break symbol means a gap longer than five times the median gap between claims; its duration is printed above the axis.</li>
        <li>Color means the ATT&amp;CK tactic of the technique tied to that claim&apos;s event; <span className="legend-dot legend-neutral" aria-hidden="true" /> neutral: no technique tied.</li>
        {presentTactics.filter((t) => t !== "other").map((t) => (
          <li key={t}><span className="legend-dot" style={{ background: TACTIC_FILL[t] }} aria-hidden="true" /> {TACTIC_NAMES[t] ?? t}</li>
        ))}
      </ul>
      <ul className="sr-only">{timeline.map((e, i) => <li key={i}>{mask(`${localStamp(e.time)}: ${e.description} (event ${e.event_uid})`)}</li>)}</ul>
    </figure>
  );
}
