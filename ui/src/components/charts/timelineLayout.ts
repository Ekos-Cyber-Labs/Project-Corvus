export type TimelineClaimInput = { time: string };
export type LabelBox = { x: number; y: number; width: number; height: number; right: number; bottom: number };
export type TimelineMark = {
  kind: "dot" | "cluster";
  indices: number[];
  claimIndices: number[];
  count: number;
  x: number;
  y: number;
  r: number;
  timeMs: number;
  firstMs: number;
  lastMs: number;
};
export type TimelineTick = { x: number; ms: number; label: string; anchor: "start" | "middle" | "end"; box: LabelBox };
export type TimelineBreak = {
  x: number;
  y1: number;
  y2: number;
  gapMs: number;
  durationMs: number;
  label: string;
  labelX: number;
  labelY: number;
  labelBox: LabelBox;
  showSymbol: boolean;
  symbol: boolean;
  prevMarkIndex: number;
  nextMarkIndex: number;
};
export type TimelineLayout = {
  width: number;
  height: number;
  axisY: number;
  axisStartMs: number | null;
  axisEndMs: number | null;
  range: { startMs: number; endMs: number } | null;
  axis: { startMs: number; endMs: number } | null;
  marks: TimelineMark[];
  dots: TimelineMark[];
  clusters: TimelineMark[];
  ticks: TimelineTick[];
  breaks: TimelineBreak[];
  dateLabel: string;
  validIndices: number[];
  skippedIndices: number[];
  outsideFirstSeen: boolean;
  outsideLastSeen: boolean;
  medianGapMs: number;
};

export const TIMELINE_HEIGHT = 84;
export const TIMELINE_AXIS_Y = 38;
export const TIMELINE_MIN_WIDTH = 320;
export const CLUSTER_DISTANCE_PX = 24;
const PLOT_LEFT = 14;
const CHAR_WIDTH = 6;
const TICK_LABEL_Y = 62;
const TICK_LABEL_HEIGHT = 11;
const GAP_LABEL_Y = 12;
const GAP_LABEL_HEIGHT = 11;

function box(x: number, y: number, width: number, height: number): LabelBox {
  return { x, y, width, height, right: x + width, bottom: y + height };
}
function parseMs(t: string): number {
  const n = Date.parse(t);
  return Number.isFinite(n) ? n : NaN;
}
function median(xs: number[]): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}
export function formatGapLabel(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s gap`;
  if (s < 3600) return `${Math.round(s / 60)}m gap`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h gap`;
  return `${(s / 86400).toFixed(1)}d gap`;
}
function timeLabel(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function localDate(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
export function clusterPositions(xs: number[], threshold = CLUSTER_DISTANCE_PX): { indices: number[]; x: number }[] {
  const groups: { indices: number[]; xs: number[]; lastX: number }[] = [];
  xs.forEach((x, i) => {
    const last = groups[groups.length - 1];
    if (last && x - last.lastX < threshold) {
      last.indices.push(i);
      last.xs.push(x);
      last.lastX = x;
    } else {
      groups.push({ indices: [i], xs: [x], lastX: x });
    }
  });
  return groups.map((g) => ({ indices: g.indices, x: g.xs.reduce((a, b) => a + b, 0) / g.xs.length }));
}

export function layoutTimeline(claims: TimelineClaimInput[], width: number, firstSeen?: string | null, lastSeen?: string | null): TimelineLayout {
  const effectiveWidth = Number.isFinite(width) && width > 0 ? Math.max(TIMELINE_MIN_WIDTH, width) : 720;
  const entries: { index: number; ms: number }[] = [];
  const skippedIndices: number[] = [];
  claims.forEach((claim, index) => {
    const ms = claim && typeof claim.time === "string" ? parseMs(claim.time) : NaN;
    if (Number.isFinite(ms)) entries.push({ index, ms });
    else skippedIndices.push(index);
  });
  entries.sort((a, b) => a.ms - b.ms || a.index - b.index);
  if (!entries.length) {
    return {
      width: effectiveWidth, height: TIMELINE_HEIGHT, axisY: TIMELINE_AXIS_Y, axisStartMs: null, axisEndMs: null,
      range: null, axis: null, marks: [], dots: [], clusters: [], ticks: [], breaks: [], dateLabel: "",
      validIndices: [], skippedIndices, outsideFirstSeen: false, outsideLastSeen: false, medianGapMs: 0,
    };
  }
  const minMs = entries[0].ms;
  const maxMs = entries[entries.length - 1].ms;
  const spanMs = maxMs - minMs;
  const padMs = spanMs > 0 ? spanMs * 0.04 : 500;
  const axisStartMs = minMs - padMs;
  const axisEndMs = maxMs + padMs;
  const axisSpan = axisEndMs - axisStartMs;
  const plotWidth = effectiveWidth - PLOT_LEFT * 2;
  const xFor = (ms: number) => PLOT_LEFT + ((ms - axisStartMs) / axisSpan) * plotWidth;
  const sortedXs = entries.map((e) => xFor(e.ms));
  const grouped = clusterPositions(sortedXs);
  const marks: TimelineMark[] = grouped.map((g) => {
    const members = g.indices.map((k) => entries[k]);
    const count = members.length;
    return {
      kind: count > 1 ? "cluster" : "dot",
      indices: members.map((m) => m.index),
      claimIndices: members.map((m) => m.index),
      count,
      x: g.x,
      y: TIMELINE_AXIS_Y,
      r: count > 1 ? 10 : 5,
      timeMs: members[0].ms,
      firstMs: members[0].ms,
      lastMs: members[members.length - 1].ms,
    };
  });
  const tickCount = Math.min(6, Math.max(2, Math.floor(plotWidth / 90) + 1));
  const ticks: TimelineTick[] = Array.from({ length: tickCount }, (_, i) => {
    const f = i / (tickCount - 1);
    const x = PLOT_LEFT + f * plotWidth;
    const ms = axisStartMs + f * axisSpan;
    const label = timeLabel(ms);
    const anchor: TimelineTick["anchor"] = i === 0 ? "start" : i === tickCount - 1 ? "end" : "middle";
    const w = label.length * CHAR_WIDTH;
    const bx = anchor === "start" ? x : anchor === "end" ? x - w : x - w / 2;
    return { x, ms, label, anchor, box: box(bx, TICK_LABEL_Y, w, TICK_LABEL_HEIGHT) };
  });
  const claimGaps: number[] = [];
  for (let i = 1; i < entries.length; i++) {
    const g = entries[i].ms - entries[i - 1].ms;
    if (g > 0) claimGaps.push(g);
  }
  const medianGapMs = median(claimGaps);
  const breaks: TimelineBreak[] = [];
  if (medianGapMs > 0) {
    for (let i = 1; i < marks.length; i++) {
      const prev = marks[i - 1];
      const next = marks[i];
      const gapMs = next.firstMs - prev.lastMs;
      if (!(gapMs > medianGapMs * 5)) continue;
      const prevEdge = prev.x + prev.r;
      const nextEdge = next.x - next.r;
      const x = (prevEdge + nextEdge) / 2;
      const showSymbol = x - prevEdge >= 12 && nextEdge - x >= 12;
      const label = formatGapLabel(gapMs);
      const w = label.length * CHAR_WIDTH;
      const labelX = Math.min(Math.max(x, w / 2), Math.max(w / 2, effectiveWidth - w / 2));
      breaks.push({
        x, y1: TIMELINE_AXIS_Y - 8, y2: TIMELINE_AXIS_Y + 8, gapMs, durationMs: gapMs, label,
        labelX, labelY: GAP_LABEL_Y + GAP_LABEL_HEIGHT, labelBox: box(labelX - w / 2, GAP_LABEL_Y, w, GAP_LABEL_HEIGHT),
        showSymbol, symbol: showSymbol, prevMarkIndex: i - 1, nextMarkIndex: i,
      });
    }
    for (let i = 1; i < breaks.length; i++) {
      const prevBox = breaks[i - 1].labelBox;
      const cur = breaks[i];
      const needed = prevBox.right + 2 - cur.labelBox.x;
      if (needed > 0) {
        cur.labelX += needed;
        cur.labelBox = box(cur.labelX - cur.labelBox.width / 2, GAP_LABEL_Y, cur.labelBox.width, GAP_LABEL_HEIGHT);
      }
    }
    for (let i = breaks.length - 1; i >= 0; i--) {
      const cur = breaks[i];
      const overflow = cur.labelBox.right - effectiveWidth;
      if (overflow > 0) {
        cur.labelX -= overflow;
        cur.labelBox = box(cur.labelX - cur.labelBox.width / 2, GAP_LABEL_Y, cur.labelBox.width, GAP_LABEL_HEIGHT);
      }
      if (i < breaks.length - 1) {
        const nextBox = breaks[i + 1].labelBox;
        const overlap = cur.labelBox.right + 2 - nextBox.x;
        if (overlap > 0) {
          cur.labelX -= overlap;
          cur.labelBox = box(cur.labelX - cur.labelBox.width / 2, GAP_LABEL_Y, cur.labelBox.width, GAP_LABEL_HEIGHT);
        }
      }
      if (cur.labelBox.x < 0) {
        cur.labelX -= cur.labelBox.x;
        cur.labelBox = box(0, GAP_LABEL_Y, cur.labelBox.width, GAP_LABEL_HEIGHT);
        cur.labelX = cur.labelBox.width / 2;
      }
    }
  }
  const firstMs = typeof firstSeen === "string" ? parseMs(firstSeen) : NaN;
  const lastMs = typeof lastSeen === "string" ? parseMs(lastSeen) : NaN;
  return {
    width: effectiveWidth,
    height: TIMELINE_HEIGHT,
    axisY: TIMELINE_AXIS_Y,
    axisStartMs,
    axisEndMs,
    range: { startMs: axisStartMs, endMs: axisEndMs },
    axis: { startMs: axisStartMs, endMs: axisEndMs },
    marks,
    dots: marks.filter((m) => m.kind === "dot"),
    clusters: marks.filter((m) => m.kind === "cluster"),
    ticks,
    breaks,
    dateLabel: localDate(minMs),
    validIndices: entries.map((e) => e.index),
    skippedIndices,
    outsideFirstSeen: Number.isFinite(firstMs) && (firstMs < axisStartMs || firstMs > axisEndMs),
    outsideLastSeen: Number.isFinite(lastMs) && (lastMs < axisStartMs || lastMs > axisEndMs),
    medianGapMs,
  };
}
