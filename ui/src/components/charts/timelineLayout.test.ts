import { describe, expect, it } from "vitest";
import { layoutTimeline } from "./timelineLayout";

const base = Date.parse("2026-11-03T00:00:00Z");
const at = (sec: number) => new Date(base + sec * 1000).toISOString();
const claims = (...secs: number[]) => secs.map((s) => ({ time: at(s) }));

function overlaps(a: { x: number; y: number; width: number; height: number }, b: { x: number; y: number; width: number; height: number }): boolean {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}

describe("layoutTimeline table cases", () => {
  it("one claim is a single centered 10 px dot", () => {
    const layout = layoutTimeline(claims(60), 720, at(60), at(60));
    expect(layout.marks).toHaveLength(1);
    expect(layout.dots).toHaveLength(1);
    expect(layout.clusters).toHaveLength(0);
    expect(layout.marks[0].r).toBe(5);
    expect(layout.marks[0].x).toBeCloseTo(360, 0);
    expect(layout.dateLabel).toBe("2026-11-03");
  });

  it("two claims at the same timestamp form one 20 px badge", () => {
    const layout = layoutTimeline(claims(10, 10), 720, null, null);
    expect(layout.marks).toHaveLength(1);
    expect(layout.clusters).toHaveLength(1);
    expect(layout.marks[0].count).toBe(2);
    expect(layout.marks[0].r).toBe(10);
    expect(layout.marks[0].indices).toEqual([0, 1]);
  });

  it("many claims within 24 px chain into one badge", () => {
    const layout = layoutTimeline(claims(0, 1, 2, 3600), 720, null, null);
    expect(layout.clusters.map((c) => c.indices)).toEqual([[0, 1, 2]]);
    expect(layout.dots.map((d) => d.indices)).toEqual([[3]]);
  });

  it("evenly spread claims stay single with no break", () => {
    const layout = layoutTimeline(claims(0, 3600, 7200, 10800, 14400), 900, null, null);
    expect(layout.marks).toHaveLength(5);
    expect(layout.clusters).toHaveLength(0);
    expect(layout.breaks).toHaveLength(0);
  });

  it("one huge gap draws one break with its duration label", () => {
    const layout = layoutTimeline(claims(0, 10, 20, 1000), 900, null, null);
    expect(layout.breaks).toHaveLength(1);
    expect(layout.breaks[0].label).toBe("16m gap");
    expect(layout.breaks[0].showSymbol).toBe(true);
  });

  it("all gaps equal means no break", () => {
    const layout = layoutTimeline(claims(0, 100, 200, 300), 720, null, null);
    expect(layout.breaks).toHaveLength(0);
  });

  it("claims with an invalid timestamp are skipped without breaking the rest", () => {
    const input = [{ time: "not-a-date" }, { time: at(0) }, { time: "" }, { time: at(3600) }, { time: at(7200) }];
    const layout = layoutTimeline(input, 720, null, null);
    expect(layout.skippedIndices).toEqual([0, 2]);
    expect(layout.marks.map((m) => m.indices)).toEqual([[1], [3], [4]]);
  });

  it("does not stretch the axis to first_seen or last_seen outside the claim range", () => {
    const layout = layoutTimeline(claims(100, 200), 720, at(0), at(100000));
    expect(layout.axisStartMs).not.toBeNull();
    expect(layout.axisStartMs as number).toBeGreaterThan(at(0) ? Date.parse(at(0)) : 0);
    expect(layout.axisStartMs as number).toBeLessThan(Date.parse(at(100)));
    expect(layout.axisEndMs as number).toBeLessThan(Date.parse(at(100000)));
    expect(layout.outsideFirstSeen).toBe(true);
    expect(layout.outsideLastSeen).toBe(true);
  });

  it("axis has 4 percent padding on both sides of the claim range", () => {
    const layout = layoutTimeline(claims(0, 1000), 720, null, null);
    expect(layout.axisStartMs).toBe(Date.parse(at(0)) - 40000);
    expect(layout.axisEndMs).toBe(Date.parse(at(1000)) + 40000);
  });
});

const realTimes = ["13:14:38", "13:14:38", "13:14:39", "13:15:17", "13:15:18", "13:15:23", "13:15:25", "13:15:30", "13:15:33", "13:15:33", "13:15:34", "13:15:56"];
const realClaims = realTimes.map((t) => ({ time: `2026-11-03T${t}Z` }));

describe("layoutTimeline on the real incident fixture", () => {
  it("at 1800 px groups, breaks and mentions last_seen outside the axis", () => {
    const layout = layoutTimeline(realClaims, 1800, "2026-11-03T13:14:38Z", "2026-11-03T13:17:14Z");
    expect(layout.marks.map((m) => m.count)).toEqual([3, 2, 1, 1, 1, 3, 1]);
    expect(layout.breaks.map((b) => b.label)).toEqual(["38s gap", "22s gap"]);
    expect(layout.breaks.every((b) => b.showSymbol)).toBe(true);
    expect(layout.outsideFirstSeen).toBe(false);
    expect(layout.outsideLastSeen).toBe(true);
    expect(layout.ticks).toHaveLength(6);
    expect(layout.ticks[0].label).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(layout.dateLabel).toBe("2026-11-03");
  });

  it("at 390 px keeps the same breaks with wider clustering", () => {
    const layout = layoutTimeline(realClaims, 390, "2026-11-03T13:14:38Z", "2026-11-03T13:17:14Z");
    expect(layout.marks.map((m) => m.count)).toEqual([3, 8, 1]);
    expect(layout.breaks.map((b) => b.label)).toEqual(["38s gap", "22s gap"]);
    expect(layout.ticks).toHaveLength(5);
    for (const mark of layout.marks) {
      expect(mark.r).toBe(mark.count > 1 ? 10 : 5);
    }
  });
});

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("layoutTimeline invariants over randomized timelines", () => {
  it("holds for 200 seeded cases at widths 320 to 1800", () => {
    const rand = mulberry32(20261103);
    for (let caseNo = 0; caseNo < 200; caseNo++) {
      const width = Math.floor(320 + rand() * 1480);
      const n = 1 + Math.floor(rand() * 9);
      let t = Math.floor(rand() * 3600);
      const secs: number[] = [];
      for (let i = 0; i < n; i++) {
        secs.push(t);
        const step = rand();
        t += step < 0.55 ? Math.floor(rand() * 8) : step < 0.9 ? Math.floor(rand() * 120) : Math.floor(rand() * 3000);
      }
      const layout = layoutTimeline(secs.map((s) => ({ time: new Date(Date.parse("2026-11-03T00:00:00Z") + s * 1000).toISOString() })), width, null, null);
      for (let i = 0; i < layout.marks.length; i++) {
        const mark = layout.marks[i];
        expect(mark.x - mark.r, `case ${caseNo} mark inside left`).toBeGreaterThanOrEqual(0);
        expect(mark.x + mark.r, `case ${caseNo} mark inside right`).toBeLessThanOrEqual(width);
        if (i > 0) expect(mark.x - layout.marks[i - 1].x, `case ${caseNo} mark distance`).toBeGreaterThanOrEqual(24 - 1e-9);
      }
      const labelBoxes = [...layout.ticks.map((tick) => tick.box), ...layout.breaks.map((b) => b.labelBox)];
      for (const b of labelBoxes) {
        expect(b.x, `case ${caseNo} label inside left`).toBeGreaterThanOrEqual(0);
        expect(b.right, `case ${caseNo} label inside right`).toBeLessThanOrEqual(width);
        expect(b.width, `case ${caseNo} label width`).toBeGreaterThan(0);
      }
      for (let i = 0; i < labelBoxes.length; i++) {
        for (let j = i + 1; j < labelBoxes.length; j++) {
          expect(overlaps(labelBoxes[i], labelBoxes[j]), `case ${caseNo} labels ${i} and ${j} overlap`).toBe(false);
        }
      }
      for (const tick of layout.ticks) {
        for (const mark of layout.marks) {
          expect(tick.box.y - (mark.y + mark.r), `case ${caseNo} tick clearance`).toBeGreaterThanOrEqual(14);
          expect(overlaps(tick.box, { x: mark.x - mark.r, y: mark.y - mark.r, width: mark.r * 2, height: mark.r * 2 }), `case ${caseNo} tick over mark`).toBe(false);
        }
      }
      for (const brk of layout.breaks) {
        for (const mark of layout.marks) {
          expect(overlaps(brk.labelBox, { x: mark.x - mark.r, y: mark.y - mark.r, width: mark.r * 2, height: mark.r * 2 }), `case ${caseNo} gap label over mark`).toBe(false);
        }
        if (brk.showSymbol) {
          const prev = layout.marks[brk.prevMarkIndex];
          const next = layout.marks[brk.nextMarkIndex];
          expect(brk.x - (prev.x + prev.r), `case ${caseNo} break distance to previous mark`).toBeGreaterThanOrEqual(12);
          expect(next.x - next.r - brk.x, `case ${caseNo} break distance to next mark`).toBeGreaterThanOrEqual(12);
        }
      }
      expect(layout.ticks.length, `case ${caseNo} tick count`).toBeGreaterThanOrEqual(2);
      expect(layout.ticks.length, `case ${caseNo} tick count`).toBeLessThanOrEqual(6);
      expect(layout.ticks[layout.ticks.length - 1].anchor).toBe("end");
    }
  });
});
