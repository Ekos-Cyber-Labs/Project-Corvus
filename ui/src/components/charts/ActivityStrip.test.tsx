import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActivityStrip, localZoneLabel } from "./ActivityStrip";
import type { TimelineEntry } from "./ActivityStrip";

const realTimes = ["13:14:38", "13:14:38", "13:14:39", "13:15:17", "13:15:18", "13:15:23", "13:15:25", "13:15:30", "13:15:33", "13:15:33", "13:15:34", "13:15:56"];
const realTimeline: TimelineEntry[] = realTimes.map((t, i) => ({ time: `2026-11-03T${t}Z`, event_uid: `evt-${i}`, description: `claim ${i + 1}` }));

let callbacks: ((entries: { contentRect: { width: number } }[]) => void)[] = [];

class FakeResizeObserver {
  constructor(cb: (entries: { contentRect: { width: number } }[]) => void) {
    callbacks.push(cb);
  }
  observe() {}
  disconnect() {}
}

function setWidth(width: number) {
  act(() => {
    for (const cb of callbacks) cb([{ contentRect: { width } }]);
  });
}

describe("ActivityStrip in real pixels", () => {
  afterEach(() => {
    callbacks = [];
    delete (globalThis as Record<string, unknown>).ResizeObserver;
  });

  it("renders marks of equal pixel size at 1800 and at 390 px on the real incident", () => {
    (globalThis as Record<string, unknown>).ResizeObserver = FakeResizeObserver;
    const { container } = render(<ActivityStrip timeline={realTimeline} firstSeen="2026-11-03T13:14:38Z" lastSeen="2026-11-03T13:17:14Z" highlighted={null} onHighlight={() => {}} onJump={() => {}} />);
    setWidth(1800);
    const svgAt1800 = container.querySelector("svg.activity-svg");
    expect(svgAt1800?.getAttribute("viewBox")).toBe("0 0 1800 84");
    expect(svgAt1800?.getAttribute("width")).toBe("1800");
    const radiiAt1800 = Array.from(container.querySelectorAll("circle")).map((c) => c.getAttribute("r")).sort();
    expect(radiiAt1800).toEqual(["10", "10", "10", "5", "5", "5", "5"].sort());
    const localDay = (iso: string) => {
      const d = new Date(iso);
      const p = (n: number) => String(n).padStart(2, "0");
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
    };
    expect(container.querySelector("figcaption")?.textContent).toContain(localDay("2026-11-03T13:14:38Z"));
    expect(container.querySelector("figcaption")?.textContent).not.toContain("(UTC)");
    expect(container.querySelector("figcaption")?.textContent).toContain(`Times in your local time zone (${localZoneLabel()})`);
    expect(screen.getByText((_, el) => el?.textContent === `Times in your local time zone (${localZoneLabel()}).`)).toBeTruthy();
    expect(container.querySelector("figcaption")?.textContent).toContain("incident last_seen 2026-11-03T13:17:14Z lies outside the displayed axis range");
    expect(Array.from(container.querySelectorAll(".svg-gap")).map((t) => t.textContent)).toEqual(["38s gap", "22s gap"]);
    setWidth(390);
    const svgAt390 = container.querySelector("svg.activity-svg");
    expect(svgAt390?.getAttribute("viewBox")).toBe("0 0 390 84");
    const radiiAt390 = Array.from(container.querySelectorAll("circle")).map((c) => c.getAttribute("r")).sort();
    expect(radiiAt390).toEqual(["10", "10", "5"].sort());
    const dotRadii = (list: (string | null)[]) => list.filter((r) => r === "5");
    expect(dotRadii(radiiAt390)).toEqual(dotRadii(radiiAt1800).slice(0, dotRadii(radiiAt390).length));
    const ticks = Array.from(container.querySelectorAll(".svg-tick")).map((t) => t.textContent ?? "");
    expect(ticks).toHaveLength(5);
    for (const tick of ticks) expect(tick).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    const lastTick = container.querySelectorAll(".svg-tick")[ticks.length - 1];
    expect(lastTick.getAttribute("text-anchor")).toBe("end");
  });

  it("uses the 720 fallback without ResizeObserver and keeps the legend wording", () => {
    delete (globalThis as Record<string, unknown>).ResizeObserver;
    const { container } = render(<ActivityStrip timeline={realTimeline} firstSeen="2026-11-03T13:14:38Z" lastSeen="2026-11-03T13:17:14Z" highlighted={null} onHighlight={() => {}} />);
    expect(container.querySelector("svg.activity-svg")?.getAttribute("viewBox")).toBe("0 0 720 84");
    const legend = container.querySelector(".activity-legend");
    expect(legend?.textContent).toContain("claims closer than 24 px are grouped into a numbered badge; activate it to jump to the first of them");
    expect(legend?.textContent).not.toContain("//");
    expect(legend?.textContent).not.toContain("6 px");
    expect(legend?.querySelector("svg")).toBeTruthy();
    expect(screen.getByText(/break symbol means a gap longer than five times the median/)).toBeTruthy();
  });

  it("keeps the screen-reader caption and claim list in local time", () => {
    delete (globalThis as Record<string, unknown>).ResizeObserver;
    const { container } = render(<ActivityStrip timeline={realTimeline} firstSeen="2026-11-03T13:14:38Z" lastSeen="2026-11-03T13:17:14Z" highlighted={null} onHighlight={() => {}} onJump={() => {}} />);
    const caption = container.querySelector("figcaption")?.textContent ?? "";
    const withoutOutside = caption.replace(/incident (first_seen|last_seen) \S+ lies outside[^,]*/g, "");
    expect(withoutOutside).not.toMatch(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/);
    expect(withoutOutside).toContain("from ");
    const srItems = Array.from(container.querySelectorAll(".sr-only li")).map((li) => li.textContent ?? "");
    expect(srItems).toHaveLength(realTimeline.length);
    for (const item of srItems) expect(item).not.toMatch(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/);
  });

  it("keeps badge jump, highlight sync and keyboard activation", () => {
    delete (globalThis as Record<string, unknown>).ResizeObserver;
    const onHighlight = vi.fn();
    const onJump = vi.fn();
    render(<ActivityStrip timeline={realTimeline} firstSeen="2026-11-03T13:14:38Z" lastSeen="2026-11-03T13:17:14Z" highlighted={null} onHighlight={onHighlight} onJump={onJump} />);
    const badge = screen.getByLabelText(/3 claims clustered at 2026-11-03T13:14:38/);
    fireEvent.mouseEnter(badge);
    expect(onHighlight).toHaveBeenCalledWith(0);
    fireEvent.focus(badge);
    expect(onHighlight).toHaveBeenCalledWith(0);
    fireEvent.keyDown(badge, { key: "Enter" });
    expect(onJump).toHaveBeenCalledWith(0);
    fireEvent.keyDown(badge, { key: " " });
    expect(onJump).toHaveBeenCalledWith(0);
    fireEvent.click(badge);
    expect(onJump).toHaveBeenCalledWith(0);
  });
});
