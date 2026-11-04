import { describe, expect, it } from "vitest";
import { formatAgo, formatDate, formatTime, formatDateTime } from "./formatDateTime";

const pad = (n: number) => String(n).padStart(2, "0");

describe("formatDateTime", () => {
  it("renders local time without seconds by default", () => {
    const d = new Date(2026, 10, 3, 17, 47, 5);
    expect(formatDateTime(d.toISOString())).toBe(`Nov ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`);
  });
  it("adds seconds only when asked", () => {
    const d = new Date(2026, 10, 3, 2, 49, 3);
    const iso = d.toISOString();
    expect(formatDateTime(iso, { seconds: true })).toBe(`Nov ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    expect(formatTime(iso)).toBe(`${pad(d.getHours())}:${pad(d.getMinutes())}`);
    expect(formatTime(iso, { seconds: true })).toBe(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
    expect(formatDate(iso)).toBe(`Nov ${d.getDate()}`);
  });
  it("passes null and garbage through as text, never throws", () => {
    expect(formatDateTime(null)).toBe("not recorded");
    expect(formatDateTime(undefined)).toBe("not recorded");
    expect(formatDateTime("not-a-date")).toBe("not-a-date");
    expect(formatTime(null)).toBe("not recorded");
    expect(formatAgo(undefined)).toBe("not recorded");
  });
  it("renders relative minutes, hours and days", () => {
    const now = new Date(2026, 10, 3, 18, 0, 0).getTime();
    const iso = (minsAgo: number) => new Date(now - minsAgo * 60000).toISOString();
    expect(formatAgo(iso(22), now)).toBe("22 min ago");
    expect(formatAgo(iso(0), now)).toBe("just now");
    expect(formatAgo(iso(180), now)).toBe("3 h ago");
    expect(formatAgo(iso(3000), now)).toBe("2 d ago");
  });
});
