import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HashRouter } from "react-router";
import { App } from "../../app/App";
import { Sidebar } from "../../components/layout/Sidebar";
import { formatMoney, policySentence, verdictChip } from "./utils/dashboard";
import type { Dashboard, SweepStatus } from "../../api/types";
const HOSTILE = "<img src=x onerror=alert(1)>\u0000\u0001red";
function dashboard(over: Partial<Dashboard> = {}): Dashboard {
  return {
    totals: { incidents: 401, by_severity: { critical: 20, high: 90, medium: 150, low: 141, informational: 0 }, by_verdict: {}, pending: 300, analyzed: 95, failed: 2, quarantined: 4, with_injection: 6 },
    spend: { total_usd: 1.1, cap_usd: 100 },
    activity: Array.from({ length: 24 }, (_, i) => ({ hour: `2026-11-02T${String(i).padStart(2, "0")}:00:00Z`, incidents: i })),
    window: { start: "2026-11-01T00:00:00Z", end: "2026-11-02T00:00:00Z", anchored_to: "now" },
    sweep_runs: [{ id: 3, started_at: "2026-11-02T05:00:00Z", finished_at: "2026-11-02T05:01:00Z", status: "ok", analyzed: 5, failed_analyses: 0, skipped_policy: 2, skipped_budget: 0 }],
    recent: [
      { id: 11, title: "recent one", final_severity: 5, verdict_kind: "verdict", analyzed_at: "2026-11-02T05:02:00Z" },
      { id: 12, title: HOSTILE, final_severity: 4, verdict_kind: "quarantined", analyzed_at: "2026-11-02T05:03:00Z" },
    ],
    ...over,
  };
}
function sweep(over: Partial<SweepStatus> = {}): SweepStatus {
  return {
    last: { id: 3, poll_cycle_id: 9, started_at: "2026-11-02T05:00:00Z", finished_at: "2026-11-02T05:01:00Z", status: "ok", error_code: "", analyzed: 5, failed_analyses: 1, skipped_policy: 2, skipped_budget: 0, new_alerts: 40, new_incidents: 7, poll_status: "ok", interval_seconds: 300 },
    running: false,
    next_run_at: new Date(Date.now() + 125000).toISOString(),
    policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 },
    ...over,
  };
}
function stub(d: Dashboard, s: SweepStatus, calls: string[]) {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    calls.push(url);
    const path = url.split("?")[0];
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => d };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => s };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
describe("dashboard helpers", () => {
  it("formats money and the policy sentence", () => {
    expect(formatMoney(1.1)).toBe("$1.10");
    expect(formatMoney(null)).toBe("not measured");
    const sentence = policySentence({ min_floor: 4, max_analyses: 5, always_analyze_injection: true }, 100);
    expect(sentence).toContain("Floor High or above");
    expect(sentence).toContain("up to 5 analyses per sweep");
    expect(sentence).toContain("Spend cap $100");
  });
  it("maps verdict kinds to chips", () => {
    expect(verdictChip("verdict")).toEqual({ text: "Verdict", className: "dash-verdict-tp" });
    expect(verdictChip("quarantined").text).toBe("Quarantined");
    expect(verdictChip("failed").text).toBe("Failed");
    expect(verdictChip("triaged").text).toBe("Skipped by policy");
  });
});
describe("DashboardPage", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("renders the four stat cards, bars, table and sweep card", async () => {
    stub(dashboard(), sweep(), []);
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText("Open incidents")).toBeTruthy();
    expect(screen.getByText("Injection quarantined")).toBeTruthy();
    expect(screen.getByText("Model spend")).toBeTruthy();
    expect(screen.getByText("Incidents by final severity")).toBeTruthy();
    expect(screen.getByText("Alert activity")).toBeTruthy();
    expect(screen.getByText("Latest verdicts from the sweep")).toBeTruthy();
    expect(screen.getByText("Sweep status")).toBeTruthy();
    expect(screen.getByLabelText(/Hourly incidents over 24 hours/)).toBeTruthy();
    expect(screen.getByText("View all").getAttribute("href")).toBe("#/incidents");
    expect(screen.getByText("View sweep policy").getAttribute("href")).toBe("#/settings");
  });
  it("shows an empty state when the sweep has not run", async () => {
    const calls: string[] = [];
    stub(dashboard({ totals: { incidents: 0, by_severity: {}, by_verdict: {}, pending: 0, analyzed: 0, failed: 0, quarantined: 0, with_injection: 0 }, recent: [], activity: [], sweep_runs: [] }), sweep({ last: null }), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText(/has not run yet/)).toBeTruthy();
    expect(screen.getByText(/corvus sweep/)).toBeTruthy();
  });
  it("shows an error state with a retry", async () => {
    vi.stubGlobal("fetch", async () => ({ ok: false, status: 503, json: async () => ({ detail: "database unavailable" }) }));
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText(/Could not load the dashboard/)).toBeTruthy();
    expect(screen.getByText("Retry")).toBeTruthy();
  });
  it("disables Sweep now with the host-run title", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const button = await screen.findByText("Sweep now");
    expect(button.tagName).toBe("BUTTON");
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("Run corvus sweep from the host");
  });
});
describe("sidebar sweep countdown", () => {
  afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); window.location.hash = "#/"; });
  it("counts down Next in m:ss from the sweep status", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-02T05:03:00Z"));
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      if (url.startsWith("/api/sweep/status")) return { ok: true, status: 200, json: async () => sweep({ running: false, next_run_at: "2026-11-02T05:05:00Z" }) };
      return { ok: true, status: 200, json: async () => ({ items: [], total: 0 }) };
    });
    render(<HashRouter><Sidebar /></HashRouter>);
    await vi.advanceTimersByTimeAsync(0);
    expect(screen.getByText("Sweep paused")).toBeTruthy();
    expect(screen.getByText("Next in 2:00")).toBeTruthy();
    await vi.advanceTimersByTimeAsync(1000);
    expect(screen.getByText("Next in 1:59")).toBeTruthy();
  });
  it("shows an incidents pill for pending high and critical", async () => {
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      if (url.startsWith("/api/incidents")) return { ok: true, status: 200, json: async () => ({ items: [], total: 7 }) };
      return { ok: true, status: 200, json: async () => ({ running: false, next_run_at: null, last: null }) };
    });
    render(<HashRouter><Sidebar /></HashRouter>);
    expect(await screen.findByText("7")).toBeTruthy();
  });
});
describe("dashboard hostile rendering", () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  it("renders hostile titles as plain text", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      calls.push(url);
      const path = url.split("?")[0];
      if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => dashboard() };
      if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => sweep() };
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
    window.location.hash = "#/dashboard";
    const { container } = render(<App />);
    await screen.findByText("recent one");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
  });
  it("exposes the sweep button to assistive tech", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const button = await screen.findByText("Sweep now");
    fireEvent.click(button);
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});
