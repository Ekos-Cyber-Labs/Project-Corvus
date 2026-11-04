import { render, screen, waitFor, within } from "@testing-library/react";
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
      { id: 11, title: "recent one", final_severity: 5, verdict_kind: "verdict", verdict: "true_positive", analyzed_at: "2026-11-02T05:02:00Z" },
      { id: 12, title: HOSTILE, final_severity: 4, verdict_kind: "quarantined", verdict: null, analyzed_at: "2026-11-02T05:03:00Z" },
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
    expect(verdictChip("true_positive")).toEqual({ text: "True positive", className: "dash-verdict-tp" });
    expect(verdictChip("benign_authorized")).toEqual({ text: "Benign", className: "dash-verdict-benign" });
    expect(verdictChip("false_positive")).toEqual({ text: "False positive", className: "dash-verdict-benign" });
    expect(verdictChip("needs_human")).toEqual({ text: "Needs human", className: "dash-verdict-quar" });
    expect(verdictChip("quarantined").text).toBe("Quarantined");
    expect(verdictChip("failed").text).toBe("Failed");
    expect(verdictChip("triaged").text).toBe("Triaged");
    expect(verdictChip("pending").text).toBe("Pending");
    expect(verdictChip("weird_new_kind").text).toBe("weird_new_kind");
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
    expect(screen.getByText(/Sweeps run from the host/)).toBeTruthy();
  });
  it("shows an error state with a retry", async () => {
    vi.stubGlobal("fetch", async () => ({ ok: false, status: 503, json: async () => ({ detail: "database unavailable" }) }));
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText(/Could not load the dashboard/)).toBeTruthy();
    expect(screen.getByText("Retry")).toBeTruthy();
  });
  it("shows a read-only sweep line instead of a Sweep now button", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText(/Sweeps run from the host/)).toBeTruthy();
    expect(screen.queryByText("Sweep now")).toBeNull();
  });
  it("reads the open-incidents caption as new in the last sweep", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByText("7 new in the last sweep")).toBeTruthy();
  });
  it("shows the last sweep as local time plus a relative part with the ISO in the title", async () => {
    const calls: string[] = [];
    const started = new Date(Date.now() - 22 * 60000).toISOString();
    stub(dashboard(), sweep({ last: sweep().last && { ...sweep().last!, started_at: started } }), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const dd = await screen.findByTitle(started);
    expect(dd.textContent).toContain("22 min ago");
    expect(dd.textContent).toMatch(/\d{2}:\d{2} · 22 min ago/);
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
    await vi.waitFor(() => { expect(screen.getByText("Sweep paused")).toBeTruthy(); });
    const first = screen.getByText(/Next in \d+:\d\d/).textContent;
    await vi.advanceTimersByTimeAsync(5000);
    await vi.waitFor(() => { expect(screen.getByText(/Next in \d+:\d\d/).textContent).not.toBe(first); });
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
  it("explains the incidents pill and matches the pending high-or-higher list total", async () => {
    const seven = Array.from({ length: 7 }, (_, i) => ({ id: 200 + i, title: `pending high ${i}`, severity_floor: 4, severity_id: 4, ai_status: "pending", verdict: null, event_count: 2, has_injection: false, analyzed: false }));
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      const path = url.split("?")[0];
      if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => sweep({ last: null, running: false, next_run_at: null }) };
      if (path === "/api/incidents") {
        const query = new URLSearchParams(url.split("?")[1] ?? "");
        const match = query.get("min_floor") === "4" && query.get("analyzed") === "false";
        return { ok: true, status: 200, json: async () => ({ items: match ? seven : [], total: match ? 7 : 0, limit: 20, offset: 0 }) };
      }
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
    window.location.hash = "#/incidents?analyzed=false&min_floor=4";
    render(<App />);
    const pill = await screen.findByText("7");
    expect(pill.getAttribute("title")).toBe("7 incidents High or Critical pending analysis");
    expect(pill.getAttribute("aria-label")).toBe("7 incidents High or Critical pending analysis");
    expect(await screen.findByText("7 incidents, 0 analyzed, 0 with injection signals")).toBeTruthy();
  });
  it("shows no sweep running without a countdown, plus the last sweep when known", async () => {
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      if (url.startsWith("/api/sweep/status")) return { ok: true, status: 200, json: async () => ({ running: false, next_run_at: null, last: { status: "ok", started_at: "2026-11-02T18:00:00Z" } }) };
      return { ok: true, status: 200, json: async () => ({ items: [], total: 0 }) };
    });
    render(<HashRouter><Sidebar /></HashRouter>);
    expect(await screen.findByText("No sweep running")).toBeTruthy();
    expect(screen.queryByText(/Next in/)).toBeNull();
    expect(screen.getByText(/Last sweep/)).toBeTruthy();
  });
});
describe("severity distribution scaling", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("scales the four levels to their own max with Informational separate", async () => {
    const base = dashboard();
    const d = dashboard({
      totals: { ...base.totals, by_severity: { critical: 5, high: 6, medium: 0, low: 2, informational: 162 } },
    });
    const calls: string[] = [];
    stub(d, sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const heading = await screen.findByText("Incidents by final severity");
    const root = heading.closest("section")!;
    const scoped = within(root);
    const widthOf = (name: string): string | null => {
      const row = scoped.getByText(name).closest("li")!;
      const fill = row.querySelector('span[style*="width"]');
      return fill ? (fill as HTMLElement).style.width : null;
    };
    const high = widthOf("High");
    const critical = widthOf("Critical");
    expect(high).toBe("100%");
    expect(critical).not.toBeNull();
    expect(parseFloat(high!)).toBeGreaterThan(parseFloat(critical!));
    expect(widthOf("Medium")).toBeNull();
    const info = scoped.getByText("Informational").closest("li")!;
    expect(info.querySelector('span[style*="width"]')).toBeNull();
    expect(info.textContent).toContain("162");
    expect(scoped.getByText("Critical includes Fatal.")).toBeTruthy();
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
  it("keeps the sweep line readable text, not a control", async () => {
    const calls: string[] = [];
    stub(dashboard(), sweep(), calls);
    window.location.hash = "#/dashboard";
    const { container } = render(<App />);
    const line = await screen.findByText(/Sweeps run from the host/);
    expect(line.tagName).not.toBe("BUTTON");
    expect(container.querySelector("button[disabled]")).toBeNull();
  });
  it("shows one real verdict per row with its tone and the ISO time in the title", async () => {
    const kinds: [string, string, string][] = [
      ["true_positive", "True positive", "dash-verdict-tp"],
      ["benign_authorized", "Benign", "dash-verdict-benign"],
      ["false_positive", "False positive", "dash-verdict-benign"],
      ["needs_human", "Needs human", "dash-verdict-quar"],
      ["quarantined", "Quarantined", "dash-verdict-quar"],
    ];
    const base = dashboard();
    const d = dashboard({
      totals: { ...base.totals, by_verdict: {} },
      recent: kinds.map(([kind], i) => ({ id: 100 + i, title: `row ${kind}`, final_severity: 4, verdict_kind: kind, verdict: null, analyzed_at: `2026-11-02T05:${String(10 + i).padStart(2, "0")}:00Z` })),
    });
    const calls: string[] = [];
    stub(d, sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const table = await screen.findByRole("table", { name: "Latest verdicts from the sweep" });
    for (const [i, [, text, cls]] of kinds.entries()) {
      const pill = within(table).getByText(text);
      expect(pill.className).toContain(cls);
      expect(pill.getAttribute("title")).toBeTruthy();
      const timeCell = within(table).getByTitle(`2026-11-02T05:${String(10 + i).padStart(2, "0")}:00Z`);
      expect(timeCell.textContent).not.toMatch(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/);
    }
  });
  it("reads the stored verdict field so no pill reads Verdict", async () => {
    const rows: [string | null, string, string, string][] = [
      ["true_positive", "verdict", "True positive", "dash-verdict-tp"],
      ["benign_authorized", "verdict", "Benign", "dash-verdict-benign"],
      ["false_positive", "verdict", "False positive", "dash-verdict-benign"],
      ["needs_human", "verdict", "Needs human", "dash-verdict-quar"],
      [null, "quarantined", "Quarantined", "dash-verdict-quar"],
      [null, "failed", "Failed", "dash-verdict-failed"],
    ];
    const base = dashboard();
    const d = dashboard({
      totals: { ...base.totals, by_verdict: {} },
      recent: rows.map(([verdict, kind], i) => ({ id: 200 + i, title: `stored ${kind} ${i}`, final_severity: 4, verdict_kind: kind, verdict, analyzed_at: `2026-11-02T06:${String(10 + i).padStart(2, "0")}:00Z` })),
    });
    const calls: string[] = [];
    stub(d, sweep(), calls);
    window.location.hash = "#/dashboard";
    render(<App />);
    const table = await screen.findByRole("table", { name: "Latest verdicts from the sweep" });
    expect(within(table).queryByText("Verdict", { selector: "span" })).toBeNull();
    for (const [, , text, cls] of rows) {
      expect(within(table).getByText(text).className).toContain(cls);
    }
    expect(within(table).getByText("True positive").getAttribute("title")).toBe("true_positive");
  });
});
