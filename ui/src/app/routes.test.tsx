import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
function stubFetch() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/health") return { ok: true, status: 200, json: async () => ({ status: "ok" }) };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    if (path === "/api/rules") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => ({ totals: { incidents: 0, by_severity: {}, by_verdict: {}, pending: 0, analyzed: 0, failed: 0, quarantined: 0, with_injection: 0 }, spend: { total_usd: 0, cap_usd: 100 }, activity: [], window: { start: null, end: null, anchored_to: null }, sweep_runs: [], recent: [] }) };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: null, running: false, next_run_at: null, policy: null }) };
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => ({ sweep_policy: { source: "configured", policy: null }, connections: [], spend_cap_usd: null, app_version: "0.1.0", attack_version: "v20.0", ocsf_version: "1.9.0" }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
describe("app shell routing", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("renders the dashboard at the root and dashboard paths", async () => {
    window.location.hash = "#/";
    stubFetch();
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeTruthy();
    expect(screen.getByText("Dashboard", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
  it("renders the incident list at the incidents path", async () => {
    window.location.hash = "#/incidents";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("No incidents found.")).toBeTruthy();
    expect(screen.getByText("Incidents", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
  it("renders the settings page with its cards", async () => {
    window.location.hash = "#/settings";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("Automatic sweep")).toBeTruthy();
    expect(screen.getByText("Settings", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
  it("marks rules active on the rules path", async () => {
    window.location.hash = "#/rules";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("No learned rules found.")).toBeTruthy();
    expect(screen.getByText("Rules", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
});
