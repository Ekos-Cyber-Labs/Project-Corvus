import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { readFileSync } from "node:fs";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { join } from "node:path";
import { App } from "./App";
// @ts-ignore: node core types are intentionally not installed (no new deps)
declare const process: { cwd(): string };
function stubAll() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => ({ totals: { incidents: 1, by_severity: { critical: 0, high: 1, medium: 0, low: 0 }, by_verdict: { true_positive: 1 }, pending: 0, analyzed: 1, failed: 0, quarantined: 0, with_injection: 0 }, spend: { total_usd: 0, cap_usd: 100 }, activity: [], window: { start: null, end: null, anchored_to: null }, sweep_runs: [], recent: [{ id: 25, title: "Recent incident", final_severity: 4, verdict_kind: "verdict", analyzed_at: "2026-11-03T18:14:51Z" }] }) };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: { id: 1, poll_cycle_id: 1, started_at: "2026-11-03T18:00:00Z", finished_at: null, status: "ok", error_code: "", analyzed: 1, failed_analyses: 0, skipped_policy: 0, skipped_budget: 0, new_alerts: 1, new_incidents: 1, poll_status: "ok", interval_seconds: 300 }, running: false, next_run_at: null, policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } }) };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [{ id: 25, title: "Listed incident", severity_floor: 4, severity_id: 5, ai_status: "failed", verdict: null, event_count: 3, has_injection: false }], total: 1, limit: 20, offset: 0 }) };
    if (path === "/api/incidents/25") return { ok: true, status: 200, json: async () => ({ id: 25, title: "Listed incident", severity_floor: 4, severity_id: 5, severity_floor_name: "High", severity_name: "Critical", ai_status: "failed", verdict: null, techniques: [{ id: "T1059" }], triage: { summary: "summary" }, llm_attempts: [{ purpose: "triage", model: "glimmer", attempt_number: 1, outcome: "quarantined", tokens: 1 }] }) };
    if (path === "/api/rules") return { ok: true, status: 200, json: async () => ({ items: [{ id: 9, title: "Rule nine", status: "shadow", mode: "shadow", version: 1, hits: 1, false_positives: 0, source_incident_id: 25 }], total: 1, limit: 20, offset: 0 }) };
    if (path === "/api/rules/9") return { ok: true, status: 200, json: async () => ({ id: 9, title: "Rule nine", status: "shadow", mode: "shadow", version: 1, hits: 1, false_positives: 0, source_incident_id: 25, sigma_text: "title: x", lineage: { source_incident: { id: 25, exists: true, title: "Listed incident" }, cited_uids: ["evt-1"], backtest: { codes: ["accepted"], target_matched: ["evt-1"], target_total: 1, baseline_count: 0 }, rounds_used: 1, model: "m", prompt_version: "v1", ledger_ids: [] }, transitions: [{ from: "candidate", to: "shadow", approver: "op", reason: "ok", at: "2026-11-03T00:00:00Z" }], findings: [] }) };
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => ({ sweep_policy: { source: "configured", policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } }, connections: [], spend_cap_usd: 100, app_version: "0.1.0", attack_version: "v20.0", ocsf_version: "1.9.0" }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
const SCREENS: [string, string][] = [
  ["#/dashboard", "Dashboard"],
  ["#/incidents", "Incidents"],
  ["#/rules", "Rules"],
  ["#/settings", "Settings"],
];
describe("themes on every screen", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; localStorage.clear(); document.documentElement.removeAttribute("data-theme"); });
  for (const theme of ["dark", "light"] as const) {
    for (const [hash, heading] of SCREENS) {
      it(`renders ${heading} with data-theme ${theme}`, async () => {
        localStorage.setItem("corvus-theme", theme);
        document.documentElement.dataset.theme = theme;
        stubAll();
        window.location.hash = hash;
        render(<App />);
        expect(await screen.findByRole("heading", { name: heading })).toBeTruthy();
        expect(document.documentElement.dataset.theme).toBe(theme);
      });
    }
  }
  it("sets the stored theme before first paint without using the system theme", () => {
    const html = readFileSync(join(process.cwd(), "index.html"), "utf-8");
    const scriptAt = html.indexOf("corvus-theme");
    const mainAt = html.indexOf("/src/main.tsx");
    expect(scriptAt).toBeGreaterThan(-1);
    expect(scriptAt).toBeLessThan(mainAt);
    expect(html).toContain("document.documentElement.dataset.theme");
    const script = /<script>([\s\S]*?corvus-theme[\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    expect(script).toContain("document.documentElement.dataset.theme");
    const run = (stored: string | null) => {
      const el = { dataset: {} as Record<string, string> };
      const fn = new Function("localStorage", "document", "window", script);
      fn({ getItem: () => stored }, { documentElement: el }, { matchMedia: () => ({ matches: true }) });
      return el.dataset.theme;
    };
    expect(run("light")).toBe("light");
    expect(run("dark")).toBe("dark");
    expect(run(null)).toBe("dark");
  });
});
