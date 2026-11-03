import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../../app/App";
import type { RuleDetail, RuleListItem } from "../../api/types";
const HOSTILE = "<img src=x onerror=alert(1)>\u0000control";
const ruleItems: RuleListItem[] = [
  { id: 3, title: "sudo shadow rule", status: "shadow", mode: "shadow", version: 1, level: "high", techniques: ["T1059"], hits: 7, false_positives: 0, created_at: "2026-11-01T00:00:00Z", source_incident_id: 11 },
  { id: 4, title: HOSTILE, status: "candidate", mode: null, version: 1, techniques: [], hits: 0, false_positives: 0, source_incident_id: 12 },
];
function ruleDetail(id: number): RuleDetail {
  return {
    id, title: id === 3 ? "sudo shadow rule" : HOSTILE, status: id === 3 ? "shadow" : "candidate", mode: id === 3 ? "shadow" : null, version: 1,
    level: "high", techniques: id === 3 ? ["T1059"] : [], hits: 7, false_positives: 0, created_at: "2026-11-01T00:00:00Z", source_incident_id: id === 3 ? 11 : 12,
    sigma_text: "title: sudo shadow rule",
    wazuh: { native_rule_id: 100100, native_rule_ids: [100100], group: "corvus_sigma", mode: "shadow", pair_note: "pair note" },
    lineage: { sigma_rule_id: "11111111-2222-4333-8444-555555555555", source_incident: { id: 11, exists: true, title: "source incident" }, cited_uids: ["evt-1"], backtest: { codes: ["accepted"], target_matched: ["evt-1", "evt-2"], target_total: 2, baseline_count: 0, group: "corvus_sigma" }, rounds_used: 2, model: "muse-spark-1.3", prompt_version: "rule_proposal/v1", ledger_ids: [1], lineage_note: null },
    transitions: [{ from: null, to: "candidate", approver: "op", reason: "stored", at: "2026-11-01T00:00:00Z" }, { from: "candidate", to: "shadow", approver: "op", reason: "promoted", at: "2026-11-02T00:00:00Z" }],
    findings: [],
  };
}
function stub() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    const query = url.includes("?") ? url.split("?")[1] : "";
    if (path === "/api/rules/3") return { ok: true, status: 200, json: async () => ruleDetail(3) };
    if (path === "/api/rules/4") return { ok: true, status: 200, json: async () => ruleDetail(4) };
    if (path === "/api/rules") {
      if (query.includes("status=candidate")) return { ok: true, status: 200, json: async () => ({ items: ruleItems.filter((r) => r.status === "candidate"), total: 1, limit: 1, offset: 0 }) };
      if (query.includes("status=shadow")) return { ok: true, status: 200, json: async () => ({ items: ruleItems.filter((r) => r.status === "shadow"), total: 1, limit: 1, offset: 0 }) };
      if (query.includes("status=active")) return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 1, offset: 0 }) };
      return { ok: true, status: 200, json: async () => ({ items: ruleItems, total: 2, limit: 20, offset: 0 }) };
    }
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => ({ totals: { incidents: 0, by_severity: {}, by_verdict: {}, pending: 0, analyzed: 0, failed: 0, quarantined: 0, with_injection: 0 }, spend: { total_usd: 0, cap_usd: 100 }, activity: [], window: { start: null, end: null, anchored_to: null }, sweep_runs: [], recent: [] }) };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: null, running: false, next_run_at: null, policy: null }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
describe("rules console", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("shows the lifecycle bar with counts and the shadow banner", async () => {
    stub();
    window.location.hash = "#/rules";
    const { container } = render(<App />);
    await screen.findByText("sudo shadow rule");
    expect(screen.getAllByText(/Proposed/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Backtested/).length).toBeGreaterThan(0);
    expect(await screen.findByText("Sigma rule (text only)")).toBeTruthy();
    expect(screen.getByText("Shadow mode. This rule is evaluated and logged only. It never changes an alert until a human promotes it.")).toBeTruthy();
    expect(screen.getAllByText("Accepted backtest").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Lifecycle history").length).toBeGreaterThan(0);
    expect(container.querySelector("img")).toBeNull();
  });
  it("selects the first rule without a selection and switches on click", async () => {
    stub();
    window.location.hash = "#/rules";
    render(<App />);
    await screen.findByText("sudo shadow rule");
    await waitFor(() => { expect(screen.getAllByText("sudo shadow rule").length).toBeGreaterThan(1); });
    fireEvent.click(screen.getByText(/control/).closest("a")!);
    await waitFor(() => { expect(screen.getAllByText(/control/).length).toBeGreaterThan(0); });
  });
  it("renders hostile rule titles as text only", async () => {
    stub();
    window.location.hash = "#/rules";
    const { container } = render(<App />);
    await screen.findByText("sudo shadow rule");
    fireEvent.click(screen.getByText(/control/).closest("a")!);
    await screen.findByText("Sigma rule (text only)");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
  });
});
