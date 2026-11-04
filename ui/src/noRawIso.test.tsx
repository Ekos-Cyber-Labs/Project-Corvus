import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./app/App";
import type { Dashboard, IncidentDetail, IncidentListItem, RuleDetail, RuleListItem, SettingsView, SweepStatus } from "./api/types";

const ISO = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ/;

function visibleText(): string {
  const parts: string[] = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node: Text | null;
  while ((node = walker.nextNode() as Text | null)) {
    const el = node.parentElement;
    if (!el) continue;
    if (el.closest(".sr-only")) continue;
    if (el.closest("script,style")) continue;
    parts.push(node.textContent ?? "");
  }
  return parts.join(" ");
}

function dashboard(): Dashboard {
  return {
    totals: { incidents: 173, by_severity: { critical: 20, high: 90, medium: 50, low: 12, informational: 1 }, by_verdict: { true_positive: 40 }, pending: 100, analyzed: 70, failed: 1, quarantined: 2, with_injection: 3 },
    spend: { total_usd: 1.1, cap_usd: 100 },
    activity: [{ hour: "2026-11-02T05:00:00Z", incidents: 4 }],
    window: { start: "2026-11-01T00:00:00Z", end: "2026-11-02T00:00:00Z", anchored_to: "now" },
    sweep_runs: [],
    recent: [{ id: 11, title: "recent one", final_severity: 5, verdict_kind: "true_positive", analyzed_at: "2026-11-02T05:02:00Z" }],
  };
}

function sweep(): SweepStatus {
  return {
    last: { id: 3, poll_cycle_id: 9, started_at: "2026-11-02T05:00:00Z", finished_at: "2026-11-02T05:01:00Z", status: "ok", error_code: "", analyzed: 5, failed_analyses: 1, skipped_policy: 2, skipped_budget: 0, new_alerts: 40, new_incidents: 7, poll_status: "ok", interval_seconds: 300 },
    running: false,
    next_run_at: null,
    policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 },
  };
}

function listItem(): IncidentListItem {
  return {
    id: 1, title: "sudo escalation on host-1", severity_floor: 4, severity_floor_name: "High",
    severity_id: 5, severity_name: "Critical", ai_status: "done", verdict: "true_positive",
    first_seen: "2026-11-02T05:00:00Z", last_seen: "2026-11-02T06:00:00Z",
    event_count: 41, has_injection: false, analyzed: true, quarantined: false,
  };
}

function incidentDetail(): IncidentDetail {
  return {
    id: 1, title: "sudo escalation on host-1", severity_floor: 4, severity_floor_name: "High",
    severity_id: 5, severity_name: "Critical", ai_status: "done", verdict: "true_positive",
    first_seen: "2026-11-02T05:00:00Z", last_seen: "2026-11-02T06:00:00Z", event_count: 41,
    techniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
    triage: { summary: "First line.", status: "resolved", model: "glimmer" },
    analysis: {
      verdict: "true_positive", severity_id: 5, confidence: 0.9,
      timeline: [{ time: "2026-11-02T05:10:11Z", event_uid: "evt-1", description: "first claim" }],
      response_plan: ["Isolate host"], visibility_gaps: [], language: "en", model: "muse-spark-1.3", status: "resolved",
    },
    agent_trace: [{ step: 1, tool: "get_events", arguments: { host: "HOST-0001" }, result_summary: "returned 2 events", tokens: 9 }],
    llm_attempts: [{ purpose: "analysis", model: "muse-spark-1.3", attempt_number: 1, outcome: "ok", failed_validator: null, tokens: 9, token_source: "usage", usd: 0.01 }],
    severity_factors: { level_cap: { applied: true, contribution: "capped" } },
    injection_signals: [],
    evidence: [{ event_uid: "evt-1", found: true, event: { host: "HOST-0001" } }],
    learned_rules: [],
    spend_total_usd: 0.098,
    pseudonym_resolution: { resolved: true, note: "Tokens resolved locally." },
  };
}

function ruleItem(): RuleListItem {
  return {
    id: 9, title: "sudo rule", status: "shadow", mode: "shadow", version: 1,
    level: "high", techniques: ["T1059"], hits: 2, false_positives: 0,
    created_at: "2026-11-01T00:00:00Z", source_incident_id: 1,
  };
}

function ruleDetail(): RuleDetail {
  return {
    ...ruleItem(),
    sigma_text: "title: sudo rule\ndescription: catches sudo\n",
    lineage: {
      source_incident: { id: 1, exists: true, title: "source incident" },
      cited_uids: ["evt-1"],
      backtest: { codes: ["accepted"], target_matched: ["evt-1"], target_total: 1, baseline_count: 0, group: "corvus_sigma", sigma_sha256: "abc" },
      rounds_used: 2, model: "muse-spark-1.3", prompt_version: "v1", ledger_ids: [1],
    },
    transitions: [{ from: "candidate", to: "shadow", approver: "op", reason: "promote", at: "2026-11-01T12:00:00Z" }],
    findings: [],
    wazuh: { native_rule_id: 100100, native_rule_ids: [100100], group: "corvus_sigma", mode: "shadow" },
  };
}

function settingsView(): SettingsView {
  return {
    sweep_policy: { source: "configured", policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } },
    connections: [{ name: "database", address: "postgresql://127.0.0.1:55432", state: "connected" }],
    spend_cap_usd: 100, app_version: "0.1.0", attack_version: "v20.0", ocsf_version: "1.9.0",
  };
}

function stubAll() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => dashboard() };
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => settingsView() };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => sweep() };
    if (path === "/api/incidents/1") return { ok: true, status: 200, json: async () => incidentDetail() };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [listItem()], total: 1, limit: 20, offset: 0 }) };
    if (path === "/api/rules/9") return { ok: true, status: 200, json: async () => ruleDetail() };
    if (path === "/api/rules") {
      const query = new URLSearchParams(url.split("?")[1] ?? "");
      const status = query.get("status");
      const total = !status || status === "shadow" ? 1 : 0;
      return { ok: true, status: 200, json: async () => ({ items: status && status !== "shadow" ? [] : [ruleItem()], total, limit: 20, offset: 0 }) };
    }
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}

describe("no raw ISO timestamps in visible text", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; localStorage.clear(); });
  const pages: [string, RegExp][] = [
    ["#/", /Latest verdicts from the sweep/],
    ["#/dashboard", /Latest verdicts from the sweep/],
    ["#/incidents", /sudo escalation on host-1/],
    ["#/incidents/1", /As seen by the cloud model \(pseudonymized\)\./],
    ["#/rules", /1 rule: 1 shadow rule/],
    ["#/rules/9", /Sigma rule \(text only\)/],
    ["#/settings", /Automatic sweep/],
  ];
  for (const [hash, marker] of pages) {
    it(`renders ${hash} without raw ISO text`, async () => {
      stubAll();
      window.location.hash = hash;
      render(<App />);
      await screen.findByText(marker);
      expect(visibleText()).not.toMatch(ISO);
    });
  }
  it("keeps the exact ISO in title attributes", async () => {
    stubAll();
    window.location.hash = "#/dashboard";
    render(<App />);
    await screen.findByText("Latest verdicts from the sweep");
    expect(document.body.innerHTML).toContain("2026-11-02T05:02:00Z");
  });
});
