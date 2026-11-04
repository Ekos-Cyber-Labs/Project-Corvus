import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./app/App";
import { PRESENTATION_STORAGE_KEY } from "./app/providers";
import { resetMaskedIpMapping } from "./lib/maskPublicIps";
import type { Dashboard, IncidentDetail, IncidentListItem, RuleDetail, RuleListItem, SettingsView, SweepStatus } from "./api/types";

const V4A = "8.8.8.8";
const V4B = "1.1.1.1";
const V4C = "203.0.113.9";
const V6A = "2606:4700:4700::1111";
const V6B = "2001:4860:4860::8888";
const PLANTED = [V4A, V4B, V4C, V6A, V6B];
const PRIVATE = "10.9.9.9";

function incidentItem(): IncidentListItem {
  return {
    id: 1, title: `escalation from ${V4A} to ${V6A}`, severity_floor: 4, severity_floor_name: "High",
    severity_id: 5, severity_name: "Critical", ai_status: "done", verdict: "true_positive",
    event_count: 7, has_injection: false, analyzed: true,
  };
}

function incidentDetail(): IncidentDetail {
  return {
    id: 1, title: `escalation from ${V4A} to ${V6A}`, severity_floor: 4, severity_floor_name: "High",
    severity_id: 5, severity_name: "Critical", ai_status: "done", verdict: "true_positive",
    first_seen: "2026-11-03T13:14:38Z", last_seen: "2026-11-03T13:15:56Z", event_count: 7,
    techniques: [{ id: "T1059", name: `runs on ${V4B}` }],
    analysis: {
      verdict: "true_positive",
      timeline: [{ time: "2026-11-03T13:14:38Z", event_uid: "evt-1", description: `dial ${V4A}:22 then ${V6A}` }],
      response_plan: [`block ${V4A} at the edge`, `watch ${V6B}`],
      visibility_gaps: [`no logs for ${V4B}`],
      language: "en", model: "muse-spark-1.3",
    },
    triage: { summary: `saw ${V4A} talking to ${V6A}`, model: "glimmer" },
    injection_signals: [{ event_uid: "evt-1", field: "command", pattern_id: "pat-1", requested_effect: "run", payload_text: `curl ${V4A}`, payload_label: "cmd" }],
    evidence: [{ event_uid: "evt-1", found: true, event: { src: V4A, dst: V6A, port: `${V4C}:22`, priv: PRIVATE } }],
    agent_trace: [{ step: 1, tool: "get_events", arguments: { ip: V4A }, result_summary: `saw ${V6A}`, tokens: 9 }],
    llm_attempts: [{ purpose: "analysis", model: "muse-spark-1.3", attempt_number: 1, outcome: `ok from ${V4B}`, failed_validator: null, tokens: 9, token_source: "measured", usd: 0.01 }],
    severity_factors: { beacon: { applied: true, contribution: `calls to ${V4A}` } },
    reasoning_unverified: { text: `thinks ${V6B} is bad`, unverified: true },
    pseudonym_resolution: { resolved: true, note: `resolved near ${PRIVATE}` },
  };
}

function ruleItem(): RuleListItem {
  return {
    id: 9, title: `block ${V4A}`, status: "shadow", mode: "shadow", version: 2,
    level: "medium", techniques: ["T1059"], hits: 3, false_positives: 1,
    created_at: "2026-10-30T12:00:00Z", source_incident_id: 1,
  };
}

function ruleDetail(): RuleDetail {
  return {
    ...ruleItem(),
    sigma_text: `title: block ${V4A}\ndetection:\n  sel:\n    dst: ${V6A}\n`,
    lineage: {
      source_incident: { id: 1, exists: true, title: `escalation from ${V4A}` },
      cited_uids: ["evt-1"], backtest: { codes: ["accepted"], group: `corvus ${V4B}`, sigma_sha256: "abc" },
      rounds_used: 2, model: "muse-spark-1.3", prompt_version: "v3",
      ledger_ids: [7], lineage_note: `learned from ${V6B}`,
    },
    transitions: [{ from: "candidate", to: "shadow", approver: `op ${V4A}`, reason: `covers ${V6A}`, at: "2026-11-01T00:00:00Z" }],
    findings: [{ incident_id: 1, incident_title: `escalation from ${V4A}`, findings: 2 }],
  };
}

function dashboard(): Dashboard {
  return {
    totals: { incidents: 1, by_severity: { critical: 1 }, by_verdict: {}, pending: 0, analyzed: 1, failed: 0, quarantined: 0, with_injection: 0 },
    spend: { total_usd: 0.01, cap_usd: 100 },
    activity: [{ hour: "2026-11-02T05:00:00Z", incidents: 1 }],
    window: { start: "2026-11-01T00:00:00Z", end: "2026-11-02T00:00:00Z", anchored_to: "now" },
    sweep_runs: [],
    recent: [{ id: 1, title: `escalation from ${V4A} to ${V6A}`, final_severity: 5, verdict_kind: "verdict", analyzed_at: "2026-11-02T05:02:00Z" }],
  };
}

function settingsView(): SettingsView {
  return {
    sweep_policy: { source: "configured", policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } },
    connections: [{ name: "wazuh_indexer", address: `https://${V4C}:9200`, state: "connected" }],
    spend_cap_usd: 100, app_version: "0.1.0", attack_version: "v20.0", ocsf_version: "1.9.0",
  };
}

function sweep(): SweepStatus {
  return { last: null, running: false, next_run_at: null, policy: null };
}

function stubAll() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/dashboard") return { ok: true, status: 200, json: async () => dashboard() };
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => settingsView() };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => sweep() };
    if (path === "/api/incidents/1") return { ok: true, status: 200, json: async () => incidentDetail() };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [incidentItem()], total: 1, limit: 20, offset: 0 }) };
    if (path === "/api/rules/9") return { ok: true, status: 200, json: async () => ruleDetail() };
    if (path === "/api/rules") return { ok: true, status: 200, json: async () => ({ items: [ruleItem()], total: 1 }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}

function leftovers(text: string): string[] {
  const found: string[] = [];
  const re = /\d{1,3}(?:\.\d{1,3}){3}/g;
  let m: RegExpExecArray | null;
  const priv = (o: number[]) =>
    o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) ||
    o[0] === 127 || (o[0] === 169 && o[1] === 254) || (o[0] === 0 && o[1] === 0 && o[2] === 0 && o[3] === 0) ||
    (o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) ||
    (o[0] === 203 && o[1] === 0 && o[2] === 113);
  while ((m = re.exec(text)) !== null) {
    const oct = m[0].split(".").map(Number);
    if (oct.some((n) => n > 255)) continue;
    if (!priv(oct)) found.push(m[0]);
  }
  return found;
}

function expectMasked() {
  const html = document.body.innerHTML;
  for (const ip of PLANTED) expect(html, `leaked ${ip}`).not.toContain(ip);
  expect(leftovers(html), "public v4 leftovers").toEqual([]);
  expect(document.body.textContent).toContain("198.51.100.");
}

describe("presentation mode coverage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    window.location.hash = "#/";
    localStorage.clear();
    resetMaskedIpMapping();
  });

  it("masks every API string on the dashboard", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/";
    render(<App />);
    await screen.findByText("Latest verdicts from the sweep");
    expectMasked();
  });

  it("masks the incidents list and preview", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/incidents";
    render(<App />);
    await screen.findByText("Open full analysis");
    expectMasked();
  });

  it("masks the incident detail view", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/incidents/1";
    render(<App />);
    await screen.findByRole("heading", { name: "Agent trace" });
    expectMasked();
  });

  it("masks the rules list and detail", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/rules";
    render(<App />);
    await screen.findByText("Sigma rule (text only)");
    expectMasked();
  });

  it("masks the rule detail view", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/rules/9";
    render(<App />);
    await screen.findByText("Sigma rule (text only)");
    expectMasked();
  });

  it("masks the settings connections", async () => {
    stubAll();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    window.location.hash = "#/settings";
    render(<App />);
    await screen.findByText("Automatic sweep");
    expectMasked();
  });

  it("leaves the addresses visible when the mode is off", async () => {
    stubAll();
    window.location.hash = "#/incidents/1";
    render(<App />);
    await screen.findByRole("heading", { name: "Agent trace" });
    expect(document.body.innerHTML).toContain(V4A);
    expect(document.body.innerHTML).toContain(V6A);
  });
});
