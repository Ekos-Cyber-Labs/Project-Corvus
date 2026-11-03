import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HashRouter } from "react-router";
import { RecentVerdicts } from "./features/dashboard/components/RecentVerdicts";
import { SeverityDist } from "./features/dashboard/components/SeverityDist";
import { RuleDetailView } from "./features/rules/components/RuleDetail";
import { IncidentPreview } from "./features/incidents/components/IncidentPreview";
import { verdictKind } from "./features/incidents/utils/incidents";
import { formatCompactTime } from "./lib/format";
import type { Dashboard, RuleDetail } from "./api/types";
describe("visual defects", () => {
  afterEach(() => { vi.unstubAllGlobals(); });
  it("shows compact local time with full ISO in title and sr-only", () => {
    const { container } = render(<RecentVerdicts recent={[{ id: 25, title: "Incident title here", final_severity: 4, verdict_kind: "verdict", analyzed_at: "2026-11-03T18:14:51Z" }]} />);
    const cell = screen.getByTitle("2026-11-03T18:14:51Z");
    expect(cell.textContent).toContain(formatCompactTime("2026-11-03T18:14:51Z"));
    expect(cell.querySelector(".sr-only")?.textContent).toBe("2026-11-03T18:14:51Z");
    expect(container.querySelector("td")?.textContent).toBe("25");
    expect(screen.getByText("High")).toBeTruthy();
  });
  it("adds the verdict split under the severity bars", () => {
    const dashboard = { totals: { incidents: 10, by_severity: { critical: 1, high: 2, medium: 3, low: 4 }, by_verdict: { true_positive: 2, benign_authorized: 1, false_positive: 1, needs_human: 1 }, pending: 3, analyzed: 4, failed: 1, quarantined: 1, with_injection: 0 }, spend: { total_usd: 0, cap_usd: 100 }, activity: [], window: { start: null, end: null, anchored_to: null }, sweep_runs: [], recent: [] } as Dashboard;
    render(<SeverityDist dashboard={dashboard} />);
    expect(screen.getByText("true positive")).toBeTruthy();
    expect(screen.getByText("benign")).toBeTruthy();
    expect(screen.getByText("needs human")).toBeTruthy();
    expect(screen.getByText("quarantined")).toBeTruthy();
    expect(screen.getByText("failed")).toBeTruthy();
    expect(screen.getByText("pending")).toBeTruthy();
  });
  it("does not repeat the status word when status and mode match", () => {
    const detail: RuleDetail = { id: 9, title: "r", status: "shadow", mode: "shadow", version: 2, hits: 1, false_positives: 0, sigma_text: "title: r", lineage: { source_incident: null, cited_uids: [], backtest: null, ledger_ids: [] }, transitions: [], findings: [] };
    const { container } = render(<RuleDetailView detail={detail} />);
    const badges = container.querySelector(".hero-badges");
    expect(badges?.querySelectorAll(".badge").length).toBe(1);
    expect(badges?.textContent?.match(/shadow/g)?.length).toBe(1);
  });
  it("keeps failed on the list and quarantined only with attempts", () => {
    expect(verdictKind(null, "failed")).toBe("failed");
    expect(verdictKind(null, "failed", [{ purpose: "triage", outcome: "quarantined" }])).toBe("quarantined");
    expect(verdictKind(null, "pending")).toBe("pending");
  });
  it("colors reached gauge segments by severity and tints reached tactics", async () => {
    vi.stubGlobal("fetch", async () => ({ ok: true, status: 200, json: async () => ({ id: 7, title: "preview", severity_floor: 4, severity_id: 5, severity_floor_name: "High", ai_status: "done", verdict: "true_positive", techniques: [{ id: "T1059" }], triage: { summary: "line one" } }) }));
    const { container } = render(<HashRouter><IncidentPreview id={7} /></HashRouter>);
    expect(await screen.findByText("preview")).toBeTruthy();
    expect(screen.getByText("Floor High, raised one level by the model")).toBeTruthy();
    expect(container.querySelectorAll("[class*=\"seg\"]").length).toBeGreaterThan(0);
    expect(screen.getByText("Execution")).toBeTruthy();
  });
});
