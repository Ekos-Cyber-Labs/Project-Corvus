import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { PRESENTATION_STORAGE_KEY, PresentationProvider } from "../../app/providers";
import { resetMaskedIpMapping } from "../../lib/maskPublicIps";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { readFileSync } from "node:fs";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// @ts-ignore: node core types are intentionally not installed (no new deps)
declare const process: { cwd(): string };
import { App } from "../../app/App";
import { HealthStrip } from "../../components/layout/StatusPill";
import { IncidentDetailView as IncidentView } from "../incidents/components/IncidentDetail";
import { LearnedRuleRefs } from "./components/LearnedRuleRefs";
import { RuleDetailView } from "./components/RuleDetail";
import { RuleFilterBar } from "./components/RuleFilterBar";
import { RuleModeBadge } from "./components/RuleModeBadge";
import { RuleStatusBadge } from "./components/RuleStatusBadge";
import { LifecycleBar } from "./components/LifecycleBar";
import { RulesBanner } from "./components/RulesBanner";
import { RulesList } from "./components/RulesList";
import { backtestCodesText, ruleAltersAlertsText, ruleCountLine } from "./utils/rules";
import { buildRuleHash, buildRulesHash, parseHash } from "../../lib/hash";
import { buildRulesQuery } from "../../api/rules";
import type { IncidentDetail, RuleDetail, RuleListItem } from "../../api/types";
import { BacktestBars, backtestFigures } from "../../components/charts/BacktestBars";
import { LifecycleStepper } from "../../components/charts/LifecycleStepper";

const IMG = "<img src=x onerror=alert(1)>";
const SCRIPT = "</scr" + "ipt>";
const FULL_SCRIPT = "<script>alert(2)</script>";
const CDATA_END = "]]>";
const JS_URL = "javascript:alert(3)";
const ANSI = "[31mred[0m";
const BIG = `payload ${IMG} ${FULL_SCRIPT} ${CDATA_END} ${JS_URL} ${ANSI} ` + "x".repeat(100 * 1024);

const evilItem: RuleListItem = {
  id: 9,
  title: BIG,
  status: "shadow",
  mode: "shadow",
  version: 2,
  level: "medium",
  techniques: ["T1059"],
  hits: 3,
  false_positives: 1,
  created_at: "2026-10-30T12:00:00Z",
  source_incident_id: 4,
};

const evilDetail: RuleDetail = {
  ...evilItem,
  sigma_text: `title: ${BIG}\ndescription: ${IMG} ${JS_URL}\nlevel: medium`,
  wazuh: {
    native_rule_id: 100000,
    native_rule_ids: [100000],
    group: "corvus_sigma",
    mode: "shadow",
    pair_note: "pair note",
  },
  lineage: {
    sigma_rule_id: "11111111-2222-4333-8444-555555555555",
    source_incident: { id: 4, exists: true, title: `Source ${IMG}` },
    cited_uids: ["evt-1"],
    backtest: {
      codes: ["accepted"],
      target_matched: ["evt-1"],
      target_total: 1,
      baseline_count: 0,
      group: "corvus_sigma",
      sigma_sha256: "abc123",
    },
    rounds_used: 2,
    model: "muse-spark-1.3",
    prompt_version: "rule_proposal/v1",
    ledger_ids: [11],
    lineage_note: null,
  },
  transitions: [
    { from: null, to: "candidate", approver: null, reason: "stored", at: "t0" },
    { from: "candidate", to: "shadow", approver: `op ${IMG}`, reason: `ok ${JS_URL}`, at: "t1" },
  ],
  findings: [{ incident_id: 4, incident_title: `Fired ${IMG}`, mode: "shadow", shadow: true, version: 2, findings: 2 }],
};

function expectInert(container: HTMLElement) {
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("[onerror]")).toBeNull();
  expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  expect(container.querySelector("style")).toBeNull();
}

describe("RulesBanner", () => {
  it("states that shadow leaves alerts unchanged and updates no model weights", () => {
    render(<RulesBanner />);
    expect(screen.getByText(/never change alerts/)).toBeTruthy();
    expect(screen.getByText(/corvus_shadow/)).toBeTruthy();
    expect(screen.getByText(/no model weights are updated/)).toBeTruthy();
  });
});

describe("rule badges", () => {
  it("gives every lifecycle status its own badge class", () => {
    const { rerender } = render(<RuleStatusBadge status="candidate" />);
    expect(screen.getByText("candidate").className).toContain("rule-candidate");
    for (const s of ["shadow", "active", "archived", "rolled_back"]) {
      rerender(<RuleStatusBadge status={s} />);
      expect(screen.getByText(s).className).toContain(`rule-${s}`);
    }
  });

  it("labels undeployed rules and unknown values without inventing a mode", () => {
    render(<RuleModeBadge mode={null} />);
    expect(screen.getByText("not deployed").className).toContain("mode-none");
    const { container } = render(<RuleModeBadge mode="shadow" />);
    expect(container.querySelector(".mode-shadow")).not.toBeNull();
  });
});

describe("RulesList renders untrusted text as text only", () => {
  it("shows a hostile title verbatim with no executable elements", () => {
    const { container } = render(
      <RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={() => undefined} />,
    );
    expect(screen.getAllByText(/payload/).length).toBeGreaterThan(0);
    expectInert(container);
    const links = Array.from(container.querySelectorAll("a"));
    expect(links.length).toBe(1);
    expect(links[0].getAttribute("href")).toBe("#/rules/9");
  });

  it("says when the list is empty", () => {
    render(
      <RulesList items={[]} total={0} page={0} setPage={() => undefined} pageSize={20} onSelect={() => undefined} />,
    );
    expect(screen.getByText("No learned rules found.")).toBeTruthy();
  });

  it("cards carry a status chip, a from-incident line and a 3px selected border", () => {
    const { container } = render(
      <RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={() => undefined} selectedId={9} />,
    );
    expect(container.querySelector(".badge.rule-shadow")?.textContent).toBe("shadow");
    expect(container.textContent).toContain("From incident 4 · T1059");
    expect(container.querySelector('[aria-current="true"]')).not.toBeNull();
  });

  it("cards open on click or Space", () => {
    const seen: number[] = [];
    const { container } = render(
      <RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={(id) => seen.push(id)} />,
    );
    const card = container.querySelector("a");
    expect(card?.getAttribute("href")).toBe("#/rules/9");
    fireEvent.click(card!);
    fireEvent.keyDown(card!, { key: " " });
    expect(seen).toEqual([9, 9]);
  });
});

describe("RuleDetailView renders untrusted text as text only", () => {
  it("shows sigma, lineage and history verbatim with no executable elements", () => {
    const { container } = render(<RuleDetailView detail={evilDetail} />);
    expect(screen.getAllByText(/payload/).length).toBeGreaterThan(0);
    expectInert(container);
    const code = container.querySelector("pre code");
    expect(code?.textContent).toContain(IMG);
    expect(code?.textContent).toContain(JS_URL);
    expect(screen.getAllByText("Copy")).toHaveLength(2);
    expect(screen.getByText("stored")).toBeTruthy();
    expect(screen.getAllByText(/backtest/).length).toBeGreaterThan(0);
    const incidentLink = screen.getByRole("link", { name: /Fired/ });
    expect(incidentLink.getAttribute("href")).toBe("#/incidents/4");
  });

  it("names a deleted source incident instead of linking nowhere", () => {
    const deleted: RuleDetail = {
      ...evilDetail,
      lineage: { ...evilDetail.lineage, source_incident: { id: 4, exists: false, title: null } },
    };
    render(<RuleDetailView detail={deleted} />);
    expect(screen.getByText(/Incident 4 \(deleted\)/)).toBeTruthy();
  });

  it("says when lineage, backtest and transitions are missing", () => {
    const bare: RuleDetail = {
      ...evilItem,
      sigma_text: "title: bare",
      lineage: { source_incident: null, cited_uids: [], backtest: null, ledger_ids: [] },
      transitions: [],
      findings: [],
    };
    render(<RuleDetailView detail={bare} />);
    expect(screen.getAllByText("none recorded").length).toBeGreaterThan(0);
    expect(screen.getByText("No accepted backtest recorded.")).toBeTruthy();
    expect(screen.getByText("No transitions recorded.")).toBeTruthy();
    expect(screen.getByText("This rule has not fired in any incident.")).toBeTruthy();
  });
});

describe("incident learned-rule badges", () => {
  const base: IncidentDetail = {
    id: 4,
    title: "t",
    severity_floor: 4,
    severity_id: 4,
    ai_status: "done",
    verdict: "true_positive",
  };

  it("links a learned rule distinctly and hides unresolved placeholders", () => {
    const { container } = render(
      <IncidentView
        detail={{
          ...base,
          learned_rules: [
            { rule_db_id: 7, version: 2, mode: "shadow", shadow: true, findings: 2 },
            { unknown: true },
          ],
        }}
      />,
    );
    const badge = screen.getByText("learned rule v2 (shadow)");
    expect(badge.tagName).toBe("A");
    expect(badge.getAttribute("href")).toBe("#/rules/7");
    expect(badge.className).toContain("learned-rule");
    expect(badge.className).toContain("learned-shadow");
    expect(screen.queryByText("unknown learned rule (unresolved)")).toBeNull();
    expect(screen.queryByText("No learned rule matched this incident.")).toBeNull();
    expectInert(container);
  });

  it("says when no learned rule matched instead of raw placeholders", () => {
    render(<IncidentView detail={{ ...base, learned_rules: [{ unknown: true }, { rule_db_id: null }] }} />);
    expect(screen.getByText("No learned rule matched this incident.")).toBeTruthy();
    expect(screen.queryByText("unknown learned rule (unresolved)")).toBeNull();
  });

  it("renders nothing without learned refs", () => {
    const { container } = render(<LearnedRuleRefs refs={[]} />);
    expect(container.textContent).toBe("");
  });
});

describe("rules hash routing", () => {
  it("parses the rules list, detail and filters", () => {
    expect(parseHash("#/rules")).toEqual({ view: "rules", page: 0, status: null, mode: null });
    expect(parseHash("#/rules?status=shadow&mode=shadow&page=2")).toEqual({
      view: "rules", page: 2, status: "shadow", mode: "shadow",
    });
    expect(parseHash("#/rules/7")).toEqual({ view: "rule", id: "7" });
  });

  it("sanitizes invalid rule filter values to defaults", () => {
    expect(parseHash("#/rules?status=bogus&mode=candidate&page=abc")).toEqual({
      view: "rules", page: 0, status: null, mode: null,
    });
  });

  it("round-trips the rules hash", () => {
    expect(parseHash(buildRulesHash({ page: 1, status: "active", mode: "active" }))).toEqual({
      view: "rules", page: 1, status: "active", mode: "active",
    });
    expect(buildRulesHash({ page: 0, status: null, mode: null })).toBe("#/rules");
    expect(buildRuleHash(7)).toBe("#/rules/7");
    expect(buildRulesQuery({ page: 2, status: "shadow", mode: null }, 20)).toContain("status=shadow");
  });
});

describe("health strip names the model", () => {
  it("says which model the latency belongs to", () => {
    render(
      <HealthStrip
        health={{
          status: "ok",
          self_observation: { latest_model_latency_ms: 123, latest_model_latency_model: "muse-spark-1.3" },
        }}
      />,
    );
    expect(screen.getByText(/model muse-spark-1\.3/)).toBeTruthy();
    expect(screen.getByText(/123 ms/)).toBeTruthy();
  });

  it("stays honest when nothing was measured", () => {
    render(<HealthStrip health={{ status: "degraded", self_observation: {} }} />);
    expect(screen.getByText(/Latest model latency: not measured/)).toBeTruthy();
  });

  it("keeps the status line only as hidden text and chip tooltips, not a visible duplicate", () => {
    const { container } = render(
      <HealthStrip health={{ status: "ok", self_observation: { latest_model_latency_ms: 123, latest_model_latency_model: "muse-spark-1.3" } }} />,
    );
    expect(container.querySelector(".health-line")).toBeNull();
    const chip = container.querySelector(".chip");
    expect(chip?.getAttribute("title")).toContain("API");
    expect(container.querySelector(".health > p.sr-only")?.textContent).toContain("Latest model latency");
  });
});

describe("App rules routing", () => {
  const ruleItems: RuleListItem[] = [
    {
      id: 3, title: "Rule three", status: "shadow", mode: "shadow", version: 1,
      hits: 2, false_positives: 0,
    },
  ];
  const ruleThree: RuleDetail = {
    ...ruleItems[0],
    sigma_text: "title: Rule three",
    lineage: { source_incident: null, cited_uids: [], backtest: null, ledger_ids: [] },
    transitions: [],
    findings: [],
  };

  function stubRules(calls: string[]) {
    vi.stubGlobal(
      "fetch",
      async (input: unknown) => {
        const url = String(input);
        calls.push(url);
        const path = url.split("?")[0];
        if (path === "/api/health") {
          return { ok: true, status: 200, json: async () => ({ status: "ok" }) };
        }
        if (path === "/api/rules/3") {
          return { ok: true, status: 200, json: async () => ruleThree };
        }
        if (path === "/api/rules") {
          return {
            ok: true,
            status: 200,
            json: async () => ({ items: ruleItems, total: 1, limit: 20, offset: 0 }),
          };
        }
        return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
      },
    );
  }

  afterEach(() => {
    vi.unstubAllGlobals();
    window.location.hash = "#/";
  });

  it("navigates from the nav link to the rules list and into a rule", async () => {
    const calls: string[] = [];
    window.location.hash = "#/";
    stubRules(calls);
    render(<App />);
    fireEvent.click(screen.getByText("Rules", { selector: "nav a" }));
    window.dispatchEvent(new Event("hashchange"));
    await screen.findByText("Rule three");
    expect(screen.getByText(/no model weights are updated/)).toBeTruthy();
    const card = screen.getByText("Rule three").closest("a");
    expect(card?.getAttribute("href")).toBe("#/rules/3");
    fireEvent.click(card!);
    window.dispatchEvent(new Event("hashchange"));
    expect(window.location.hash).toBe("#/rules/3");
    await screen.findByText("Sigma rule (text only)");
    fireEvent.click(screen.getByText("Back to rules"));
    window.dispatchEvent(new Event("hashchange"));
    await screen.findByText("Rule three");
  });

  it("shows an error state for unknown or non-numeric rule ids", async () => {
    const calls: string[] = [];
    window.location.hash = "#/rules/<img src=x onerror=alert(1)>";
    stubRules(calls);
    const { container } = render(<App />);
    await screen.findByText(/Invalid rule id/);
    expect(calls.filter((c) => c.startsWith("/api/rules/"))).toEqual([]);
    expectInert(container);
  });

  it("rule filter bar calls the API with the right params", async () => {
    const calls: string[] = [];
    window.location.hash = "#/rules";
    stubRules(calls);
    render(<App />);
    await screen.findByText("Rule three");
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "shadow" } });
    window.dispatchEvent(new Event("hashchange"));
    await waitFor(() => {
      expect(calls.some((c) => c.includes("status=shadow"))).toBe(true);
    });
    expect(window.location.hash).toContain("status=shadow");
  });

  it("Back to rules is the first control on the rule page", async () => {
    const calls: string[] = [];
    window.location.hash = "#/rules/3";
    stubRules(calls);
    render(<App />);
    const back = await screen.findByText("Back to rules");
    const heading = await screen.findByRole("heading", { name: "Rule three" });
    expect(back.compareDocumentPosition(heading) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

describe("badge color contrast", () => {
  function luminance(hex: string): number {
    const c = hex.replace("#", "");
    const f = (i: number) => {
      const v = Number.parseInt(c.slice(i, i + 2), 16) / 255;
      return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * f(0) + 0.7152 * f(2) + 0.0722 * f(4);
  }

  function ratio(a: string, b: string): number {
    const hi = Math.max(luminance(a), luminance(b));
    const lo = Math.min(luminance(a), luminance(b));
    return (hi + 0.05) / (lo + 0.05);
  }

  it("every badge text color reaches 4.5:1 on the badge background in both themes", () => {
    const css = (readFileSync(join(process.cwd(), "src", "styles", "tokens.css"), "utf-8") + readFileSync(join(process.cwd(), "src", "styles", "utilities.css"), "utf-8"));
    const theme = (name: "dark" | "light") => {
      const pattern = name === "dark"
        ? /:root,\s*\[data-theme="dark"\]\s*\{([^}]*)\}/
        : /\[data-theme="light"\]\s*\{([^}]*)\}/;
      const block = pattern.exec(css)?.[1] ?? "";
      const vars: Record<string, string> = {};
      for (const m of block.matchAll(/--([\w-]+)\s*:\s*(#[0-9a-fA-F]{6})/g)) vars[m[1]] = m[2];
      return vars;
    };
    const dark = theme("dark");
    const light = theme("light");
    const badgeBgVar = /\.badge\s*\{[^}]*background\s*:\s*var\(--([\w-]+)\)/.exec(css)?.[1];
    expect(badgeBgVar).toBe("panel2");
    const colors: Record<string, string> = {};
    for (const m of css.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
      const color = /color\s*:\s*var\(--([\w-]+)\)/.exec(m[2])?.[1]
        ?? /color\s*:\s*(#[0-9a-fA-F]{6})/.exec(m[2])?.[1];
      if (!color) continue;
      for (const sel of m[1].split(",")) {
        const cls = /\.badge\.([\w-]+)/.exec(sel.trim())?.[1];
        if (cls && !(cls in colors)) colors[cls] = color;
      }
    }
    const defaults: Record<string, string> = { triaged: "text", pending: "muted" };
    for (const [cls, v] of Object.entries(defaults)) colors[cls] ??= v;
    for (const s of ["candidate", "shadow", "active", "archived", "rolled_back"]) {
      expect(colors, `badge class for status ${s}`).toHaveProperty(`rule-${s}`);
    }
    for (const m of ["shadow", "active"]) {
      expect(colors, `badge class for mode ${m}`).toHaveProperty(`mode-${m}`);
    }
    expect(colors, "learned-rule badge").toHaveProperty("learned-rule");
    const failures: string[] = [];
    for (const [cls, ref] of Object.entries(colors)) {
      const fg = (vars: Record<string, string>) => (ref.startsWith("#") ? ref : vars[ref]);
      const rd = ratio(fg(dark), dark[badgeBgVar!]);
      const rl = ratio(fg(light), light[badgeBgVar!]);
      if (rd < 4.5) failures.push(`${cls} dark ${rd.toFixed(2)}`);
      if (rl < 4.5) failures.push(`${cls} light ${rl.toFixed(2)}`);
    }
    expect(failures).toEqual([]);
  });
});

describe("part 2 rules polish", () => {
  it("count line comes from the loaded items", () => {
    expect(ruleCountLine([evilItem], 1)).toBe("1 rule: 1 shadow rule, 0 candidate rules, 0 active rules, 0 archived rules, 0 rolled back rules");
    expect(ruleCountLine([evilItem], 2)).toBe("2 rules: 1 shadow rule, 0 candidate rules, 0 active rules, 0 archived rules, 0 rolled back rules (status counts from this page, n=1)");
    expect(ruleCountLine([evilItem, { ...evilItem, id: 10, status: "candidate" }], 5)).toContain("(status counts from this page, n=2)");
    render(<RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={() => undefined} />);
    expect(screen.getByText(/1 rule: 1 shadow rule/)).toBeTruthy();
  });

  it("list cards carry an id, a status chip and a from-incident line", () => {
    const { container } = render(<RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={() => undefined} />);
    expect(container.querySelector(".badge.rule-shadow")?.textContent).toBe("shadow");
    expect(container.textContent).toContain("From incident 4 · T1059");
    expect(container.querySelector("a")?.getAttribute("href")).toBe("#/rules/9");
  });

  it("summary card, does-line, lifecycle history, tiles and bars render from the payload", () => {
    const { container } = render(<RuleDetailView detail={evilDetail} />);
    expect(screen.getByText(/What this rule does: shadow — it does not alter alerts/)).toBeTruthy();
    expect(screen.getByText("Approved by")).toBeTruthy();
    expect(screen.getByText("Lifecycle history")).toBeTruthy();
    expect(container.textContent).toContain("shadow");
    expect(container.textContent).toContain("baseline size not recorded");
    expect(container.textContent).toContain("1 (n=1)");
    expect(container.querySelector(".backtest-table")).toBeNull();
    expect(screen.getByLabelText(/Target events matched: 1 matches of n=1/)).toBeTruthy();
    const source = screen.getByRole("link", { name: /Source/ });
    expect(source.getAttribute("href")).toBe("#/incidents/4");
    expectInert(container);
  });

  it("lineage shows only the review facts and keeps the rest in technical details", () => {
    const dated: RuleDetail = { ...evilDetail, updated_at: "2026-11-02T00:00:00Z", deployed_at: "2026-11-03T00:00:00Z" };
    const { container } = render(<RuleDetailView detail={dated} />);
    const lineageSection = screen.getByLabelText("Lineage", { selector: "section" });
    const lineageTerms = Array.from(lineageSection.querySelectorAll(":scope > dl.lineage-grid dt")).map((dt) => dt.textContent);
    for (const term of ["Source incident", "Cited events", "Rounds used", "Model", "Approved by", "Created"]) {
      expect(lineageTerms).toContain(term);
    }
    for (const term of ["Name", "Status", "Mode", "Version", "Native rule id", "Hits", "False positives", "Accepted backtest", "sigma_sha256", "ledger_ids", "sigma_rule_id"]) {
      expect(lineageTerms).not.toContain(term);
    }
    const technical = screen.getByText("Technical details").closest("details");
    const technicalTerms = Array.from(technical?.querySelectorAll("dt") ?? []).map((dt) => dt.textContent);
    for (const term of ["sigma_sha256", "Codes", "Group", "ledger_ids", "sigma_rule_id", "Native rule id", "Hits", "False positives", "Prompt version", "Accepted backtest", "Source incident id", "Updated"]) {
      expect(technicalTerms).toContain(term);
    }
    expect(container.querySelector("h2")?.textContent).toBe(evilDetail.title);
    expect(container.querySelector(".hero-badges")?.textContent).toContain("shadow");
    expect(container.querySelector(".hero-badges")?.textContent).toContain("v2");
  });

  it("lineage shows backtest codes as text and never a bare null", () => {
    const { container } = render(<RuleDetailView detail={evilDetail} />);
    expect(container.textContent).toContain("accepted");
    expect(container.textContent).not.toContain('["accepted"]');
    expect(backtestCodesText({ codes: ["accepted"] })).toBe("accepted");
    expect(backtestCodesText({ codes: [] })).toBe("no codes recorded");
    expect(backtestCodesText({})).toBe("no codes recorded");
    expect(backtestCodesText({ codes: null })).toBe("no codes recorded");
    expect(backtestCodesText(null)).toBe("none recorded");
    const noCodes: RuleDetail = {
      ...evilDetail,
      lineage: {
        ...evilDetail.lineage,
        backtest: { target_matched: ["evt-1"], target_total: 1, baseline_count: 0, group: "corvus_sigma" },
      },
    };
    const { container: bare } = render(<RuleDetailView detail={noCodes} />);
    expect(screen.getAllByText("no codes recorded").length).toBeGreaterThan(0);
    expect(bare.textContent).not.toMatch(/\bnull\b/);
    expect(bare.querySelector(".backtest-table")).toBeNull();
    expect(bare.textContent).toContain("Target events matched");
  });

  it("does-line follows mode and status without inventing payload fields", () => {
    expect(ruleAltersAlertsText({ status: "shadow", mode: "shadow" })).toContain("does not alter alerts");
    expect(ruleAltersAlertsText({ status: "active", mode: "active" })).toContain("alters alerts");
    expect(ruleAltersAlertsText({ status: "candidate", mode: null })).toContain("does not alter alerts");
  });

  it("backtest figures keep the API numbers and name a missing baseline n", () => {
    expect(backtestFigures({ target_matched: ["a", "b"], target_total: 7, baseline_count: 3 })).toEqual({ matched: 2, targetTotal: 7, baselineCount: 3, baselineTotal: null });
    const { container } = render(<BacktestBars backtest={{ target_matched: ["a"], target_total: 4, baseline_count: 2 }} />);
    expect(container.textContent).toContain("1 (n=4)");
    expect(container.textContent).toContain("2 (baseline size not recorded)");
  });

  it("shows the exact read-only approve command only for promotable rules", () => {
    const candidate: RuleDetail = { ...evilDetail, status: "candidate", mode: null };
    const { unmount } = render(<RuleDetailView detail={candidate} />);
    expect(screen.getByText("Next step")).toBeTruthy();
    expect(screen.getByText('corvus rules approve 9 --to shadow --approver <name> --reason "<why>"')).toBeTruthy();
    expect(screen.getByText("A human approves every step. The console never changes a rule.")).toBeTruthy();
    unmount();
    render(<RuleDetailView detail={evilDetail} />);
    expect(screen.getByText('corvus rules approve 9 --to active --approver <name> --reason "<why>"')).toBeTruthy();
  });
  it("shows no next step once a rule left the promotable stages", () => {
    render(<RuleDetailView detail={{ ...evilDetail, status: "active", mode: "active" }} />);
    expect(screen.queryByText("Next step")).toBeNull();
  });
  it("copies the next-step command with the clipboard button", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const candidate: RuleDetail = { ...evilDetail, status: "candidate", mode: null };
    render(<RuleDetailView detail={candidate} />);
    fireEvent.click(screen.getAllByText("Copy")[0]);
    await waitFor(() => { expect(writeText).toHaveBeenCalledWith('corvus rules approve 9 --to shadow --approver <name> --reason "<why>"'); });
  });
  it("copies exact sigma text when presentation mode is off and masked text when on", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const ipDetail: RuleDetail = { ...evilDetail, status: "active", mode: "active", sigma_text: "title: edge\ndescription: dial 8.8.8.8\n" };
    localStorage.removeItem(PRESENTATION_STORAGE_KEY);
    resetMaskedIpMapping();
    const { unmount } = render(<MemoryRouter><PresentationProvider><RuleDetailView detail={ipDetail} /></PresentationProvider></MemoryRouter>);
    fireEvent.click(screen.getByText("Copy"));
    await waitFor(() => { expect(writeText).toHaveBeenCalledWith(ipDetail.sigma_text); });
    unmount();
    writeText.mockClear();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    resetMaskedIpMapping();
    render(<MemoryRouter><PresentationProvider><RuleDetailView detail={ipDetail} /></PresentationProvider></MemoryRouter>);
    fireEvent.click(screen.getByText("Copy"));
    await waitFor(() => { expect(writeText).toHaveBeenCalledTimes(1); });
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).not.toContain("8.8.8.8");
    expect(copied).toContain("198.51.100.");
    localStorage.removeItem(PRESENTATION_STORAGE_KEY);
    resetMaskedIpMapping();
  });
  it("counts a single candidate in Proposed only and marks its stage", async () => {
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      if (url.includes("status=candidate")) return { ok: true, status: 200, json: async () => ({ items: [], total: 1 }) };
      if (url.includes("/api/rules")) return { ok: true, status: 200, json: async () => ({ items: [], total: 0 }) };
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
    render(<LifecycleBar nonce={0} sideStatus="candidate" />);
    expect(await screen.findByText("Proposed 1 (current)")).toBeTruthy();
    expect(screen.getByText("Backtested 0")).toBeTruthy();
    expect(screen.getByText("Shadow 0")).toBeTruthy();
    expect(screen.getByText("Active 0")).toBeTruthy();
    vi.unstubAllGlobals();
  });
  it("stepper marks the current side state with its transition date", () => {
    const { container } = render(<LifecycleStepper status="rolled_back" transitions={[{ from: "active", to: "rolled_back", approver: "op", reason: "bad", at: "2026-11-01T00:00:00Z" }]} />);
    expect(container.querySelector(".lc-current")?.textContent).toContain("rolled_back");
    expect(container.querySelector(".lc-current")?.textContent).toContain("2026-11-01");
    expect(screen.getByText(/Current status is rolled_back/)).toBeTruthy();
  });

  it("carried-over layout guards are in the stylesheet", () => {
    const css = (readFileSync(join(process.cwd(), "src", "styles", "tokens.css"), "utf-8") + readFileSync(join(process.cwd(), "src", "styles", "utilities.css"), "utf-8"));
    expect(css).toContain("table.incidents tr.rowlink");
    expect(css).toMatch(/\.col-usd[^{]*\{[^}]*white-space:nowrap/);
    expect(css).toContain("scroll-margin-top:5rem");
    expect(css).toContain("scroll-margin-top:6.5rem");
  });
});

describe("RuleFilterBar", () => {
  it("edits status and mode", () => {
    const seen: { page: number; status: string | null; mode: string | null }[] = [];
    render(<RuleFilterBar filters={{ page: 0, status: null, mode: null }} onChange={(n) => seen.push(n)} />);
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "active" } });
    expect(seen.at(-1)).toEqual({ page: 0, status: null, mode: "active" });
  });
});
