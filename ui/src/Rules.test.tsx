import { fireEvent, render, screen, waitFor } from "@testing-library/react";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { readFileSync } from "node:fs";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// @ts-ignore: node core types are intentionally not installed (no new deps)
declare const process: { cwd(): string };
import App, {
  HealthStrip,
  IncidentView,
  LearnedRuleRefs,
  RuleDetailView,
  RuleFilterBar,
  RuleModeBadge,
  RuleStatusBadge,
  RulesBanner,
  RulesList,
  buildRuleHash,
  buildRulesHash,
  buildRulesQuery,
  parseHash,
  type IncidentDetail,
  type RuleDetail,
  type RuleListItem,
} from "./App";

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

  it("rows are keyboard-focusable and open on Enter or Space", () => {
    const seen: number[] = [];
    const { container } = render(
      <RulesList items={[evilItem]} total={1} page={0} setPage={() => undefined} pageSize={20} onSelect={(id) => seen.push(id)} />,
    );
    const row = container.querySelector("tr.rowlink");
    expect(row?.getAttribute("tabindex")).toBe("0");
    fireEvent.keyDown(row!, { key: "Enter" });
    fireEvent.keyDown(row!, { key: " " });
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
    expect(screen.getByText("Copy Sigma text")).toBeTruthy();
    expect(screen.getByText("stored")).toBeTruthy();
    expect(screen.getByText(/backtest/)).toBeTruthy();
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
    expect(screen.getByText("none recorded")).toBeTruthy();
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

  it("links a learned rule distinctly from shipped findings", () => {
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
    expect(screen.getByText("unknown learned rule (unresolved)").className).toContain("learned-unknown");
    expectInert(container);
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
    const row = screen.getByText("Rule three").closest("tr");
    fireEvent.click(row!);
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
    const heading = await screen.findByText("Rule three");
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
    const css = readFileSync(join(process.cwd(), "src", "styles.css"), "utf-8");
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

describe("RuleFilterBar", () => {
  it("edits status and mode", () => {
    const seen: { page: number; status: string | null; mode: string | null }[] = [];
    render(<RuleFilterBar filters={{ page: 0, status: null, mode: null }} onChange={(n) => seen.push(n)} />);
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "active" } });
    expect(seen.at(-1)).toEqual({ page: 0, status: null, mode: "active" });
  });
});
