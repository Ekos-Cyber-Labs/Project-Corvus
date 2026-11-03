import { useCallback, useEffect, useRef, useState } from "react";
import { TACTIC_NAMES, TACTIC_ORDER, parentForTechnique, tacticForTechnique } from "./attackMap";
import { ActivityStrip, BacktestBars, ConfidenceMeter, KillChainStrip, LifecycleStepper, SeverityChip, SeverityGauge, SeverityScale, backtestFigures } from "./visuals";
import { IconAlert, IconCheck, IconChevron, IconClock, IconCopy, IconHost, IconShield, IconSpark } from "./icons";

export type IncidentListItem = {
  id: number; title: string; severity_floor: number; severity_floor_name?: string | null;
  severity_id: number; severity_name?: string | null; ai_status: string; verdict?: string | null;
  first_seen?: string | null; last_seen?: string | null; event_count: number; has_injection: boolean;
  analyzed?: boolean | null;
};
export type LearnedRuleRef = {
  rule_db_id?: number | null; sigma_rule_id?: string | null; version?: number | null;
  mode?: string | null; lineage_id?: string | null; native_rule_id?: number | string | null;
  shadow?: boolean | null; unknown?: boolean | null; findings?: number | null;
};
export type RuleListItem = {
  id: number; title: string; status: string; mode: string | null; version: number;
  level?: string | null; techniques?: string[]; hits: number; false_positives: number;
  created_at?: string | null; source_incident_id?: number | null;
};
export type RuleDetail = RuleListItem & {
  sigma_text: string;
  wazuh?: { native_rule_id?: number | null; native_rule_ids?: number[]; group?: string | null; mode?: string | null; pair_note?: string } | null;
  updated_at?: string | null; deployed_at?: string | null;
  lineage?: {
    sigma_rule_id?: string | null;
    source_incident?: { id: number; exists: boolean; title?: string | null } | null;
    cited_uids?: string[]; backtest?: Record<string, unknown> | null;
    rounds_used?: number | null; model?: string | null; prompt_version?: string | null;
    ledger_ids?: unknown[]; lineage_note?: string | null;
  } | null;
  transitions?: { from?: string | null; to?: string | null; approver?: string | null; reason?: string | null; at?: string | null }[];
  findings?: { incident_id: number; incident_title?: string | null; mode?: string | null; shadow?: boolean | null; version?: number | null; findings?: number | null }[];
};
export type IncidentDetail = {
  id: number; title: string; severity_floor: number; severity_id: number;
  severity_floor_name?: string | null; severity_name?: string | null; ai_status: string;
  verdict?: string | null; first_seen?: string | null; last_seen?: string | null;
  severity_factors?: Record<string, unknown>;
  severity?: { floor: number; final: number; factors?: Record<string, unknown> };
  techniques?: { id: string; name?: string | null }[];
  analysis?: { verdict?: string | null; severity_id?: number; confidence?: number; timeline?: { time: string; event_uid: string; description: string }[]; response_plan?: string[]; visibility_gaps?: string[]; language?: string | null; model?: string | null; status?: string } | null;
  triage?: { summary?: string | null; status?: string | null; model?: string | null } | null;
  injection_signals?: { event_uid: string; field: string; pattern_id: string; requested_effect: string; payload_text?: string | null; payload_label?: string }[];
  evidence?: { event_uid: string; found: boolean; event?: unknown; note?: string }[];
  agent_trace?: { step: number; tool: string; arguments?: Record<string, unknown>; result_summary?: string | null; tokens: number }[];
  llm_attempts?: { purpose: string; model: string; attempt_number: number; outcome: string; failed_validator?: string | null; tokens: number; token_source?: string | null; usd?: number | null }[];
  spend_total_usd?: number;
  reasoning_unverified?: { text: string; unverified: boolean; label?: string } | null;
  pseudonym_resolution?: { resolved: boolean; note: string };
  event_count?: number;
  learned_rules?: LearnedRuleRef[] | null;
};
export type Health = {
  status: string;
  database?: { reachable?: boolean; detail?: string } | null;
  models?: { glimmer?: { reachable?: boolean; detail?: string }; meta?: { reachable?: boolean; detail?: string } } | null;
  self_observation?: Record<string, unknown>;
};

export const REAL_VERDICTS = new Set(["true_positive", "benign_authorized", "false_positive", "needs_human"]);
export type ListFilters = { page: number; minFloor: number | null; verdict: string | null; analyzed: boolean | null };
export type Route =
  | { view: "list" } & ListFilters
  | { view: "detail"; id: string }
  | { view: "rules" } & RuleFilters
  | { view: "rule"; id: string }
  | { view: "unknown" };
export const RULE_STATUSES = new Set(["candidate", "shadow", "active", "archived", "rolled_back"]);
export const RULE_MODES = new Set(["shadow", "active"]);
export type RuleFilters = { page: number; status: string | null; mode: string | null };

function parseNonNegativeInt(raw: string | null): number {
  if (raw === null || raw === "") return 0;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : 0;
}
function parseMinFloor(raw: string | null): number | null {
  if (raw === null || raw === "") return null;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 6 ? n : null;
}
export function parseHash(hash: string): Route {
  let h = hash.startsWith("#") ? hash.slice(1) : hash;
  let pathPart = h;
  let queryPart = "";
  const q = h.indexOf("?");
  if (q >= 0) { pathPart = h.slice(0, q); queryPart = h.slice(q + 1); }
  if (pathPart === "" || pathPart === "/") {
    const params = new URLSearchParams(queryPart);
    const verdictRaw = params.get("verdict");
    const analyzedRaw = params.get("analyzed");
    return {
      view: "list", page: parseNonNegativeInt(params.get("page")),
      minFloor: parseMinFloor(params.get("min_floor")),
      verdict: verdictRaw !== null && REAL_VERDICTS.has(verdictRaw) ? verdictRaw : null,
      analyzed: analyzedRaw === "true" ? true : analyzedRaw === "false" ? false : null,
    };
  }
  const match = /^\/incidents\/([^/]+)$/.exec(pathPart);
  if (match) {
    let id = match[1];
    try { id = decodeURIComponent(id); } catch { id = ""; }
    return { view: "detail", id };
  }
  if (pathPart === "/rules") {
    const params = new URLSearchParams(queryPart);
    const statusRaw = params.get("status");
    const modeRaw = params.get("mode");
    return {
      view: "rules", page: parseNonNegativeInt(params.get("page")),
      status: statusRaw !== null && RULE_STATUSES.has(statusRaw) ? statusRaw : null,
      mode: modeRaw !== null && RULE_MODES.has(modeRaw) ? modeRaw : null,
    };
  }
  const ruleMatch = /^\/rules\/([^/]+)$/.exec(pathPart);
  if (ruleMatch) {
    let id = ruleMatch[1];
    try { id = decodeURIComponent(id); } catch { id = ""; }
    return { view: "rule", id };
  }
  return { view: "unknown" };
}
export function isNumericId(id: string): boolean { return /^\d+$/.test(id); }
export function buildListHash(filters: ListFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.minFloor !== null) params.set("min_floor", String(filters.minFloor));
  if (filters.verdict !== null) params.set("verdict", filters.verdict);
  if (filters.analyzed !== null) params.set("analyzed", String(filters.analyzed));
  const query = params.toString();
  return query ? `#/?${query}` : "#/";
}
export function buildDetailHash(id: number): string { return `#/incidents/${id}`; }
export function buildRulesHash(filters: RuleFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.status !== null) params.set("status", filters.status);
  if (filters.mode !== null) params.set("mode", filters.mode);
  const query = params.toString();
  return query ? `#/rules?${query}` : "#/rules";
}
export function buildRuleHash(id: number): string { return `#/rules/${id}`; }
export type AttemptOutcomeKind = "ok" | "neutral" | "quarantined" | "invalid";
export function attemptOutcomeKind(outcome: string, failedValidator?: string | null): AttemptOutcomeKind {
  if (typeof failedValidator === "string" ? failedValidator.trim() !== "" : Boolean(failedValidator)) return "invalid";
  if (outcome === "ok" || outcome === "accepted") return "ok";
  if (outcome.includes("quarantin")) return "quarantined";
  if (outcome === "invalid") return "invalid";
  return "neutral";
}
export function attemptOutcomeText(outcome: string, failedValidator?: string | null): string {
  const kind = attemptOutcomeKind(outcome, failedValidator);
  if (kind === "invalid") return `invalid${failedValidator ? ` (failed validator: ${failedValidator})` : ""}`;
  return outcome;
}
export function hasQuarantinedTriage(attempts?: { purpose: string; outcome: string }[] | null): boolean {
  if (!attempts) return false;
  return attempts.some(
    (a) => a.purpose === "triage" && typeof a.outcome === "string" && a.outcome.includes("quarantin"),
  );
}
export function verdictKind(
  verdict: string | null | undefined,
  aiStatus: string,
  attempts?: { purpose: string; outcome: string }[] | null,
): "verdict" | "triaged" | "failed" | "quarantined" | "pending" {
  if (verdict !== null && verdict !== undefined && REAL_VERDICTS.has(verdict)) return "verdict";
  if (hasQuarantinedTriage(attempts)) return "quarantined";
  if (aiStatus === "failed") return "failed";
  if (aiStatus === "done") return "triaged";
  return "pending";
}
async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return (await res.json()) as T;
}
export function buildListQuery(filters: ListFilters, pageSize: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(pageSize));
  params.set("offset", String(filters.page * pageSize));
  if (filters.minFloor !== null) params.set("min_floor", String(filters.minFloor));
  if (filters.verdict !== null) params.set("verdict", filters.verdict);
  if (filters.analyzed !== null) params.set("analyzed", String(filters.analyzed));
  return `/api/incidents?${params.toString()}`;
}
export function buildRulesQuery(filters: RuleFilters, pageSize: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(pageSize));
  params.set("offset", String(filters.page * pageSize));
  if (filters.status !== null) params.set("status", filters.status);
  if (filters.mode !== null) params.set("mode", filters.mode);
  return `/api/rules?${params.toString()}`;
}
export function agentTraceEmptyMessage(detail: IncidentDetail): string {
  const attempts = detail.llm_attempts ?? [];
  if ((!detail.agent_trace || detail.agent_trace.length === 0) && attempts.length === 1) {
    return "This incident was analyzed in a single model call without the tool loop";
  }
  return "No agent steps recorded";
}
export function groupTechniques(techniques: { id: string; name?: string | null }[]): { tactic: string; name: string; items: { id: string; name?: string | null }[] }[] {
  const byTactic = new Map<string, { id: string; name?: string | null }[]>();
  for (const t of techniques) {
    const tactic = tacticForTechnique(t.id);
    const list = byTactic.get(tactic) ?? [];
    list.push(t);
    byTactic.set(tactic, list);
  }
  const order = [...TACTIC_ORDER, "other"];
  const groups: { tactic: string; name: string; items: { id: string; name?: string | null }[] }[] = [];
  for (const tactic of order) {
    const items = byTactic.get(tactic);
    if (!items?.length) continue;
    const sorted = [...items].sort((a, b) => {
      const ka = parentForTechnique(a.id) ?? a.id;
      const kb = parentForTechnique(b.id) ?? b.id;
      return ka.localeCompare(kb) || a.id.localeCompare(b.id);
    });
    groups.push({ tactic, name: tactic === "other" ? "Other" : (TACTIC_NAMES[tactic] ?? tactic), items: sorted });
  }
  return groups;
}

export function RulesBanner() {
  return (
    <section className="panel banner banner-compact" aria-label="About shadow mode">
      <p><strong>Shadow mode:</strong> shadow rules never change alerts — matching events keep their existing alerts and gain the <span className="mono">corvus_shadow</span> tag for review. Learning here means stored detection rules only — no model weights are updated.</p>
    </section>
  );
}
export function ruleCountLine(items: RuleListItem[], total: number): string {
  const count = (s: string) => items.filter((it) => it.status === s).length;
  const parts = ["shadow", "candidate", "active", "archived", "rolled_back"].map((s) => `${count(s)} ${s}`);
  const scope = items.length < total ? ` (status counts from this page, n=${items.length})` : "";
  return `${total} rules: ${parts.join(", ")}${scope}`;
}
export function ruleAltersAlertsText(detail: Pick<RuleDetail, "status" | "mode">): string {
  if (detail.mode === "shadow" || detail.status === "shadow") return "What this rule does: shadow — it does not alter alerts. Matching events keep their existing alerts and gain the corvus_shadow tag for review.";
  if (detail.mode === "active" || detail.status === "active") return "What this rule does: active — deployed active, so matching events can raise an alert; it alters alerts.";
  if (detail.status === "candidate") return "What this rule does: candidate — not deployed, so it does not alter alerts.";
  if (detail.status === "archived" || detail.status === "rolled_back") return `What this rule does: ${detail.status} — not deployed, so it does not alter alerts.`;
  return "What this rule does: not deployed, so it does not alter alerts.";
}
export function backtestCodesText(backtest: Record<string, unknown> | null | undefined): string {
  if (!backtest) return "none recorded";
  const codes = backtest.codes;
  if (typeof codes === "string") return codes.trim() ? codes : "no codes recorded";
  if (Array.isArray(codes)) {
    const parts = codes.map((c) => String(c)).filter((c) => c.trim());
    return parts.length ? parts.join(", ") : "no codes recorded";
  }
  return "no codes recorded";
}
export function RuleStatusBadge({ status }: { status: string }) {
  if (!RULE_STATUSES.has(status)) return <span className="badge rule-unknown">{status || "unknown"}</span>;
  return <span className={`badge rule-${status}`}>{status}</span>;
}
export function RuleModeBadge({ mode }: { mode: string | null | undefined }) {
  if (mode === null || mode === undefined) return <span className="badge mode-none">not deployed</span>;
  if (!RULE_MODES.has(mode)) return <span className="badge mode-unknown">{mode}</span>;
  return <span className={`badge mode-${mode}`}>{mode}</span>;
}
export function RuleFilterBar({ filters, onChange }: { filters: RuleFilters; onChange: (next: RuleFilters) => void }) {
  return (
    <form className="filterbar" aria-label="Rule filters" onSubmit={(e) => e.preventDefault()}>
      <label>
        Status
        <select aria-label="Status" value={filters.status ?? ""} onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, status: v === "" ? null : v }); }}>
          <option value="">Any</option>
          <option value="candidate">candidate</option>
          <option value="shadow">shadow</option>
          <option value="active">active</option>
          <option value="archived">archived</option>
          <option value="rolled_back">rolled_back</option>
        </select>
      </label>
      <label>
        Mode
        <select aria-label="Mode" value={filters.mode ?? ""} onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, mode: v === "" ? null : v }); }}>
          <option value="">Any</option>
          <option value="shadow">shadow</option>
          <option value="active">active</option>
        </select>
      </label>
    </form>
  );
}
export function RulesList({ items, total, page, setPage, pageSize, onSelect }: {
  items: RuleListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (!items.length) return <p>No learned rules found.</p>;
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  return (
    <div>
      <p className="summary-count">{ruleCountLine(items, total)}</p>
    <div className="table-wrap">
      <table className="rules" aria-label="Learned rules">
        <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Mode</th><th>Version</th><th>Level</th><th>Techniques</th><th>Hits</th><th>FP</th></tr></thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.id} className="rowlink" tabIndex={0} onClick={() => open(it.id)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(it.id); } }}>
              <td className="mono cell-id"><span className={`rail rule-rail-${RULE_STATUSES.has(it.status) ? it.status : "unknown"}`} aria-hidden="true" />{it.id}</td>
              <td className="cell-title"><a className="title-link" href={buildRuleHash(it.id)}>{it.title || `Rule ${it.id}`}</a></td>
              <td><RuleStatusBadge status={it.status} /></td>
              <td><RuleModeBadge mode={it.mode} /></td>
              <td className="mono">v{it.version}</td>
              <td>{it.level ?? "—"}</td>
              <td className="mono">{it.techniques?.length ? it.techniques.join(", ") : "—"}</td>
              <td className="num">{it.hits}</td>
              <td className="num">{it.false_positives}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="pager">
        <button type="button" disabled={page <= 0} onClick={() => setPage(page - 1)}>Previous</button>{" "}
        Page {page + 1} of {pages} ({total} total){" "}
        <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
      </p>
    </div>
    </div>
  );
}
export function LearnedRuleRefs({ refs }: { refs: LearnedRuleRef[] }) {
  if (!refs.length) return null;
  return (
    <section className="panel" aria-label="Learned-rule findings">
      <h3>Learned-rule findings</h3>
      <ul className="plain">
        {refs.map((r, i) => {
          if (r.unknown || r.rule_db_id === null || r.rule_db_id === undefined) {
            return <li key={i}><span className="badge learned-unknown">unknown learned rule (unresolved)</span></li>;
          }
          const id = Number(r.rule_db_id);
          if (!Number.isInteger(id)) return <li key={i}><span className="badge learned-unknown">unknown learned rule (unresolved)</span></li>;
          const mode = typeof r.mode === "string" && r.mode ? r.mode : "unknown mode";
          const modeClass = mode === "shadow" ? "learned-shadow" : mode === "active" ? "learned-active" : "learned-other";
          return (
            <li key={i}>
              <a className={`badge learned-rule ${modeClass}`} href={buildRuleHash(id)}>learned rule v{r.version ?? "?"} ({mode})</a>
              {typeof r.findings === "number" ? <> · {r.findings} finding{r.findings === 1 ? "" : "s"}</> : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function RuleDetailView({ detail }: { detail: RuleDetail }) {
  const [copied, setCopied] = useState(false);
  const lineage = detail.lineage ?? null;
  const source = lineage?.source_incident ?? null;
  const backtest = lineage?.backtest ?? null;
  const transitions = detail.transitions ?? [];
  const findings = detail.findings ?? [];
  const cited = lineage?.cited_uids ?? [];
  const copySigma = async () => {
    try {
      const clipboard = navigator.clipboard;
      if (!clipboard) { setCopied(false); return; }
      await clipboard.writeText(detail.sigma_text);
      setCopied(true);
    } catch { setCopied(false); }
  };
  const lastTransition = transitions.length ? transitions[transitions.length - 1] : null;
  const figures = backtestFigures(backtest);
  const nativeId = detail.wazuh?.native_rule_id ?? null;
  return (
    <article className="detail rule-detail">
      <section className="panel hero" aria-label="Rule summary">
        <h2>{detail.title || `Rule ${detail.id}`}</h2>
        <p className="hero-badges">
          <RuleStatusBadge status={detail.status} /> <RuleModeBadge mode={detail.mode} /> <span className="mono">v{detail.version}</span>
          {detail.level ? <> · Level: {detail.level}</> : null}
          {detail.techniques?.length ? <> · Techniques: <span className="mono">{detail.techniques.join(", ")}</span></> : null}
        </p>
        <p className="does-line">{ruleAltersAlertsText(detail)}</p>
        <LifecycleStepper status={detail.status} transitions={transitions} />
        <dl className="args summary-grid">
          {nativeId != null ? <div><dt>Native rule id</dt><dd className="mono">{nativeId}</dd></div> : null}
          {detail.wazuh?.native_rule_ids?.length && detail.wazuh.native_rule_ids.length > 1 ? <div><dt>Native rule ids</dt><dd className="mono">{detail.wazuh.native_rule_ids.join(", ")}</dd></div> : null}
          {detail.wazuh?.group ? <div><dt>Group</dt><dd className="mono">{detail.wazuh.group}</dd></div> : null}
          <div><dt>Last transition approver</dt><dd>{lastTransition?.approver ?? "not recorded"}</dd></div>
          <div><dt>Last transition date</dt><dd className="mono">{lastTransition?.at ?? "not recorded"}</dd></div>
          <div><dt>Hits</dt><dd className="num">{detail.hits}</dd></div>
          <div><dt>False positives</dt><dd className="num">{detail.false_positives}</dd></div>
          {detail.created_at ? <div><dt>Created</dt><dd className="mono">{detail.created_at}</dd></div> : null}
          {detail.updated_at ? <div><dt>Updated</dt><dd className="mono">{detail.updated_at}</dd></div> : null}
          {detail.deployed_at ? <div><dt>Deployed</dt><dd className="mono">{detail.deployed_at}</dd></div> : null}
          {detail.source_incident_id != null ? <div><dt>Source incident id</dt><dd className="mono">{detail.source_incident_id}</dd></div> : null}
        </dl>
        {detail.wazuh?.pair_note ? <p className="muted">{detail.wazuh.pair_note}</p> : null}
      </section>
      <section className="panel" aria-label="Sigma rule">
        <h3>Sigma rule (text only)</h3>
        <p><button type="button" onClick={copySigma}><IconCopy /> {copied ? "Copied" : "Copy"}</button></p>
        <pre className="payload sigma"><code>{detail.sigma_text}</code></pre>
      </section>
      <section className="panel" aria-label="Lineage">
        <h3>Lineage</h3>
        {lineage?.lineage_note ? <p className="muted">{lineage.lineage_note}</p> : null}
        <dl className="args lineage-grid">
          <div><dt>Source incident</dt><dd>{source === null || source === undefined ? "none recorded" : source.exists ? (<a href={buildDetailHash(source.id)}>Incident {source.id}{source.title ? ` — ${source.title}` : ""}</a>) : (<>Incident {source.id} (deleted)</>)}</dd></div>
          <div><dt>Cited event uids</dt><dd className="mono">{cited.length ? cited.join(", ") : "none"}</dd></div>
          <div><dt>Accepted backtest</dt><dd>{backtest ? <span className="mono">{backtestCodesText(backtest)}</span> : "none recorded"}</dd></div>
          <div><dt>Rounds used</dt><dd>{lineage?.rounds_used ?? "not recorded"}</dd></div>
          <div><dt>Model</dt><dd className="mono">{lineage?.model ?? "not recorded"}</dd></div>
          <div><dt>Prompt version</dt><dd className="mono">{lineage?.prompt_version ?? "not recorded"}</dd></div>
          <div><dt className="mono">ledger_ids</dt><dd className="mono">{lineage?.ledger_ids?.length ? JSON.stringify(lineage.ledger_ids) : "none"}</dd></div>
          {lineage?.sigma_rule_id ? <div><dt className="mono">sigma_rule_id</dt><dd className="mono">{lineage.sigma_rule_id}</dd></div> : null}
        </dl>
      </section>
      <section className="panel" aria-label="Accepted backtest">
        <h3>Accepted backtest</h3>
        {backtest ? (
          <>
            <div className="table-wrap"><table className="cost backtest-table" aria-label="Backtest numbers">
              <thead><tr><th>Figure</th><th>Matches</th><th>n</th></tr></thead>
              <tbody>
                <tr><td>Target events matched</td><td className="num">{figures.matched ?? "not recorded"}</td><td className="num">{figures.targetTotal ?? "not recorded"}</td></tr>
                <tr><td>Benign baseline matches</td><td className="num">{figures.baselineCount ?? "not recorded"}</td><td className="num">{figures.baselineTotal ?? "not recorded"}</td></tr>
                <tr><td>Codes</td><td className="mono" colSpan={2}>{backtestCodesText(backtest)}</td></tr>
                <tr><td>Group</td><td className="mono" colSpan={2}>{typeof backtest.group === "string" ? backtest.group : "not recorded"}</td></tr>
                {typeof backtest.sigma_sha256 === "string" ? <tr><td className="mono">sigma_sha256</td><td className="mono" colSpan={2}>{backtest.sigma_sha256}</td></tr> : null}
              </tbody>
            </table></div>
            <BacktestBars backtest={backtest} />
          </>
        ) : <p>No accepted backtest recorded.</p>}
        {Array.isArray(backtest?.target_matched) && (backtest.target_matched as unknown[]).length ? (
          <details><summary>Matched target events (text only)</summary><pre className="payload mono">{JSON.stringify(backtest.target_matched, null, 2)}</pre></details>
        ) : null}
      </section>
      <section className="panel" aria-label="Transitions">
        <h3>Transitions</h3>
        {transitions.length ? (
          <div className="table-wrap"><table className="cost" aria-label="Rule transitions">
            <thead><tr><th>From</th><th>To</th><th>Approver</th><th>Reason</th><th>At</th></tr></thead>
            <tbody>{transitions.map((t, i) => (<tr key={i}><td>{t.from ?? "—"}</td><td><RuleStatusBadge status={t.to ?? ""} /></td><td>{t.approver ?? "—"}</td><td>{t.reason ?? "—"}</td><td className="mono num">{t.at ?? "—"}</td></tr>))}</tbody>
          </table></div>
        ) : <p>No transitions recorded.</p>}
      </section>
      <section className="panel" aria-label="Fired in">
        <h3>Fired in</h3>
        {findings.length ? (
          <ul className="plain">{findings.map((f) => (<li key={f.incident_id}><a href={buildDetailHash(f.incident_id)}>Incident {f.incident_id}{f.incident_title ? ` — ${f.incident_title}` : ""}</a>{typeof f.findings === "number" ? <> · {f.findings} finding{f.findings === 1 ? "" : "s"}</> : null}</li>))}</ul>
        ) : <p>This rule has not fired in any incident.</p>}
      </section>
    </article>
  );
}

function Chip({ label, state, detail }: { label: string; state: "ok" | "degraded" | "down" | "unknown"; detail: string }) {
  const word = state === "ok" ? "OK" : state === "degraded" ? "Degraded" : state === "down" ? "Unavailable" : "Not measured";
  return (
    <li className={`chip chip-${state}`} title={`${label}: ${word} — ${detail}`}>
      <span className="chip-dot" aria-hidden="true" />
      <span className="chip-label">{label}</span>
      <span className="chip-state">{word}</span>
      <span className="chip-detail">{detail}</span>
      <span className="sr-only">{label}: {word} — {detail}</span>
    </li>
  );
}
export function HealthStrip({ health, error }: { health: Health | null; error?: string | null }) {
  if (error) return <p role="alert">Health: unavailable — {error}</p>;
  if (!health) return <p className="health muted" aria-live="polite">Health: loading…</p>;
  const o = health.self_observation ?? {};
  const fmt = (v: unknown) => (v === undefined || v === null ? "not measured" : String(v));
  const latency = o.latest_model_latency_ms;
  const latencyModel = o.latest_model_latency_model;
  const latencyText = latency === undefined || latency === null || latency === "not measured"
    ? "Latest model latency: not measured"
    : `Latest model latency (model ${fmt(latencyModel)}): ${fmt(latency)} ms`;
  const comp = (c?: { reachable?: boolean; detail?: string } | null): { state: "ok" | "degraded" | "down" | "unknown"; detail: string } => {
    if (!c || typeof c.reachable !== "boolean") return { state: "unknown", detail: "not measured" };
    return c.reachable ? { state: "ok", detail: "reachable" } : { state: "down", detail: c.detail ? String(c.detail) : "unreachable" };
  };
  const db = comp(health.database);
  const gl = comp(health.models?.glimmer);
  const mt = comp(health.models?.meta);
  const apiState: "ok" | "degraded" | "down" = health.status === "ok" ? "ok" : "degraded";
  const spend = o.spend_today_usd;
  const cap = o.spend_cap_usd;
  const queue = o.queue_depth;
  return (
    <div className="health" aria-label="System health">
      <ul className="chips">
        <Chip label="API" state={apiState} detail={`status ${health.status}`} />
        <Chip label="Database" state={db.state} detail={db.state === "ok" ? "reachable" : `Database: ${db.detail}`} />
        <Chip label="Glimmer" state={gl.state} detail={gl.state === "ok" ? "reachable" : `Glimmer: ${gl.detail}`} />
        <Chip label="Meta" state={mt.state} detail={mt.state === "ok" ? "reachable" : `Meta: ${mt.detail}`} />
        <Chip label="Spend today" state={spend === "not measured" || spend === undefined ? "unknown" : "ok"} detail={`${fmt(spend)} / cap ${fmt(cap)} USD`} />
        <Chip label="Queue" state={queue === "not measured" || queue === undefined ? "unknown" : "ok"} detail={`Queue depth: ${fmt(queue)}`} />
      </ul>
      <p className="sr-only">
        Status: {health.status} · {latencyText} · Model error rate: {fmt(o.model_error_rate)} · Spend today: {fmt(o.spend_today_usd)} / cap {fmt(o.spend_cap_usd)} USD · Queue depth: {fmt(o.queue_depth)}
        {health.status !== "ok" ? <> · Degraded: {[
          db.state !== "ok" ? `Database (${db.detail})` : null,
          gl.state !== "ok" ? `Glimmer (${gl.detail})` : null,
          mt.state !== "ok" && mt.state !== "unknown" ? `Meta (${mt.detail})` : null,
        ].filter(Boolean).join(", ") || "see chips above"}</> : null}
      </p>
    </div>
  );
}
export function VerdictBadge({ verdict, aiStatus, attempts }: {
  verdict?: string | null; aiStatus: string; attempts?: { purpose: string; outcome: string }[] | null;
}) {
  const kind = verdictKind(verdict, aiStatus, attempts);
  if (kind === "verdict") return <span className={`badge verdict-${verdict}`}>{verdict}</span>;
  if (kind === "triaged") return <span className="badge triaged">triaged</span>;
  if (kind === "failed") return <span className="badge failed">failed</span>;
  if (kind === "quarantined") return <span className="badge quarantined">quarantined</span>;
  return <span className="badge pending">pending</span>;
}
export function FilterBar({ filters, onChange }: { filters: ListFilters; onChange: (next: ListFilters) => void }) {
  return (
    <form className="filterbar" aria-label="Incident filters" onSubmit={(e) => e.preventDefault()}>
      <label>
        Floor at least
        <select aria-label="Floor at least" value={filters.minFloor === null ? "" : String(filters.minFloor)}
          onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, minFloor: v === "" ? null : Number(v) }); }}>
          <option value="">Any</option><option value="1">1+</option><option value="2">2+</option><option value="3">3+</option><option value="4">4+</option><option value="5">5+</option><option value="6">6</option>
        </select>
      </label>
      <label>
        Verdict
        <select aria-label="Verdict" value={filters.verdict ?? ""}
          onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, verdict: v === "" ? null : v }); }}>
          <option value="">Any</option><option value="true_positive">true_positive</option><option value="benign_authorized">benign_authorized</option><option value="false_positive">false_positive</option><option value="needs_human">needs_human</option>
        </select>
      </label>
      <label>
        Analyzed
        <select aria-label="Analyzed" value={filters.analyzed === null ? "" : String(filters.analyzed)}
          onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, analyzed: v === "" ? null : v === "true" }); }}>
          <option value="">Any</option><option value="true">Analyzed only</option><option value="false">Not analyzed only</option>
        </select>
      </label>
    </form>
  );
}

export function IncidentList({ items, total, page, setPage, pageSize, onSelect, onStripFilter, emptyMessage }: {
  items: IncidentListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
  onStripFilter?: (patch: Partial<ListFilters>) => void; emptyMessage?: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  if (!items.length) return <p>{emptyMessage ?? "No incidents found."}</p>;
  const analyzedCount = items.filter((it) => {
    const k = verdictKind(it.verdict, it.ai_status);
    return (k === "verdict" || k === "triaged") && it.analyzed !== false;
  }).length;
  const injectionCount = items.filter((it) => it.has_injection).length;
  const maxEvents = Math.max(1, ...items.map((it) => it.event_count));
  const sevCounts = [1, 2, 3, 4, 5, 6].map((n) => ({ n, c: items.filter((it) => it.severity_id === n).length }));
  const verdictCats: { key: string; label: string; c: number; patch: Partial<ListFilters> }[] = [
    { key: "true_positive", label: "true_positive", c: items.filter((it) => it.verdict === "true_positive").length, patch: { verdict: "true_positive", analyzed: null } },
    { key: "needs_human", label: "needs_human", c: items.filter((it) => it.verdict === "needs_human").length, patch: { verdict: "needs_human", analyzed: null } },
    { key: "false_positive", label: "false_positive", c: items.filter((it) => it.verdict === "false_positive").length, patch: { verdict: "false_positive", analyzed: null } },
    { key: "benign_authorized", label: "benign_authorized", c: items.filter((it) => it.verdict === "benign_authorized").length, patch: { verdict: "benign_authorized", analyzed: null } },
    { key: "not_analyzed", label: "not analyzed", c: items.filter((it) => !it.verdict && verdictKind(it.verdict, it.ai_status) === "pending").length, patch: { verdict: null, analyzed: false } },
  ];
  const sevTotal = Math.max(1, sevCounts.reduce((a, b) => a + b.c, 0));
  const verdTotal = Math.max(1, verdictCats.reduce((a, b) => a + b.c, 0));
  return (
    <div>
      <p className="summary-count">{total} incidents, {analyzedCount} analyzed, {injectionCount} with injection signals</p>
      <div className="dist" aria-label="Severity distribution">
        <p className="dist-title">Severity distribution (this page, by final severity)</p>
        <div className="dist-bar" role="group" aria-label="Severity distribution bar">
          {sevCounts.filter((s) => s.c > 0).map((s) => onStripFilter ? (
            <button key={s.n} type="button" className={`dist-seg sev-bg-${s.n} grow`} style={{ width: `${(s.c / sevTotal) * 100}%` }}
              aria-label={`Severity ${s.n}: ${s.c} incidents. Filter to floor at least ${s.n}`}
              title={`Severity ${s.n}: ${s.c}`} onClick={() => onStripFilter({ minFloor: s.n, page: 0 })}>{s.c}</button>
          ) : (<span key={s.n} className={`dist-seg sev-bg-${s.n} grow`} style={{ width: `${(s.c / sevTotal) * 100}%` }} title={`Severity ${s.n}: ${s.c}`}>{s.c}</span>))}
        </div>
        <ul className="dist-legend">{sevCounts.map((s) => <li key={s.n}>Severity {s.n}: {s.c}</li>)}</ul>
      </div>
      <div className="dist" aria-label="Verdict distribution">
        <p className="dist-title">Verdicts (this page)</p>
        <div className="dist-bar verdict-bar" role="group" aria-label="Verdict strip">
          {verdictCats.filter((v) => v.c > 0).map((v) => onStripFilter ? (
            <button key={v.key} type="button" className={`dist-seg verdict-bg-${v.key} grow`} style={{ width: `${(v.c / verdTotal) * 100}%` }}
              aria-label={`${v.label}: ${v.c} incidents. Apply this filter`} title={`${v.label}: ${v.c}`}
              onClick={() => onStripFilter({ ...v.patch, page: 0 })}>{v.c}</button>
          ) : (<span key={v.key} className={`dist-seg verdict-bg-${v.key} grow`} style={{ width: `${(v.c / verdTotal) * 100}%` }} title={`${v.label}: ${v.c}`}>{v.c}</span>))}
        </div>
        <ul className="dist-legend">{verdictCats.map((v) => <li key={v.key}>{v.label}: {v.c}</li>)}</ul>
      </div>
      <div className="table-wrap">
        <table className="incidents" aria-label="Incidents">
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Verdict</th><th>Events</th><th className="col-inj">Injection</th></tr></thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.id} className="rowlink" tabIndex={0} onClick={() => open(it.id)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(it.id); } }}>
                <td className="mono cell-id"><span className={`rail sev-bg-${it.severity_id}`} aria-hidden="true" />{it.id}</td>
                <td><a className="title-link" href={buildDetailHash(it.id)}>{it.title || `Incident ${it.id}`}</a></td>
                <td className="cell-sev"><SeverityChip floor={it.severity_floor} final={it.severity_id} /></td>
                <td className="cell-verdict"><VerdictBadge verdict={it.verdict} aiStatus={it.ai_status} /></td>
                <td className="cell-events"><span className="num">{it.event_count}</span><span className="event-bar" aria-hidden="true"><span className="event-fill grow" style={{ width: `${(it.event_count / maxEvents) * 100}%` }} /></span><span className="sr-only">{it.event_count} events</span></td>
                <td className="cell-inj">{it.has_injection ? <span className="badge injection">injection</span> : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="pager">
          <button type="button" disabled={page <= 0} onClick={() => setPage(page - 1)}>Previous</button>{" "}
          Page {page + 1} of {pages} ({total} total){" "}
          <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
        </p>
      </div>
    </div>
  );
}

const TRACE_RESULT_CAP = 4000;
const TRACE_SUMMARY_CAP = 200;
function oneLineSummary(text: string | null | undefined): string {
  if (!text) return "";
  const first = text.split("\n", 1)[0].replace(/\s+/g, " ").trim();
  return first.length > TRACE_SUMMARY_CAP ? `${first.slice(0, TRACE_SUMMARY_CAP)}…` : first;
}
function formatArgValue(value: unknown): string {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}
function factorStatus(factor: unknown): { applied: boolean | null; contribution: string } {
  if (typeof factor !== "object" || factor === null) return { applied: null, contribution: String(factor) };
  const o = factor as Record<string, unknown>;
  let applied: boolean | null = null;
  for (const key of ["added_level", "applied", "fired"]) {
    if (typeof o[key] === "boolean") { applied = o[key] as boolean; break; }
  }
  const contribution = typeof o.contribution === "string" ? o.contribution : formatArgValue(factor);
  return { applied, contribution };
}
const SECTIONS: { id: string; label: string }[] = [
  { id: "summary", label: "Summary" }, { id: "timeline", label: "Timeline" }, { id: "attack", label: "ATT&CK" },
  { id: "trace", label: "Trace" }, { id: "cost", label: "Cost" }, { id: "severity", label: "Severity" },
  { id: "gaps", label: "Gaps" }, { id: "response", label: "Response plan" },
];
function scrollToSection(id: string) {
  const el = document.getElementById(`section-${id}`);
  if (!el) return;
  el.scrollIntoView({ block: "start" });
  const heading = el.querySelector<HTMLElement>("h3, h2");
  if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
}

export function IncidentView({ detail }: { detail: IncidentDetail }) {
  const [highlighted, setHighlighted] = useState<number | null>(null);
  const [triageExpanded, setTriageExpanded] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const analysis = detail.analysis;
  const timeline = analysis?.timeline ?? [];
  const evidenceByUid = new Map((detail.evidence ?? []).map((e) => [e.event_uid, e]));
  const factors = detail.severity?.factors ?? detail.severity_factors ?? {};
  const reasoningText = detail.reasoning_unverified?.text ?? "";
  const floor = detail.severity?.floor ?? detail.severity_floor;
  const final = detail.severity?.final ?? detail.severity_id;
  const models = Array.from(new Set([analysis?.model, detail.triage?.model, ...(detail.llm_attempts ?? []).map((a) => a.model)].filter(Boolean))) as string[];
  const citedUids = Array.from(new Set(timeline.map((t) => t.event_uid)));
  const foundCount = citedUids.filter((u) => evidenceByUid.get(u)?.found).length;
  const eventCount = detail.event_count ?? detail.evidence?.length ?? 0;
  const citedCount = detail.evidence?.length ?? 0;
  const triageSummary = detail.triage?.summary ?? "";
  const triageLong = triageSummary.length > 300 || triageSummary.split("\n").length > 3;
  const groups = groupTechniques(detail.techniques ?? []);
  const tacticCounts: Record<string, number> = {};
  for (const g of groups) tacticCounts[g.tactic] = g.items.length;
  const visibleGroups = selectedTactic ? groups.filter((g) => g.tactic === selectedTactic) : groups;
  const maxTokens = Math.max(1, ...(detail.llm_attempts ?? []).map((a) => a.tokens));
  const timeRange = timeline.length ? `${timeline[0].time} to ${timeline[timeline.length - 1].time}` : (detail.first_seen || detail.last_seen ? `${detail.first_seen ?? "unknown"} to ${detail.last_seen ?? "unknown"}` : "not recorded");
  return (
    <article className="detail">
      <nav className="section-nav" aria-label="Incident sections">
        <div className="section-scroll">
          {SECTIONS.map((s) => (
            <a key={s.id} href={`#section-${s.id}`} onClick={(e) => { e.preventDefault(); scrollToSection(s.id); }}>{s.label}</a>
          ))}
        </div>
        <label className="section-select">
          <span className="sr-only">Go to section</span>
          <select aria-label="Go to section" defaultValue="" onChange={(e) => { if (e.target.value) scrollToSection(e.target.value); }}>
            <option value="">Go to section…</option>
            {SECTIONS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </label>
      </nav>

      <section id="section-summary" className="panel hero" aria-label="Incident summary">
        <h2>{detail.title || `Incident ${detail.id}`}</h2>
        <p className="hero-badges">
          <VerdictBadge verdict={analysis?.verdict ?? detail.verdict} aiStatus={detail.ai_status} attempts={detail.llm_attempts} />{" "}
          <SeverityChip floor={floor} final={final} />
        </p>
        <SeverityGauge floor={floor} final={final} />
        {typeof analysis?.confidence === "number" ? <ConfidenceMeter value={analysis.confidence} /> : null}
        <p className="hero-facts">
          Models used: <span className="mono">{models.length ? models.join(", ") : "not recorded"}</span>
          {" · "}Language: {analysis?.language ?? "not recorded"}
          {" · "}Time range: <span className="mono">{timeRange}</span>
        </p>
        <ul className="stat-tiles">
          <li><IconHost /> <strong className="num">{eventCount}</strong><span>events (event_count)</span></li>
          <li><IconShield /> <strong className="num">{citedCount}</strong><span>cited events (evidence)</span></li>
          <li><IconCheck /> <strong className="num">{foundCount} of {citedUids.length}</strong><span>evidence found of cited</span></li>
          <li><IconAlert /> <strong className="num">{detail.injection_signals?.length ?? 0}</strong><span>injection signals</span></li>
          <li><IconSpark /> <strong className="num">{detail.spend_total_usd ?? "not measured"}</strong><span>spend (USD)</span></li>
        </ul>
        {detail.pseudonym_resolution ? <p className="muted">{detail.pseudonym_resolution.note} {detail.pseudonym_resolution.resolved ? "(resolved locally)" : ""}</p> : null}
      </section>

      {detail.triage?.summary ? (
        <section className="panel" aria-label="Triage summary">
          <h3><IconClock /> Triage summary</h3>
          {triageLong ? (
            <>
              <p className={triageExpanded ? "triage-text expanded" : "triage-text clamped"}>{triageSummary}</p>
              <button type="button" aria-expanded={triageExpanded} onClick={() => setTriageExpanded((v) => !v)}>
                {triageExpanded ? "Show less" : "Show full summary"} <IconChevron />
              </button>
            </>
          ) : <p className="triage-text">{triageSummary}</p>}
        </section>
      ) : null}
      {detail.learned_rules?.length ? <LearnedRuleRefs refs={detail.learned_rules} /> : null}

      <section id="section-timeline" aria-label="Timeline">
        <h3>Timeline (every claim cites an event)</h3>
        <ActivityStrip timeline={timeline} firstSeen={detail.first_seen} lastSeen={detail.last_seen} techniques={detail.techniques} evidence={detail.evidence} highlighted={highlighted} onHighlight={setHighlighted}
          onJump={(i) => { setHighlighted(i); const el = document.getElementById(`timeline-row-${i}`); el?.scrollIntoView({ block: "center" }); el?.focus({ preventScroll: true }); }} />
        {timeline.length ? (
          <ol className="timeline">
            {timeline.map((entry, i) => {
              const ev = evidenceByUid.get(entry.event_uid);
              return (
                <li key={`${entry.event_uid}-${i}`} id={`timeline-row-${i}`} tabIndex={-1} className={`tl-row ${highlighted === i ? "highlighted" : ""}`}
                  onMouseEnter={() => setHighlighted(i)} onMouseLeave={() => setHighlighted(null)}
                  onFocus={() => setHighlighted(i)} onBlur={() => setHighlighted(null)}>
                  <span className="mono tl-time">{entry.time}</span>
                  <span className="tl-body">
                    <span className="tl-claim">{entry.description}</span>{" "}
                    <span className="mono">event_uid: {entry.event_uid}</span>
                    <details>
                      <summary>Evidence for {entry.event_uid}</summary>
                      {ev?.found ? <pre className="payload">{JSON.stringify(ev.event, null, 2)}</pre> : <p>Missing: no event with this uid in the replay store. This citation could not be verified.</p>}
                    </details>
                  </span>
                </li>
              );
            })}
          </ol>
        ) : <p>No timeline recorded.</p>}
      </section>

      <section id="section-attack" aria-label="ATT&CK chain">
        <h3>ATT&amp;CK chain</h3>
        {detail.techniques?.length ? (
          <>
            <KillChainStrip counts={tacticCounts} selected={selectedTactic} onSelect={setSelectedTactic} />
            {selectedTactic ? <p><button type="button" onClick={() => setSelectedTactic(null)}>Clear tactic filter</button></p> : null}
            {visibleGroups.map((g) => (
              <div key={g.tactic} className="tactic-group">
                <h4>{g.name} ({g.items.length})</h4>
                <ul className="chips-tech">
                  {g.items.map((t) => (
                    <li key={t.id} className="tech-chip" title={`${t.id} — ${t.name ?? "name not measured"}`}>
                      <span className="mono tech-id">{t.id}</span> <span className="tech-name">{t.name ?? "name not measured"}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {!visibleGroups.length ? <p>No techniques in this tactic.</p> : null}
          </>
        ) : <p>No techniques recorded.</p>}
      </section>

      <section id="section-trace" aria-label="Agent trace">
        <h3>Agent trace</h3>
        <p className="muted">As seen by the cloud model (pseudonymized).</p>
        {detail.agent_trace?.length ? (
          <ol className="trace">
            {detail.agent_trace.map((s) => {
              const full = s.result_summary ?? "";
              const truncated = full.length > TRACE_RESULT_CAP;
              const shown = truncated ? full.slice(0, TRACE_RESULT_CAP) : full;
              const args = s.arguments ?? {};
              return (
                <li key={s.step}>
                  <span className="mono">{s.tool}</span> · tokens: {s.tokens}
                  {Object.keys(args).length ? (
                    <dl className="args">{Object.entries(args).map(([k, v]) => (<div key={k}><dt className="mono">{k}</dt><dd className="mono">{formatArgValue(v)}</dd></div>))}</dl>
                  ) : <p className="muted">No arguments.</p>}
                  <p>Result: {oneLineSummary(full) || "—"}</p>
                  <details>
                    <summary>Full result (text only)</summary>
                    <pre className="payload mono">{shown}</pre>
                    {truncated ? <p className="muted">Result truncated to {TRACE_RESULT_CAP} characters.</p> : null}
                  </details>
                </li>
              );
            })}
          </ol>
        ) : <p>{agentTraceEmptyMessage(detail)}.</p>}
      </section>

      <section id="section-cost" aria-label="Model attempts and cost">
        <h3>Model attempts and cost</h3>
        {detail.llm_attempts?.length ? (
          <div className="table-wrap"><table className="cost" aria-label="Model attempts and cost">
            <thead><tr><th>Purpose</th><th>Model</th><th>Attempt</th><th>Outcome</th><th>Tokens</th><th>USD</th></tr></thead>
            <tbody>
              {detail.llm_attempts.map((a, i) => {
                const outcomeKind = attemptOutcomeKind(a.outcome, a.failed_validator);
                const outcomeText = attemptOutcomeText(a.outcome, a.failed_validator);
                return (
                  <tr key={i}>
                    <td>{a.purpose}</td><td className="mono">{a.model}</td><td className="num">{a.attempt_number}</td>
                    <td><span className={`outcome-dot outcome-${outcomeKind}`} aria-hidden="true" />{a.outcome}{a.failed_validator ? ` (failed validator: ${a.failed_validator})` : ""} · {a.token_source ?? "not measured"}<span className="sr-only"> Outcome: {outcomeText}</span></td>
                    <td><span className="num">{a.tokens}</span><span className="token-bar" aria-hidden="true"><span className="token-fill grow" style={{ width: `${(a.tokens / maxTokens) * 100}%` }} /></span></td>
                    <td className="num col-usd">{a.usd ?? "not measured"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        ) : <p>No model attempts recorded.</p>}
        <p>Spend total for this incident: {detail.spend_total_usd ?? "not measured"} USD</p>
      </section>

      <section id="section-severity" aria-label="Severity factors">
        <h3>Severity factors (floor vs final)</h3>
        <p>Deterministic floor: {floor}. Final severity: {final}. A model may raise the floor by at most one level, citing evidence.</p>
        <SeverityScale floor={floor} final={final} />
        {Object.keys(factors).length ? (
          <>
            <ul className="plain">
              {Object.entries(factors).map(([name, factor]) => {
                const status = factorStatus(factor);
                return <li key={name}><span className="mono">{name}</span> — {status.applied === null ? "not measured" : status.applied ? "applied" : "not applied"}{": "}{status.contribution}</li>;
              })}
            </ul>
            <details><summary>Raw severity factors (JSON)</summary><pre className="payload">{JSON.stringify(factors, null, 2)}</pre></details>
          </>
        ) : <p>No severity factors recorded.</p>}
      </section>

      <section aria-label="Injection signals">
        <h3>Injection signals</h3>
        {detail.injection_signals?.length ? (
          <div className="inj-cards">
            {detail.injection_signals.map((s, i) => (
              <article key={i} className="inj-card">
                <p><IconAlert /> <strong>Injection signal</strong> · <span className="mono">{s.pattern_id}</span> in <span className="mono">{s.field}</span> (event <span className="mono">{s.event_uid}</span>, effect: {s.requested_effect})</p>
                {s.payload_text ? <><p>{s.payload_label ?? "payload (shown as text)"}:</p><pre className="payload mono">{s.payload_text}</pre></> : null}
              </article>
            ))}
          </div>
        ) : <p>No injection signals.</p>}
      </section>

      <section id="section-gaps" aria-label="Visibility gaps">
        <h3>Visibility gaps</h3>
        {analysis?.visibility_gaps?.length ? <ul className="plain">{analysis.visibility_gaps.map((g, i) => <li key={i}>{g}</li>)}</ul> : <p>None recorded.</p>}
      </section>

      <section id="section-response" aria-label="Response plan">
        <h3>Response plan</h3>
        {analysis?.response_plan?.length ? (
          <ol className="response-plan">{analysis.response_plan.map((r, i) => <li key={i}><span className="resp-num" aria-hidden="true">{i + 1}</span><span>{r}</span></li>)}</ol>
        ) : <p>No response plan recorded.</p>}
      </section>

      {reasoningText.trim() ? (
        <section>
          <h3>Unverified reasoning</h3>
          <details><summary>Stored on-prem reasoning (not evidence)</summary><pre className="payload">{reasoningText}</pre></details>
        </section>
      ) : null}
    </article>
  );
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("corvus-theme") || "dark");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));
  const [items, setItems] = useState<IncidentListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [listState, setListState] = useState<"loading" | "ready" | "error">("loading");
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "ready" | "error" | "invalid" | "missing">("idle");
  const [ruleItems, setRuleItems] = useState<RuleListItem[]>([]);
  const [ruleTotal, setRuleTotal] = useState(0);
  const [ruleListState, setRuleListState] = useState<"loading" | "ready" | "error">("loading");
  const [ruleDetail, setRuleDetail] = useState<RuleDetail | null>(null);
  const [ruleDetailState, setRuleDetailState] = useState<"idle" | "loading" | "ready" | "error" | "invalid">("idle");
  const [retryNonce, setRetryNonce] = useState(0);
  const lastListHash = useRef<string>("#/");
  const lastRulesHash = useRef<string>("#/rules");
  const pageSize = 20;
  const go = useCallback((hash: string) => {
    if (window.location.hash !== hash) window.location.hash = hash;
    else setRoute(parseHash(hash));
  }, []);
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem("corvus-theme", theme); }, [theme]);
  useEffect(() => { getJson<Health>("/api/health").then(setHealth).catch((e: Error) => setHealthError(e.message)); }, [retryNonce]);
  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);
  useEffect(() => {
    if (route.view === "list") {
      lastListHash.current = buildListHash(route);
      setListState("loading");
      getJson<{ items: IncidentListItem[]; total: number }>(buildListQuery(route, pageSize))
        .then((d) => { setItems(d.items); setTotal(d.total); setListState("ready"); })
        .catch(() => setListState("error"));
      setDetail(null); setDetailState("idle");
    } else if (route.view === "detail") {
      if (!isNumericId(route.id)) { setDetail(null); setDetailState("invalid"); return; }
      setDetailState("loading"); setDetail(null);
      getJson<IncidentDetail>(`/api/incidents/${route.id}`)
        .then((d) => { setDetail(d); setDetailState("ready"); })
        .catch(() => setDetailState("error"));
    } else if (route.view === "rules") {
      lastRulesHash.current = buildRulesHash(route);
      setRuleListState("loading");
      getJson<{ items: RuleListItem[]; total: number }>(buildRulesQuery(route, pageSize))
        .then((d) => { setRuleItems(d.items); setRuleTotal(d.total); setRuleListState("ready"); })
        .catch(() => setRuleListState("error"));
      setRuleDetail(null); setRuleDetailState("idle");
    } else if (route.view === "rule") {
      if (!isNumericId(route.id)) { setRuleDetail(null); setRuleDetailState("invalid"); return; }
      setRuleDetailState("loading"); setRuleDetail(null);
      getJson<RuleDetail>(`/api/rules/${route.id}`)
        .then((d) => { setRuleDetail(d); setRuleDetailState("ready"); })
        .catch(() => setRuleDetailState("error"));
    }
  }, [route, pageSize, retryNonce]);
  const setFilters = useCallback((next: ListFilters) => { go(buildListHash(next)); }, [go]);
  const setRuleFilters = useCallback((next: RuleFilters) => { go(buildRulesHash(next)); }, [go]);
  const open = useCallback((id: number) => { go(buildDetailHash(id)); }, [go]);
  const openRule = useCallback((id: number) => { go(buildRuleHash(id)); }, [go]);
  const retry = useCallback(() => setRetryNonce((n) => n + 1), []);
  const isIncidents = route.view === "list" || route.view === "detail";
  const isRules = route.view === "rules" || route.view === "rule";
  const filterDesc = route.view === "list" ? [
    route.minFloor !== null ? `floor at least ${route.minFloor}` : null,
    route.verdict ? `verdict ${route.verdict}` : null,
    route.analyzed !== null ? (route.analyzed ? "analyzed only" : "not analyzed only") : null,
  ].filter(Boolean).join(", ") : "";
  return (
    <div className="wrap">
      <header className="top">
        <div className="brand"><IconShield size={22} /><div><h1>Corvus</h1><p className="muted tagline">Every claim is verifiable: severity, timeline, trace, and cost cite stored evidence.</p></div></div>
        <nav aria-label="Sections">
          <a href="#/" aria-current={isIncidents ? "page" : undefined}>Incidents</a>{" · "}
          <a href="#/rules" aria-current={isRules ? "page" : undefined}>Rules</a>
        </nav>
        <button type="button" aria-label="Toggle color theme" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? "Light theme" : "Dark theme"}</button>
      </header>
      <HealthStrip health={health} error={healthError} />
      {route.view === "detail" || route.view === "rule" || route.view === "unknown" ? (
        <main>
          {route.view === "rule" ? (
            <>
              <button type="button" onClick={() => go(lastRulesHash.current)}>Back to rules</button>
              {ruleDetailState === "loading" ? <div aria-live="polite" className="reserve"><p>Loading rule…</p><div className="skeleton" aria-hidden="true"><span /><span /><span /></div></div>
                : ruleDetailState === "invalid" ? <p role="alert">Invalid rule id: the URL must be #/rules/&lt;number&gt;.</p>
                : ruleDetailState === "error" ? <p role="alert">Could not load this rule. It may not exist. <button type="button" onClick={retry}>Retry</button></p>
                : ruleDetail ? <RuleDetailView detail={ruleDetail} /> : null}
            </>
          ) : (
            <>
              <button type="button" onClick={() => go(lastListHash.current)}>Back to incidents</button>
              {route.view === "unknown" ? (
                <p role="alert">Page not found. <a href={lastListHash.current}>Back to incidents</a></p>
              ) : detailState === "loading" ? <div aria-live="polite"><p>Loading incident…</p><div className="skeleton" aria-hidden="true"><span /><span /><span /></div></div>
                : detailState === "invalid" ? <p role="alert">Invalid incident id: the URL must be #/incidents/&lt;number&gt;.</p>
                : detailState === "error" || detailState === "missing" ? <p role="alert">Could not load this incident. It may not exist. <button type="button" onClick={retry}>Retry</button></p>
                : detail ? <IncidentView detail={detail} /> : null}
            </>
          )}
        </main>
      ) : route.view === "rules" ? (
        <main><h2>Learned rules</h2>
          <RulesBanner />
          <RuleFilterBar filters={route} onChange={setRuleFilters} />
          {ruleListState === "loading" ? <div aria-live="polite" className="reserve"><p>Loading rules…</p><div className="skeleton" aria-hidden="true"><span /><span /><span /></div></div> : ruleListState === "error" ? <p role="alert">Could not load rules. Check that the API and database are running, then reload. <button type="button" onClick={retry}>Retry</button></p> : (
            <RulesList items={ruleItems} total={ruleTotal} page={route.page} setPage={(n) => setRuleFilters({ ...route, page: n })} pageSize={pageSize} onSelect={openRule} />
          )}
        </main>
      ) : (
        <main><h2>Incidents</h2>
          <FilterBar filters={route} onChange={setFilters} />
          {listState === "loading" ? <div aria-live="polite"><p>Loading incidents…</p><div className="skeleton" aria-hidden="true"><span /><span /><span /></div></div>
            : listState === "error" ? <p role="alert">Could not load incidents. Check that the API and database are running, then reload. <button type="button" onClick={retry}>Retry</button></p> : (
            <IncidentList items={items} total={total} page={route.page} setPage={(n) => setFilters({ ...route, page: n })} pageSize={pageSize} onSelect={open}
              onStripFilter={(patch) => setFilters({ ...route, ...patch, page: 0 })}
              emptyMessage={filterDesc ? `No incidents found matching ${filterDesc}.` : "No incidents found."} />
          )}
        </main>
      )}
    </div>
  );
}

