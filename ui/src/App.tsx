import { useCallback, useEffect, useRef, useState } from "react";

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
export type Health = { status: string; self_observation?: Record<string, unknown> };

export const REAL_VERDICTS = new Set([
  "true_positive",
  "benign_authorized",
  "false_positive",
  "needs_human",
]);

export type ListFilters = {
  page: number;
  minFloor: number | null;
  verdict: string | null;
  analyzed: boolean | null;
};

export type Route =
  | { view: "list" } & ListFilters
  | { view: "detail"; id: string }
  | { view: "rules" } & RuleFilters
  | { view: "rule"; id: string }
  | { view: "unknown" };

export const RULE_STATUSES = new Set([
  "candidate",
  "shadow",
  "active",
  "archived",
  "rolled_back",
]);

export const RULE_MODES = new Set(["shadow", "active"]);

export type RuleFilters = {
  page: number;
  status: string | null;
  mode: string | null;
};

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
  if (q >= 0) {
    pathPart = h.slice(0, q);
    queryPart = h.slice(q + 1);
  }
  if (pathPart === "" || pathPart === "/") {
    const params = new URLSearchParams(queryPart);
    const verdictRaw = params.get("verdict");
    const analyzedRaw = params.get("analyzed");
    return {
      view: "list",
      page: parseNonNegativeInt(params.get("page")),
      minFloor: parseMinFloor(params.get("min_floor")),
      verdict: verdictRaw !== null && REAL_VERDICTS.has(verdictRaw) ? verdictRaw : null,
      analyzed: analyzedRaw === "true" ? true : analyzedRaw === "false" ? false : null,
    };
  }
  const match = /^\/incidents\/([^/]+)$/.exec(pathPart);
  if (match) {
    let id = match[1];
    try {
      id = decodeURIComponent(id);
    } catch {
      id = "";
    }
    return { view: "detail", id };
  }
  if (pathPart === "/rules") {
    const params = new URLSearchParams(queryPart);
    const statusRaw = params.get("status");
    const modeRaw = params.get("mode");
    return {
      view: "rules",
      page: parseNonNegativeInt(params.get("page")),
      status: statusRaw !== null && RULE_STATUSES.has(statusRaw) ? statusRaw : null,
      mode: modeRaw !== null && RULE_MODES.has(modeRaw) ? modeRaw : null,
    };
  }
  const ruleMatch = /^\/rules\/([^/]+)$/.exec(pathPart);
  if (ruleMatch) {
    let id = ruleMatch[1];
    try {
      id = decodeURIComponent(id);
    } catch {
      id = "";
    }
    return { view: "rule", id };
  }
  return { view: "unknown" };
}

export function isNumericId(id: string): boolean {
  return /^\d+$/.test(id);
}

export function buildListHash(filters: ListFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.minFloor !== null) params.set("min_floor", String(filters.minFloor));
  if (filters.verdict !== null) params.set("verdict", filters.verdict);
  if (filters.analyzed !== null) params.set("analyzed", String(filters.analyzed));
  const query = params.toString();
  return query ? `#/?${query}` : "#/";
}

export function buildDetailHash(id: number): string {
  return `#/incidents/${id}`;
}

export function buildRulesHash(filters: RuleFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.status !== null) params.set("status", filters.status);
  if (filters.mode !== null) params.set("mode", filters.mode);
  const query = params.toString();
  return query ? `#/rules?${query}` : "#/rules";
}

export function buildRuleHash(id: number): string {
  return `#/rules/${id}`;
}

export function verdictKind(
  verdict: string | null | undefined,
  aiStatus: string,
): "verdict" | "triaged" | "pending" {
  if (verdict !== null && verdict !== undefined && REAL_VERDICTS.has(verdict)) return "verdict";
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

export function RulesBanner() {
  return (
    <section className="panel banner" aria-label="About shadow mode">
      <h3>Shadow mode</h3>
      <p>
        Shadow rules never change alerts: matching events keep their existing
        alerts and gain the <span className="mono">corvus_shadow</span> tag for
        review. Learning here means stored detection rules only — no model
        weights are updated.
      </p>
    </section>
  );
}

export function RuleStatusBadge({ status }: { status: string }) {
  if (!RULE_STATUSES.has(status)) {
    return <span className="badge rule-unknown">{status || "unknown"}</span>;
  }
  return <span className={`badge rule-${status}`}>{status}</span>;
}

export function RuleModeBadge({ mode }: { mode: string | null | undefined }) {
  if (mode === null || mode === undefined) {
    return <span className="badge mode-none">not deployed</span>;
  }
  if (!RULE_MODES.has(mode)) {
    return <span className="badge mode-unknown">{mode}</span>;
  }
  return <span className={`badge mode-${mode}`}>{mode}</span>;
}

export function RuleFilterBar({
  filters, onChange,
}: {
  filters: RuleFilters;
  onChange: (next: RuleFilters) => void;
}) {
  return (
    <form
      className="filterbar"
      aria-label="Rule filters"
      onSubmit={(e) => e.preventDefault()}
    >
      <label>
        Status
        <select
          aria-label="Status"
          value={filters.status ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            onChange({ ...filters, page: 0, status: v === "" ? null : v });
          }}
        >
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
        <select
          aria-label="Mode"
          value={filters.mode ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            onChange({ ...filters, page: 0, mode: v === "" ? null : v });
          }}
        >
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
    <div className="table-wrap">
      <table className="rules" aria-label="Learned rules">
        <thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Mode</th><th>Version</th><th>Level</th><th>Techniques</th><th>Hits</th><th>FP</th></tr></thead>
        <tbody>
          {items.map((it) => (
            <tr
              key={it.id}
              className="rowlink"
              tabIndex={0}
              onClick={() => open(it.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  open(it.id);
                }
              }}
            >
              <td className="mono">{it.id}</td>
              <td><a className="title-link" href={buildRuleHash(it.id)}>{it.title || `Rule ${it.id}`}</a></td>
              <td><RuleStatusBadge status={it.status} /></td>
              <td><RuleModeBadge mode={it.mode} /></td>
              <td className="mono">v{it.version}</td>
              <td>{it.level ?? "—"}</td>
              <td className="mono">{it.techniques?.length ? it.techniques.join(", ") : "—"}</td>
              <td>{it.hits}</td>
              <td>{it.false_positives}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        <button type="button" disabled={page <= 0} onClick={() => setPage(page - 1)}>Previous</button>{" "}
        Page {page + 1} of {pages} ({total} total){" "}
        <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
      </p>
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
            return (
              <li key={i}>
                <span className="badge learned-unknown">unknown learned rule (unresolved)</span>
              </li>
            );
          }
          const id = Number(r.rule_db_id);
          if (!Number.isInteger(id)) {
            return (
              <li key={i}>
                <span className="badge learned-unknown">unknown learned rule (unresolved)</span>
              </li>
            );
          }
          const mode = typeof r.mode === "string" && r.mode ? r.mode : "unknown mode";
          const modeClass = mode === "shadow" ? "learned-shadow" : mode === "active" ? "learned-active" : "learned-other";
          return (
            <li key={i}>
              <a className={`badge learned-rule ${modeClass}`} href={buildRuleHash(id)}>
                learned rule v{r.version ?? "?"} ({mode})
              </a>
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
      if (!clipboard) {
        setCopied(false);
        return;
      }
      await clipboard.writeText(detail.sigma_text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <article>
      <h2>{detail.title || `Rule ${detail.id}`}</h2>
      <p>
        <RuleStatusBadge status={detail.status} />{" "}
        <RuleModeBadge mode={detail.mode} />{" "}
        <span className="mono">v{detail.version}</span>
        {detail.level ? <> · Level: {detail.level}</> : null}
        {detail.techniques?.length ? <> · Techniques: <span className="mono">{detail.techniques.join(", ")}</span></> : null}
      </p>
      <p className="muted">
        Hits: {detail.hits} · False positives: {detail.false_positives}
        {detail.wazuh?.native_rule_id != null ? <> · Wazuh native id: <span className="mono">{detail.wazuh.native_rule_id}</span></> : null}
        {detail.wazuh?.group ? <> · Group: <span className="mono">{detail.wazuh.group}</span></> : null}
      </p>
      {detail.wazuh?.pair_note ? <p className="muted">{detail.wazuh.pair_note}</p> : null}

      <h3>Sigma rule (text only)</h3>
      <p>
        <button type="button" onClick={copySigma}>
          {copied ? "Copied" : "Copy Sigma text"}
        </button>
      </p>
      <pre className="payload"><code>{detail.sigma_text}</code></pre>

      <h3>Lineage</h3>
      {lineage?.lineage_note ? <p className="muted">{lineage.lineage_note}</p> : null}
      <dl className="args">
        <div>
          <dt className="mono">source_incident</dt>
          <dd>
            {source === null || source === undefined ? (
              "none recorded"
            ) : source.exists ? (
              <a href={buildDetailHash(source.id)}>Incident {source.id}{source.title ? ` — ${source.title}` : ""}</a>
            ) : (
              <>Incident {source.id} (deleted)</>
            )}
          </dd>
        </div>
        <div>
          <dt className="mono">cited_uids</dt>
          <dd className="mono">{cited.length ? cited.join(", ") : "none"}</dd>
        </div>
        <div>
          <dt className="mono">rounds_used</dt>
          <dd>{lineage?.rounds_used ?? "not recorded"}</dd>
        </div>
        <div>
          <dt className="mono">model</dt>
          <dd className="mono">{lineage?.model ?? "not recorded"}</dd>
        </div>
        <div>
          <dt className="mono">prompt_version</dt>
          <dd className="mono">{lineage?.prompt_version ?? "not recorded"}</dd>
        </div>
        <div>
          <dt className="mono">ledger_ids</dt>
          <dd className="mono">{lineage?.ledger_ids?.length ? JSON.stringify(lineage.ledger_ids) : "none"}</dd>
        </div>
      </dl>

      <h3>Accepted backtest</h3>
      {backtest ? (
        <dl className="args">
          <div>
            <dt className="mono">codes</dt>
            <dd className="mono">{JSON.stringify(backtest.codes ?? null)}</dd>
          </div>
          <div>
            <dt className="mono">target_matches</dt>
            <dd>
              {Array.isArray(backtest.target_matched) ? `${backtest.target_matched.length} of ${String(backtest.target_total ?? "?")}` : "not recorded"}
            </dd>
          </div>
          <div>
            <dt className="mono">baseline_count</dt>
            <dd>{String(backtest.baseline_count ?? "not recorded")}</dd>
          </div>
          <div>
            <dt className="mono">group</dt>
            <dd className="mono">{typeof backtest.group === "string" ? backtest.group : "not recorded"}</dd>
          </div>
        </dl>
      ) : <p>No accepted backtest recorded.</p>}
      {Array.isArray(backtest?.target_matched) && (backtest.target_matched as unknown[]).length ? (
        <details>
          <summary>Matched target events (text only)</summary>
          <pre className="payload mono">{JSON.stringify(backtest.target_matched, null, 2)}</pre>
        </details>
      ) : null}

      <h3>Transitions</h3>
      {transitions.length ? (
        <table className="cost" aria-label="Rule transitions">
          <thead><tr><th>From</th><th>To</th><th>Approver</th><th>Reason</th><th>At</th></tr></thead>
          <tbody>
            {transitions.map((t, i) => (
              <tr key={i}>
                <td>{t.from ?? "—"}</td>
                <td><RuleStatusBadge status={t.to ?? ""} /></td>
                <td>{t.approver ?? "—"}</td>
                <td>{t.reason ?? "—"}</td>
                <td className="mono">{t.at ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <p>No transitions recorded.</p>}

      <h3>Fired in</h3>
      {findings.length ? (
        <ul className="plain">
          {findings.map((f) => (
            <li key={f.incident_id}>
              <a href={buildDetailHash(f.incident_id)}>Incident {f.incident_id}{f.incident_title ? ` — ${f.incident_title}` : ""}</a>
              {typeof f.findings === "number" ? <> · {f.findings} finding{f.findings === 1 ? "" : "s"}</> : null}
            </li>
          ))}
        </ul>
      ) : <p>This rule has not fired in any incident.</p>}
    </article>
  );
}

export function HealthStrip({ health, error }: { health: Health | null; error?: string | null }) {
  if (error) return <p role="alert">Health: unavailable — {error}</p>;
  if (!health) return <p className="health muted">Health: loading…</p>;
  const o = health.self_observation ?? {};
  const fmt = (v: unknown) => (v === undefined || v === null ? "not measured" : String(v));
  const latency = o.latest_model_latency_ms;
  const latencyModel = o.latest_model_latency_model;
  const latencyText =
    latency === undefined || latency === null || latency === "not measured"
      ? "Latest model latency: not measured"
      : `Latest model latency (model ${fmt(latencyModel)}): ${fmt(latency)} ms`;
  return (
    <p className="health" aria-label="System health">
      Status: <strong>{health.status}</strong> · {latencyText} · Model error rate: {fmt(o.model_error_rate)} · Spend today: {fmt(o.spend_today_usd)} / cap {fmt(o.spend_cap_usd)} USD · Queue depth: {fmt(o.queue_depth)}
    </p>
  );
}

export function VerdictBadge({
  verdict, aiStatus,
}: { verdict?: string | null; aiStatus: string }) {
  const kind = verdictKind(verdict, aiStatus);
  if (kind === "verdict") {
    return <span className={`badge verdict-${verdict}`}>{verdict}</span>;
  }
  if (kind === "triaged") return <span className="badge triaged">triaged</span>;
  return <span className="badge pending">pending</span>;
}

export function FilterBar({
  filters, onChange,
}: {
  filters: ListFilters;
  onChange: (next: ListFilters) => void;
}) {
  return (
    <form
      className="filterbar"
      aria-label="Incident filters"
      onSubmit={(e) => e.preventDefault()}
    >
      <label>
        Floor at least
        <select
          aria-label="Floor at least"
          value={filters.minFloor === null ? "" : String(filters.minFloor)}
          onChange={(e) => {
            const v = e.target.value;
            onChange({ ...filters, page: 0, minFloor: v === "" ? null : Number(v) });
          }}
        >
          <option value="">Any</option>
          <option value="1">1+</option>
          <option value="2">2+</option>
          <option value="3">3+</option>
          <option value="4">4+</option>
          <option value="5">5+</option>
          <option value="6">6</option>
        </select>
      </label>
      <label>
        Verdict
        <select
          aria-label="Verdict"
          value={filters.verdict ?? ""}
          onChange={(e) => {
            const v = e.target.value;
            onChange({ ...filters, page: 0, verdict: v === "" ? null : v });
          }}
        >
          <option value="">Any</option>
          <option value="true_positive">true_positive</option>
          <option value="benign_authorized">benign_authorized</option>
          <option value="false_positive">false_positive</option>
          <option value="needs_human">needs_human</option>
        </select>
      </label>
      <label>
        Analyzed
        <select
          aria-label="Analyzed"
          value={filters.analyzed === null ? "" : String(filters.analyzed)}
          onChange={(e) => {
            const v = e.target.value;
            onChange({
              ...filters,
              page: 0,
              analyzed: v === "" ? null : v === "true",
            });
          }}
        >
          <option value="">Any</option>
          <option value="true">Analyzed only</option>
          <option value="false">Not analyzed only</option>
        </select>
      </label>
    </form>
  );
}

export function IncidentList({ items, total, page, setPage, pageSize, onSelect }: {
  items: IncidentListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (!items.length) return <p>No incidents found.</p>;
  const open = useCallback((id: number) => onSelect(id), [onSelect]);
  return (
    <div className="table-wrap">
      <table aria-label="Incidents">
        <thead><tr><th>ID</th><th>Title</th><th>Floor</th><th>Final</th><th>Verdict</th><th>Events</th><th>Injection</th></tr></thead>
        <tbody>
          {items.map((it) => (
            <tr
              key={it.id}
              className="rowlink"
              tabIndex={0}
              onClick={() => open(it.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  open(it.id);
                }
              }}
            >
              <td className="mono">{it.id}</td>
              <td><a className="title-link" href={buildDetailHash(it.id)}>{it.title || `Incident ${it.id}`}</a></td>
              <td><span className={`badge sev-${it.severity_floor}`}>{it.severity_floor} {it.severity_floor_name ?? ""}</span></td>
              <td><span className={`badge sev-${it.severity_id}`}>{it.severity_id} {it.severity_name ?? ""}</span></td>
              <td><VerdictBadge verdict={it.verdict} aiStatus={it.ai_status} /></td>
              <td>{it.event_count}</td>
              <td>{it.has_injection ? <span className="badge injection">injection</span> : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>
        <button type="button" disabled={page <= 0} onClick={() => setPage(page - 1)}>Previous</button>{" "}
        Page {page + 1} of {pages} ({total} total){" "}
        <button type="button" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>Next</button>
      </p>
    </div>
  );
}

const TRACE_RESULT_CAP = 4000;
const TRACE_SUMMARY_CAP = 200;

function oneLineSummary(text: string | null | undefined): string {
  if (!text) return "";
  const first = text.split("\n", 1)[0].replace(/\s+/g, " ").trim();
  return first.length > TRACE_SUMMARY_CAP
    ? `${first.slice(0, TRACE_SUMMARY_CAP)}…`
    : first;
}

function formatArgValue(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function factorStatus(
  factor: unknown,
): { applied: boolean | null; contribution: string } {
  if (typeof factor !== "object" || factor === null) {
    return { applied: null, contribution: String(factor) };
  }
  const o = factor as Record<string, unknown>;
  let applied: boolean | null = null;
  for (const key of ["added_level", "applied", "fired"]) {
    if (typeof o[key] === "boolean") {
      applied = o[key] as boolean;
      break;
    }
  }
  const contribution = typeof o.contribution === "string"
    ? o.contribution
    : formatArgValue(factor);
  return { applied, contribution };
}

export function IncidentView({ detail }: { detail: IncidentDetail }) {
  const analysis = detail.analysis;
  const timeline = analysis?.timeline ?? [];
  const evidenceByUid = new Map((detail.evidence ?? []).map((e) => [e.event_uid, e]));
  const factors = detail.severity?.factors ?? detail.severity_factors ?? {};
  const reasoningText = detail.reasoning_unverified?.text ?? "";
  return (
    <article>
      <h2>{detail.title || `Incident ${detail.id}`}</h2>
      <p>
        <span className={`badge sev-${detail.severity_floor}`}>Floor {detail.severity_floor} {detail.severity_floor_name ?? ""}</span>{" "}
        <span className={`badge sev-${detail.severity_id}`}>Final {detail.severity_id} {detail.severity_name ?? ""}</span>{" "}
        Verdict: <VerdictBadge verdict={analysis?.verdict ?? detail.verdict} aiStatus={detail.ai_status} />
        {analysis?.model ? <> · Model: <span className="mono">{analysis.model}</span></> : null}
        {analysis?.language ? <> · Language: {analysis.language}</> : null}
      </p>
      {detail.pseudonym_resolution ? <p className="muted">{detail.pseudonym_resolution.note} {detail.pseudonym_resolution.resolved ? "(resolved locally)" : ""}</p> : null}
      {detail.triage?.summary ? <section className="panel"><h3>Triage summary</h3><p>{detail.triage.summary}</p></section> : null}
      {detail.learned_rules?.length ? <LearnedRuleRefs refs={detail.learned_rules} /> : null}

      <h3>Timeline (every claim cites an event)</h3>
      {timeline.length ? (
        <ol className="plain">
          {timeline.map((entry, i) => {
            const ev = evidenceByUid.get(entry.event_uid);
            return (
              <li key={`${entry.event_uid}-${i}`}>
                <span className="mono">{entry.time}</span> — {entry.description}{" "}
                <span className="mono">event_uid: {entry.event_uid}</span>
                <details>
                  <summary>Evidence for {entry.event_uid}</summary>
                  {ev?.found ? <pre className="payload">{JSON.stringify(ev.event, null, 2)}</pre> : <p>Missing: no event with this uid in the replay store. This citation could not be verified.</p>}
                </details>
              </li>
            );
          })}
        </ol>
      ) : <p>No timeline recorded.</p>}

      <h3>ATT&amp;CK chain</h3>
      {detail.techniques?.length ? <ul className="plain">{detail.techniques.map((t) => <li key={t.id}><span className="mono">{t.id}</span> — {t.name ?? "name not measured"}</li>)}</ul> : <p>No techniques recorded.</p>}

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
                  <dl className="args">
                    {Object.entries(args).map(([k, v]) => (
                      <div key={k}>
                        <dt className="mono">{k}</dt>
                        <dd className="mono">{formatArgValue(v)}</dd>
                      </div>
                    ))}
                  </dl>
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
      ) : <p>No agent steps recorded.</p>}

      <h3>Model attempts and cost</h3>
      {detail.llm_attempts?.length ? (
        <table className="cost" aria-label="Model attempts and cost">
          <thead><tr><th>Purpose</th><th>Model</th><th>Attempt</th><th>Outcome</th><th>Tokens</th><th>USD</th></tr></thead>
          <tbody>
            {detail.llm_attempts.map((a, i) => (
              <tr key={i}>
                <td>{a.purpose}</td>
                <td className="mono">{a.model}</td>
                <td>{a.attempt_number}</td>
                <td>{a.outcome}{a.failed_validator ? ` (failed validator: ${a.failed_validator})` : ""} · {a.token_source ?? "not measured"}</td>
                <td>{a.tokens}</td>
                <td>{a.usd ?? "not measured"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <p>No model attempts recorded.</p>}
      <p>Spend total for this incident: {detail.spend_total_usd ?? "not measured"} USD</p>

      <h3>Severity factors (floor vs final)</h3>
      <p>Deterministic floor: {detail.severity_floor}. Final severity: {detail.severity_id}. A model may raise the floor by at most one level, citing evidence.</p>
      {Object.keys(factors).length ? (
        <>
          <ul className="plain">
            {Object.entries(factors).map(([name, factor]) => {
              const status = factorStatus(factor);
              return (
                <li key={name}>
                  <span className="mono">{name}</span> —{" "}
                  {status.applied === null ? "not measured" : status.applied ? "applied" : "not applied"}
                  {": "}{status.contribution}
                </li>
              );
            })}
          </ul>
          <details>
            <summary>Raw severity factors (JSON)</summary>
            <pre className="payload">{JSON.stringify(factors, null, 2)}</pre>
          </details>
        </>
      ) : <p>No severity factors recorded.</p>}

      <h3>Injection signals</h3>
      {detail.injection_signals?.length ? (
        <ul className="plain">
          {detail.injection_signals.map((s, i) => (
            <li key={i}>
              <span className="mono">{s.pattern_id}</span> in <span className="mono">{s.field}</span> (event <span className="mono">{s.event_uid}</span>, effect: {s.requested_effect})
              {s.payload_text ? <><p>{s.payload_label ?? "payload (shown as text)"}:</p><pre className="payload">{s.payload_text}</pre></> : null}
            </li>
          ))}
        </ul>
      ) : <p>No injection signals.</p>}

      <h3>Visibility gaps</h3>
      {analysis?.visibility_gaps?.length ? <ul className="plain">{analysis.visibility_gaps.map((g, i) => <li key={i}>{g}</li>)}</ul> : <p>None recorded.</p>}

      <h3>Response plan</h3>
      {analysis?.response_plan?.length ? <ol className="plain">{analysis.response_plan.map((r, i) => <li key={i}>{r}</li>)}</ol> : <p>No response plan recorded.</p>}

      {reasoningText.trim() ? (
        <section>
          <h3>Unverified reasoning</h3>
          <details>
            <summary>Stored on-prem reasoning (not evidence)</summary>
            <pre className="payload">{reasoningText}</pre>
          </details>
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
  const lastListHash = useRef<string>("#/");
  const lastRulesHash = useRef<string>("#/rules");
  const pageSize = 20;

  const go = useCallback((hash: string) => {
    if (window.location.hash !== hash) {
      window.location.hash = hash;
    } else {
      setRoute(parseHash(hash));
    }
  }, []);

  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem("corvus-theme", theme); }, [theme]);
  useEffect(() => { getJson<Health>("/api/health").then(setHealth).catch((e: Error) => setHealthError(e.message)); }, []);

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
      setDetail(null);
      setDetailState("idle");
    } else if (route.view === "detail") {
      if (!isNumericId(route.id)) {
        setDetail(null);
        setDetailState("invalid");
        return;
      }
      setDetailState("loading");
      setDetail(null);
      getJson<IncidentDetail>(`/api/incidents/${route.id}`)
        .then((d) => { setDetail(d); setDetailState("ready"); })
        .catch(() => setDetailState("error"));
    } else if (route.view === "rules") {
      lastRulesHash.current = buildRulesHash(route);
      setRuleListState("loading");
      getJson<{ items: RuleListItem[]; total: number }>(buildRulesQuery(route, pageSize))
        .then((d) => { setRuleItems(d.items); setRuleTotal(d.total); setRuleListState("ready"); })
        .catch(() => setRuleListState("error"));
      setRuleDetail(null);
      setRuleDetailState("idle");
    } else if (route.view === "rule") {
      if (!isNumericId(route.id)) {
        setRuleDetail(null);
        setRuleDetailState("invalid");
        return;
      }
      setRuleDetailState("loading");
      setRuleDetail(null);
      getJson<RuleDetail>(`/api/rules/${route.id}`)
        .then((d) => { setRuleDetail(d); setRuleDetailState("ready"); })
        .catch(() => setRuleDetailState("error"));
    }
  }, [route, pageSize]);

  const setFilters = useCallback((next: ListFilters) => {
    go(buildListHash(next));
  }, [go]);

  const setRuleFilters = useCallback((next: RuleFilters) => {
    go(buildRulesHash(next));
  }, [go]);

  const open = useCallback((id: number) => {
    go(buildDetailHash(id));
  }, [go]);

  const openRule = useCallback((id: number) => {
    go(buildRuleHash(id));
  }, [go]);

  return (
    <div className="wrap">
      <header className="top">
        <div><h1>Corvus</h1><p className="muted">Every claim is verifiable: severity, timeline, trace, and cost cite stored evidence.</p></div>
        <nav aria-label="Sections">
          <a href="#/">Incidents</a>{" · "}<a href="#/rules">Rules</a>
        </nav>
        <button type="button" aria-label="Toggle color theme" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? "Light theme" : "Dark theme"}</button>
      </header>
      <HealthStrip health={health} error={healthError} />
      {route.view === "detail" || route.view === "rule" || route.view === "unknown" ? (
        <main>
          {route.view === "rule" ? (
            <>
              <button type="button" onClick={() => go(lastRulesHash.current)}>Back to rules</button>
              {ruleDetailState === "loading" ? <p>Loading rule…</p>
                : ruleDetailState === "invalid" ? <p role="alert">Invalid rule id: the URL must be #/rules/&lt;number&gt;.</p>
                : ruleDetailState === "error" ? <p role="alert">Could not load this rule. It may not exist.</p>
                : ruleDetail ? <RuleDetailView detail={ruleDetail} /> : null}
            </>
          ) : (
            <>
              <button type="button" onClick={() => go(lastListHash.current)}>Back to incidents</button>
              {route.view === "unknown" ? (
                <p role="alert">Page not found. <a href={lastListHash.current}>Back to incidents</a></p>
              ) : detailState === "loading" ? <p>Loading incident…</p>
                : detailState === "invalid" ? <p role="alert">Invalid incident id: the URL must be #/incidents/&lt;number&gt;.</p>
                : detailState === "error" || detailState === "missing" ? <p role="alert">Could not load this incident. It may not exist.</p>
                : detail ? <IncidentView detail={detail} /> : null}
            </>
          )}
        </main>
      ) : route.view === "rules" ? (
        <main><h2>Learned rules</h2>
          <RulesBanner />
          <RuleFilterBar filters={route} onChange={setRuleFilters} />
          {ruleListState === "loading" ? <p>Loading rules…</p> : ruleListState === "error" ? <p role="alert">Could not load rules. Check that the API and database are running, then reload.</p> : (
            <RulesList
              items={ruleItems}
              total={ruleTotal}
              page={route.page}
              setPage={(n) => setRuleFilters({ ...route, page: n })}
              pageSize={pageSize}
              onSelect={openRule}
            />
          )}
        </main>
      ) : (
        <main><h2>Incidents</h2>
          <FilterBar filters={route} onChange={setFilters} />
          {listState === "loading" ? <p>Loading incidents…</p> : listState === "error" ? <p role="alert">Could not load incidents. Check that the API and database are running, then reload.</p> : (
            <IncidentList
              items={items}
              total={total}
              page={route.page}
              setPage={(n) => setFilters({ ...route, page: n })}
              pageSize={pageSize}
              onSelect={open}
            />
          )}
        </main>
      )}
    </div>
  );
}
