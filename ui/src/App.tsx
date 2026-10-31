import { useCallback, useEffect, useState } from "react";

export type IncidentListItem = {
  id: number; title: string; severity_floor: number; severity_floor_name?: string | null;
  severity_id: number; severity_name?: string | null; ai_status: string; verdict?: string | null;
  first_seen?: string | null; last_seen?: string | null; event_count: number; has_injection: boolean;
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
};
export type Health = { status: string; self_observation?: Record<string, unknown> };

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed (${res.status})`);
  return (await res.json()) as T;
}

export function HealthStrip({ health, error }: { health: Health | null; error?: string | null }) {
  if (error) return <p role="alert">Health: unavailable — {error}</p>;
  if (!health) return <p className="health muted">Health: loading…</p>;
  const o = health.self_observation ?? {};
  const fmt = (v: unknown) => (v === undefined || v === null ? "not measured" : String(v));
  return (
    <p className="health" aria-label="System health">
      Status: <strong>{health.status}</strong> · Latest model latency: {fmt(o.latest_model_latency_ms)} ms · Model error rate: {fmt(o.model_error_rate)} · Spend today: {fmt(o.spend_today_usd)} / cap {fmt(o.spend_cap_usd)} USD · Queue depth: {fmt(o.queue_depth)}
    </p>
  );
}

export function IncidentList({ items, total, page, setPage, pageSize, onSelect }: {
  items: IncidentListItem[]; total: number; page: number; setPage: (n: number) => void; pageSize: number; onSelect: (id: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (!items.length) return <p>No incidents found.</p>;
  return (
    <div>
      <table aria-label="Incidents">
        <thead><tr><th>ID</th><th>Title</th><th>Floor</th><th>Final</th><th>Verdict</th><th>Events</th><th>Injection</th></tr></thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.id}>
              <td className="mono">{it.id}</td>
              <td><button type="button" onClick={() => onSelect(it.id)}>{it.title || `Incident ${it.id}`}</button></td>
              <td><span className={`badge sev-${it.severity_floor}`}>{it.severity_floor} {it.severity_floor_name ?? ""}</span></td>
              <td><span className={`badge sev-${it.severity_id}`}>{it.severity_id} {it.severity_name ?? ""}</span></td>
              <td>{it.verdict ?? it.ai_status}</td>
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

export function IncidentView({ detail }: { detail: IncidentDetail }) {
  const analysis = detail.analysis;
  const timeline = analysis?.timeline ?? [];
  const evidenceByUid = new Map((detail.evidence ?? []).map((e) => [e.event_uid, e]));
  const factors = detail.severity?.factors ?? detail.severity_factors ?? {};
  return (
    <article>
      <h2>{detail.title || `Incident ${detail.id}`}</h2>
      <p>
        <span className={`badge sev-${detail.severity_floor}`}>Floor {detail.severity_floor} {detail.severity_floor_name ?? ""}</span>{" "}
        <span className={`badge sev-${detail.severity_id}`}>Final {detail.severity_id} {detail.severity_name ?? ""}</span>{" "}
        Verdict: <strong>{analysis?.verdict ?? detail.verdict ?? detail.ai_status}</strong>
        {analysis?.model ? <> · Model: <span className="mono">{analysis.model}</span></> : null}
        {analysis?.language ? <> · Language: {analysis.language}</> : null}
      </p>
      {detail.pseudonym_resolution ? <p className="muted">{detail.pseudonym_resolution.note} {detail.pseudonym_resolution.resolved ? "(resolved locally)" : ""}</p> : null}
      {detail.triage?.summary ? <section className="panel"><h3>Triage summary</h3><p>{detail.triage.summary}</p></section> : null}

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
      {detail.agent_trace?.length ? (
        <ol className="trace">
          {detail.agent_trace.map((s) => (
            <li key={s.step}><span className="mono">{s.tool}</span> · arguments: <span className="mono">{JSON.stringify(s.arguments ?? {})}</span> · result: {s.result_summary ?? "—"} · tokens: {s.tokens}</li>
          ))}
        </ol>
      ) : <p>No agent steps recorded.</p>}

      <h3>Model attempts and cost</h3>
      {detail.llm_attempts?.length ? (
        <ul className="plain">
          {detail.llm_attempts.map((a, i) => (
            <li key={i}>{a.purpose} · <span className="mono">{a.model}</span> · attempt {a.attempt_number} · {a.outcome}{a.failed_validator ? ` · failed validator: ${a.failed_validator}` : ""} · tokens: {a.tokens} ({a.token_source ?? "not measured"}) · USD: {a.usd ?? "not measured"}</li>
          ))}
        </ul>
      ) : <p>No model attempts recorded.</p>}
      <p>Spend total for this incident: {detail.spend_total_usd ?? "not measured"} USD</p>

      <h3>Severity factors (floor vs final)</h3>
      <p>Deterministic floor: {detail.severity_floor}. Final severity: {detail.severity_id}. A model may raise the floor by at most one level, citing evidence.</p>
      {Object.keys(factors).length ? <pre className="payload">{JSON.stringify(factors, null, 2)}</pre> : <p>No severity factors recorded.</p>}

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

      {detail.reasoning_unverified ? (
        <details>
          <summary>Unverified reasoning (stored on-prem, not evidence)</summary>
          <pre className="payload">{detail.reasoning_unverified.text}</pre>
        </details>
      ) : null}
    </article>
  );
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("corvus-theme") || "dark");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [items, setItems] = useState<IncidentListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [listState, setListState] = useState<"loading" | "ready" | "error">("loading");
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailState, setDetailState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const pageSize = 20;

  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem("corvus-theme", theme); }, [theme]);
  useEffect(() => { getJson<Health>("/api/health").then(setHealth).catch((e: Error) => setHealthError(e.message)); }, []);
  useEffect(() => {
    setListState("loading");
    getJson<{ items: IncidentListItem[]; total: number }>(`/api/incidents?limit=${pageSize}&offset=${page * pageSize}`)
      .then((d) => { setItems(d.items); setTotal(d.total); setListState("ready"); })
      .catch(() => setListState("error"));
  }, [page]);
  const open = useCallback((id: number) => {
    setSelected(id); setDetailState("loading"); setDetail(null);
    getJson<IncidentDetail>(`/api/incidents/${id}`).then((d) => { setDetail(d); setDetailState("ready"); }).catch(() => setDetailState("error"));
  }, []);

  return (
    <div className="wrap">
      <header className="top">
        <div><h1>Corvus</h1><p className="muted">Every claim is verifiable: severity, timeline, trace, and cost cite stored evidence.</p></div>
        <button type="button" aria-label="Toggle color theme" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? "Light theme" : "Dark theme"}</button>
      </header>
      <HealthStrip health={health} error={healthError} />
      {selected === null ? (
        <main><h2>Incidents</h2>
          {listState === "loading" ? <p>Loading incidents…</p> : listState === "error" ? <p role="alert">Could not load incidents. Check that the API and database are running, then reload.</p> : <IncidentList items={items} total={total} page={page} setPage={setPage} pageSize={pageSize} onSelect={open} />}
        </main>
      ) : (
        <main>
          <button type="button" onClick={() => { setSelected(null); setDetail(null); }}>Back to incidents</button>
          {detailState === "loading" ? <p>Loading incident…</p> : detailState === "error" ? <p role="alert">Could not load this incident.</p> : detail ? <IncidentView detail={detail} /> : null}
        </main>
      )}
    </div>
  );
}
