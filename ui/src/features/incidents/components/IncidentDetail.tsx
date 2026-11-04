import { useState } from "react";
import { Clock, ChevronDown, TriangleAlert, Monitor, Shield, Check, Sparkles } from "lucide-react";
import type { IncidentDetail } from "../../../api/types";
import { ActivityStrip } from "../../../components/charts/ActivityStrip";
import { KillChain } from "../../../components/charts/KillChain";
import { ConfidenceMeter } from "../../../components/charts/ConfidenceMeter";
import { SeverityGauge } from "../../../components/charts/SeverityGauge";
import { SeverityScale } from "../../../components/charts/SeverityScale";
import { SeverityChip } from "../../../components/charts/SeverityChip";
import { groupTechniques } from "../../../lib/attack";
import { scrollToSection } from "../../../lib/a11y";
import { useMaskFn } from "../../../lib/presentation";
import { agentTraceEmptyMessage, attemptOutcomeKind, attemptOutcomeText } from "../utils/incidents";
import { VerdictBadge } from "./VerdictBadge";
import { LearnedRuleRefs } from "../../rules/components/LearnedRuleRefs";
import detailStyles from "./IncidentDetail.module.css";
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

export function IncidentDetailView({ detail }: { detail: IncidentDetail }) {
  const mask = useMaskFn();
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
    <article className={`detail ${detailStyles.detailRoot}`}>
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
        <h2>{mask(detail.title || `Incident ${detail.id}`)}</h2>
        <p className="hero-badges">
          <VerdictBadge verdict={analysis?.verdict ?? detail.verdict} aiStatus={detail.ai_status} attempts={detail.llm_attempts} />{" "}
          <SeverityChip floor={floor} final={final} />
        </p>
        <SeverityGauge floor={floor} final={final} />
        {typeof analysis?.confidence === "number" ? <ConfidenceMeter value={analysis.confidence} /> : null}
        <p className="hero-facts">
          Models used: <span className="mono">{mask(models.length ? models.join(", ") : "not recorded")}</span>
          {" · "}Language: {mask(analysis?.language ?? "not recorded")}
          {" · "}Time range: <span className="mono">{mask(timeRange)}</span>
        </p>
        <ul className="stat-tiles">
          <li><Monitor /> <strong className="num">{eventCount}</strong><span>events (event_count)</span></li>
          <li><Shield /> <strong className="num">{citedCount}</strong><span>cited events (evidence)</span></li>
          <li><Check /> <strong className="num">{foundCount} of {citedUids.length}</strong><span>evidence found of cited</span></li>
          <li><TriangleAlert /> <strong className="num">{detail.injection_signals?.length ?? 0}</strong><span>injection signals</span></li>
          <li><Sparkles /> <strong className="num">{detail.spend_total_usd ?? "not measured"}</strong><span>spend (USD)</span></li>
        </ul>
        {detail.pseudonym_resolution ? <p className="muted">{mask(detail.pseudonym_resolution.note)} {detail.pseudonym_resolution.resolved ? "(resolved locally)" : ""}</p> : null}
      </section>

      {detail.triage?.summary ? (
        <section className="panel" aria-label="Triage summary">
          <h3><Clock /> Triage summary</h3>
          {triageLong ? (
            <>
              <p className={triageExpanded ? "triage-text expanded" : "triage-text clamped"}>{mask(triageSummary)}</p>
              <button type="button" aria-expanded={triageExpanded} onClick={() => setTriageExpanded((v) => !v)}>
                {triageExpanded ? "Show less" : "Show full summary"} <ChevronDown />
              </button>
            </>
          ) : <p className="triage-text">{mask(triageSummary)}</p>}
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
                  <span className="mono tl-time">{mask(entry.time)}</span>
                  <span className="tl-body">
                    <span className="tl-claim">{mask(entry.description)}</span>{" "}
                    <span className="mono">event_uid: {mask(entry.event_uid)}</span>
                    <details>
                      <summary>Evidence for {mask(entry.event_uid)}</summary>
                      {ev?.found ? <pre className="payload">{mask(JSON.stringify(ev.event, null, 2))}</pre> : <p>Missing: no event with this uid in the replay store. This citation could not be verified.</p>}
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
            <KillChain counts={tacticCounts} selected={selectedTactic} onSelect={setSelectedTactic} />
            {selectedTactic ? <p><button type="button" onClick={() => setSelectedTactic(null)}>Clear tactic filter</button></p> : null}
            {visibleGroups.map((g) => (
              <div key={g.tactic} className="tactic-group">
                <h4>{g.name} ({g.items.length})</h4>
                <ul className="chips-tech">
                  {g.items.map((t) => (
                    <li key={t.id} className="tech-chip" title={mask(`${t.id} — ${t.name ?? "name not measured"}`)}>
                      <span className="mono tech-id">{t.id}</span> <span className="tech-name">{mask(t.name ?? "name not measured")}</span>
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
                  <span className="mono">{mask(s.tool)}</span> · tokens: {s.tokens}
                  {Object.keys(args).length ? (
                    <dl className="args">{Object.entries(args).map(([k, v]) => (<div key={k}><dt className="mono">{mask(k)}</dt><dd className="mono">{mask(formatArgValue(v))}</dd></div>))}</dl>
                  ) : <p className="muted">No arguments.</p>}
                  <p>Result: {mask(oneLineSummary(full) || "—")}</p>
                  <details>
                    <summary>Full result (text only)</summary>
                    <pre className="payload mono">{mask(shown)}</pre>
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
                    <td>{mask(a.purpose)}</td><td className="mono">{mask(a.model)}</td><td className="num">{a.attempt_number}</td>
                    <td><span className={`outcome-dot outcome-${outcomeKind}`} aria-hidden="true" />{mask(a.outcome)}{a.failed_validator ? ` (failed validator: ${mask(a.failed_validator)})` : ""} · {mask(a.token_source ?? "not measured")}<span className="sr-only"> Outcome: {mask(outcomeText)}</span></td>
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
                return <li key={name}><span className="mono">{mask(name)}</span> — {status.applied === null ? "not measured" : status.applied ? "applied" : "not applied"}{": "}{mask(status.contribution)}</li>;
              })}
            </ul>
            <details><summary>Raw severity factors (JSON)</summary><pre className="payload">{mask(JSON.stringify(factors, null, 2))}</pre></details>
          </>
        ) : <p>No severity factors recorded.</p>}
      </section>

      <section aria-label="Injection signals">
        <h3>Injection signals</h3>
        {detail.injection_signals?.length ? (
          <div className="inj-cards">
            {detail.injection_signals.map((s, i) => (
              <article key={i} className="inj-card">
                <p><TriangleAlert /> <strong>Injection signal</strong> · <span className="mono">{mask(s.pattern_id)}</span> in <span className="mono">{mask(s.field)}</span> (event <span className="mono">{mask(s.event_uid)}</span>, effect: {mask(s.requested_effect)})</p>
                {s.payload_text ? <><p>{mask(s.payload_label ?? "payload (shown as text)")}: </p><pre className="payload mono">{mask(s.payload_text)}</pre></> : null}
              </article>
            ))}
          </div>
        ) : <p>No injection signals.</p>}
      </section>

      <section id="section-gaps" aria-label="Visibility gaps">
        <h3>Visibility gaps</h3>
        {analysis?.visibility_gaps?.length ? <ul className="plain">{analysis.visibility_gaps.map((g, i) => <li key={i}>{mask(g)}</li>)}</ul> : <p>None recorded.</p>}
      </section>

      <section id="section-response" aria-label="Response plan">
        <h3>Response plan</h3>
        {analysis?.response_plan?.length ? (
          <ol className="response-plan">{analysis.response_plan.map((r, i) => <li key={i}><span className="resp-num" aria-hidden="true">{i + 1}</span><span>{mask(r)}</span></li>)}</ol>
        ) : <p>No response plan recorded.</p>}
      </section>

      {reasoningText.trim() ? (
        <section>
          <h3>Unverified reasoning</h3>
          <details><summary>Stored on-prem reasoning (not evidence)</summary><pre className="payload">{mask(reasoningText)}</pre></details>
        </section>
      ) : null}
    </article>
  );
}
