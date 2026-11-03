import { useState } from "react";
import { Copy } from "lucide-react";
import type { RuleDetail } from "../../../api/types";
import { buildDetailHash } from "../../../lib/hash";
import { LifecycleStepper } from "../../../components/charts/LifecycleStepper";
import { BacktestBars, backtestFigures } from "../../../components/charts/BacktestBars";
import { backtestCodesText, ruleAltersAlertsText } from "../utils/rules";
import { RuleStatusBadge } from "./RuleStatusBadge";
import { RuleModeBadge } from "./RuleModeBadge";
import detailStyles from "./RuleDetail.module.css";
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
    <article className={`detail rule-detail ${detailStyles.detailRoot}`}>
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
        <p><button type="button" onClick={copySigma}><Copy /> {copied ? "Copied" : "Copy"}</button></p>
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
