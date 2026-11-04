import { useState } from "react";
import { Copy } from "lucide-react";
import type { RuleDetail } from "../../../api/types";
import { buildDetailHash } from "../../../lib/hash";
import { useMaskFn } from "../../../lib/presentation";
import { BacktestBars, backtestFigures } from "../../../components/charts/BacktestBars";
import { backtestCodesText, ruleAltersAlertsText } from "../utils/rules";
import { RuleStatusBadge } from "./RuleStatusBadge";
import { RuleModeBadge } from "./RuleModeBadge";
import detailStyles from "./RuleDetail.module.css";
export function RuleDetailView({ detail }: { detail: RuleDetail }) {
  const mask = useMaskFn();
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
      await clipboard.writeText(mask(detail.sigma_text));
      setCopied(true);
    } catch { setCopied(false); }
  };
  const lastTransition = transitions.length ? transitions[transitions.length - 1] : null;
  const figures = backtestFigures(backtest);
  const nativeId = detail.wazuh?.native_rule_id ?? null;
  const showMode = detail.mode != null && detail.mode !== detail.status;
  return (
    <article className={`detail rule-detail ${detailStyles.detailRoot}`}>
      <section className="panel hero" aria-label="Rule summary">
        <h2>{mask(detail.title || `Rule ${detail.id}`)}</h2>
        <p className="hero-badges">
          <RuleStatusBadge status={detail.status} />{showMode ? <> <RuleModeBadge mode={detail.mode} /></> : null} <span className={`mono ${detailStyles.nowrap}`}>v{detail.version}</span>
          {detail.level ? <> · Level: {detail.level}</> : null}
          {detail.techniques?.length ? <> · Techniques: <span className="mono">{detail.techniques.join(", ")}</span></> : null}
        </p>
        <p className="does-line">{ruleAltersAlertsText(detail)}</p>
      </section>
      {detail.status === "shadow" || detail.mode === "shadow" ? <p className={detailStyles.shadow} role="note">Shadow mode. This rule is evaluated and logged only. It never changes an alert until a human promotes it.</p> : null}
      <section className="panel" aria-label="Backtest">
        <h3>Backtest</h3>
        {backtest ? (
          <>
            <ul className={detailStyles.bigNums}>
              <li><strong className="num">{figures.matched ?? "not recorded"}</strong><span>Target events matched (n={figures.targetTotal ?? "not recorded"})</span></li>
              <li><strong className="num">{figures.baselineCount ?? "not recorded"}</strong><span>Benign baseline matches (n={figures.baselineTotal ?? "not recorded"})</span></li>
              <li><strong className="num">{detail.false_positives}</strong><span>False positives</span></li>
            </ul>
            <div className="table-wrap"><table className="cost backtest-table" aria-label="Backtest numbers">
              <thead><tr><th>Figure</th><th>Matches</th><th>n</th></tr></thead>
              <tbody>
                <tr><td>Target events matched</td><td className="num">{figures.matched ?? "not recorded"}</td><td className="num">{figures.targetTotal ?? "not recorded"}</td></tr>
                <tr><td>Benign baseline matches</td><td className="num">{figures.baselineCount ?? "not recorded"}</td><td className="num">{figures.baselineTotal ?? "not recorded"}</td></tr>
                <tr><td>Codes</td><td className="mono" colSpan={2}>{mask(backtestCodesText(backtest))}</td></tr>
                <tr><td>Group</td><td className="mono" colSpan={2}>{mask(typeof backtest.group === "string" ? backtest.group : "not recorded")}</td></tr>
                {typeof backtest.sigma_sha256 === "string" ? <tr><td className="mono">sigma_sha256</td><td className="mono" colSpan={2}>{mask(backtest.sigma_sha256)}</td></tr> : null}
              </tbody>
            </table></div>
            <BacktestBars backtest={backtest} />
          </>
        ) : <p>No accepted backtest recorded.</p>}
        {Array.isArray(backtest?.target_matched) && (backtest.target_matched as unknown[]).length ? (
          <details><summary>Matched target events (text only)</summary><pre className="payload mono">{mask(JSON.stringify(backtest.target_matched, null, 2))}</pre></details>
        ) : null}
      </section>
      <section className="panel" aria-label="Sigma rule">
        <h3>Sigma rule (text only)</h3>
        <p><button type="button" onClick={copySigma}><Copy /> {copied ? "Copied" : "Copy"}</button></p>
        <pre className="payload sigma"><code>{mask(detail.sigma_text)}</code></pre>
      </section>
      <section className="panel" aria-label="Lineage">
        <h3>Lineage</h3>
        {lineage?.lineage_note ? <p className="muted">{mask(lineage.lineage_note)}</p> : null}
        <dl className="args lineage-grid">
          <div><dt>Source incident</dt><dd>{source === null || source === undefined ? "none recorded" : source.exists ? (<a href={buildDetailHash(source.id)}>Incident {source.id}{source.title ? ` — ${mask(source.title)}` : ""}</a>) : (<>Incident {source.id} (deleted)</>)}</dd></div>
          <div><dt>Cited event uids</dt><dd className="mono">{cited.length ? mask(cited.join(", ")) : "none"}</dd></div>
          <div><dt>Accepted backtest</dt><dd>{backtest ? <span className="mono">{mask(backtestCodesText(backtest))}</span> : "none recorded"}</dd></div>
          <div><dt>Rounds used</dt><dd className="num">{lineage?.rounds_used ?? "not recorded"}</dd></div>
          <div><dt>Model</dt><dd className="mono">{mask(lineage?.model ?? "not recorded")}</dd></div>
          <div><dt>Prompt version</dt><dd className="mono">{mask(lineage?.prompt_version ?? "not recorded")}</dd></div>
          <div><dt className="mono">ledger_ids</dt><dd className="mono">{lineage?.ledger_ids?.length ? mask(JSON.stringify(lineage.ledger_ids)) : "none"}</dd></div>
          {lineage?.sigma_rule_id ? <div><dt className="mono">sigma_rule_id</dt><dd className="mono">{mask(lineage.sigma_rule_id)}</dd></div> : null}
          {nativeId != null ? <div><dt>Native rule id</dt><dd className="mono nowrap">{nativeId}</dd></div> : null}
          {detail.wazuh?.native_rule_ids?.length && detail.wazuh.native_rule_ids.length > 1 ? <div><dt>Native rule ids</dt><dd className="mono">{detail.wazuh.native_rule_ids.join(", ")}</dd></div> : null}
          {detail.wazuh?.group ? <div><dt>Group</dt><dd className="mono">{detail.wazuh.group}</dd></div> : null}
          <div><dt>Last transition approver</dt><dd>{mask(lastTransition?.approver ?? "not recorded")}</dd></div>
          <div><dt>Last transition date</dt><dd className="mono nowrap">{mask(lastTransition?.at ?? "not recorded")}</dd></div>
          <div><dt>Hits</dt><dd className="num">{detail.hits}</dd></div>
          <div><dt>False positives</dt><dd className="num">{detail.false_positives}</dd></div>
          {detail.created_at ? <div><dt>Created</dt><dd className="mono nowrap">{detail.created_at}</dd></div> : null}
          {detail.updated_at ? <div><dt>Updated</dt><dd className="mono nowrap">{detail.updated_at}</dd></div> : null}
          {detail.deployed_at ? <div><dt>Deployed</dt><dd className="mono nowrap">{detail.deployed_at}</dd></div> : null}
          {detail.source_incident_id != null ? <div><dt>Source incident id</dt><dd className="mono nowrap">{detail.source_incident_id}</dd></div> : null}
        </dl>
        {detail.wazuh?.pair_note ? <p className="muted">{mask(detail.wazuh.pair_note)}</p> : null}
      </section>
      <section className="panel" aria-label="Lifecycle history">
        <h3>Lifecycle history</h3>
        {transitions.length ? (
          <ol className={detailStyles.timeline}>
            {transitions.map((t, i) => (
              <li key={i} className={detailStyles.tlItem}>
                <span className={detailStyles.dot} aria-hidden="true" />
                <div>
                  <p className={detailStyles.tlHead}><RuleStatusBadge status={t.to ?? ""} /> <span className="mono nowrap">{t.at ?? "—"}</span></p>
                  <p className={detailStyles.tlMeta}><span>{t.from ?? "—"} → {t.to ?? "—"}</span> · Approver: <span>{mask(t.approver ?? "—")}</span> · Reason: <span>{mask(t.reason ?? "—")}</span></p>
                </div>
              </li>
            ))}
          </ol>
        ) : <p>No transitions recorded.</p>}
      </section>
      <section className="panel" aria-label="Fired in">
        <h3>Fired in</h3>
        {findings.length ? (
          <ul className="plain">{findings.map((f) => (<li key={f.incident_id}><a href={buildDetailHash(f.incident_id)}>Incident {f.incident_id}{f.incident_title ? ` — ${mask(f.incident_title)}` : ""}</a>{typeof f.findings === "number" ? <> · {f.findings} finding{f.findings === 1 ? "" : "s"}</> : null}</li>))}
          </ul>
        ) : <p>This rule has not fired in any incident.</p>}
      </section>
    </article>
  );
}
