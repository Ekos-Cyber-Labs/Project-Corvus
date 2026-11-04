import { useNavigate } from "react-router";
import { useIncidentDetail } from "../hooks/useIncidentDetail";
import { useMaskedText } from "../../../lib/presentation";
import { TACTIC_NAMES, TACTIC_ORDER, tacticForTechnique } from "../../../lib/attackMap";
import { VerdictBadge } from "./VerdictBadge";
import previewStyles from "./IncidentPreview.module.css";
function gaugeIndex(severityId: number): number {
  if (severityId <= 2) return 1;
  if (severityId === 3) return 2;
  if (severityId === 4) return 3;
  return 4;
}
function gaugeCaption(floor: number, final: number, floorName: string): string {
  if (final === floor + 1) return `Floor ${floorName}, raised one level by the model`;
  if (final === floor) return `Floor ${floorName}, kept by the model`;
  return `Floor ${floorName}, final severity ${final}`;
}
function summaryTwoLines(text: string): string {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  return lines.slice(0, 2).join(" ");
}
export function IncidentPreview({ id }: { id: number }) {
  const navigate = useNavigate();
  const { detail, state } = useIncidentDetail(String(id), 0);
  const maskedTitle = useMaskedText(detail?.title || (detail ? `Incident ${detail.id}` : ""));
  const maskedSummary = useMaskedText(detail ? summaryTwoLines(detail.triage?.summary ?? detail.title) : "");
  const maskedCaption = useMaskedText(detail ? gaugeCaption(detail.severity_floor, detail.severity_id, detail.severity_floor_name ?? String(detail.severity_floor)) : "");
  return (
    <aside className={`panel ${previewStyles.preview}`} aria-label="Incident preview">
      {state === "loading" || !detail ? (
        <div aria-live="polite"><p>Loading preview…</p></div>
      ) : (
        <>
          <p className={previewStyles.top}><span className="mono">{detail.id}</span> <VerdictBadge verdict={detail.analysis?.verdict ?? detail.verdict} aiStatus={detail.ai_status} attempts={detail.llm_attempts} /></p>
          <h2 className={previewStyles.title}>{maskedTitle}</h2>
          <div role="img" aria-label={`Severity gauge: ${maskedCaption}`} className={previewStyles.gauge}>
            {[1, 2, 3, 4].map((n) => {
              const litClass = [previewStyles.segLow, previewStyles.segMedium, previewStyles.segHigh, previewStyles.segCritical][n - 1];
              return <span key={n} aria-hidden="true" className={n <= gaugeIndex(detail.severity_id) ? `${previewStyles.seg} ${litClass}` : previewStyles.seg} />;
            })}
          </div>
          <p className="muted">{maskedCaption}</p>
          <ul className={previewStyles.chain} aria-label="Kill chain">
            {TACTIC_ORDER.map((t) => {
              const hit = (detail.techniques ?? []).some((tech) => tacticForTechnique(tech.id) === t);
              return <li key={t} className={hit ? previewStyles.on : previewStyles.off}>{TACTIC_NAMES[t] ?? t}</li>;
            })}
          </ul>
          <p className={previewStyles.summary}>{maskedSummary}</p>
          <button type="button" className={previewStyles.open} onClick={() => navigate(`/incidents/${detail.id}`)}>Open full analysis</button>
        </>
      )}
    </aside>
  );
}
