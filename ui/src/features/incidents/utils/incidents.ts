import { REAL_VERDICTS } from "../../../lib/hash";
import type { IncidentDetail, IncidentListItem } from "../../../api/types";
export const STATUS_LABELS: Record<string, string> = {
  true_positive: "True positive",
  benign_authorized: "Benign",
  false_positive: "False positive",
  needs_human: "Needs human",
  quarantined: "Quarantined",
  failed: "Failed",
  triaged: "Triaged",
  pending: "Pending",
};
export function statusLabel(kind: string, raw?: string | null): string {
  return STATUS_LABELS[kind] ?? raw ?? kind;
}
export function listQuarantined(it: Pick<IncidentListItem, "quarantined" | "has_injection">): boolean {
  if (it.quarantined === true) return true;
  if (it.quarantined === false) return false;
  return it.has_injection;
}
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
  quarantinedFlag?: boolean | null,
): "verdict" | "triaged" | "failed" | "quarantined" | "pending" {
  if (verdict !== null && verdict !== undefined && REAL_VERDICTS.has(verdict)) return "verdict";
  if (quarantinedFlag === true || hasQuarantinedTriage(attempts)) return "quarantined";
  if (aiStatus === "failed") return "failed";
  if (aiStatus === "done") return "triaged";
  return "pending";
}
export function agentTraceEmptyMessage(detail: IncidentDetail): string {
  const attempts = detail.llm_attempts ?? [];
  if ((!detail.agent_trace || detail.agent_trace.length === 0) && attempts.length === 1) {
    return "This incident was analyzed in a single model call without the tool loop";
  }
  return "No agent steps recorded";
}
