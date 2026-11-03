import type { IncidentDetail, IncidentListItem, RuleDetail, RuleListItem } from "../api/types";
export const HOSTILE_PAYLOAD = "<img src=x onerror=alert(1)>";
export const baseIncidentItem: IncidentListItem = {
  id: 1, title: "t", severity_floor: 3, severity_id: 3,
  ai_status: "done", event_count: 1, has_injection: false,
};
export const baseIncidentDetail: IncidentDetail = {
  id: 4, title: "t", severity_floor: 4, severity_id: 4, ai_status: "done", verdict: "true_positive",
};
export const baseRuleItem: RuleListItem = {
  id: 9, title: "rule", status: "shadow", mode: "shadow", version: 2, level: "medium", techniques: ["T1059"], hits: 3, false_positives: 1, created_at: "2026-10-30T12:00:00Z", source_incident_id: 4,
};
export const baseRuleDetail: RuleDetail = {
  ...baseRuleItem, sigma_text: "title: rule", lineage: { source_incident: null, cited_uids: [], backtest: null, ledger_ids: [] }, transitions: [], findings: [],
};
