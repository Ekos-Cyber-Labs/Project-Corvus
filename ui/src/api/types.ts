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
