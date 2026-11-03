import { getJson } from "./client";
import type { RuleDetail, RuleListItem } from "./types";
import type { RuleFilters } from "../lib/hash";
export function buildRulesQuery(filters: RuleFilters, pageSize: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(pageSize));
  params.set("offset", String(filters.page * pageSize));
  if (filters.status !== null) params.set("status", filters.status);
  if (filters.mode !== null) params.set("mode", filters.mode);
  return `/api/rules?${params.toString()}`;
}
export function fetchRules(filters: RuleFilters, pageSize: number, signal?: AbortSignal): Promise<{ items: RuleListItem[]; total: number }> {
  return getJson(buildRulesQuery(filters, pageSize), signal);
}
export function fetchRule(id: string, signal?: AbortSignal): Promise<RuleDetail> {
  return getJson(`/api/rules/${id}`, signal);
}
