import { getJson } from "./client";
import type { IncidentDetail, IncidentListItem } from "./types";
import type { ListFilters } from "../lib/hash";
export function buildListQuery(filters: ListFilters, pageSize: number): string {
  const params = new URLSearchParams();
  params.set("limit", String(pageSize));
  params.set("offset", String(filters.page * pageSize));
  if (filters.minFloor !== null) params.set("min_floor", String(filters.minFloor));
  if (filters.verdict !== null) params.set("verdict", filters.verdict);
  if (filters.analyzed !== null) params.set("analyzed", String(filters.analyzed));
  return `/api/incidents?${params.toString()}`;
}
export function fetchIncidents(filters: ListFilters, pageSize: number, signal?: AbortSignal): Promise<{ items: IncidentListItem[]; total: number }> {
  return getJson(buildListQuery(filters, pageSize), signal);
}
export function fetchIncident(id: string, signal?: AbortSignal): Promise<IncidentDetail> {
  return getJson(`/api/incidents/${id}`, signal);
}
