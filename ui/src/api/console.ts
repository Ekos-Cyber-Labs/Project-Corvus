import { getJson } from "./client";
import type { Dashboard, SettingsView, SweepStatus } from "./types";
export function fetchDashboard(signal?: AbortSignal): Promise<Dashboard> {
  return getJson<Dashboard>("/api/dashboard", signal);
}
export function fetchSweepStatus(signal?: AbortSignal): Promise<SweepStatus> {
  return getJson<SweepStatus>("/api/sweep/status", signal);
}
export function fetchSettings(signal?: AbortSignal): Promise<SettingsView> {
  return getJson<SettingsView>("/api/settings", signal);
}
