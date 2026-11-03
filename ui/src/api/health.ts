import { getJson } from "./client";
import type { Health } from "./types";
export function fetchHealth(signal?: AbortSignal): Promise<Health> {
  return getJson("/api/health", signal);
}
