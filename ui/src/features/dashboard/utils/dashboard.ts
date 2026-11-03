export const SEVERITY_NAMES: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal" };
export const FLOOR_NAMES: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal" };
export function severityName(id: number): string {
  return SEVERITY_NAMES[id] ?? "Unknown";
}
export function floorName(id: number): string {
  return FLOOR_NAMES[id] ?? "Unknown";
}
export function formatMoney(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "not measured";
  return `$${value.toFixed(2)}`;
}
export function formatClock(date: Date | null): string {
  if (!date) return "—";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
}
export function policySentence(policy: Record<string, unknown> | null, cap: number | null): string {
  if (!policy) return "Sweep policy not recorded.";
  const floor = typeof policy.min_floor === "number" ? policy.min_floor : 4;
  const maxN = typeof policy.max_analyses === "number" ? policy.max_analyses : 5;
  const always = policy.always_analyze_injection !== false;
  const capText = cap === null || cap === undefined || !Number.isFinite(cap) ? "not measured" : `$${Number(cap)}`;
  const injection = always ? ", or an injection signal," : "";
  return `Floor ${floorName(floor)} or above${injection} up to ${maxN} analyses per sweep. Spend cap ${capText}.`;
}
export function verdictChip(kind: string): { text: string; className: string } {
  if (kind === "verdict") return { text: "Verdict", className: "dash-verdict-tp" };
  if (kind === "quarantined") return { text: "Quarantined", className: "dash-verdict-quar" };
  if (kind === "failed") return { text: "Failed", className: "dash-verdict-failed" };
  return { text: "Skipped by policy", className: "dash-verdict-skipped" };
}
