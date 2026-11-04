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
export const VERDICT_LABELS: Record<string, string> = {
  true_positive: "True positive",
  benign_authorized: "Benign",
  false_positive: "False positive",
  needs_human: "Needs human",
  quarantined: "Quarantined",
  failed: "Failed",
  triaged: "Triaged",
  pending: "Pending",
};
export function verdictLabel(kind: string | null | undefined): string {
  if (!kind) return "Pending";
  return VERDICT_LABELS[kind] ?? kind;
}
export function recentChip(row: { verdict?: string | null; verdict_kind: string }): { text: string; className: string } {
  if (typeof row.verdict === "string" && VERDICT_LABELS[row.verdict]) return verdictChip(row.verdict);
  return verdictChip(row.verdict_kind);
}
export function verdictChip(kind: string): { text: string; className: string } {
  if (kind === "true_positive" || kind === "verdict") return { text: kind === "verdict" ? "Verdict" : "True positive", className: "dash-verdict-tp" };
  if (kind === "benign_authorized" || kind === "false_positive") return { text: kind === "benign_authorized" ? "Benign" : "False positive", className: "dash-verdict-benign" };
  if (kind === "needs_human") return { text: "Needs human", className: "dash-verdict-quar" };
  if (kind === "quarantined") return { text: "Quarantined", className: "dash-verdict-quar" };
  if (kind === "failed") return { text: "Failed", className: "dash-verdict-failed" };
  if (kind === "triaged") return { text: "Triaged", className: "dash-verdict-skipped" };
  if (kind === "pending") return { text: "Pending", className: "dash-verdict-skipped" };
  return { text: kind, className: "dash-verdict-skipped" };
}
