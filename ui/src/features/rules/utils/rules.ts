import type { RuleDetail, RuleListItem } from "../../../api/types";
const STATUS_WORDS: Record<string, string> = { shadow: "shadow", candidate: "candidate", active: "active", archived: "archived", rolled_back: "rolled back" };
export function ruleStatusWord(status: string): string {
  return STATUS_WORDS[status] ?? status;
}
export function ruleCountLine(items: RuleListItem[], total: number): string {
  const count = (s: string) => items.filter((it) => it.status === s).length;
  const parts = ["shadow", "candidate", "active", "archived", "rolled_back"].map((s) => {
    const n = count(s);
    return `${n} ${ruleStatusWord(s)}${n === 1 ? " rule" : " rules"}`;
  });
  const scope = items.length < total ? ` (status counts from this page, n=${items.length})` : "";
  const noun = total === 1 ? "rule" : "rules";
  return `${total} ${noun}: ${parts.join(", ")}${scope}`;
}
export function ruleAltersAlertsText(detail: Pick<RuleDetail, "status" | "mode">): string {
  if (detail.mode === "shadow" || detail.status === "shadow") return "What this rule does: shadow — it does not alter alerts. Matching events keep their existing alerts and gain the corvus_shadow tag for review.";
  if (detail.mode === "active" || detail.status === "active") return "What this rule does: active — deployed active, so matching events can raise an alert; it alters alerts.";
  if (detail.status === "candidate") return "What this rule does: candidate — not deployed, so it does not alter alerts.";
  if (detail.status === "archived" || detail.status === "rolled_back") return `What this rule does: ${detail.status} — not deployed, so it does not alter alerts.`;
  return "What this rule does: not deployed, so it does not alter alerts.";
}
export function backtestCodesText(backtest: Record<string, unknown> | null | undefined): string {
  if (!backtest) return "none recorded";
  const codes = backtest.codes;
  if (typeof codes === "string") return codes.trim() ? codes : "no codes recorded";
  if (Array.isArray(codes)) {
    const parts = codes.map((c) => String(c)).filter((c) => c.trim());
    return parts.length ? parts.join(", ") : "no codes recorded";
  }
  return "no codes recorded";
}
