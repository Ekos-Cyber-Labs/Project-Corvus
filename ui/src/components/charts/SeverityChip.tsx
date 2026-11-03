import chipStyles from "./SeverityChip.module.css";
export const SEV_NAMES: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Critical+" };
export function sevLabel(n: number): string { return `${n} ${SEV_NAMES[n] ?? ""}`.trim(); }
export function SeverityChip({ floor, final }: { floor: number; final: number }) {
  if (floor === final) return <span className={`${chipStyles.chipRoot} badge sev-${final}`}>{sevLabel(final)}</span>;
  return <span className={`${chipStyles.chipRoot} badge sev-${final}`}>{sevLabel(floor)} <span aria-hidden="true">→</span><span className="sr-only">to</span> {sevLabel(final)}</span>;
}
