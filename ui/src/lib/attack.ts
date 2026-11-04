import { TACTIC_NAMES, TACTIC_ORDER, parentForTechnique, tacticForTechnique } from "./attackMap";
export function groupTechniques(techniques: { id: string; name?: string | null }[]): { tactic: string; name: string; items: { id: string; name?: string | null }[] }[] {
  const byTactic = new Map<string, { id: string; name?: string | null }[]>();
  for (const t of techniques) {
    const tactic = tacticForTechnique(t.id);
    const list = byTactic.get(tactic) ?? [];
    list.push(t);
    byTactic.set(tactic, list);
  }
  const order = [...TACTIC_ORDER, "other"];
  const groups: { tactic: string; name: string; items: { id: string; name?: string | null }[] }[] = [];
  for (const tactic of order) {
    const items = byTactic.get(tactic);
    if (!items?.length) continue;
    const sorted = [...items].sort((a, b) => {
      const ka = parentForTechnique(a.id) ?? a.id;
      const kb = parentForTechnique(b.id) ?? b.id;
      return ka.localeCompare(kb) || a.id.localeCompare(b.id);
    });
    groups.push({ tactic, name: tactic === "other" ? "Other" : (TACTIC_NAMES[tactic] ?? tactic), items: sorted });
  }
  return groups;
}
