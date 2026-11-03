#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const src = join(root, "data", "attack", "enterprise.json");
const out = join(here, "..", "src", "lib", "attackMap.ts");
const data = JSON.parse(readFileSync(src, "utf-8"));
const version = data.attack_version;
const order = data.tactic_order;
const tactics = data.tactics;
const techniques = data.techniques;
const tacticOf = {};
const parentOf = {};
for (const id of Object.keys(techniques).sort()) {
  const entry = techniques[id];
  const list = Array.isArray(entry.tactics) ? entry.tactics : [];
  tacticOf[id] = list.length ? list[0] : "other";
  if (entry.parent) parentOf[id] = entry.parent;
}
const body = `export const ATTACK_VERSION = "${version}";
export const TACTIC_ORDER: string[] = ${JSON.stringify(order)};
export const TACTIC_NAMES: Record<string, string> = ${JSON.stringify(
  Object.fromEntries(order.map((s) => [s, tactics[s]?.name ?? s])),
)};
export const TECHNIQUE_TACTIC: Record<string, string> = ${JSON.stringify(tacticOf)};
export const TECHNIQUE_PARENT: Record<string, string> = ${JSON.stringify(parentOf)};
export function tacticForTechnique(id: string): string {
  return TECHNIQUE_TACTIC[id] ?? TECHNIQUE_TACTIC[id.toUpperCase()] ?? "other";
}
export function parentForTechnique(id: string): string | null {
  return TECHNIQUE_PARENT[id] ?? TECHNIQUE_PARENT[id.toUpperCase()] ?? null;
}
`;
writeFileSync(out, body, "utf-8");
console.log(`wrote ${out}: ${Object.keys(tacticOf).length} techniques, ${order.length} tactics, ATT&CK ${version}, ${body.length} bytes`);
