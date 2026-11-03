import { describe, expect, it } from "vitest";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { readdirSync, readFileSync, statSync } from "node:fs";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { join } from "node:path";
// @ts-ignore: node core types are intentionally not installed (no new deps)
declare const process: { cwd(): string };
function sources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sources(full, out);
    else if (/\.(tsx|ts|css)$/.test(entry) && !/\.test\.(tsx|ts)$/.test(entry)) out.push(full);
  }
  return out;
}
describe("no raw HTML injection surface", () => {
  it("uses no innerHTML or dangerouslySetInnerHTML anywhere in ui/src", () => {
    const root = join(process.cwd(), "src");
    const offenders: string[] = [];
    for (const file of sources(root)) {
      const text = readFileSync(file, "utf-8");
      if (text.includes("innerHTML") || text.includes("dangerouslySetInnerHTML")) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
