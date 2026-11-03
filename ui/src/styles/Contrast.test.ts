import { describe, expect, it } from "vitest";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { readFileSync, readdirSync, statSync } from "node:fs";
// @ts-ignore: node core types are intentionally not installed (no new deps)
import { join } from "node:path";
// @ts-ignore: node core types are intentionally not installed (no new deps)
declare const process: { cwd(): string };
function luminance(hex: string): number {
  const c = hex.replace("#", "");
  const full = c.length === 3 ? c.split("").map((ch) => ch + ch).join("") : c;
  const f = (i: number) => {
    const v = Number.parseInt(full.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(0) + 0.7152 * f(2) + 0.0722 * f(4);
}
function ratio(a: string, b: string): number {
  const hi = Math.max(luminance(a), luminance(b));
  const lo = Math.min(luminance(a), luminance(b));
  return (hi + 0.05) / (lo + 0.05);
}
function themeVars(css: string, name: "dark" | "light"): Record<string, string> {
  const pattern = name === "dark"
    ? /:root,\s*\[data-theme="dark"\]\s*\{([^}]*)\}/
    : /\[data-theme="light"\]\s*\{([^}]*)\}/;
  const block = pattern.exec(css)?.[1] ?? "";
  const vars: Record<string, string> = {};
  for (const m of block.matchAll(/--([\w-]+)\s*:\s*(#[0-9a-fA-F]{6})/g)) vars[m[1]] = m[2];
  return vars;
}
function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir) as string[]) {
    const path = join(dir, name);
    const st = statSync(path) as { isDirectory(): boolean };
    if (st.isDirectory()) out.push(...listFiles(path));
    else out.push(path);
  }
  return out;
}
const TEXT_45: [string, string][] = [
  ["text", "ground"], ["text", "surface"], ["text", "raised"], ["text", "panel2"],
  ["muted", "ground"], ["muted", "surface"], ["muted", "panel"], ["muted", "panel2"],
  ["accent", "ground"], ["accent", "surface"], ["accent-ink", "accent"],
  ["danger", "panel"], ["danger", "panel2"], ["warning", "panel"], ["warning", "panel2"],
  ["low", "panel"], ["low", "panel2"], ["ok", "panel"], ["success", "panel"],
  ["critical", "panel"], ["high", "panel"], ["medium", "panel"],
  ["sev1", "panel2"], ["sev2", "panel2"], ["sev3", "panel2"], ["sev4", "panel2"], ["sev5", "panel2"], ["sev6", "panel2"],
];
const SHELL_PAIRS: [string, string, string][] = [
  ["brand word", "text", "sidebar"],
  ["caption", "muted", "sidebar"],
  ["nav label", "text", "sidebar"],
  ["nav label on nav-active", "text", "nav-active"],
  ["active nav label", "accent", "nav-active"],
  ["count pill", "danger", "tint-danger"],
  ["sweep box text", "text", "sidebar"],
  ["sweep box muted", "muted", "sidebar"],
  ["selected row text", "text", "row-selected"],
  ["chip accent text", "accent", "tint-accent"],
  ["chip danger text", "danger", "tint-danger"],
  ["chip warning text", "warning", "tint-warning"],
  ["chip low text", "low", "tint-low"],
  ["chip text on tint-accent", "text", "tint-accent"],
  ["banner text on tint-warning", "text", "tint-warning"],
];
const NON_TEXT_3: [string, string][] = [
  ["accent-dim", "panel"], ["accent", "panel2"],
];
describe("console color contrast", () => {
  it("holds text contrast in both themes and marks in both themes", () => {
    const css = readFileSync(join(process.cwd(), "src", "styles", "tokens.css"), "utf-8");
    const dark = themeVars(css, "dark");
    const light = themeVars(css, "light");
    const failures: string[] = [];
    for (const theme of [{ name: "dark", vars: dark }, { name: "light", vars: light }] as const) {
      for (const [fg, bg] of TEXT_45) {
        const f = theme.vars[fg];
        const b = theme.vars[bg];
        if (!f || !b) { failures.push(`${theme.name} ${fg}/${bg} missing`); continue; }
        const r = ratio(f, b);
        if (r < 4.5) failures.push(`${theme.name} ${fg} on ${bg}: ${r.toFixed(2)}`);
      }
      for (const [fg, bg] of NON_TEXT_3) {
        const f = theme.vars[fg];
        const b = theme.vars[bg];
        if (!f || !b) { failures.push(`${theme.name} ${fg}/${bg} missing`); continue; }
        const r = ratio(f, b);
        if (r < 3) failures.push(`${theme.name} mark ${fg} on ${bg}: ${r.toFixed(2)}`);
      }
    }
    expect(failures).toEqual([]);
  });
  it("keeps every shell pair at 4.5 to 1 in both themes from tokens only", () => {
    const css = readFileSync(join(process.cwd(), "src", "styles", "tokens.css"), "utf-8");
    const dark = themeVars(css, "dark");
    const light = themeVars(css, "light");
    const failures: string[] = [];
    for (const theme of [{ name: "dark", vars: dark }, { name: "light", vars: light }] as const) {
      for (const [label, fg, bg] of SHELL_PAIRS) {
        const f = theme.vars[fg];
        const b = theme.vars[bg];
        if (!f || !b) { failures.push(`${theme.name} ${label}: ${fg} on ${bg} is not a token`); continue; }
        const r = ratio(f, b);
        if (r < 4.5) failures.push(`${theme.name} ${label} ${fg} on ${bg}: ${r.toFixed(2)}`);
      }
    }
    expect(failures).toEqual([]);
  });
  it("has no hex or rgba color outside tokens.css", () => {
    const root = join(process.cwd(), "src");
    const offenders: string[] = [];
    for (const path of listFiles(root)) {
      if (path.endsWith("tokens.css")) continue;
      if (path.includes(".test.")) continue;
      if (!/\.(css|ts|tsx)$/.test(path)) continue;
      const text = readFileSync(path, "utf-8");
      if (/#[0-9a-fA-F]{3,8}\b/.test(text) || /rgba?\(/.test(text)) offenders.push(path);
    }
    expect(offenders).toEqual([]);
  });
});
