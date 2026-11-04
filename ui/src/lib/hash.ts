export const REAL_VERDICTS = new Set(["true_positive", "benign_authorized", "false_positive", "needs_human"]);
export type ListFilters = { page: number; minFloor: number | null; verdict: string | null; analyzed: boolean | null; q: string | null; quarantined: boolean | null };
export type Route =
  | { view: "list" } & ListFilters
  | { view: "detail"; id: string }
  | { view: "rules" } & RuleFilters
  | { view: "rule"; id: string }
  | { view: "unknown" };
export const RULE_STATUSES = new Set(["candidate", "shadow", "active", "archived", "rolled_back"]);
export const RULE_MODES = new Set(["shadow", "active"]);
export type RuleFilters = { page: number; status: string | null; mode: string | null };
function parseNonNegativeInt(raw: string | null): number {
  if (raw === null || raw === "") return 0;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : 0;
}
function parseMinFloor(raw: string | null): number | null {
  if (raw === null || raw === "") return null;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 6 ? n : null;
}
export function parseHash(hash: string): Route {
  const h = hash.startsWith("#") ? hash.slice(1) : hash;
  let pathPart = h;
  let queryPart = "";
  const q = h.indexOf("?");
  if (q >= 0) { pathPart = h.slice(0, q); queryPart = h.slice(q + 1); }
  if (pathPart === "/incidents") {
    const params = new URLSearchParams(queryPart);
    const verdictRaw = params.get("verdict");
    const analyzedRaw = params.get("analyzed");
    const qRaw = params.get("q");
    const quarRaw = params.get("quarantined");
    return {
      view: "list", page: parseNonNegativeInt(params.get("page")),
      minFloor: parseMinFloor(params.get("min_floor")),
      verdict: verdictRaw !== null && REAL_VERDICTS.has(verdictRaw) ? verdictRaw : null,
      analyzed: analyzedRaw === "true" ? true : analyzedRaw === "false" ? false : null,
      q: qRaw !== null && qRaw !== "" ? qRaw.slice(0, 200) : null,
      quarantined: quarRaw === "true" ? true : null,
    };
  }
  const match = /^\/incidents\/([^/]+)$/.exec(pathPart);
  if (match) {
    let id = match[1];
    try { id = decodeURIComponent(id); } catch { id = ""; }
    return { view: "detail", id };
  }
  if (pathPart === "/rules") {
    const params = new URLSearchParams(queryPart);
    const statusRaw = params.get("status");
    const modeRaw = params.get("mode");
    return {
      view: "rules", page: parseNonNegativeInt(params.get("page")),
      status: statusRaw !== null && RULE_STATUSES.has(statusRaw) ? statusRaw : null,
      mode: modeRaw !== null && RULE_MODES.has(modeRaw) ? modeRaw : null,
    };
  }
  const ruleMatch = /^\/rules\/([^/]+)$/.exec(pathPart);
  if (ruleMatch) {
    let id = ruleMatch[1];
    try { id = decodeURIComponent(id); } catch { id = ""; }
    return { view: "rule", id };
  }
  return { view: "unknown" };
}
export function isNumericId(id: string): boolean { return /^\d+$/.test(id); }
export function buildListHash(filters: ListFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.minFloor !== null) params.set("min_floor", String(filters.minFloor));
  if (filters.verdict !== null) params.set("verdict", filters.verdict);
  if (filters.analyzed !== null) params.set("analyzed", String(filters.analyzed));
  if (filters.q !== null && filters.q !== "") params.set("q", filters.q);
  if (filters.quarantined === true) params.set("quarantined", "true");
  const query = params.toString();
  return query ? `#/incidents?${query}` : "#/incidents";
}
export function buildDetailHash(id: number): string { return `#/incidents/${id}`; }
export function buildRulesHash(filters: RuleFilters): string {
  const params = new URLSearchParams();
  if (filters.page > 0) params.set("page", String(filters.page));
  if (filters.status !== null) params.set("status", filters.status);
  if (filters.mode !== null) params.set("mode", filters.mode);
  const query = params.toString();
  return query ? `#/rules?${query}` : "#/rules";
}
export function buildRuleHash(id: number): string { return `#/rules/${id}`; }
