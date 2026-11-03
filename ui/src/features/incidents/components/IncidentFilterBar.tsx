import { Search } from "lucide-react";
import type { ListFilters } from "../../../lib/hash";
import { FilterChips } from "../../../components/ui/FilterChips";
import filterStyles from "./IncidentFilterBar.module.css";
export type ChipKey = "all" | "analyzed" | "pending" | "quarantined";
export function chipForFilters(filters: ListFilters): ChipKey {
  if (filters.quarantined === true) return "quarantined";
  if (filters.analyzed === true) return "analyzed";
  if (filters.analyzed === false) return "pending";
  return "all";
}
export function IncidentFilterBar({ filters, onChange }: { filters: ListFilters; onChange: (next: ListFilters) => void }) {
  const chip = chipForFilters(filters);
  const pick = (key: ChipKey) => {
    if (key === "all") onChange({ ...filters, page: 0, analyzed: null, quarantined: null });
    else if (key === "analyzed") onChange({ ...filters, page: 0, analyzed: true, quarantined: null });
    else if (key === "pending") onChange({ ...filters, page: 0, analyzed: false, quarantined: null });
    else onChange({ ...filters, page: 0, analyzed: null, quarantined: true });
  };
  return (
    <div className={filterStyles.wrap}>
      <div className={filterStyles.searchRow}>
        <Search size={18} aria-hidden="true" />
        <input
          type="search"
          aria-label="Search incidents"
          placeholder="Search title, host or technique"
          value={filters.q ?? ""}
          onChange={(e) => onChange({ ...filters, page: 0, q: e.target.value === "" ? null : e.target.value.slice(0, 200) })}
        />
      </div>
      <div role="group" aria-label="Quick filters" className={filterStyles.chips}>
        {(["all", "analyzed", "pending", "quarantined"] as ChipKey[]).map((key) => (
          <button key={key} type="button" aria-pressed={chip === key} onClick={() => pick(key)} className={chip === key ? filterStyles.active : undefined}>
            {key === "all" ? "All" : key === "analyzed" ? "Analyzed" : key === "pending" ? "Pending" : "Quarantined"}
          </button>
        ))}
      </div>
      <FilterChips label="Incident filters">
        <label>
          Floor at least
          <select aria-label="Floor at least" value={filters.minFloor === null ? "" : String(filters.minFloor)}
            onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, minFloor: v === "" ? null : Number(v) }); }}>
            <option value="">Any</option><option value="1">1+</option><option value="2">2+</option><option value="3">3+</option><option value="4">4+</option><option value="5">5+</option><option value="6">6</option>
          </select>
        </label>
        <label>
          Severity
          <select aria-label="Severity" value={filters.minFloor === null ? "" : String(filters.minFloor)}
            onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, minFloor: v === "" ? null : Number(v) }); }}>
            <option value="">Any</option><option value="2">Low+</option><option value="3">Medium+</option><option value="4">High+</option><option value="5">Critical</option>
          </select>
        </label>
        <label>
          Verdict
          <select aria-label="Verdict" value={filters.verdict ?? ""}
            onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, verdict: v === "" ? null : v }); }}>
            <option value="">Any</option><option value="true_positive">true_positive</option><option value="benign_authorized">benign_authorized</option><option value="false_positive">false_positive</option><option value="needs_human">needs_human</option>
          </select>
        </label>
        <label>
          Analyzed
          <select aria-label="Analyzed" value={filters.analyzed === null ? "" : String(filters.analyzed)}
            onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, analyzed: v === "" ? null : v === "true" }); }}>
            <option value="">Any</option><option value="true">Analyzed only</option><option value="false">Not analyzed only</option>
          </select>
        </label>
      </FilterChips>
    </div>
  );
}
