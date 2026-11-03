import type { ListFilters } from "../../../lib/hash";
import { FilterChips } from "../../../components/ui/FilterChips";
export function IncidentFilterBar({ filters, onChange }: { filters: ListFilters; onChange: (next: ListFilters) => void }) {
  return (
    <FilterChips label="Incident filters">
      <label>
        Floor at least
        <select aria-label="Floor at least" value={filters.minFloor === null ? "" : String(filters.minFloor)}
          onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, minFloor: v === "" ? null : Number(v) }); }}>
          <option value="">Any</option><option value="1">1+</option><option value="2">2+</option><option value="3">3+</option><option value="4">4+</option><option value="5">5+</option><option value="6">6</option>
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
  );
}