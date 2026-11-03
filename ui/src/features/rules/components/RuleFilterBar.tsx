import type { RuleFilters } from "../../../lib/hash";
import { FilterChips } from "../../../components/ui/FilterChips";
export function RuleFilterBar({ filters, onChange }: { filters: RuleFilters; onChange: (next: RuleFilters) => void }) {
  return (
    <FilterChips label="Rule filters">
      <label>
        Status
        <select aria-label="Status" value={filters.status ?? ""} onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, status: v === "" ? null : v }); }}>
          <option value="">Any</option>
          <option value="candidate">candidate</option>
          <option value="shadow">shadow</option>
          <option value="active">active</option>
          <option value="archived">archived</option>
          <option value="rolled_back">rolled_back</option>
        </select>
      </label>
      <label>
        Mode
        <select aria-label="Mode" value={filters.mode ?? ""} onChange={(e) => { const v = e.target.value; onChange({ ...filters, page: 0, mode: v === "" ? null : v }); }}>
          <option value="">Any</option>
          <option value="shadow">shadow</option>
          <option value="active">active</option>
        </select>
      </label>
    </FilterChips>
  );
}
