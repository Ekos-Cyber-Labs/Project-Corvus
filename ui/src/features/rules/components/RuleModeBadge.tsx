import { RULE_MODES } from "../../../lib/hash";
import { Badge } from "../../../components/ui/Badge";
export function RuleModeBadge({ mode }: { mode: string | null | undefined }) {
  if (mode === null || mode === undefined) return <Badge className="mode-none">not deployed</Badge>;
  if (!RULE_MODES.has(mode)) return <Badge className="mode-unknown">{mode}</Badge>;
  return <Badge className={`mode-${mode}`}>{mode}</Badge>;
}
