import { RULE_MODES } from "../../../lib/hash";
import { Badge } from "../../../components/ui/Badge";
import { useMaskedText } from "../../../lib/presentation";
export function RuleModeBadge({ mode }: { mode: string | null | undefined }) {
  const masked = useMaskedText(mode ?? "not deployed");
  if (mode === null || mode === undefined) return <Badge className="mode-none">{masked}</Badge>;
  if (!RULE_MODES.has(mode)) return <Badge className="mode-unknown">{masked}</Badge>;
  return <Badge className={`mode-${mode}`}>{masked}</Badge>;
}
