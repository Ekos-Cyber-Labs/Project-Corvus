import { RULE_STATUSES } from "../../../lib/hash";
import { Badge } from "../../../components/ui/Badge";
import { useMaskedText } from "../../../lib/presentation";
export function RuleStatusBadge({ status }: { status: string }) {
  const masked = useMaskedText(status || "unknown");
  if (!RULE_STATUSES.has(status)) return <Badge className="rule-unknown">{masked}</Badge>;
  return <Badge className={`rule-${status}`}>{masked}</Badge>;
}
