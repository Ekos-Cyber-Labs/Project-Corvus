import { RULE_STATUSES } from "../../../lib/hash";
import { Badge } from "../../../components/ui/Badge";
export function RuleStatusBadge({ status }: { status: string }) {
  if (!RULE_STATUSES.has(status)) return <Badge className="rule-unknown">{status || "unknown"}</Badge>;
  return <Badge className={`rule-${status}`}>{status}</Badge>;
}
