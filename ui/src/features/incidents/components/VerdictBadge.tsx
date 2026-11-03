import { verdictKind } from "../utils/incidents";
import { Badge } from "../../../components/ui/Badge";
export function VerdictBadge({ verdict, aiStatus, attempts }: {
  verdict?: string | null; aiStatus: string; attempts?: { purpose: string; outcome: string }[] | null;
}) {
  const kind = verdictKind(verdict, aiStatus, attempts);
  if (kind === "verdict") return <Badge className={`verdict-${verdict}`}>{verdict}</Badge>;
  if (kind === "triaged") return <Badge className="triaged">triaged</Badge>;
  if (kind === "failed") return <Badge className="failed">failed</Badge>;
  if (kind === "quarantined") return <Badge className="quarantined">quarantined</Badge>;
  return <Badge className="pending">pending</Badge>;
}
