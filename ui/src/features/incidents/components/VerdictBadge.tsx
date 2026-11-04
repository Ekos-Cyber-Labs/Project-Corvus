import { verdictKind } from "../utils/incidents";
import { Badge } from "../../../components/ui/Badge";
import { useMaskedText } from "../../../lib/presentation";
export function VerdictBadge({ verdict, aiStatus, attempts }: {
  verdict?: string | null; aiStatus: string; attempts?: { purpose: string; outcome: string }[] | null;
}) {
  const kind = verdictKind(verdict, aiStatus, attempts);
  const maskedVerdict = useMaskedText(verdict ?? null);
  if (kind === "verdict") return <Badge className={`verdict-${verdict}`}>{maskedVerdict}</Badge>;
  if (kind === "triaged") return <Badge className="triaged">triaged</Badge>;
  if (kind === "failed") return <Badge className="failed">failed</Badge>;
  if (kind === "quarantined") return <Badge className="quarantined">quarantined</Badge>;
  return <Badge className="pending">pending</Badge>;
}
