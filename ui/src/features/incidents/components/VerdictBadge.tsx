import { statusLabel, verdictKind } from "../utils/incidents";
import { Badge } from "../../../components/ui/Badge";
import { useMaskFn } from "../../../lib/presentation";
export function VerdictBadge({ verdict, aiStatus, attempts, quarantined }: {
  verdict?: string | null; aiStatus: string; attempts?: { purpose: string; outcome: string }[] | null;
  quarantined?: boolean | null;
}) {
  const kind = verdictKind(verdict, aiStatus, attempts, quarantined);
  const mask = useMaskFn();
  if (kind === "verdict") return <Badge className={`verdict-${verdict}`} title={mask(verdict ?? "verdict")}>{statusLabel(verdict ?? "", "True positive")}</Badge>;
  if (kind === "triaged") return <Badge className="triaged" title={mask("triaged")}>Triaged</Badge>;
  if (kind === "failed") return <Badge className="failed" title={mask("failed")}>Failed</Badge>;
  if (kind === "quarantined") return <Badge className="quarantined" title={mask("quarantined")}>Quarantined</Badge>;
  return <Badge className="pending" title={mask("pending")}>Pending</Badge>;
}
