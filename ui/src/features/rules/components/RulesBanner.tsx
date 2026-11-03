import { Card } from "../../../components/ui/Card";
export function RulesBanner() {
  return (
    <Card className="banner banner-compact" label="About shadow mode">
      <p><strong>Shadow mode:</strong> shadow rules never change alerts — matching events keep their existing alerts and gain the <span className="mono">corvus_shadow</span> tag for review. Learning here means stored detection rules only — no model weights are updated.</p>
    </Card>
  );
}
