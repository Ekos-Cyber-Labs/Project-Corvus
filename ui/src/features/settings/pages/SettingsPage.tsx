import { useEffect, useState } from "react";
import { useSettingsPage } from "../hooks/useSettingsPage";
import { useMaskFn, usePresentation, useTheme } from "../../../app/providers";
import type { ThemeChoice } from "../../../app/providers";
import { PageHeader } from "../../../components/layout/PageHeader";
import { Skeleton } from "../../../components/ui/Skeleton";
import { ErrorState } from "../../../components/ui/ErrorState";
import { FLOOR_NAMES } from "../../dashboard/utils/dashboard";
import pageStyles from "./SettingsPage.module.css";
const CONNECTION_LABELS: Record<string, { title: string; note?: string }> = {
  database: { title: "Database" },
  wazuh_indexer: { title: "Wazuh indexer" },
  triage_model: { title: "Triage model (on-prem)" },
  reasoning_model: { title: "Reasoning model (cloud, pseudonymized input only)" },
};
function connectionClass(state: string): string {
  if (state === "connected") return pageStyles.connected;
  if (state === "unreachable") return pageStyles.unreachable;
  return pageStyles.unknown;
}
function connectionText(state: string): string {
  if (state === "connected") return "Connected";
  if (state === "unreachable") return "Unreachable";
  return "Not configured";
}
export function SettingsPage() {
  const { settings, sweep, state, retry } = useSettingsPage();
  const { choice, setTheme } = useTheme();
  const { enabled: presentation, setEnabled: setPresentation } = usePresentation();
  const mask = useMaskFn();
  const [reduceMotion, setReduceMotion] = useState<boolean>(() => {
    try { return localStorage.getItem("corvus-reduce-motion") === "true"; } catch { return false; }
  });
  useEffect(() => {
    try {
      document.documentElement.classList.toggle("reduce-motion", reduceMotion);
      localStorage.setItem("corvus-reduce-motion", String(reduceMotion));
    } catch { }
  }, [reduceMotion]);
  return (
    <main className={pageStyles.page}>
      <PageHeader title="Settings" subtitle="Sweep policy, connections and display. Secrets are never shown." />
      {state === "loading" ? <div aria-live="polite"><p>Loading settings…</p><Skeleton /></div>
        : state === "error" || !settings ? <ErrorState message="Could not load settings. Check that the API and database are running, then reload." onRetry={retry} />
        : (
          <>
            <section className="panel" aria-label="Automatic sweep">
              <h2>Automatic sweep</h2>
              <p>
                <span className={sweep?.running ? pageStyles.dotRun : sweep?.last ? pageStyles.dotPause : pageStyles.dotNone} aria-hidden="true" />
                {sweep?.running ? "Running" : sweep?.last ? "Paused" : "Not detected"}
              </p>
              <dl className={pageStyles.defList}>
                <div><dt>Poll interval</dt><dd>{typeof settings.sweep_policy.policy?.interval_seconds === "number" ? `${settings.sweep_policy.policy.interval_seconds} s` : "not recorded"}</dd></div>
                <div><dt>Analyze when floor is at least</dt><dd title={typeof settings.sweep_policy.policy?.min_floor === "number" ? String(settings.sweep_policy.policy.min_floor) : undefined}>{typeof settings.sweep_policy.policy?.min_floor === "number" ? (FLOOR_NAMES[settings.sweep_policy.policy.min_floor] ?? settings.sweep_policy.policy.min_floor) : "not recorded"}</dd></div>
                <div><dt>Max analyses per sweep</dt><dd>{typeof settings.sweep_policy.policy?.max_analyses === "number" ? settings.sweep_policy.policy.max_analyses : "not recorded"}</dd></div>
                <div><dt>Spend cap</dt><dd>{typeof settings.spend_cap_usd === "number" ? `$${settings.spend_cap_usd}` : "not measured"}</dd></div>
                <div><dt>Injection signals always analyzed</dt><dd>{settings.sweep_policy.policy?.always_analyze_injection !== false ? "Yes" : "No"}</dd></div>
              </dl>
              <p className="muted">Set with corvus sweep flags or SWEEP_* environment variables</p>
              <p className="muted">Anything below the threshold stays pending and can be analyzed by hand. When the spend cap is reached the sweep keeps collecting but stops analyzing.</p>
            </section>
            <section className="panel" aria-label="Connections">
              <h2>Connections</h2>
              <ul className={pageStyles.conns}>
                {settings.connections.map((c) => (
                  <li key={c.name}>
                    <span>{CONNECTION_LABELS[c.name]?.title ?? c.name} <span className="mono muted" title={mask(`payload name: ${c.name}`)}>{mask(c.name)}</span></span>
                    <span className="mono">{c.address ? mask(c.address) : "—"}</span>
                    <span className={connectionClass(c.state)}>{connectionText(c.state)}</span>
                  </li>
                ))}
              </ul>
            </section>
            <section className="panel" aria-label="Display">
              <h2>Display</h2>
              <div role="group" aria-label="Theme" className={pageStyles.seg}>
                {(["dark", "light", "system"] as ThemeChoice[]).map((t) => (
                  <button key={t} type="button" aria-pressed={choice === t} onClick={() => setTheme(t)}>{t === "dark" ? "Dark" : t === "light" ? "Light" : "System"}</button>
                ))}
              </div>
              <p><label><input type="checkbox" checked={reduceMotion} onChange={(e) => setReduceMotion(e.target.checked)} /> Reduce motion</label></p>
              <p><label><input type="checkbox" checked={presentation} onChange={(e) => setPresentation(e.target.checked)} /> Presentation mode: mask public IP addresses</label></p>
            </section>
            <section className="panel" aria-label="Privacy">
              <h2>Privacy</h2>
              <p>Incidents are pseudonymized on-prem before any reasoning-model call; raw events never leave the on-prem path.</p>
              <p>Shadow rules never change alerts. Model text is rendered as plain text.</p>
            </section>
          </>
        )}
    </main>
  );
}
