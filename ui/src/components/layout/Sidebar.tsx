import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { LayoutDashboard, ScrollText, Settings, Shield } from "lucide-react";
import { getJson } from "../../api/client";
import { useMaskFn, usePresentation } from "../../app/providers";
import { formatTime } from "../../lib/formatDateTime";
import sidebarStyles from "./Sidebar.module.css";
function usePendingHighCritical(): number | null {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    getJson<{ total: number }>("/api/incidents?min_floor=4&analyzed=false&limit=1", controller.signal)
      .then((d) => { if (!controller.signal.aborted) setCount(d.total); })
      .catch(() => { if (!controller.signal.aborted) setCount(null); });
    return () => controller.abort();
  }, []);
  return count;
}
function useSweepCountdown(): { label: string; seconds: number | null; lastStartedAt: string | null } {
  const [nextAt, setNextAt] = useState<string | null>(null);
  const [running, setRunning] = useState<boolean | null>(null);
  const [lastStartedAt, setLastStartedAt] = useState<string | null>(null);
  const [, setTick] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    getJson<{ running: boolean; next_run_at: string | null; last: { status: string; started_at: string | null } | null }>("/api/sweep/status", controller.signal)
      .then((d) => {
        if (controller.signal.aborted) return;
        setRunning(d.running === true || d.last?.status === "running");
        setNextAt(d.next_run_at);
        setLastStartedAt(d.last?.started_at ?? null);
      })
      .catch(() => { if (!controller.signal.aborted) { setRunning(null); setNextAt(null); setLastStartedAt(null); } });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (nextAt === null) return;
    const timer = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(timer);
  }, [nextAt]);
  if (running === null && nextAt === null) return { label: "No sweep running", seconds: null, lastStartedAt };
  const label = running ? "Sweep running" : nextAt ? "Sweep paused" : "No sweep running";
  if (!nextAt) return { label, seconds: null, lastStartedAt };
  const ms = Date.parse(nextAt) - Date.now();
  const seconds = ms > 0 ? Math.floor(ms / 1000) : 0;
  return { label, seconds, lastStartedAt };
}
export function Sidebar() {
  const location = useLocation();
  const path = location.pathname;
  const isDashboard = path === "/dashboard" || path === "/";
  const isIncidents = path === "/incidents" || path.startsWith("/incidents/");
  const isRules = path === "/rules" || path.startsWith("/rules/");
  const isSettings = path === "/settings";
  const pendingHigh = usePendingHighCritical();
  const sweep = useSweepCountdown();
  const mask = useMaskFn();
  const { enabled: presentation } = usePresentation();
  const nextText = sweep.seconds === null ? null : `${Math.floor(sweep.seconds / 60)}:${String(sweep.seconds % 60).padStart(2, "0")}`;
  const pillLabel = typeof pendingHigh === "number" ? `${pendingHigh} incidents High or Critical pending analysis` : null;
  return (
    <div className={sidebarStyles.sidebarRoot}>
      <div className={sidebarStyles.brand}>
        <svg width="26" height="26" viewBox="0 0 26 26" role="img" aria-label="Corvus bird mark">
          <path d="M3 15 C6 9 11 5 19 4 C15 8 13 10 12 12 L21 12 L14 16 L18 21 L11 17 C8 18 5 17 3 15 Z" fill="currentColor" />
          <circle cx="15.5" cy="8.5" r="1.3" style={{ fill: "var(--sidebar)" }} />
        </svg>
        <div>
          <p className={sidebarStyles.word}>Corvus</p>
          <p className={sidebarStyles.caption}>SOC analyst</p>
        </div>
      </div>
      <nav aria-label="Sections" className={sidebarStyles.nav}>
        <Link to="/dashboard" aria-current={isDashboard ? "page" : undefined}><LayoutDashboard size={18} /> Dashboard</Link>
        <Link to="/incidents" aria-current={isIncidents ? "page" : undefined}><Shield size={18} /> Incidents{typeof pendingHigh === "number" && pendingHigh > 0 && pillLabel ? <span className={sidebarStyles.pill} role="img" title={pillLabel} aria-label={pillLabel}>{pendingHigh}</span> : null}</Link>
        <Link to="/rules" aria-current={isRules ? "page" : undefined}><ScrollText size={18} /> Rules</Link>
        <Link to="/settings" aria-current={isSettings ? "page" : undefined}><Settings size={18} /> Settings</Link>
      </nav>
      {presentation ? <p className={sidebarStyles.presentBadge} role="status">Presentation mode</p> : null}
      <div className={sidebarStyles.sweepBox} aria-live="polite">
        <p className={sidebarStyles.sweepRow}><span className={sidebarStyles.sweepDot} aria-hidden="true" />{sweep.label}</p>
        {nextText !== null ? <p className={sidebarStyles.sweepNext}>Next in {nextText}</p> : null}
        {nextText === null && sweep.lastStartedAt ? <p className={sidebarStyles.sweepNext} title={mask(sweep.lastStartedAt)}>Last sweep {formatTime(sweep.lastStartedAt)}</p> : null}
      </div>
    </div>
  );
}
