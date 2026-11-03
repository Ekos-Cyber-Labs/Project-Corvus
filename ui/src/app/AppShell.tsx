import { useEffect, useState, type ReactNode } from "react";
import { fetchHealth } from "../api/health";
import type { Health } from "../api/types";
import { Sidebar } from "../components/layout/Sidebar";
import { HealthStrip } from "../components/layout/StatusPill";
import { useTheme } from "./providers";
import shellStyles from "./AppShell.module.css";
export function AppShell({ children }: { children: ReactNode }) {
  const { theme, toggleTheme } = useTheme();
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    fetchHealth(controller.signal).then((value) => { if (!controller.signal.aborted) setHealth(value); }).catch((e: Error) => { if (!controller.signal.aborted) setHealthError(e.message); });
    return () => controller.abort();
  }, []);
  return (
    <div className={`shell ${shellStyles.shellRoot}`}>
      <header className="shell-sidebar">
        <Sidebar theme={theme} onToggleTheme={toggleTheme} />
      </header>
      <div className="shell-main">
        <div className="shell-content">
          <HealthStrip health={health} error={healthError} />
          {children}
        </div>
      </div>
    </div>
  );
}
