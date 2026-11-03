import type { ReactNode } from "react";
import { Sidebar } from "../components/layout/Sidebar";
import shellStyles from "./AppShell.module.css";
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className={shellStyles.shellRoot}>
      <header className={shellStyles.sidebar}>
        <Sidebar />
      </header>
      <div className={shellStyles.main}>
        <div className={shellStyles.content}>{children}</div>
      </div>
    </div>
  );
}
