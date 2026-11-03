import type { ReactNode } from "react";
import badgeStyles from "./Badge.module.css";
export function Badge({ className, children }: { className: string; children: ReactNode }) {
  return <span className={`${badgeStyles.badgeRoot} badge ${className}`}>{children}</span>;
}
