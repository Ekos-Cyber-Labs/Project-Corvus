import type { ReactNode } from "react";
import badgeStyles from "./Badge.module.css";
export function Badge({ className, children, title }: { className: string; children: ReactNode; title?: string }) {
  return <span className={`${badgeStyles.badgeRoot} badge ${className}`} title={title}>{children}</span>;
}
