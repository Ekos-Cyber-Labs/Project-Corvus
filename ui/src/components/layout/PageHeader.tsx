import type { ReactNode } from "react";
import headerStyles from "./PageHeader.module.css";
export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return <div className={headerStyles.headerRoot}><h2>{title}</h2>{children}</div>;
}
