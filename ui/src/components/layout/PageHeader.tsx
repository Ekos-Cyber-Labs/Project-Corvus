import type { ReactNode } from "react";
import headerStyles from "./PageHeader.module.css";
export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  return (
    <div className={headerStyles.headerRoot}>
      <div className={headerStyles.text}>
        <h1>{title}</h1>
        {subtitle ? <p className={headerStyles.subtitle}>{subtitle}</p> : null}
      </div>
      {children ? <div className={headerStyles.actions}>{children}</div> : null}
    </div>
  );
}
