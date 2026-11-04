import type { ReactNode } from "react";
import { useMaskedText } from "../../lib/presentation";
import headerStyles from "./PageHeader.module.css";
export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  const maskedTitle = useMaskedText(title);
  const maskedSubtitle = useMaskedText(subtitle ?? null);
  return (
    <div className={headerStyles.headerRoot}>
      <div className={headerStyles.text}>
        <h1>{maskedTitle}</h1>
        {subtitle ? <p className={headerStyles.subtitle}>{maskedSubtitle}</p> : null}
      </div>
      {children ? <div className={headerStyles.actions}>{children}</div> : null}
    </div>
  );
}
