import type { ReactNode } from "react";
import tableStyles from "./Table.module.css";
export function Table({ className, label, children }: { className?: string; label: string; children: ReactNode }) {
  return <div className="table-wrap"><table className={className ? `${tableStyles.tableRoot} ${className}` : tableStyles.tableRoot} aria-label={label}>{children}</table></div>;
}
