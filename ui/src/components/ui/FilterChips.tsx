import type { ReactNode } from "react";
import filterStyles from "./FilterChips.module.css";
export function FilterChips({ label, children }: { label: string; children: ReactNode }) {
  return <form className={`${filterStyles.filterRoot} filterbar`} aria-label={label} onSubmit={(e) => e.preventDefault()}>{children}</form>;
}
