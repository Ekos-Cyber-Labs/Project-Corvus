import type { ReactNode } from "react";
import cardStyles from "./Card.module.css";
export function Card({ className, children, label }: { className?: string; children: ReactNode; label?: string }) {
  return <section className={className ? `${cardStyles.cardRoot} panel ${className}` : `${cardStyles.cardRoot} panel`} aria-label={label}>{children}</section>;
}
