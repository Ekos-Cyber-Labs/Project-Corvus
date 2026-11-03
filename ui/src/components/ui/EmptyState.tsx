import emptyStyles from "./EmptyState.module.css";
export function EmptyState({ title, message }: { title: string; message?: string }) {
  return <div className={`${emptyStyles.emptyRoot} panel`}><h2>{title}</h2>{message ? <p className="muted">{message}</p> : null}</div>;
}
