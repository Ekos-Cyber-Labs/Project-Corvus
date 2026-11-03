import spinnerStyles from "./Spinner.module.css";
export function Spinner({ label }: { label: string }) {
  return <span className={spinnerStyles.spinnerRoot} role="status" aria-label={label} />;
}
