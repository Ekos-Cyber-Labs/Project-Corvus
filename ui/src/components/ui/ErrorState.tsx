import errorStyles from "./ErrorState.module.css";
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <p role="alert" className={errorStyles.errorRoot}>{message} {onRetry ? <button type="button" onClick={onRetry}>Retry</button> : null}</p>;
}
