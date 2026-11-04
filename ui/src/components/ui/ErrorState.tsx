import { useMaskedText } from "../../lib/presentation";
import errorStyles from "./ErrorState.module.css";
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const masked = useMaskedText(message);
  return <p role="alert" className={errorStyles.errorRoot}>{masked} {onRetry ? <button type="button" onClick={onRetry}>Retry</button> : null}</p>;
}
