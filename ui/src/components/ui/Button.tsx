import type { ButtonHTMLAttributes } from "react";
import buttonStyles from "./Button.module.css";
export function Button(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  const { className, type, ...rest } = props;
  return <button type={type ?? "button"} className={className ? `${buttonStyles.buttonRoot} ${className}` : buttonStyles.buttonRoot} {...rest} />;
}
