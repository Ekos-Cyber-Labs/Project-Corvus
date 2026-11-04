import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { maskPublicIps } from "./maskPublicIps";

export const PRESENTATION_STORAGE_KEY = "corvus-presentation";

type PresentationValue = { enabled: boolean; setEnabled: (next: boolean) => void };

const PresentationContext = createContext<PresentationValue>({ enabled: false, setEnabled: () => undefined });

function readStored(): boolean {
  try {
    return localStorage.getItem(PRESENTATION_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function PresentationProvider({ children }: { children: ReactNode }) {
  const [enabled, setEnabledState] = useState<boolean>(readStored);
  const [params] = useSearchParams();
  const present = params.get("present");
  useEffect(() => {
    if (present === "1") setEnabledState(true);
    else if (present === "0") setEnabledState(false);
  }, [present]);
  useEffect(() => {
    try {
      localStorage.setItem(PRESENTATION_STORAGE_KEY, String(enabled));
    } catch {
      return;
    }
  }, [enabled]);
  const setEnabled = useCallback((next: boolean) => setEnabledState(next), []);
  const value = useMemo(() => ({ enabled, setEnabled }), [enabled, setEnabled]);
  return <PresentationContext.Provider value={value}>{children}</PresentationContext.Provider>;
}

export function usePresentation(): PresentationValue {
  return useContext(PresentationContext);
}

export function maskForPresentation(enabled: boolean, value: string | null | undefined): string {
  if (value === null || value === undefined) return "";
  return enabled ? maskPublicIps(value) : value;
}

export function useMaskedText(value: string | null | undefined): string {
  const { enabled } = usePresentation();
  return useMemo(() => maskForPresentation(enabled, value), [enabled, value]);
}

export function useMaskFn(): (value: string | null | undefined) => string {
  const { enabled } = usePresentation();
  return useCallback((value: string | null | undefined) => maskForPresentation(enabled, value), [enabled]);
}

export function MaskedText({ text, title, label, className }: {
  text: string | null | undefined; title?: string; label?: string; className?: string;
}) {
  const { enabled } = usePresentation();
  const masked = useMemo(() => maskForPresentation(enabled, text), [enabled, text]);
  const maskedTitle = useMemo(
    () => (title === undefined ? undefined : maskForPresentation(enabled, title)),
    [enabled, title],
  );
  const maskedLabel = useMemo(
    () => (label === undefined ? undefined : maskForPresentation(enabled, label)),
    [enabled, label],
  );
  if (title === undefined && label === undefined && className === undefined) return <>{masked}</>;
  return <span className={className} title={maskedTitle} aria-label={maskedLabel}>{masked}</span>;
}
