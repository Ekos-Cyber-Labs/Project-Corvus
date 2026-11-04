import { useEffect, useRef, useState } from "react";
import type { RefObject } from "react";

export function useContainerWidth<T extends HTMLElement = HTMLDivElement>(fallback = 720): [RefObject<T | null>, number] {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const measure = (next?: number) => {
      const measured = typeof next === "number" && Number.isFinite(next) && next > 0 ? next : el.getBoundingClientRect().width;
      if (Number.isFinite(measured) && measured > 0) setWidth(measured);
    };
    measure();
    let observer: ResizeObserver;
    try {
      observer = new ResizeObserver((entries) => {
        const entry = entries[0];
        measure(entry?.contentRect?.width);
      });
    } catch {
      return;
    }
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}
