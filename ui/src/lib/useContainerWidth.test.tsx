import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { useContainerWidth } from "./useContainerWidth";

function Probe() {
  const [ref, width] = useContainerWidth<HTMLDivElement>(720);
  return <div ref={ref} data-testid="probe">{Math.round(width)}</div>;
}

describe("useContainerWidth", () => {
  afterEach(() => {
    delete (globalThis as Record<string, unknown>).ResizeObserver;
  });

  it("falls back to 720 when ResizeObserver is not available", () => {
    delete (globalThis as Record<string, unknown>).ResizeObserver;
    render(<Probe />);
    expect(screen.getByTestId("probe").textContent).toBe("720");
  });

  it("updates from a fake ResizeObserver and stops after unmount", () => {
    let callback: ((entries: { contentRect: { width: number } }[]) => void) | null = null;
    let disconnected = false;
    class FakeResizeObserver {
      constructor(cb: (entries: { contentRect: { width: number } }[]) => void) {
        callback = cb;
      }
      observe() {}
      disconnect() {
        disconnected = true;
      }
    }
    (globalThis as Record<string, unknown>).ResizeObserver = FakeResizeObserver;
    const { unmount } = render(<Probe />);
    expect(screen.getByTestId("probe").textContent).toBe("720");
    act(() => callback?.([{ contentRect: { width: 900 } }]));
    expect(screen.getByTestId("probe").textContent).toBe("900");
    act(() => callback?.([{ contentRect: { width: 1800 } }]));
    expect(screen.getByTestId("probe").textContent).toBe("1800");
    unmount();
    expect(disconnected).toBe(true);
  });
});
