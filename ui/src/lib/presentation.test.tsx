import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HashRouter } from "react-router";
import { App } from "../app/App";
import { MaskedText, PRESENTATION_STORAGE_KEY, PresentationProvider } from "../app/providers";
import { resetMaskedIpMapping } from "./maskPublicIps";
import type { SettingsView, SweepStatus } from "../api/types";

function settingsView(): SettingsView {
  return {
    sweep_policy: { source: "configured", policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } },
    connections: [{ name: "database", address: "postgresql://127.0.0.1:55432", state: "connected" }],
    spend_cap_usd: 100,
    app_version: "0.1.0",
    attack_version: "v20.0",
    ocsf_version: "1.9.0",
  };
}

function stubSettings() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => settingsView() };
    if (path === "/api/sweep/status") {
      const sweep: SweepStatus = { last: null, running: false, next_run_at: null, policy: null };
      return { ok: true, status: 200, json: async () => sweep };
    }
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}

describe("presentation mode switch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    window.location.hash = "#/";
    localStorage.clear();
    resetMaskedIpMapping();
  });

  it("round-trips the toggle through localStorage and the sidebar badge", async () => {
    stubSettings();
    window.location.hash = "#/settings";
    render(<App />);
    await screen.findByText("Automatic sweep");
    expect(localStorage.getItem(PRESENTATION_STORAGE_KEY)).toBe("false");
    expect(screen.queryByText("Presentation mode")).toBeNull();
    fireEvent.click(screen.getByLabelText("Presentation mode: mask public IP addresses"));
    expect(localStorage.getItem(PRESENTATION_STORAGE_KEY)).toBe("true");
    expect(screen.getByText("Presentation mode")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Presentation mode: mask public IP addresses"));
    expect(localStorage.getItem(PRESENTATION_STORAGE_KEY)).toBe("false");
    expect(screen.queryByText("Presentation mode")).toBeNull();
  });

  it("starts on when stored on and masks a connection address", async () => {
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      const path = url.split("?")[0];
      if (path === "/api/settings") {
        return {
          ok: true, status: 200, json: async () => ({
            ...settingsView(),
            connections: [{ name: "wazuh_indexer", address: "https://203.0.113.10:9200", state: "connected" }],
          }),
        };
      }
      if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: null, running: false, next_run_at: null, policy: null }) };
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
    window.location.hash = "#/settings";
    render(<App />);
    await screen.findByText("Automatic sweep");
    expect(screen.getByText("Presentation mode")).toBeTruthy();
    expect(screen.getByText("https://198.51.100.1:9200")).toBeTruthy();
    expect(screen.queryByText("https://203.0.113.10:9200")).toBeNull();
  });

  it("masks text, title and aria-label through MaskedText only when on", () => {
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "true");
    resetMaskedIpMapping();
    const { container, unmount } = render(
      <HashRouter><PresentationProvider><MaskedText text="call 8.8.8.8 now" title="to 1.1.1.1" label="ring 9.9.9.9" /></PresentationProvider></HashRouter>,
    );
    const span = container.querySelector("span") as HTMLElement;
    expect(span.textContent).toBe("call 198.51.100.1 now");
    expect(span.getAttribute("title")).toBe("to 198.51.100.2");
    expect(span.getAttribute("aria-label")).toBe("ring 198.51.100.3");
    unmount();
    localStorage.setItem(PRESENTATION_STORAGE_KEY, "false");
    const plain = render(
      <HashRouter><PresentationProvider><MaskedText text="call 8.8.8.8 now" /></PresentationProvider></HashRouter>,
    );
    expect(plain.container.querySelector("span")).toBeNull();
    expect(plain.container.textContent).toBe("call 8.8.8.8 now");
    plain.unmount();
  });

  it("turns on and off through the present query on the hash route", async () => {
    stubSettings();
    window.location.hash = "#/settings?present=1";
    const first = render(<App />);
    await screen.findByText("Automatic sweep");
    expect(localStorage.getItem(PRESENTATION_STORAGE_KEY)).toBe("true");
    expect(screen.getByText("Presentation mode")).toBeTruthy();
    first.unmount();
    vi.unstubAllGlobals();
    stubSettings();
    window.location.hash = "#/settings?present=0";
    render(<App />);
    await screen.findByText("Automatic sweep");
    expect(localStorage.getItem(PRESENTATION_STORAGE_KEY)).toBe("false");
    expect(screen.queryByText("Presentation mode")).toBeNull();
  });
});
