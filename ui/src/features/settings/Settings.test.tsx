import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../../app/App";
import type { SettingsView, SweepStatus } from "../../api/types";
function settingsView(): SettingsView {
  return {
    sweep_policy: { source: "configured", policy: { min_floor: 4, max_analyses: 5, always_analyze_injection: true, spend_cap_usd: 100, lang: "en", interval_seconds: 300 } },
    connections: [
      { name: "database", address: "postgresql://127.0.0.1:55432", state: "connected" },
      { name: "wazuh_indexer", address: "https://wazuh.example.com:9200", state: "unreachable" },
      { name: "triage_model", address: "http://127.0.0.1:8001", state: "connected" },
      { name: "reasoning_model", address: "https://api.meta.ai", state: "not_configured" },
    ],
    spend_cap_usd: 100,
    app_version: "0.1.0",
    attack_version: "v20.0",
    ocsf_version: "1.9.0",
  };
}
function sweepStatus(): SweepStatus {
  return { last: null, running: false, next_run_at: null, policy: null };
}
describe("SettingsPage", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; localStorage.clear(); });
  function stubSettings() {
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      const path = url.split("?")[0];
      if (path === "/api/settings") return { ok: true, status: 200, json: async () => settingsView() };
      if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => sweepStatus() };
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
  }
  it("renders the read-only policy, connections and privacy text", async () => {
    stubSettings();
    window.location.hash = "#/settings";
    const { container } = render(<App />);
    expect(await screen.findByText("Automatic sweep")).toBeTruthy();
    expect(screen.getByText("No sweep running")).toBeTruthy();
    expect(screen.getByText(/Set with corvus sweep flags/)).toBeTruthy();
    expect(screen.getByText(/stays pending and can be analyzed by hand/)).toBeTruthy();
    expect(screen.getByText(/keeps collecting but stops analyzing/)).toBeTruthy();
    expect(screen.getByText("Poll interval")).toBeTruthy();
    expect(screen.getByText("300 s")).toBeTruthy();
    expect(screen.getByText("High").getAttribute("title")).toBe("4");
    expect(screen.getByText("Injection signals always analyzed")).toBeTruthy();
    expect(screen.getByText("Yes")).toBeTruthy();
    expect(screen.getByText("Unreachable")).toBeTruthy();
    expect(screen.getAllByText("Connected").length).toBe(2);
    expect(screen.getAllByText("Not configured")).toHaveLength(1);
    expect(screen.queryByText("triage_model")).toBeNull();
    expect(screen.queryByText("wazuh_indexer")).toBeNull();
    expect(container.querySelector('[title="triage_model"]')?.textContent).toBe("Triage model (on-prem)");
    expect(container.querySelector('[title="wazuh_indexer"]')?.textContent).toBe("Wazuh indexer");
    expect(screen.getByText("Start the SSH tunnel or check the address; see docs/wazuh.md")).toBeTruthy();
    expect(screen.getByText(/pseudonymized on-prem/)).toBeTruthy();
    expect(screen.getByText(/Shadow rules never change alerts/)).toBeTruthy();
    expect(screen.getByText(/rendered as plain text/)).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("input[type=checkbox]:disabled")).toBeNull();
  });
  it("leaks no secrets in the connections card", async () => {
    stubSettings();
    window.location.hash = "#/settings";
    const { container } = render(<App />);
    await screen.findByText("Automatic sweep");
    const text = container.textContent ?? "";
    expect(text).not.toContain("META_API_KEY");
    expect(text).not.toContain("password");
    expect(text).not.toContain("@");
  });
  it("shows the policy as text with no fields and no save button", async () => {
    stubSettings();
    window.location.hash = "#/settings";
    const { container } = render(<App />);
    await screen.findByText("Automatic sweep");
    expect(screen.queryByLabelText(/Always analyze incidents with an injection signal/)).toBeNull();
    expect(screen.queryByText("Save")).toBeNull();
    expect(container.querySelector("input[disabled]")).toBeNull();
    expect(screen.getByText("5")).toBeTruthy();
    expect(screen.getByText("$100")).toBeTruthy();
  });
  it("writes the theme choice and toggles reduce motion locally", async () => {
    stubSettings();
    window.location.hash = "#/settings";
    render(<App />);
    await screen.findByText("Automatic sweep");
    fireEvent.click(screen.getByText("Light", { selector: "button" }));
    expect(localStorage.getItem("corvus-theme")).toBe("light");
    fireEvent.click(screen.getByText("System", { selector: "button" }));
    expect(localStorage.getItem("corvus-theme")).toBe("system");
    const motion = screen.getByLabelText("Reduce motion") as HTMLInputElement;
    fireEvent.click(motion);
    expect(document.documentElement.classList.contains("reduce-motion")).toBe(true);
  });
});
