import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../../app/App";
import { buildListHash, parseHash } from "../../lib/hash";
import type { IncidentDetail, IncidentListItem } from "../../api/types";
const items: IncidentListItem[] = [
  { id: 1, title: "sudo escalation on host-1", severity_floor: 4, severity_floor_name: "High", severity_id: 5, severity_name: "Critical", ai_status: "done", verdict: "true_positive", event_count: 41, has_injection: false, analyzed: true },
  { id: 2, title: "weird cron on host-2", severity_floor: 3, severity_floor_name: "Medium", severity_id: 3, severity_name: "Medium", ai_status: "pending", verdict: null, event_count: 5, has_injection: true, analyzed: false },
];
const detailOne: IncidentDetail = {
  id: 1, title: "sudo escalation on host-1", severity_floor: 4, severity_floor_name: "High", severity_id: 5, severity_name: "Critical",
  ai_status: "done", verdict: "true_positive", techniques: [{ id: "T1059", name: "Command and Scripting Interpreter" }],
  triage: { summary: "First line.\nSecond line.\nThird line." },
};
function stub() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/settings") return { ok: true, status: 200, json: async () => ({ sweep_policy: { source: "configured", policy: null }, connections: [], spend_cap_usd: null, app_version: "x", attack_version: "y", ocsf_version: "z" }) };
    if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: null, running: false, next_run_at: null, policy: null }) };
    if (path === "/api/incidents/1") return { ok: true, status: 200, json: async () => detailOne };
    if (path === "/api/incidents/2") return { ok: true, status: 200, json: async () => ({ ...detailOne, id: 2, title: "weird cron on host-2", severity_floor: 3, severity_id: 3, severity_floor_name: "Medium", severity_name: "Medium", analysis: null, verdict: null, ai_status: "pending" }) };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items, total: 401, limit: 20, offset: 0 }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
describe("incidents console", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("shows the correlated count line and the selected preview", async () => {
    stub();
    window.location.hash = "#/incidents";
    const { container } = render(<App />);
    await screen.findByText("sudo escalation on host-1");
    expect(screen.getByText("401 correlated · 2 shown")).toBeTruthy();
    expect(await screen.findByText("Floor High, raised one level by the model")).toBeTruthy();
    expect(await screen.findByText("Open full analysis")).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
  });
  it("filters by search text and round-trips the URL", async () => {
    stub();
    window.location.hash = "#/incidents";
    render(<App />);
    await screen.findByText("sudo escalation on host-1");
    fireEvent.change(screen.getByPlaceholderText("Search title, host or technique"), { target: { value: "cron" } });
    window.dispatchEvent(new Event("hashchange"));
    await waitFor(() => { expect(screen.queryByText("sudo escalation on host-1")).toBeNull(); });
    expect(screen.getByText("weird cron on host-2")).toBeTruthy();
    expect(screen.getByText("401 correlated · 1 shown")).toBeTruthy();
    expect(window.location.hash).toContain("q=cron");
    expect(parseHash(window.location.hash)).toMatchObject({ view: "list", q: "cron" });
    expect(parseHash(buildListHash({ page: 0, minFloor: null, verdict: null, analyzed: null, q: "cron", quarantined: null }))).toMatchObject({ q: "cron" });
  });
  it("chips filter to quarantined injection rows", async () => {
    stub();
    window.location.hash = "#/incidents";
    render(<App />);
    await screen.findByText("sudo escalation on host-1");
    fireEvent.click(screen.getByText("Quarantined", { selector: "button" }));
    window.dispatchEvent(new Event("hashchange"));
    await waitFor(() => { expect(screen.queryByText("sudo escalation on host-1")).toBeNull(); });
    expect(screen.getByText("weird cron on host-2")).toBeTruthy();
    expect(window.location.hash).toContain("quarantined=true");
  });
  it("opens the full analysis from the preview button", async () => {
    stub();
    window.location.hash = "#/incidents";
    render(<App />);
    await screen.findByText("sudo escalation on host-1");
    fireEvent.click(await screen.findByText("Open full analysis"));
    window.dispatchEvent(new Event("hashchange"));
    expect(window.location.hash).toBe("#/incidents/1");
  });
  it("renders hostile incident titles as text only", async () => {
    const hostile: IncidentListItem = { ...items[0], id: 3, title: "<img src=x onerror=alert(1)>\u0007bad" };
    vi.stubGlobal("fetch", async (input: unknown) => {
      const url = String(input);
      const path = url.split("?")[0];
      if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [hostile], total: 1, limit: 20, offset: 0 }) };
      if (path === "/api/incidents/3") return { ok: true, status: 200, json: async () => ({ ...detailOne, id: 3, title: hostile.title }) };
      if (path === "/api/sweep/status") return { ok: true, status: 200, json: async () => ({ last: null, running: false, next_run_at: null, policy: null }) };
      return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
    });
    window.location.hash = "#/incidents";
    const { container } = render(<App />);
    await screen.findByText(/bad/);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
  });
});
