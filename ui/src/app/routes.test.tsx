import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
function stubFetch() {
  vi.stubGlobal("fetch", async (input: unknown) => {
    const url = String(input);
    const path = url.split("?")[0];
    if (path === "/api/health") return { ok: true, status: 200, json: async () => ({ status: "ok" }) };
    if (path === "/api/incidents") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    if (path === "/api/rules") return { ok: true, status: 200, json: async () => ({ items: [], total: 0, limit: 20, offset: 0 }) };
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
}
describe("app shell routing", () => {
  afterEach(() => { vi.unstubAllGlobals(); window.location.hash = "#/"; });
  it("renders the incident list at both root and incidents paths", async () => {
    window.location.hash = "#/incidents";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("No incidents found.")).toBeTruthy();
    expect(screen.getByText("Incidents", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
  it("shows Coming next for dashboard and settings", async () => {
    window.location.hash = "#/dashboard";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("Coming next")).toBeTruthy();
    expect(screen.getByText("Dashboard", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
  it("marks rules active on the rules path", async () => {
    window.location.hash = "#/rules";
    stubFetch();
    render(<App />);
    expect(await screen.findByText("No learned rules found.")).toBeTruthy();
    expect(screen.getByText("Rules", { selector: "nav a" }).getAttribute("aria-current")).toBe("page");
  });
});
