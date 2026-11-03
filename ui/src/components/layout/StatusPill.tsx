import type { Health } from "../../api/types";
import pillStyles from "./StatusPill.module.css";
function Chip({ label, state, detail }: { label: string; state: "ok" | "degraded" | "down" | "unknown"; detail: string }) {
  const word = state === "ok" ? "OK" : state === "degraded" ? "Degraded" : state === "down" ? "Unavailable" : "Not measured";
  return (
    <li className={`chip chip-${state}`} title={`${label}: ${word} — ${detail}`}>
      <span className="chip-dot" aria-hidden="true" />
      <span className="chip-label">{label}</span>
      <span className="chip-state">{word}</span>
      <span className="chip-detail">{detail}</span>
      <span className="sr-only">{label}: {word} — {detail}</span>
    </li>
  );
}
export function HealthStrip({ health, error }: { health: Health | null; error?: string | null }) {
  if (error) return <p role="alert">Health: unavailable — {error}</p>;
  if (!health) return <p className="health muted" aria-live="polite">Health: loading…</p>;
  const o = health.self_observation ?? {};
  const fmt = (v: unknown) => (v === undefined || v === null ? "not measured" : String(v));
  const latency = o.latest_model_latency_ms;
  const latencyModel = o.latest_model_latency_model;
  const latencyText = latency === undefined || latency === null || latency === "not measured"
    ? "Latest model latency: not measured"
    : `Latest model latency (model ${fmt(latencyModel)}): ${fmt(latency)} ms`;
  const comp = (c?: { reachable?: boolean; detail?: string } | null): { state: "ok" | "degraded" | "down" | "unknown"; detail: string } => {
    if (!c || typeof c.reachable !== "boolean") return { state: "unknown", detail: "not measured" };
    return c.reachable ? { state: "ok", detail: "reachable" } : { state: "down", detail: c.detail ? String(c.detail) : "unreachable" };
  };
  const db = comp(health.database);
  const gl = comp(health.models?.glimmer);
  const mt = comp(health.models?.meta);
  const apiState: "ok" | "degraded" | "down" = health.status === "ok" ? "ok" : "degraded";
  const spend = o.spend_today_usd;
  const cap = o.spend_cap_usd;
  const queue = o.queue_depth;
  return (
    <div className={`health ${pillStyles.pillRoot}`} aria-label="System health">
      <ul className="chips">
        <Chip label="API" state={apiState} detail={`status ${health.status}`} />
        <Chip label="Database" state={db.state} detail={db.state === "ok" ? "reachable" : `Database: ${db.detail}`} />
        <Chip label="Glimmer" state={gl.state} detail={gl.state === "ok" ? "reachable" : `Glimmer: ${gl.detail}`} />
        <Chip label="Meta" state={mt.state} detail={mt.state === "ok" ? "reachable" : `Meta: ${mt.detail}`} />
        <Chip label="Spend today" state={spend === "not measured" || spend === undefined ? "unknown" : "ok"} detail={`${fmt(spend)} / cap ${fmt(cap)} USD`} />
        <Chip label="Queue" state={queue === "not measured" || queue === undefined ? "unknown" : "ok"} detail={`Queue depth: ${fmt(queue)}`} />
      </ul>
      <p className="sr-only">
        Status: {health.status} · {latencyText} · Model error rate: {fmt(o.model_error_rate)} · Spend today: {fmt(o.spend_today_usd)} / cap {fmt(o.spend_cap_usd)} USD · Queue depth: {fmt(o.queue_depth)}
        {health.status !== "ok" ? <> · Degraded: {[
          db.state !== "ok" ? `Database (${db.detail})` : null,
          gl.state !== "ok" ? `Glimmer (${gl.detail})` : null,
          mt.state !== "ok" && mt.state !== "unknown" ? `Meta (${mt.detail})` : null,
        ].filter(Boolean).join(", ") || "see chips above"}</> : null}
      </p>
    </div>
  );
}
