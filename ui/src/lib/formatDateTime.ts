const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function asDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

export function formatDateTime(value: string | null | undefined, opts?: { seconds?: boolean }): string {
  const d = asDate(value);
  if (value === null || value === undefined) return "not recorded";
  if (!d) return value;
  const clock = opts?.seconds
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${clock}`;
}

export function formatTime(value: string | null | undefined, opts?: { seconds?: boolean }): string {
  const d = asDate(value);
  if (value === null || value === undefined) return "not recorded";
  if (!d) return value;
  if (opts?.seconds) return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatDate(value: string | null | undefined): string {
  const d = asDate(value);
  if (value === null || value === undefined) return "not recorded";
  if (!d) return value;
  return `${MONTHS[d.getMonth()]} ${d.getDate()}`;
}

export function formatAgo(value: string | null | undefined, nowMs?: number): string {
  const d = asDate(value);
  if (value === null || value === undefined) return "not recorded";
  if (!d) return value;
  const diffMs = (nowMs ?? Date.now()) - d.getTime();
  if (diffMs < 0) return "in the future";
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  return `${days} d ago`;
}

export function isValidDateTime(value: string | null | undefined): boolean {
  return asDate(value) !== null;
}
