const V4_DOC_A = "198.51.100";
const V4_DOC_B = "203.0.113";
const V6_DOC = "2001:db8";
const V4_POOL = 254;
const V6_POOL = 65535;

const V4_RE = /(?<![0-9A-Za-z])(?<![0-9]\.)(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z])(?!\.\d)/g;
const V6_RUN = /(?<![0-9A-Za-z:.])([0-9A-Fa-f:.]{2,})(?![0-9A-Za-z:.])/g;

const v4ByKey = new Map<string, string>();
const v6ByKey = new Map<string, string>();
const issuedV4 = new Set<string>();
const issuedV6 = new Set<string>();
let v4Next = 1;
let v6Next = 1;

export function resetMaskedIpMapping(): void {
  v4ByKey.clear();
  v6ByKey.clear();
  issuedV4.clear();
  issuedV6.clear();
  v4Next = 1;
  v6Next = 1;
}

function parseV4Octets(text: string): number[] | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n > 255) return null;
    out.push(n);
  }
  return out;
}

function isPrivateV4(o: number[]): boolean {
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  if (o[0] === 0 && o[1] === 0 && o[2] === 0 && o[3] === 0) return true;
  return false;
}

function parseHexGroups(parts: string[]): number[] | null {
  const out: number[] = [];
  for (const part of parts) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) return null;
    out.push(parseInt(part, 16));
  }
  return out;
}

type V6Side = { nums: number[]; tail: number[] | null };

function parseV6Side(raw: string[]): V6Side | null {
  if (raw.length === 0) return { nums: [], tail: null };
  const last = raw[raw.length - 1];
  if (last.includes(".")) {
    const tail = parseV4Octets(last);
    if (!tail) return null;
    const head = parseHexGroups(raw.slice(0, -1));
    if (!head) return null;
    return { nums: [...head, (tail[0] << 8) | tail[1], (tail[2] << 8) | tail[3]], tail };
  }
  const head = parseHexGroups(raw);
  if (!head) return null;
  return { nums: head, tail: null };
}

function parseV6Groups(text: string): { groups: number[]; v4tail: number[] | null } | null {
  if (!text.includes(":")) return null;
  if (text.includes(":::")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const compressed = halves.length === 2;
  const leftRaw = halves[0] === "" ? [] : halves[0].split(":");
  const rightRaw = !compressed ? [] : halves[1] === "" ? [] : halves[1].split(":");
  const left = parseV6Side(leftRaw);
  if (!left) return null;
  if (left.tail && (compressed ? rightRaw.length > 0 : false)) return null;
  const right = parseV6Side(rightRaw);
  if (!right) return null;
  const tail = right.tail ?? left.tail;
  if (!compressed) {
    if (leftRaw.length === 0 || left.nums.length !== 8) return null;
    return { groups: left.nums, v4tail: tail };
  }
  const total = left.nums.length + right.nums.length;
  if (total === 0) return { groups: [0, 0, 0, 0, 0, 0, 0, 0], v4tail: null };
  if (total > 7) return null;
  const zeros = new Array<number>(8 - total).fill(0);
  return { groups: [...left.nums, ...zeros, ...right.nums], v4tail: tail };
}

function isSpecialV6(groups: number[], v4tail: number[] | null): boolean {
  if (groups.every((g) => g === 0)) return true;
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true;
  const head = groups[0];
  if ((head & 0xfe00) === 0xfc00) return true;
  if ((head & 0xffc0) === 0xfe80) return true;
  if (v4tail && isPrivateV4(v4tail)) return true;
  return false;
}

function allocV4(key: string): string {
  const known = v4ByKey.get(key);
  if (known) return known;
  const n = v4Next++;
  const name = n <= V4_POOL ? `${V4_DOC_A}.${n}` : `${V4_DOC_B}.${((n - V4_POOL - 1) % V4_POOL) + 1}`;
  v4ByKey.set(key, name);
  issuedV4.add(name);
  return name;
}

function allocV6(key: string): string {
  const known = v6ByKey.get(key);
  if (known) return known;
  const n = ((v6Next++ - 1) % V6_POOL) + 1;
  const name = `${V6_DOC}::${n.toString(16)}`;
  v6ByKey.set(key, name);
  issuedV6.add(name);
  return name;
}

function replaceV4(match: string): string {
  const octets = parseV4Octets(match);
  if (!octets) return match;
  if (isPrivateV4(octets)) return match;
  if (issuedV4.has(match)) return match;
  return allocV4(octets.join("."));
}

function replaceV6Run(match: string): string {
  let prefix = "";
  let suffix = "";
  let core = match;
  if (core.startsWith(":") && !core.startsWith("::")) {
    prefix = ":";
    core = core.slice(1);
  }
  if (core.length > 2 && !core.endsWith("::") && (core.endsWith(":") || core.endsWith("."))) {
    suffix = core.slice(-1);
    core = core.slice(0, -1);
  }
  if (core.length < 2 || !core.includes(":")) return match;
  const parsed = parseV6Groups(core);
  if (!parsed) return match;
  if (isSpecialV6(parsed.groups, parsed.v4tail)) return match;
  if (issuedV6.has(`${prefix}${core}${suffix}`)) return match;
  return `${prefix}${allocV6(parsed.groups.map((g) => g.toString(16)).join(":"))}${suffix}`;
}

export function maskPublicIps(text: string): string {
  if (!text) return text;
  return text.replace(V6_RUN, replaceV6Run).replace(V4_RE, replaceV4);
}
