import type { OSApi } from "../context";

export type Kind = "out" | "err" | "ok" | "warn" | "info" | "dim" | "accent" | "crit" | "prompt";
export interface Seg {
  t: string;
  k?: Kind;
}

export interface ShellCtx {
  print: (t: string, k?: Kind) => void;
  segs: (s: Seg[]) => void;
  clear: () => void;
  cwd: string;
  setCwd: (p: string) => void;
  user: string;
  setUser: (u: string) => void;
  root: boolean;
  sleep: (ms: number) => Promise<void>;
  os: OSApi;
  history: string[];
  stdin?: string[];
  env: Record<string, string>;
  closeSelf: () => void;
  run: (line: string) => Promise<void>;
}

export interface Cmd {
  desc: string;
  usage?: string;
  cat: string;
  run: (args: string[], c: ShellCtx) => Promise<void> | void;
}

export function parseFlags(args: string[], valueFlags: string[] = []) {
  const flags = new Set<string>();
  const values: Record<string, string> = {};
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("--") && a.length > 2) {
      const [k, v] = a.slice(2).split("=");
      if (v !== undefined) values[k] = v;
      else if (valueFlags.includes(k) && args[i + 1]) values[k] = args[++i];
      else flags.add(k);
    } else if (a.startsWith("-") && a.length > 1 && !/^-\d+$/.test(a)) {
      for (const ch of a.slice(1)) flags.add(ch);
      const last = a.slice(-1);
      if (valueFlags.includes(last) && a.length === 2 && args[i + 1]) values[last] = args[++i];
    } else rest.push(a);
  }
  return { flags, values, rest };
}

export const pad = (s: string | number, n: number) => String(s).padEnd(n);
export const lpad = (s: string | number, n: number) => String(s).padStart(n);

export function fmtLsDate(ts: number) {
  const d = new Date(ts);
  const mon = d.toLocaleString("en-US", { month: "short" });
  return `${mon} ${String(d.getDate()).padStart(2)} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
export function syslogDate(ts: number) {
  const d = new Date(ts);
  return `${d.toLocaleString("en-US", { month: "short" })} ${String(d.getDate()).padStart(2)} ${d.toLocaleTimeString("en-GB", { hour12: false })}`;
}

export function globToRegex(g: string) {
  return new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
}
