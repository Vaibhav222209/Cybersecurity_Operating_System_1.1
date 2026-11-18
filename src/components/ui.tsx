import type { ReactNode } from "react";
import { SEV_COLOR, type Severity } from "../os/kernel";

export function Sparkline({ data, color = "var(--accent)", height = 40, max, min = 0, fill = true, className = "" }: { data: number[]; color?: string; height?: number; max?: number; min?: number; fill?: boolean; className?: string }) {
  const w = 200;
  const mx = max ?? Math.max(1, ...data) * 1.1;
  const pts = data.map((v, i) => [(i / Math.max(1, data.length - 1)) * w, height - ((v - min) / (mx - min || 1)) * (height - 2) - 1]);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const id = "g" + Math.abs(hashStr(color + height + className)).toString(36);
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className={`w-full ${className}`} style={{ height }}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.35" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={`${line} L${w},${height} L0,${height} Z`} fill={`url(#${id})`} />}
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
function hashStr(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

export function Ring({ value, size = 84, stroke = 8, color = "var(--accent)", label, sub }: { value: number; size?: number; stroke?: number; color?: string; label?: string; sub?: string }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#14283b" strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (c * v) / 100} style={{ transition: "stroke-dashoffset .8s, stroke .8s", filter: `drop-shadow(0 0 4px ${color})` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-tight">
        <span className="font-mono text-sm font-bold text-white">{label ?? Math.round(v) + "%"}</span>
        {sub && <span className="text-[9px] uppercase tracking-wider text-slate-500">{sub}</span>}
      </div>
    </div>
  );
}

export function SevBadge({ sev, className = "" }: { sev: Severity | string; className?: string }) {
  const c = SEV_COLOR[sev as Severity] ?? "#6b8aa3";
  return (
    <span className={`inline-block rounded px-1.5 py-[1px] font-mono text-[10px] font-bold uppercase tracking-wide ${className}`} style={{ color: c, background: c + "1f", border: `1px solid ${c}55` }}>
      {sev}
    </span>
  );
}

export function Card({ title, icon, right, children, className = "", bodyClass = "" }: { title?: string; icon?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <div className={`flex min-h-0 flex-col rounded-lg border border-line bg-panel/80 ${className}`}>
      {title && (
        <div className="flex items-center justify-between border-b border-line px-3 py-2">
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-slate-400">
            {icon && <span className="text-accent">{icon}</span>}
            {title}
          </div>
          {right}
        </div>
      )}
      <div className={`min-h-0 flex-1 ${bodyClass || "p-3"}`}>{children}</div>
    </div>
  );
}

export function Stat({ label, value, sub, color = "#fff", icon }: { label: string; value: ReactNode; sub?: ReactNode; color?: string; icon?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-panel/80 px-3 py-2">
      <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.14em] text-slate-500">
        {label}
        {icon && <span className="text-accent/80">{icon}</span>}
      </div>
      <div className="font-mono text-xl font-bold leading-tight" style={{ color }}>
        {value}
      </div>
      {sub && <div className="text-[10px] text-slate-500">{sub}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; icon?: ReactNode; badge?: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-line bg-base/60 px-2 pt-1.5">
      {tabs.map((t) => (
        <button key={t.id} onClick={() => onChange(t.id)} className={`flex items-center gap-1.5 whitespace-nowrap rounded-t-md border border-b-0 px-3 py-1.5 text-xs transition ${value === t.id ? "border-line bg-panel text-accent" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
          {t.icon}
          {t.label}
          {t.badge}
        </button>
      ))}
    </div>
  );
}

export function Bar({ value, max = 100, color = "var(--accent)", height = 6 }: { value: number; max?: number; color?: string; height?: number }) {
  return (
    <div className="w-full overflow-hidden rounded-full bg-[#112233]" style={{ height }}>
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(100, (value / max) * 100)}%`, background: color, boxShadow: `0 0 8px ${color}` }} />
    </div>
  );
}

export function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!on)} className={`relative h-5 w-9 rounded-full border transition ${on ? "border-accent bg-accent/30" : "border-line bg-raised"}`}>
      <span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${on ? "left-[18px] bg-accent" : "left-0.5 bg-slate-500"}`} />
    </button>
  );
}

export const fmtTime = (ts: number) => new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
export const fmtUptime = (ms: number) => {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h ? h + "h " : ""}${m}m ${s % 60}s`;
};
export const fmtNum = (n: number) => n.toLocaleString("en-US");
export const fmtRate = (kb: number) => (kb >= 1024 ? (kb / 1024).toFixed(1) + " MB/s" : kb.toFixed(0) + " KB/s");

export function SugreevLogo({ size = 28, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className={className}>
      <defs>
        <linearGradient id="sgvlogo" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#00ffa3" />
          <stop offset="1" stopColor="var(--accent)" />
        </linearGradient>
      </defs>
      <path d="M32 5 55 13v17c0 14-10 25-23 29C19 55 9 44 9 30V13z" fill="rgba(0,229,255,0.06)" stroke="url(#sgvlogo)" strokeWidth="3" />
      <path d="M41 24c-2-4-7-5-10-4-4 1-6 4-5 7 1 4 6 4 9 5 3 1 4 3 3 6-1 3-6 4-10 2" fill="none" stroke="url(#sgvlogo)" strokeWidth="4.5" strokeLinecap="round" />
    </svg>
  );
}
