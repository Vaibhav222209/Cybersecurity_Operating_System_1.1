import { useEffect, useState } from "react";
import { Lock, LogOut, Power, RotateCw, X } from "lucide-react";
import type { Notification, PowerAction } from "../os/context";
import { SEV_COLOR, useKernel, threatLabel } from "../os/kernel";
import { Ring } from "./ui";
import { fmtUptime } from "./ui";

export function Toasts({ toasts, onDismiss, onClick }: { toasts: Notification[]; onDismiss: (id: number) => void; onClick: (n: Notification) => void }) {
  return (
    <div className="pointer-events-none fixed right-3 top-12 z-[6200] flex w-80 flex-col gap-2">
      {toasts.map((t) => (
        <Toast key={t.id} n={t} onDismiss={onDismiss} onClick={onClick} />
      ))}
    </div>
  );
}
function Toast({ n, onDismiss, onClick }: { n: Notification; onDismiss: (id: number) => void; onClick: (n: Notification) => void }) {
  useEffect(() => {
    const t = setTimeout(() => onDismiss(n.id), 6500);
    return () => clearTimeout(t);
  }, [n.id, onDismiss]);
  return (
    <div onClick={() => onClick(n)} className="glass-strong anim-slide pointer-events-auto cursor-pointer rounded-lg p-3 shadow-2xl transition hover:brightness-125" style={{ borderLeft: `3px solid ${SEV_COLOR[n.sev]}`, boxShadow: `0 10px 30px -8px ${SEV_COLOR[n.sev]}55` }}>
      <div className="flex items-start justify-between gap-2">
        <div className="font-mono text-[10px] font-bold uppercase tracking-widest" style={{ color: SEV_COLOR[n.sev] }}>{n.sev} · SIEM</div>
        <button onClick={(e) => (e.stopPropagation(), onDismiss(n.id))} className="text-slate-500 hover:text-white"><X size={12} /></button>
      </div>
      <div className="text-sm font-semibold text-white">{n.title}</div>
      <div className="line-clamp-2 text-[11px] text-slate-400">{n.body}</div>
    </div>
  );
}

export function ContextMenu({ x, y, items, onClose }: { x: number; y: number; items: ({ label: string; onClick: () => void; danger?: boolean } | "sep")[]; onClose: () => void }) {
  return (
    <>
      <div className="fixed inset-0 z-[6600]" onClick={onClose} onContextMenu={(e) => (e.preventDefault(), onClose())} />
      <div className="glass-strong anim-pop fixed z-[6700] w-52 rounded-lg p-1 shadow-2xl" style={{ left: Math.min(x, window.innerWidth - 220), top: Math.min(y, window.innerHeight - items.length * 32 - 20) }}>
        {items.map((it, i) =>
          it === "sep" ? (
            <div key={i} className="my-1 h-px bg-line" />
          ) : (
            <button key={i} onClick={() => (onClose(), it.onClick())} className={`block w-full rounded px-3 py-1.5 text-left text-xs transition hover:bg-accent/15 ${it.danger ? "text-crit" : "text-slate-200"} hover:text-accent`}>
              {it.label}
            </button>
          ),
        )}
      </div>
    </>
  );
}

export function ConfirmPower({ action, onCancel, onConfirm }: { action: PowerAction; onCancel: () => void; onConfirm: () => void }) {
  const meta = {
    lock: { t: "Lock screen", d: "Your session stays active and apps keep running.", i: <Lock size={26} />, c: "#00e5ff", b: "Lock" },
    logout: { t: "Log out", d: "All open windows will be closed and unsaved work lost.", i: <LogOut size={26} />, c: "#ffb020", b: "Log out" },
    restart: { t: "Restart", d: "Sugreev OS will reboot. Unsaved work will be lost.", i: <RotateCw size={26} />, c: "#ff7a3c", b: "Restart" },
    shutdown: { t: "Shut down", d: "Sugreev OS will power off completely.", i: <Power size={26} />, c: "#ff3b5c", b: "Shut down" },
  }[action];
  const [left, setLeft] = useState(action === "lock" ? 0 : 30);
  useEffect(() => {
    if (action === "lock") return;
    const t = setInterval(() => setLeft((l) => l - 1), 1000);
    return () => clearInterval(t);
  }, [action]);
  useEffect(() => {
    if (left <= 0 && action !== "lock") onConfirm();
  }, [left, action, onConfirm]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => (e.key === "Escape" ? onCancel() : e.key === "Enter" && onConfirm());
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onCancel, onConfirm]);
  return (
    <div className="anim-fade fixed inset-0 z-[7000] flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onCancel}>
      <div onClick={(e) => e.stopPropagation()} className="glass-strong anim-pop w-[360px] rounded-2xl p-6 text-center" style={{ boxShadow: `0 0 60px -10px ${meta.c}66`, borderColor: meta.c + "66" }}>
        <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-full" style={{ color: meta.c, background: meta.c + "1a", boxShadow: `0 0 24px ${meta.c}55` }}>{meta.i}</div>
        <h2 className="font-display text-lg font-bold tracking-widest text-white">{meta.t.toUpperCase()}</h2>
        <p className="mt-2 text-xs text-slate-400">{meta.d}</p>
        {action !== "lock" && <p className="mt-2 font-mono text-[11px] text-slate-500">Automatically in <span style={{ color: meta.c }}>{left}s</span></p>}
        <div className="mt-5 flex gap-3">
          <button onClick={onCancel} className="btn flex-1 justify-center !py-2">Cancel</button>
          <button onClick={onConfirm} className="btn flex-1 justify-center !py-2 font-semibold" style={{ color: meta.c, borderColor: meta.c + "88", background: meta.c + "1a" }}>{meta.b}</button>
        </div>
      </div>
    </div>
  );
}

export function DesktopWidget() {
  const k = useKernel();
  const tl = threatLabel(k.threatLevel);
  return (
    <div className="glass absolute right-4 top-14 hidden w-60 rounded-2xl p-4 xl:block">
      <div className="font-display text-3xl font-bold tracking-wider text-white">{new Date(k.now).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}</div>
      <div className="mb-3 font-mono text-[10px] uppercase tracking-widest text-slate-500">{new Date(k.now).toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" })}</div>
      <div className="flex items-center gap-3">
        <Ring value={k.threatLevel} size={64} stroke={6} color={tl.color} label={String(k.threatLevel)} />
        <div>
          <div className="text-[9px] uppercase tracking-widest text-slate-500">Threat level</div>
          <div className="font-display text-sm font-bold" style={{ color: tl.color }}>{tl.label}</div>
          <div className="font-mono text-[10px] text-slate-500">{k.eps} eps · {k.alerts.filter((a) => a.status === "open").length} open</div>
        </div>
      </div>
      <div className="mt-3 space-y-1.5 font-mono text-[10px] text-slate-400">
        <div className="flex justify-between"><span>CPU</span><span className="text-accent">{k.cpuTotal.toFixed(0)}%</span></div>
        <div className="flex justify-between"><span>MEM</span><span className="text-violet">{((k.memUsed / k.memTotal) * 100).toFixed(0)}%</span></div>
        <div className="flex justify-between"><span>UPTIME</span><span>{fmtUptime(k.now - k.bootTime)}</span></div>
      </div>
    </div>
  );
}
