import { useEffect, useRef, useState } from "react";
import { Lock, LogOut, Power, RotateCw, Search } from "lucide-react";
import { APPS } from "../os/registry";
import type { AppId, PowerAction } from "../os/context";
import { SugreevLogo } from "./ui";

export function Launcher({ onClose, onOpen, onPower }: { onClose: () => void; onOpen: (id: AppId) => void; onPower: (a: PowerAction) => void }) {
  const [q, setQ] = useState("");
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => ref.current?.focus(), []);
  const list = APPS.filter((a) => (a.title + a.desc).toLowerCase().includes(q.toLowerCase()));
  const launch = (id: AppId) => {
    onOpen(id);
    onClose();
  };
  return (
    <>
      <div className="fixed inset-0 z-[5400]" onClick={onClose} />
      <div className="glass-strong anim-pop fixed bottom-4 left-[72px] top-12 z-[5500] flex w-[400px] max-w-[calc(100vw-90px)] flex-col rounded-2xl p-4 shadow-2xl neon-border">
        <div className="mb-4 flex items-center gap-3">
          <SugreevLogo size={34} />
          <div>
            <div className="font-display text-sm font-bold tracking-[0.3em] neon-text">SUGREEV OS</div>
            <div className="font-mono text-[10px] text-slate-500">Kishkindha 1.0 · Cybersecurity Edition</div>
          </div>
        </div>
        <div className="relative mb-4">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
          <input ref={ref} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => (e.key === "Escape" ? onClose() : e.key === "Enter" && list[0] && launch(list[0].id))} placeholder="Search apps…" className="inp !w-full !rounded-lg !py-2 !pl-9 !text-sm" />
        </div>
        <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-slate-500">Applications</div>
        <div className="grid min-h-0 flex-1 grid-cols-3 content-start gap-2 overflow-y-auto pr-1">
          {list.map((a) => {
            const Icon = a.icon;
            return (
              <button key={a.id} onClick={() => launch(a.id)} className="group flex flex-col items-center gap-2 rounded-xl border border-transparent p-3 text-center transition hover:border-line hover:bg-white/5">
                <span className="flex h-12 w-12 items-center justify-center rounded-xl transition group-hover:scale-110" style={{ background: a.color + "18", boxShadow: `inset 0 0 0 1px ${a.color}44` }}>
                  <Icon size={24} style={{ color: a.color }} />
                </span>
                <span className="text-[11px] font-medium leading-tight text-slate-200">{a.title}</span>
                <span className="line-clamp-2 text-[9px] leading-tight text-slate-500">{a.desc}</span>
              </button>
            );
          })}
          {!list.length && <div className="col-span-3 py-10 text-center text-xs text-slate-500">No apps match “{q}”.</div>}
        </div>
        <div className="mt-3 flex items-center justify-between border-t border-line pt-3">
          <div className="flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-neon to-accent font-display text-[10px] font-black text-black">VT</span>
            <div className="leading-tight">
              <div className="text-xs text-white">Vaibhav Thakur</div>
              <div className="font-mono text-[9px] text-slate-500">uid=1000 · sudo</div>
            </div>
          </div>
          <div className="flex gap-1">
            {([["lock", <Lock size={14} />, "Lock"], ["logout", <LogOut size={14} />, "Log out"], ["restart", <RotateCw size={14} />, "Restart"], ["shutdown", <Power size={14} />, "Shut down"]] as [PowerAction, React.ReactNode, string][]).map(([a, i, t]) => (
              <button key={a} title={t} onClick={() => (onClose(), onPower(a))} className={`rounded-lg border border-line p-2 transition hover:bg-white/10 ${a === "shutdown" ? "text-crit" : a === "restart" ? "text-warn" : "text-slate-300"}`}>{i}</button>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
