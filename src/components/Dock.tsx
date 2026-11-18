import { LayoutGrid, Monitor } from "lucide-react";
import { APPS } from "../os/registry";
import type { AppId } from "../os/context";
import type { WinState } from "./WindowFrame";

interface Props {
  wins: WinState[];
  activeId: string | null;
  onApp: (id: AppId) => void;
  onLauncher: () => void;
  onShowDesktop: () => void;
}

export function Dock({ wins, activeId, onApp, onLauncher, onShowDesktop }: Props) {
  const pinned = APPS.filter((a) => a.pinned);
  const extra = APPS.filter((a) => !a.pinned && wins.some((w) => w.app === a.id));
  const list = [...pinned, ...extra];
  const activeApp = wins.find((w) => w.id === activeId)?.app;
  return (
    <div className="glass-strong fixed bottom-0 left-0 top-10 z-[5000] flex w-16 flex-col items-center gap-1.5 border-y-0 border-l-0 py-3">
      <button onClick={onLauncher} title="All applications" className="group relative mb-1 flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-raised text-slate-300 transition hover:border-accent hover:text-accent">
        <LayoutGrid size={18} />
        <Tip>Applications</Tip>
      </button>
      <div className="h-px w-8 bg-line" />
      <div className="flex min-h-0 flex-1 flex-col items-center gap-1.5 py-1">
        {list.map((a) => {
          const Icon = a.icon;
          const running = wins.filter((w) => w.app === a.id);
          const isActive = activeApp === a.id;
          return (
            <button key={a.id} onClick={() => onApp(a.id)} className="group relative flex h-11 w-11 shrink-0 items-center justify-center rounded-xl transition hover:scale-110" style={isActive ? { background: a.color + "22", boxShadow: `0 0 0 1px ${a.color}66, 0 0 18px -2px ${a.color}66` } : undefined}>
              <span className="absolute inset-0 rounded-xl opacity-0 transition group-hover:opacity-100" style={{ background: a.color + "14" }} />
              <Icon size={21} style={{ color: a.color, filter: `drop-shadow(0 0 6px ${a.color}77)` }} />
              {running.length > 0 && <span className="absolute -left-2 h-5 w-1 rounded-r" style={{ background: a.color, opacity: isActive ? 1 : 0.5, boxShadow: `0 0 8px ${a.color}` }} />}
              {running.length > 1 && <span className="absolute -right-0.5 -top-0.5 rounded-full bg-raised px-1 font-mono text-[8px] text-slate-300">{running.length}</span>}
              <Tip>{a.title}</Tip>
            </button>
          );
        })}
      </div>
      <div className="h-px w-8 bg-line" />
      <button onClick={onShowDesktop} title="Show desktop" className="group relative mt-1 flex h-9 w-9 items-center justify-center rounded-lg text-slate-500 transition hover:bg-white/10 hover:text-accent">
        <Monitor size={16} />
        <Tip>Show desktop</Tip>
      </button>
    </div>
  );
}

function Tip({ children }: { children: React.ReactNode }) {
  return (
    <span className="pointer-events-none absolute left-full top-1/2 z-50 ml-3 -translate-y-1/2 whitespace-nowrap rounded-md border border-line bg-ink px-2 py-1 font-mono text-[10px] text-slate-200 opacity-0 shadow-xl transition group-hover:opacity-100">
      {children}
    </span>
  );
}
