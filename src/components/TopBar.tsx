import { useEffect, useState } from "react";
import { Bell, Cpu, Lock, LogOut, MemoryStick, Power, RotateCw, Volume2, Wifi, BatteryFull, ArrowDown, Trash2, ShieldAlert } from "lucide-react";
import { useKernel, threatLabel, SEV_COLOR } from "../os/kernel";
import { useOS, type PowerAction } from "../os/context";
import { appById } from "../os/registry";
import { SugreevLogo, fmtRate, fmtTime } from "./ui";
import type { WinState } from "./WindowFrame";

interface Props {
  wins: WinState[];
  activeId: string | null;
  launcherOpen: boolean;
  toggleLauncher: () => void;
  onWinClick: (id: string) => void;
  onPower: (a: PowerAction) => void;
}

export function TopBar({ wins, activeId, launcherOpen, toggleLauncher, onWinClick, onPower }: Props) {
  const k = useKernel();
  const os = useOS();
  const [now, setNow] = useState(new Date());
  const [menu, setMenu] = useState<null | "power" | "notif">(null);
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const tl = threatLabel(k.threatLevel);
  const activeWin = wins.find((w) => w.id === activeId);
  const unread = os.notifications.length;

  return (
    <>
      <div className="glass-strong fixed inset-x-0 top-0 z-[6000] flex h-10 items-center gap-2 border-x-0 border-t-0 px-2 text-xs">
        <button onClick={toggleLauncher} className={`flex h-7 items-center gap-2 rounded-md px-2 transition ${launcherOpen ? "bg-accent/20 text-accent" : "hover:bg-white/10"}`}>
          <SugreevLogo size={20} />
          <span className="hidden font-display text-[11px] font-bold tracking-[0.25em] sm:block">SUGREEV</span>
        </button>
        <div className="hidden max-w-[160px] truncate font-mono text-[11px] text-slate-400 lg:block">{activeWin ? activeWin.title : "Desktop"}</div>
        <div className="mx-1 hidden h-4 w-px bg-line md:block" />
        <div className="hidden min-w-0 flex-1 items-center gap-1 overflow-hidden md:flex">
          {wins.slice(0, 9).map((w) => {
            const d = appById(w.app);
            const Icon = d.icon;
            return (
              <button key={w.id} onClick={() => onWinClick(w.id)} className={`flex h-7 max-w-[150px] items-center gap-1.5 rounded-md border px-2 transition ${w.id === activeId ? "border-accent/50 bg-accent/10 text-accent" : w.min ? "border-transparent text-slate-500 hover:bg-white/5" : "border-transparent text-slate-300 hover:bg-white/5"}`}>
                <Icon size={12} style={{ color: d.color }} />
                <span className="truncate font-mono text-[10px]">{w.title}</span>
              </button>
            );
          })}
        </div>

        <div className="pointer-events-none absolute left-1/2 hidden -translate-x-1/2 text-center leading-tight xl:block">
          <div className="font-mono text-[12px] font-medium text-slate-100">{now.toLocaleTimeString("en-GB")}</div>
          <div className="text-[9px] uppercase tracking-widest text-slate-500">{now.toLocaleDateString("en-GB", { weekday: "short", day: "2-digit", month: "short", year: "numeric" })}</div>
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <div className="hidden items-center gap-3 rounded-md border border-line bg-ink/50 px-2.5 py-1 font-mono text-[10px] text-slate-400 lg:flex">
            <span className="flex items-center gap-1" title="CPU"><Cpu size={11} className="text-accent" />{k.cpuTotal.toFixed(0)}%</span>
            <span className="flex items-center gap-1" title="Memory"><MemoryStick size={11} className="text-violet" />{((k.memUsed / k.memTotal) * 100).toFixed(0)}%</span>
            <span className="flex items-center gap-1" title="Network RX"><ArrowDown size={11} className="text-neon" />{fmtRate(k.rx)}</span>
          </div>
          <button onClick={() => os.openApp("threats")} className="flex h-7 items-center gap-1.5 rounded-md border px-2 font-mono text-[10px] font-bold transition hover:bg-white/5" style={{ color: tl.color, borderColor: tl.color + "55", background: tl.color + "12" }} title="Threat level">
            <ShieldAlert size={12} className={k.threatLevel > 60 ? "animate-pulse" : ""} />
            <span className="hidden sm:inline">{tl.label}</span>
          </button>
          <div className="hidden items-center gap-2 px-1 text-slate-400 sm:flex">
            <Wifi size={14} />
            <Volume2 size={14} />
            <BatteryFull size={15} className="text-neon" />
          </div>
          <button onClick={() => setMenu(menu === "notif" ? null : "notif")} className="relative rounded-md p-1.5 text-slate-300 hover:bg-white/10">
            <Bell size={15} />
            {unread > 0 && <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-crit px-1 font-mono text-[9px] font-bold text-white">{unread > 9 ? "9+" : unread}</span>}
          </button>
          <button onClick={() => setMenu(menu === "power" ? null : "power")} className={`flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-white/10 ${menu === "power" ? "bg-white/10" : ""}`}>
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-gradient-to-br from-neon to-accent font-display text-[9px] font-black text-black">VT</span>
            <Power size={14} className="text-crit" />
          </button>
        </div>
      </div>

      {menu && <div className="fixed inset-0 z-[6400]" onClick={() => setMenu(null)} />}
      {menu === "power" && (
        <div className="glass-strong anim-pop fixed right-2 top-11 z-[6500] w-64 rounded-xl p-2 shadow-2xl">
          <div className="flex items-center gap-3 border-b border-line px-2 pb-3 pt-1">
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-neon to-accent font-display text-sm font-black text-black">VT</span>
            <div>
              <div className="text-sm font-semibold text-white">Vaibhav Thakur</div>
              <div className="font-mono text-[10px] text-slate-500">vaibhav@sgv-node-01</div>
            </div>
          </div>
          <div className="mt-1 space-y-0.5">
            {([["lock", "Lock screen", <Lock size={14} />, ""], ["logout", "Log out", <LogOut size={14} />, ""], ["restart", "Restart", <RotateCw size={14} />, "text-warn"], ["shutdown", "Shut down", <Power size={14} />, "text-crit"]] as [PowerAction, string, React.ReactNode, string][]).map(([a, label, icon, cls]) => (
              <button key={a} onClick={() => (setMenu(null), onPower(a))} className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition hover:bg-white/10 ${cls || "text-slate-200"}`}>
                {icon}
                {label}
              </button>
            ))}
          </div>
        </div>
      )}
      {menu === "notif" && (
        <div className="glass-strong anim-pop fixed right-2 top-11 z-[6500] w-80 rounded-xl shadow-2xl">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="font-mono text-[11px] uppercase tracking-widest text-slate-400">Notifications</span>
            <button className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-crit" onClick={os.clearNotifications}><Trash2 size={11} />Clear</button>
          </div>
          <div className="max-h-80 overflow-auto">
            {os.notifications.length === 0 && <div className="p-8 text-center text-xs text-slate-500">All caught up ✔</div>}
            {os.notifications.map((n) => (
              <button key={n.id} onClick={() => (setMenu(null), n.app && os.openApp(n.app))} className="block w-full border-b border-line/60 px-3 py-2 text-left hover:bg-white/5" style={{ borderLeft: `3px solid ${SEV_COLOR[n.sev]}` }}>
                <div className="flex justify-between"><span className="text-xs font-semibold text-slate-100">{n.title}</span><span className="font-mono text-[9px] text-slate-500">{fmtTime(n.ts)}</span></div>
                <div className="truncate text-[11px] text-slate-400">{n.body}</div>
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
