import { memo, useMemo, type PointerEvent as RPE } from "react";
import { Minus, Square, X, Copy } from "lucide-react";
import { WinContext } from "../os/context";
import { appById } from "../os/registry";
import type { AppId } from "../os/context";

export interface WinState {
  id: string;
  app: AppId;
  title: string;
  x: number;
  y: number;
  w: number;
  h: number;
  z: number;
  min: boolean;
  max: boolean;
  props: Record<string, unknown>;
}

export const TOP = 40;
export const DOCK = 64;

interface Actions {
  focus: (id: string) => void;
  close: (id: string) => void;
  minimize: (id: string) => void;
  toggleMax: (id: string) => void;
  geom: (id: string, g: Partial<Pick<WinState, "x" | "y" | "w" | "h">>) => void;
}

function WindowFrameImpl({ win, active, actions }: { win: WinState; active: boolean; actions: Actions }) {
  const def = appById(win.app);
  const Comp = def.Comp;
  const ctx = useMemo(() => ({ winId: win.id, props: win.props }), [win.id, win.props]);

  const startDrag = (e: RPE) => {
    if ((e.target as HTMLElement).closest("button")) return;
    actions.focus(win.id);
    if (win.max) return;
    const sx = e.clientX;
    const sy = e.clientY;
    const ox = win.x;
    const oy = win.y;
    const move = (ev: PointerEvent) => {
      const nx = Math.min(window.innerWidth - 120, Math.max(DOCK - win.w + 120, ox + ev.clientX - sx));
      const ny = Math.min(window.innerHeight - 40, Math.max(TOP, oy + ev.clientY - sy));
      actions.geom(win.id, { x: nx, y: ny });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const startResize = (dir: string) => (e: RPE) => {
    e.preventDefault();
    e.stopPropagation();
    actions.focus(win.id);
    const sx = e.clientX;
    const sy = e.clientY;
    const o = { x: win.x, y: win.y, w: win.w, h: win.h };
    const minW = 380;
    const minH = 260;
    const move = (ev: PointerEvent) => {
      const dx = ev.clientX - sx;
      const dy = ev.clientY - sy;
      let { x, y, w, h } = o;
      if (dir.includes("e")) w = Math.max(minW, o.w + dx);
      if (dir.includes("s")) h = Math.max(minH, o.h + dy);
      if (dir.includes("w")) {
        w = Math.max(minW, o.w - dx);
        x = o.x + (o.w - w);
      }
      if (dir.includes("n")) {
        h = Math.max(minH, o.h - dy);
        y = Math.max(TOP, o.y + (o.h - h));
      }
      actions.geom(win.id, { x, y, w, h });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const Icon = def.icon;
  const style: React.CSSProperties = win.max ? { left: DOCK, top: TOP, right: 0, bottom: 0, zIndex: win.z } : { left: win.x, top: win.y, width: win.w, height: win.h, zIndex: win.z };

  return (
    <div
      style={{ ...style, display: win.min ? "none" : "flex" }}
      className={`glass-strong absolute flex-col overflow-hidden ${win.max ? "" : "rounded-xl"} ${active ? "win-shadow-active" : "win-shadow"} anim-pop`}
      onPointerDownCapture={() => !active && actions.focus(win.id)}
      onContextMenu={(e) => e.stopPropagation()}
    >
      <div onPointerDown={startDrag} onDoubleClick={() => actions.toggleMax(win.id)} className={`flex h-9 shrink-0 cursor-default items-center gap-2 border-b px-3 ${active ? "border-accent/30 bg-gradient-to-r from-accent/10 via-transparent to-transparent" : "border-line"}`}>
        <Icon size={14} style={{ color: def.color }} />
        <span className={`truncate font-mono text-[11px] uppercase tracking-[0.14em] ${active ? "text-slate-100" : "text-slate-500"}`}>{win.title}</span>
        <div className="ml-auto flex items-center gap-1">
          <button className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-white" onClick={() => actions.minimize(win.id)} title="Minimize"><Minus size={13} /></button>
          <button className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-white" onClick={() => actions.toggleMax(win.id)} title="Maximize">{win.max ? <Copy size={11} /> : <Square size={11} />}</button>
          <button className="rounded p-1 text-slate-400 hover:bg-crit/80 hover:text-white" onClick={() => actions.close(win.id)} title="Close"><X size={13} /></button>
        </div>
      </div>
      <div className="relative min-h-0 flex-1">
        <WinContext.Provider value={ctx}>
          <Comp />
        </WinContext.Provider>
      </div>
      {!win.max && (
        <>
          <div onPointerDown={startResize("e")} className="absolute right-0 top-9 bottom-3 w-1.5 cursor-ew-resize" />
          <div onPointerDown={startResize("w")} className="absolute left-0 top-9 bottom-3 w-1.5 cursor-ew-resize" />
          <div onPointerDown={startResize("s")} className="absolute bottom-0 left-3 right-3 h-1.5 cursor-ns-resize" />
          <div onPointerDown={startResize("n")} className="absolute left-3 right-3 top-0 h-1 cursor-ns-resize" />
          <div onPointerDown={startResize("se")} className="absolute bottom-0 right-0 h-3.5 w-3.5 cursor-nwse-resize" />
          <div onPointerDown={startResize("sw")} className="absolute bottom-0 left-0 h-3.5 w-3.5 cursor-nesw-resize" />
        </>
      )}
    </div>
  );
}

export const WindowFrame = memo(WindowFrameImpl);
