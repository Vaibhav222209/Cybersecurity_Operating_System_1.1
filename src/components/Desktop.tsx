import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FileText, Folder, FolderOpen, Wrench, FileBarChart } from "lucide-react";
import { OSContext, ACCENTS, type AppId, type Notification, type OSApi, type PowerAction, type Settings, type Wallpaper as WP } from "../os/context";
import { appById } from "../os/registry";
import { setAppProcs, useKernel, type Severity } from "../os/kernel";
import { basename, HOME } from "../os/vfs";
import { WindowFrame, DOCK, TOP, type WinState } from "./WindowFrame";
import { TopBar } from "./TopBar";
import { Dock } from "./Dock";
import { Launcher } from "./Launcher";
import { Wallpaper } from "./Wallpaper";
import { ContextMenu, ConfirmPower, DesktopWidget, Toasts } from "./Overlays";

function AlertWatcher({ notify }: { notify: OSApi["notify"] }) {
  const k = useKernel();
  const last = useRef(k.alerts[0]?.id ?? 0);
  useEffect(() => {
    const fresh = k.alerts.filter((a) => a.id > last.current);
    if (!fresh.length) return;
    last.current = Math.max(...fresh.map((a) => a.id));
    fresh
      .filter((a) => a.sev === "critical")
      .slice(0, 2)
      .forEach((a) => notify({ title: a.title, body: `${a.srcIp} (${a.country}) — ${a.msg}`, sev: a.sev as Severity, app: "siem" }));
  }, [k.alerts, notify]);
  return null;
}

const ICONS = [
  { name: "Home", icon: FolderOpen, path: HOME, color: "#ffb020" },
  { name: "README.md", icon: FileText, path: HOME + "/README.md", color: "#38bdf8" },
  { name: "Reports", icon: FileBarChart, path: HOME + "/Reports", color: "#ff7a3c" },
  { name: "Tools", icon: Wrench, path: HOME + "/Tools", color: "#00ff9c" },
  { name: "Documents", icon: Folder, path: HOME + "/Documents", color: "#a78bfa" },
];

export default function Desktop({ settings, setSettings, onPower }: { settings: Settings; setSettings: (p: Partial<Settings>) => void; onPower: (a: PowerAction) => void }) {
  const [wins, setWins] = useState<WinState[]>([]);
  const winsRef = useRef(wins);
  winsRef.current = wins;
  const zRef = useRef(10);
  const idRef = useRef(1);
  const nid = useRef(1);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  const [launcher, setLauncher] = useState(false);
  const [notifs, setNotifs] = useState<Notification[]>([]);
  const [toasts, setToasts] = useState<Notification[]>([]);
  const [confirm, setConfirm] = useState<PowerAction | null>(null);
  const [ctx, setCtx] = useState<{ x: number; y: number } | null>(null);
  const [selIcon, setSelIcon] = useState<string | null>(null);

  const activeId = useMemo(() => {
    const vis = wins.filter((w) => !w.min);
    return vis.length ? vis.reduce((a, b) => (a.z > b.z ? a : b)).id : null;
  }, [wins]);

  useEffect(() => {
    setAppProcs(wins.map((w) => ({ id: w.id, app: w.app })));
  }, [wins]);

  const focus = useCallback((id: string) => setWins((p) => p.map((w) => (w.id === id ? { ...w, z: ++zRef.current, min: false } : w))), []);
  const close = useCallback((id: string) => setWins((p) => p.filter((w) => w.id !== id)), []);
  const minimize = useCallback((id: string) => setWins((p) => p.map((w) => (w.id === id ? { ...w, min: true } : w))), []);
  const toggleMax = useCallback((id: string) => setWins((p) => p.map((w) => (w.id === id ? { ...w, max: !w.max } : w))), []);
  const geom = useCallback((id: string, g: Partial<WinState>) => setWins((p) => p.map((w) => (w.id === id ? { ...w, ...g } : w))), []);
  const actions = useMemo(() => ({ focus, close, minimize, toggleMax, geom }), [focus, close, minimize, toggleMax, geom]);

  const titleFor = (app: AppId, props: Record<string, unknown>) => {
    const d = appById(app);
    if (app === "editor") return `Editor — ${props.path ? basename(props.path as string) : "untitled"}`;
    if (app === "files" && props.path) return `Files — ${basename(props.path as string) || "/"}`;
    return d.title;
  };

  const openApp = useCallback((app: AppId, props: Record<string, unknown> = {}) => {
    const def = appById(app);
    const cur = winsRef.current;
    const existing = !def.multi ? cur.find((w) => w.app === app) : app === "editor" && props.path ? cur.find((w) => w.app === "editor" && w.props.path === props.path) : undefined;
    if (existing) {
      setWins((p) => p.map((w) => (w.id === existing.id ? { ...w, z: ++zRef.current, min: false } : w)));
      return;
    }
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = Math.min(def.w, vw - DOCK - 24);
    const h = Math.min(def.h, vh - TOP - 24);
    const n = cur.filter((x) => !x.min).length;
    const x = Math.max(DOCK + 12, Math.min(vw - w - 12, DOCK + 40 + (n % 7) * 30));
    const y = Math.max(TOP + 8, Math.min(vh - h - 12, TOP + 28 + (n % 7) * 28));
    const win: WinState = { id: "w" + idRef.current++, app, title: titleFor(app, props), x, y, w, h, z: ++zRef.current, min: false, max: vw < 820, props };
    setWins((p) => [...p, win]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openFile = useCallback((path: string) => openApp("editor", { path }), [openApp]);

  const notify = useCallback((n: { title: string; body: string; sev?: Severity; app?: AppId }) => {
    const item: Notification = { id: nid.current++, ts: Date.now(), title: n.title, body: n.body, sev: n.sev ?? "info", app: n.app };
    setNotifs((p) => [item, ...p].slice(0, 30));
    if (settingsRef.current.notifications) setToasts((p) => [item, ...p].slice(0, 3));
  }, []);

  const api: OSApi = useMemo(
    () => ({
      openApp,
      openFile,
      closeWindow: close,
      notify,
      power: onPower,
      settings,
      setSettings,
      notifications: notifs,
      clearNotifications: () => setNotifs([]),
    }),
    [openApp, openFile, close, notify, onPower, settings, setSettings, notifs],
  );

  // boot-up actions
  const booted = useRef(false);
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    openApp("terminal");
    setTimeout(() => notify({ title: "Welcome, Vaibhav", body: "SIEM engine online · IDS in prevention mode · all sensors healthy.", sev: "info", app: "siem" }), 600);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.altKey && e.key.toLowerCase() === "t") {
        e.preventDefault();
        openApp("terminal");
      }
      if (e.key === "Escape") setLauncher(false);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [openApp]);

  const onDock = (id: AppId) => {
    const mine = wins.filter((w) => w.app === id);
    if (!mine.length) return openApp(id);
    const top = mine.reduce((a, b) => (a.z > b.z ? a : b));
    if (top.id === activeId && !top.min) {
      const def = appById(id);
      if (def.multi && mine.length === 1) return openApp(id); // second click on multi-instance apps opens another
      minimize(top.id);
    } else focus(top.id);
  };
  const onWinClick = (id: string) => (id === activeId ? minimize(id) : focus(id));
  const showDesktop = () => setWins((p) => p.map((w) => ({ ...w, min: true })));
  const cycleWall = () => {
    const order: WP[] = ["matrix", "grid", "aurora"];
    setSettings({ wallpaper: order[(order.indexOf(settings.wallpaper) + 1) % 3] });
  };
  const cycleAccent = () => {
    const i = ACCENTS.findIndex((a) => a.value === settings.accent);
    setSettings({ accent: ACCENTS[(i + 1) % ACCENTS.length].value });
  };
  const confirmCb = useCallback(() => {
    setConfirm((c) => {
      if (c) setTimeout(() => onPower(c), 0);
      return null;
    });
  }, [onPower]);
  const cancelCb = useCallback(() => setConfirm(null), []);
  const dismiss = useCallback((id: number) => setToasts((p) => p.filter((t) => t.id !== id)), []);

  return (
    <OSContext.Provider value={api}>
      <div className="absolute inset-0 overflow-hidden" onContextMenu={(e) => (e.preventDefault(), setCtx({ x: e.clientX, y: e.clientY }))} onClick={() => setSelIcon(null)}>
        <Wallpaper kind={settings.wallpaper} animate={settings.animations} accent={settings.accent} />
        <DesktopWidget />
        <div className="absolute left-[84px] top-[56px] z-[1] flex flex-col gap-2">
          {ICONS.map((i) => {
            const Icon = i.icon;
            return (
              <button
                key={i.name}
                onClick={(e) => (e.stopPropagation(), setSelIcon(i.name))}
                onDoubleClick={() => (i.path.includes(".") ? openFile(i.path) : openApp("files", { path: i.path }))}
                className={`flex w-[78px] flex-col items-center gap-1 rounded-lg p-2 transition ${selIcon === i.name ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-white/5"}`}
              >
                <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-black/30 backdrop-blur-sm" style={{ boxShadow: `inset 0 0 0 1px ${i.color}55` }}>
                  <Icon size={22} style={{ color: i.color }} />
                </span>
                <span className="font-mono text-[10px] text-slate-200 [text-shadow:0_1px_4px_#000]">{i.name}</span>
              </button>
            );
          })}
        </div>

        {wins.map((w) => (
          <WindowFrame key={w.id} win={w} active={w.id === activeId} actions={actions} />
        ))}

        <Dock wins={wins} activeId={activeId} onApp={onDock} onLauncher={() => setLauncher((v) => !v)} onShowDesktop={showDesktop} />
        <TopBar wins={wins} activeId={activeId} launcherOpen={launcher} toggleLauncher={() => setLauncher((v) => !v)} onWinClick={onWinClick} onPower={setConfirm} />
        {launcher && <Launcher onClose={() => setLauncher(false)} onOpen={(id) => openApp(id)} onPower={setConfirm} />}
        <Toasts toasts={toasts} onDismiss={dismiss} onClick={(n) => (dismiss(n.id), n.app && openApp(n.app))} />
        <AlertWatcher notify={notify} />
        {ctx && (
          <ContextMenu
            x={ctx.x}
            y={ctx.y}
            onClose={() => setCtx(null)}
            items={[
              { label: "New Terminal", onClick: () => openApp("terminal") },
              { label: "Open Files", onClick: () => openApp("files") },
              { label: "Open Browser", onClick: () => openApp("browser") },
              "sep",
              { label: "Change wallpaper", onClick: cycleWall },
              { label: "Change accent colour", onClick: cycleAccent },
              { label: "Settings", onClick: () => openApp("settings") },
              "sep",
              { label: "Lock screen", onClick: () => setConfirm("lock") },
              { label: "Log out", onClick: () => setConfirm("logout"), danger: true },
            ]}
          />
        )}
        {confirm && <ConfirmPower action={confirm} onCancel={cancelCb} onConfirm={confirmCb} />}
      </div>
    </OSContext.Provider>
  );
}
