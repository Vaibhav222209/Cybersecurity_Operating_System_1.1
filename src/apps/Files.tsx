import { useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, ArrowUp, FilePlus, FileText, Folder, FolderPlus, Grid2X2, Home, List, Pencil, Search, Terminal as TermIcon, Trash2, HardDrive, ScrollText, Settings2, Binary, FileCode, Shield, Download, Image as ImageIcon, FileBarChart, Wrench, FolderLock, Monitor } from "lucide-react";
import { useOS, useWin } from "../os/context";
import * as fs from "../os/vfs";

const PLACES: { name: string; path: string; icon: React.ReactNode }[] = [
  { name: "Home", path: fs.HOME, icon: <Home size={14} /> },
  { name: "Desktop", path: fs.HOME + "/Desktop", icon: <Monitor size={14} /> },
  { name: "Documents", path: fs.HOME + "/Documents", icon: <FileText size={14} /> },
  { name: "Downloads", path: fs.HOME + "/Downloads", icon: <Download size={14} /> },
  { name: "Pictures", path: fs.HOME + "/Pictures", icon: <ImageIcon size={14} /> },
  { name: "Reports", path: fs.HOME + "/Reports", icon: <FileBarChart size={14} /> },
  { name: "Tools", path: fs.HOME + "/Tools", icon: <Wrench size={14} /> },
  { name: "File System", path: "/", icon: <HardDrive size={14} /> },
  { name: "/etc", path: "/etc", icon: <Settings2 size={14} /> },
  { name: "/var/log", path: "/var/log", icon: <ScrollText size={14} /> },
  { name: "/opt/sugreev", path: "/opt/sugreev", icon: <Shield size={14} /> },
  { name: "/root (locked)", path: "/root", icon: <FolderLock size={14} /> },
];

function iconFor(name: string, node: fs.FSNode, size = 36) {
  if (node.type === "dir") return <Folder size={size} className="text-accent" fill="currentColor" fillOpacity={0.15} />;
  const ext = name.split(".").pop()?.toLowerCase();
  if (fs.isBinary(node.content)) return <Binary size={size} className="text-violet" />;
  if (ext === "sh") return <FileCode size={size} className="text-neon" />;
  if (ext === "log") return <ScrollText size={size} className="text-warn" />;
  if (ext === "md") return <FileText size={size} className="text-info" />;
  if (["conf", "yaml", "yml", "cfg", "rule"].includes(ext || "")) return <Settings2 size={size} className="text-amber-300" />;
  return <FileText size={size} className="text-slate-300" />;
}

export default function Files() {
  const os = useOS();
  const { props } = useWin();
  fs.useFsVersion();
  const [stack, setStack] = useState<string[]>([(props.path as string) || fs.HOME]);
  const [idx, setIdx] = useState(0);
  const [view, setView] = useState<"grid" | "list">("grid");
  const [sel, setSel] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [showHidden, setShowHidden] = useState(false);
  const [msg, setMsg] = useState("");
  const path = stack[idx];

  const nav = (p: string) => {
    const np = fs.resolvePath(p);
    const n = fs.getNode(np);
    if (!n) return setMsg(`'${p}' does not exist`);
    if (n.type === "file") return os.openFile(np);
    const s = stack.slice(0, idx + 1);
    s.push(np);
    setStack(s);
    setIdx(s.length - 1);
    setSel(null);
    setFilter("");
    setMsg("");
  };
  const locked = path === "/root" || path.startsWith("/root/");
  const entries = useMemo(() => {
    if (locked) return [];
    let l = fs.listDir(path) || [];
    if (!showHidden) l = l.filter((e) => !e.name.startsWith("."));
    if (filter) l = l.filter((e) => e.name.toLowerCase().includes(filter.toLowerCase()));
    return l;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, filter, showHidden, locked, fs.getNode(path)?.mtime, Object.keys(fs.getNode(path)?.children || {}).join("|")]);

  const parent = fs.getNode(path);
  const writable = !!parent && !locked && (parent.owner === "vaibhav" || parent.mode[8] === "w");
  const selNode = sel ? fs.getNode(path + "/" + sel) ?? fs.getNode(fs.resolvePath(sel, path)) : null;
  const deny = (what: string) => setMsg(`Permission denied: cannot ${what} here (owned by ${parent?.owner}). Use the terminal with sudo.`);

  const newItem = (dir: boolean) => {
    if (!writable) return deny("create items");
    const name = fs.uniqueName(path, dir ? "New Folder" : "untitled.txt");
    const full = (path === "/" ? "" : path) + "/" + name;
    dir ? fs.mkdir(full) : fs.writeFile(full, "");
    setSel(name);
    setMsg(`Created ${name}`);
  };
  const del = () => {
    if (!sel || !selNode) return;
    if (!writable || selNode.owner === "root") return deny("delete");
    if (!confirm(`Delete '${sel}'? This cannot be undone.`)) return;
    fs.remove((path === "/" ? "" : path) + "/" + sel);
    setSel(null);
    setMsg(`Deleted ${sel}`);
  };
  const ren = () => {
    if (!sel || !selNode) return;
    if (!writable || selNode.owner === "root") return deny("rename");
    const n = prompt("Rename to:", sel);
    if (!n || n === sel) return;
    if (fs.exists(path + "/" + n)) return setMsg(`'${n}' already exists`);
    fs.rename((path === "/" ? "" : path) + "/" + sel, (path === "/" ? "" : path) + "/" + n);
    setSel(n);
  };

  const crumbs = path === "/" ? [""] : path.split("/");
  const open = (name: string, node: fs.FSNode) => (node.type === "dir" ? nav((path === "/" ? "" : path) + "/" + name) : os.openFile((path === "/" ? "" : path) + "/" + name));

  return (
    <div className="flex h-full flex-col bg-base/80 text-sm" tabIndex={0} onKeyDown={(e) => (e.key === "Delete" ? del() : e.key === "F2" ? ren() : null)}>
      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-line bg-panel/70 px-2 py-1.5">
        <button className="btn !px-1.5" disabled={idx === 0} onClick={() => setIdx(idx - 1)} title="Back">
          <ArrowLeft size={14} />
        </button>
        <button className="btn !px-1.5" disabled={idx >= stack.length - 1} onClick={() => setIdx(idx + 1)} title="Forward">
          <ArrowRight size={14} />
        </button>
        <button className="btn !px-1.5" disabled={path === "/"} onClick={() => nav(fs.dirname(path))} title="Up">
          <ArrowUp size={14} />
        </button>
        <div className="flex min-w-[140px] flex-1 items-center gap-0.5 overflow-hidden rounded-md border border-line bg-ink px-2 py-1 font-mono text-[11px]">
          {crumbs.map((c, i) => (
            <span key={i} className="flex items-center">
              <button className="rounded px-1 text-slate-300 hover:bg-accent/10 hover:text-accent" onClick={() => nav(i === 0 ? "/" : crumbs.slice(0, i + 1).join("/"))}>
                {i === 0 ? "/" : c}
              </button>
              {i > 0 && i < crumbs.length - 1 && <span className="text-slate-600">/</span>}
            </span>
          ))}
        </div>
        <div className="relative">
          <Search size={12} className="absolute left-2 top-2 text-slate-500" />
          <input className="inp !w-32 !pl-6" placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        <button className="btn !px-1.5" onClick={() => newItem(true)} title="New folder">
          <FolderPlus size={14} />
        </button>
        <button className="btn !px-1.5" onClick={() => newItem(false)} title="New file">
          <FilePlus size={14} />
        </button>
        <button className="btn !px-1.5" disabled={!sel} onClick={ren} title="Rename (F2)">
          <Pencil size={14} />
        </button>
        <button className="btn btn-danger !px-1.5" disabled={!sel} onClick={del} title="Delete (Del)">
          <Trash2 size={14} />
        </button>
        <button className="btn !px-1.5" onClick={() => setView(view === "grid" ? "list" : "grid")} title="Toggle view">
          {view === "grid" ? <List size={14} /> : <Grid2X2 size={14} />}
        </button>
        <button className={`btn !px-1.5 ${showHidden ? "btn-primary" : ""}`} onClick={() => setShowHidden(!showHidden)} title="Show hidden files">
          .*
        </button>
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="hidden w-44 shrink-0 overflow-y-auto border-r border-line bg-panel/50 p-2 sm:block">
          <div className="mb-1 px-2 font-mono text-[10px] uppercase tracking-widest text-slate-500">Places</div>
          {PLACES.map((p) => (
            <button key={p.path} onClick={() => nav(p.path)} className={`flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs transition ${path === p.path ? "bg-accent/15 text-accent" : "text-slate-300 hover:bg-white/5"}`}>
              {p.icon}
              {p.name}
            </button>
          ))}
          <div className="mt-4 rounded-md border border-line p-2 text-[10px] text-slate-500">
            <div className="mb-1 flex justify-between">
              <span>/dev/nvme0n1p2</span>
              <span>49%</span>
            </div>
            <div className="h-1 rounded bg-line">
              <div className="h-full w-[49%] rounded bg-accent" />
            </div>
            <div className="mt-1">214 GB of 468 GB used</div>
          </div>
        </div>

        <div className="min-w-0 flex-1 overflow-auto p-3" onClick={() => setSel(null)}>
          {locked ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-slate-400">
              <FolderLock size={48} className="text-crit" />
              <div className="font-mono text-crit">Permission denied</div>
              <div className="max-w-xs text-xs">/root is owned by root. Elevate with <span className="font-mono text-accent">sudo -i</span> in the terminal.</div>
            </div>
          ) : entries.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-slate-500">This folder is empty</div>
          ) : view === "grid" ? (
            <div className="grid grid-cols-[repeat(auto-fill,minmax(92px,1fr))] gap-2">
              {entries.map((e) => (
                <button
                  key={e.name}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setSel(e.name);
                  }}
                  onDoubleClick={() => open(e.name, e.node)}
                  className={`flex flex-col items-center gap-1.5 rounded-lg border p-2 text-center transition ${sel === e.name ? "border-accent/60 bg-accent/10" : "border-transparent hover:bg-white/5"}`}
                >
                  {iconFor(e.name, e.node)}
                  <span className="line-clamp-2 w-full break-all text-[11px] leading-tight text-slate-200">{e.name}</span>
                </button>
              ))}
            </div>
          ) : (
            <table className="tbl w-full">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Size</th>
                  <th>Permissions</th>
                  <th>Owner</th>
                  <th>Modified</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.name} onClick={(ev) => (ev.stopPropagation(), setSel(e.name))} onDoubleClick={() => open(e.name, e.node)} className={`cursor-default ${sel === e.name ? "!bg-accent/10" : ""}`}>
                    <td>
                      <span className="flex items-center gap-2">
                        {iconFor(e.name, e.node, 14)}
                        {e.name}
                      </span>
                    </td>
                    <td className="font-mono text-slate-400">{e.node.type === "dir" ? "—" : fs.fmtSize(fs.sizeOf(e.node))}</td>
                    <td className="font-mono text-slate-400">{e.node.mode}</td>
                    <td className="text-slate-400">{e.node.owner}</td>
                    <td className="text-slate-500">{new Date(e.node.mtime).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-line bg-panel/70 px-3 py-1 font-mono text-[10px] text-slate-500">
        <span className="truncate">
          {sel && selNode ? `${sel} — ${selNode.type === "dir" ? "folder" : fs.fmtSize(fs.sizeOf(selNode))} — ${selNode.mode} ${selNode.owner}` : `${entries.length} items`}
          {msg && <span className="ml-3 text-warn">{msg}</span>}
        </span>
        <button className="flex items-center gap-1 hover:text-accent" onClick={() => os.openApp("terminal")}>
          <TermIcon size={11} /> terminal
        </button>
      </div>
    </div>
  );
}
