import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Eye, FilePlus, FolderOpen, Save, SaveAll } from "lucide-react";
import { useOS, useWin } from "../os/context";
import * as fs from "../os/vfs";

function Markdown({ text }: { text: string }) {
  const out: React.ReactNode[] = [];
  const lines = text.split("\n");
  let code = false;
  let buf: string[] = [];
  const inline = (s: string) =>
    s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, i) => (p.startsWith("**") ? <strong key={i} className="text-white">{p.slice(2, -2)}</strong> : p.startsWith("`") ? <code key={i} className="rounded bg-raised px-1 font-mono text-[12px] text-neon">{p.slice(1, -1)}</code> : <Fragment key={i}>{p}</Fragment>));
  lines.forEach((l, i) => {
    if (l.startsWith("```")) {
      if (code) out.push(<pre key={i} className="my-2 overflow-x-auto rounded-md border border-line bg-ink p-3 font-mono text-[12px] text-emerald-300">{buf.join("\n")}</pre>);
      buf = [];
      code = !code;
      return;
    }
    if (code) return void buf.push(l);
    if (l.startsWith("### ")) out.push(<h3 key={i} className="mt-4 text-sm font-semibold text-accent">{inline(l.slice(4))}</h3>);
    else if (l.startsWith("## ")) out.push(<h2 key={i} className="mt-5 border-b border-line pb-1 text-base font-semibold text-white">{inline(l.slice(3))}</h2>);
    else if (l.startsWith("# ")) out.push(<h1 key={i} className="mt-2 font-display text-xl font-bold text-accent">{inline(l.slice(2))}</h1>);
    else if (/^[-*] /.test(l)) out.push(<div key={i} className="ml-4 flex gap-2"><span className="text-accent">▸</span><span>{inline(l.slice(2))}</span></div>);
    else if (/^\d+\. /.test(l)) out.push(<div key={i} className="ml-4">{inline(l)}</div>);
    else if (l.startsWith("|")) out.push(<div key={i} className="font-mono text-[12px] text-slate-300">{l}</div>);
    else if (l.startsWith("> ")) out.push(<div key={i} className="my-1 border-l-2 border-accent pl-3 text-slate-400">{inline(l.slice(2))}</div>);
    else if (l.trim() === "---") out.push(<hr key={i} className="my-3 border-line" />);
    else out.push(<div key={i} className="min-h-[1.2em]">{inline(l)}</div>);
  });
  return <div className="selectable space-y-0.5 p-4 text-[13px] leading-relaxed text-slate-300">{out}</div>;
}

export default function Editor() {
  const os = useOS();
  const { props } = useWin();
  const initial = (props.path as string) || "";
  const [path, setPath] = useState(initial);
  const [text, setText] = useState(() => (initial ? fs.readFile(initial) ?? "" : ""));
  const [saved, setSaved] = useState(text);
  const [cursor, setCursor] = useState({ ln: 1, col: 1 });
  const [preview, setPreview] = useState(false);
  const [msg, setMsg] = useState("");
  const gutter = useRef<HTMLDivElement>(null);
  const area = useRef<HTMLTextAreaElement>(null);
  const binary = fs.isBinary(text);
  const dirty = text !== saved;
  const lines = useMemo(() => text.split("\n").length, [text]);
  const isMd = path.endsWith(".md");

  useEffect(() => {
    area.current?.focus();
  }, []);

  const save = (as = false) => {
    let p = path;
    if (!p || as) {
      const v = prompt("Save as (absolute path):", p || fs.HOME + "/untitled.txt");
      if (!v) return;
      p = fs.resolvePath(v);
    }
    const parent = fs.getNode(fs.dirname(p));
    if (!parent || parent.type !== "dir") return setMsg("Directory does not exist");
    if (parent.owner === "root" && parent.mode[8] !== "w") return setMsg("Permission denied — directory owned by root");
    const ex = fs.getNode(p);
    if (ex && ex.owner === "root") return setMsg("Permission denied — file owned by root (read-only)");
    if (fs.writeFile(p, text)) {
      setPath(p);
      setSaved(text);
      setMsg("Saved " + p);
    } else setMsg("Could not save file");
  };
  const openPath = () => {
    const v = prompt("Open file (path):", fs.HOME + "/");
    if (!v) return;
    const p = fs.resolvePath(v);
    if (p === "/etc/shadow" || p.startsWith("/root")) return setMsg("Permission denied");
    const t = fs.readFile(p);
    if (t === null) return setMsg("File not found");
    setPath(p);
    setText(t);
    setSaved(t);
  };

  return (
    <div
      className="flex h-full flex-col bg-ink/90"
      onKeyDown={(e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "s") {
          e.preventDefault();
          save();
        }
      }}
    >
      <div className="flex items-center gap-1.5 border-b border-line bg-panel/70 px-2 py-1.5">
        <button className="btn" onClick={() => { setPath(""); setText(""); setSaved(""); }}><FilePlus size={13} />New</button>
        <button className="btn" onClick={openPath}><FolderOpen size={13} />Open</button>
        <button className="btn btn-primary" onClick={() => save()}><Save size={13} />Save</button>
        <button className="btn" onClick={() => save(true)}><SaveAll size={13} />Save As</button>
        {isMd && <button className={`btn ${preview ? "btn-primary" : ""}`} onClick={() => setPreview(!preview)}><Eye size={13} />Preview</button>}
        <div className="ml-auto truncate font-mono text-[11px] text-slate-400">{path || "untitled"}{dirty && <span className="ml-1 text-warn">●</span>}</div>
      </div>
      <div className="relative flex min-h-0 flex-1">
        {binary ? (
          <div className="flex flex-1 items-center justify-center font-mono text-xs text-slate-500">Binary / builtin executable — cannot be edited</div>
        ) : preview ? (
          <div className="flex-1 overflow-auto"><Markdown text={text} /></div>
        ) : (
          <>
            <div ref={gutter} className="w-12 shrink-0 overflow-hidden border-r border-line bg-panel/40 py-3 pr-2 text-right font-mono text-[12px] leading-[1.55] text-slate-600">
              {Array.from({ length: lines }, (_, i) => (
                <div key={i} className={cursor.ln === i + 1 ? "text-accent" : ""}>{i + 1}</div>
              ))}
            </div>
            <textarea
              ref={area}
              value={text}
              spellCheck={false}
              wrap="off"
              onChange={(e) => setText(e.target.value)}
              onScroll={(e) => gutter.current && (gutter.current.scrollTop = e.currentTarget.scrollTop)}
              onKeyUp={(e) => {
                const v = e.currentTarget.value.slice(0, e.currentTarget.selectionStart);
                const l = v.split("\n");
                setCursor({ ln: l.length, col: l[l.length - 1].length + 1 });
              }}
              onClick={(e) => {
                const v = e.currentTarget.value.slice(0, e.currentTarget.selectionStart);
                const l = v.split("\n");
                setCursor({ ln: l.length, col: l[l.length - 1].length + 1 });
              }}
              onKeyDown={(e) => {
                if (e.key === "Tab") {
                  e.preventDefault();
                  const t = e.currentTarget;
                  const s = t.selectionStart;
                  setText(text.slice(0, s) + "  " + text.slice(t.selectionEnd));
                  requestAnimationFrame(() => (t.selectionStart = t.selectionEnd = s + 2));
                }
              }}
              className="selectable min-w-0 flex-1 resize-none bg-transparent py-3 pl-3 font-mono text-[12px] leading-[1.55] text-slate-200 caret-[var(--accent)] outline-none"
            />
          </>
        )}
      </div>
      <div className="flex items-center justify-between border-t border-line bg-panel/70 px-3 py-1 font-mono text-[10px] text-slate-500">
        <span>Ln {cursor.ln}, Col {cursor.col} · {text.length} chars · {lines} lines · UTF-8</span>
        <span className="text-warn">{msg}</span>
        <button className="hover:text-accent" onClick={() => os.openApp("files")}>files</button>
      </div>
    </div>
  );
}
