import { useCallback, useEffect, useRef, useState } from "react";
import { useOS, useWin } from "../os/context";
import { HOME, prettyPath } from "../os/vfs";
import { execute, complete } from "../os/shell/engine";
import type { Kind, Seg, ShellCtx } from "../os/shell/types";

interface Line {
  id: number;
  segs: Seg[];
}

const KIND_CLASS: Record<Kind, string> = {
  out: "text-slate-200",
  err: "text-red-400",
  ok: "text-emerald-400",
  warn: "text-amber-400",
  info: "text-sky-400",
  dim: "text-slate-500",
  accent: "text-accent",
  crit: "text-red-500 font-bold",
  prompt: "text-emerald-400",
};

const L = {
  S: [" ____  ", "/ ___| ", "\\___ \\ ", " ___) |", "|____/ "],
  U: [" _   _ ", "| | | |", "| | | |", "| |_| |", " \\___/ "],
  G: ["  ____ ", " / ___|", "| |  _ ", "| |_| |", " \\____|"],
  R: [" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"],
  E: [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
  V: ["__     __", "\\ \\   / /", " \\ \\ / / ", "  \\ V /  ", "   \\_/   "],
};
const BANNER = [0, 1, 2, 3, 4].map((r) => [L.S, L.U, L.G, L.R, L.E, L.E, L.V].map((l) => l[r]).join(""));

let lineId = 0;
const mk = (segs: Seg[]): Line => ({ id: lineId++, segs });

export default function Terminal() {
  const os = useOS();
  const { winId } = useWin();
  const [lines, setLines] = useState<Line[]>(() => [
    ...BANNER.map((b) => mk([{ t: b, k: "accent" }])),
    mk([{ t: "" }]),
    mk([{ t: "Sugreev OS 1.0 “Kishkindha” — Cybersecurity Edition", k: "ok" }]),
    mk([{ t: "Shell: sgsh 5.2   Kernel: 6.8.0-sgv   Author: Vaibhav Thakur (github.com/Vaibhav222209)", k: "dim" }]),
    mk([{ t: "Type ", k: "dim" }, { t: "help", k: "warn" }, { t: " for commands · ", k: "dim" }, { t: "neofetch", k: "warn" }, { t: " · ", k: "dim" }, { t: "siem status", k: "warn" }, { t: " · ", k: "dim" }, { t: "vapt scan 192.168.56.101", k: "warn" }]),
    mk([{ t: "" }]),
  ]);
  const [input, setInput] = useState("");
  const [cwd, setCwdState] = useState(HOME);
  const [user, setUserState] = useState("vaibhav");
  const [busy, setBusy] = useState(false);
  const history = useRef<string[]>(["siem status"]);
  const hIdx = useRef(-1);
  const abort = useRef(false);
  const env = useRef<Record<string, string>>({ HOME, USER: "vaibhav", LOGNAME: "vaibhav", SHELL: "/bin/sgsh", HOSTNAME: "sgv-node-01", PATH: "/usr/local/bin:/usr/bin:/bin:/opt/sugreev/bin", LANG: "en_IN.UTF-8", TERM: "xterm-256color", PWD: HOME, OLDPWD: HOME, EDITOR: "edit", SUGREEV_VERSION: "1.0" });
  const scroller = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const osRef = useRef(os);
  osRef.current = os;

  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, busy]);
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const push = useCallback((ls: Line[]) => setLines((p) => [...p, ...ls].slice(-2500)), []);

  const promptSegs = (u: string, p: string): Seg[] => [
    { t: `${u}@sgv-node-01`, k: u === "root" ? "crit" : "ok" },
    { t: ":", k: "out" },
    { t: prettyPath(p), k: "info" },
    { t: u === "root" ? "# " : "$ ", k: "out" },
  ];

  const sleep = useCallback(async (ms: number) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (abort.current) throw new Error("ABORT");
      await new Promise((r) => setTimeout(r, Math.min(50, Math.max(1, end - Date.now()))));
    }
    if (abort.current) throw new Error("ABORT");
  }, []);

  const run = async (cmd: string) => {
    push([mk([...promptSegs(user, cwd), { t: cmd, k: "out" }])]);
    if (!cmd.trim()) return;
    history.current.push(cmd);
    hIdx.current = -1;
    abort.current = false;
    setBusy(true);
    const ctx: ShellCtx = {
      print: (t, k) => push(t.split("\n").map((x) => mk([{ t: x, k: k ?? "out" }]))),
      segs: (s) => push([mk(s)]),
      clear: () => setLines([]),
      cwd,
      setCwd: (p) => {
        ctx.cwd = p;
        env.current.PWD = p;
        setCwdState(p);
      },
      user,
      setUser: (u) => {
        ctx.user = u;
        ctx.root = u === "root";
        env.current.USER = u;
        setUserState(u);
        if (u === "vaibhav") ctx.setCwd(HOME);
      },
      root: user === "root",
      sleep,
      os: osRef.current,
      history: history.current,
      env: env.current,
      closeSelf: () => osRef.current.closeWindow(winId),
      run: async (l) => void (await execute(l, ctx)),
    };
    try {
      await execute(cmd, ctx);
    } catch (e) {
      if (e instanceof Error && e.message === "ABORT") push([mk([{ t: "^C", k: "warn" }])]);
      else push([mk([{ t: `sgsh: internal error: ${(e as Error).message}`, k: "err" }])]);
    }
    setBusy(false);
    setTimeout(() => inputRef.current?.focus(), 0);
  };

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.ctrlKey && e.key.toLowerCase() === "c") {
      e.preventDefault();
      if (busy) abort.current = true;
      else {
        push([mk([...promptSegs(user, cwd), { t: input + "^C", k: "out" }])]);
        setInput("");
      }
      return;
    }
    if (busy) {
      e.preventDefault();
      return;
    }
    if (e.key === "Enter") {
      const c = input;
      setInput("");
      void run(c);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (!history.current.length) return;
      hIdx.current = hIdx.current < 0 ? history.current.length - 1 : Math.max(0, hIdx.current - 1);
      setInput(history.current[hIdx.current]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (hIdx.current < 0) return;
      hIdx.current++;
      if (hIdx.current >= history.current.length) {
        hIdx.current = -1;
        setInput("");
      } else setInput(history.current[hIdx.current]);
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    } else if (e.key === "u" && e.ctrlKey) {
      e.preventDefault();
      setInput("");
    } else if (e.key === "Tab") {
      e.preventDefault();
      const parts = input.split(" ");
      const word = parts[parts.length - 1];
      const isFirst = parts.length === 1;
      const m = complete(word, isFirst, cwd);
      if (!m.length) return;
      if (m.length === 1) {
        parts[parts.length - 1] = m[0];
        setInput(parts.join(" ") + (m[0].endsWith("/") ? "" : " "));
      } else {
        let pre = m[0];
        for (const x of m) while (!x.startsWith(pre)) pre = pre.slice(0, -1);
        if (pre.length > word.length) {
          parts[parts.length - 1] = pre;
          setInput(parts.join(" "));
        } else push([mk([...promptSegs(user, cwd), { t: input }]), mk([{ t: m.join("   "), k: "info" }])]);
      }
    }
  };

  return (
    <div className="flex h-full flex-col bg-[#03070b]/95" onClick={() => !window.getSelection()?.toString() && inputRef.current?.focus()}>
      <div ref={scroller} className="selectable term-out min-h-0 flex-1 overflow-y-auto p-3 pb-1">
        {lines.map((l) => (
          <div key={l.id} className="min-h-[1.45em]">
            {l.segs.map((s, i) => (
              <span key={i} className={KIND_CLASS[s.k ?? "out"]}>
                {s.t}
              </span>
            ))}
            {!l.segs.length && " "}
          </div>
        ))}
        <div className="flex items-center">
          {busy ? (
            <span className="text-slate-500">
              running… <span className="text-slate-600">(Ctrl+C to abort)</span> <span className="term-cursor" />
            </span>
          ) : (
            <>
              <span className="term-out whitespace-pre">
                {promptSegs(user, cwd).map((s, i) => (
                  <span key={i} className={KIND_CLASS[s.k ?? "out"]}>
                    {s.t}
                  </span>
                ))}
              </span>
              <input ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey} spellCheck={false} autoCapitalize="off" autoComplete="off" className="term-out min-w-0 flex-1 bg-transparent text-slate-100 caret-[var(--accent)] outline-none" />
            </>
          )}
          {busy && <input ref={inputRef} onKeyDown={onKey} className="absolute h-0 w-0 opacity-0" readOnly autoFocus />}
        </div>
      </div>
    </div>
  );
}
