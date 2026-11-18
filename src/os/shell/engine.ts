import * as fs from "../vfs";
import { SYS, canWrite } from "./sys";
import { SEC } from "./sec";
import { pad, globToRegex, type Cmd, type ShellCtx, type Kind, type Seg } from "./types";

const META: Record<string, Cmd> = {
  help: {
    cat: "System", desc: "List commands or show help for one", usage: "help [command]",
    run(args, c) {
      if (args[0]) return COMMANDS.man.run(args, c);
      const names = Object.keys(COMMANDS).sort();
      c.print(`Sugreev Shell (sgsh 5.2) — ${names.length} commands available`, "accent");
      c.print("Pipes (|), redirects (> >>), && ; chaining, globbing (*) and $VARS are supported.  Tab = autocomplete, ↑/↓ = history, Ctrl+C = abort, Ctrl+L = clear.\n", "dim");
      const order = ["Security", "Firewall", "Network", "Crypto", "Files", "Text", "System", "Process", "Desktop", "Power", "Fun"];
      order.forEach((cat) => {
        const list = names.filter((n) => COMMANDS[n].cat === cat);
        if (!list.length) return;
        c.print(`── ${cat} `.padEnd(60, "─"), "info");
        list.forEach((n) => c.segs([{ t: "  " + pad(n, 17), k: "ok" }, { t: COMMANDS[n].desc, k: "out" }]));
      });
      c.print("\nStart here:  neofetch · siem status · threats · vapt scan 192.168.56.101 · searchsploit apache · open siem", "accent");
    },
  },
  man: {
    cat: "System", desc: "Manual page for a command", usage: "man <command>",
    run(args, c) {
      const n = args[0];
      if (!n) return c.print("What manual page do you want?", "warn");
      const cmd = COMMANDS[n];
      if (!cmd) return c.print(`No manual entry for ${n}`, "err");
      c.print(`${n.toUpperCase()}(1)                 Sugreev Manual                 ${n.toUpperCase()}(1)\n`, "dim");
      c.print("NAME", "accent");
      c.print(`       ${n} - ${cmd.desc}\n`);
      c.print("SYNOPSIS", "accent");
      c.print(`       ${cmd.usage ?? n}\n`);
      c.print("CATEGORY", "accent");
      c.print(`       ${cmd.cat}\n`);
      c.print("AUTHOR", "accent");
      c.print("       Written for Sugreev OS by Vaibhav Thakur (github.com/Vaibhav222209).");
    },
  },
  alias: { cat: "System", desc: "Show command aliases", run: (_a, c) => Object.entries(ALIASES).forEach(([k, v]) => c.print(`alias ${k}='${v}'`)) },
  su: { cat: "System", desc: "Switch to root user", run: () => undefined },
  sudo: { cat: "System", desc: "Run a command as root", usage: "sudo <command> | sudo -i", run: () => undefined },
  bash: { cat: "System", desc: "Run a shell script", usage: "bash <script>", run: () => undefined },
  sh: { cat: "System", desc: "Run a shell script", usage: "sh <script>", run: () => undefined },
  source: { cat: "System", desc: "Run a script in current shell", run: () => undefined },
};

export const COMMANDS: Record<string, Cmd> = { ...SYS, ...SEC, ...META };

const ALIASES: Record<string, string> = {
  ll: "ls -la",
  la: "ls -A",
  l: "ls -CF",
  cls: "clear",
  "..": "cd ..",
  "...": "cd ../..",
  scan: "vapt scan",
  alerts: "siem alerts",
  poweroff: "shutdown",
  halt: "shutdown",
  restart: "reboot",
};

interface Tok {
  v: string;
  op?: string;
  glob?: boolean;
}

function readVar(line: string, i: number, env: Record<string, string>) {
  if (line[i + 1] === "{") {
    const end = line.indexOf("}", i);
    if (end > 0) {
      const body = line.slice(i + 2, end);
      const [name, def] = body.split(":-");
      return { val: env[name] || def || "", next: end + 1 };
    }
  }
  const m = /^(\?|\$|[A-Za-z_][A-Za-z0-9_]*|\d)/.exec(line.slice(i + 1));
  if (!m) return { val: "$", next: i + 1 };
  return { val: m[1] === "?" ? "0" : m[1] === "$" ? "4242" : env[m[1]] ?? "", next: i + 1 + m[1].length };
}

function tokenize(line: string, env: Record<string, string>): Tok[] {
  const toks: Tok[] = [];
  let cur = "";
  let has = false;
  let glob = false;
  let i = 0;
  const flush = () => {
    if (has) toks.push({ v: cur, glob });
    cur = "";
    has = false;
    glob = false;
  };
  while (i < line.length) {
    const ch = line[i];
    if (ch === "'") {
      has = true;
      i++;
      while (i < line.length && line[i] !== "'") cur += line[i++];
      i++;
      continue;
    }
    if (ch === '"') {
      has = true;
      i++;
      while (i < line.length && line[i] !== '"') {
        if (line[i] === "\\" && i + 1 < line.length) {
          cur += line[i + 1];
          i += 2;
          continue;
        }
        if (line[i] === "$") {
          const r = readVar(line, i, env);
          cur += r.val;
          i = r.next;
          continue;
        }
        cur += line[i++];
      }
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < line.length) {
      has = true;
      cur += line[i + 1];
      i += 2;
      continue;
    }
    if (ch === "$") {
      if (line.startsWith("$(date +%F)", i)) {
        cur += new Date().toISOString().slice(0, 10);
        has = true;
        i += 11;
        continue;
      }
      const r = readVar(line, i, env);
      cur += r.val;
      has = true;
      i = r.next;
      continue;
    }
    if (ch === "~" && !has && (i + 1 >= line.length || /[\s/]/.test(line[i + 1]))) {
      cur += env.HOME || fs.HOME;
      has = true;
      i++;
      continue;
    }
    if (ch === " " || ch === "\t") {
      flush();
      i++;
      continue;
    }
    if (ch === "#" && !has) break;
    if (ch === "|" || ch === ";" || ch === "&" || ch === ">") {
      flush();
      if (ch === "&" && line[i + 1] === "&") {
        toks.push({ v: "&&", op: "&&" });
        i += 2;
        continue;
      }
      if (ch === ">" && line[i + 1] === ">") {
        toks.push({ v: ">>", op: ">>" });
        i += 2;
        continue;
      }
      if (ch === "&") {
        i++;
        continue;
      }
      toks.push({ v: ch, op: ch });
      i++;
      continue;
    }
    if (ch === "*" || ch === "?") glob = true;
    cur += ch;
    has = true;
    i++;
  }
  flush();
  return toks;
}

function expandGlob(v: string, cwd: string): string[] {
  const idx = v.lastIndexOf("/");
  const dirPart = idx >= 0 ? v.slice(0, idx + 1) : "";
  const pat = v.slice(idx + 1);
  const list = fs.listDir(fs.resolvePath(dirPart || ".", cwd));
  if (!list) return [v];
  const re = globToRegex(pat);
  const m = list.filter((e) => re.test(e.name) && (pat.startsWith(".") || !e.name.startsWith("."))).map((e) => dirPart + e.name);
  return m.length ? m : [v];
}

type Out = { print: (t: string, k?: Kind) => void; segs: (s: Seg[]) => void };

async function runScript(path: string, args: string[], ctx: ShellCtx, needExec: boolean) {
  const n = fs.getNode(path);
  if (!n) return ctx.print(`bash: ${path}: No such file or directory`, "err");
  if (n.type === "dir") return ctx.print(`bash: ${path}: Is a directory`, "err");
  if (needExec && !(n.mode[3] === "x")) return ctx.print(`bash: ${path}: Permission denied (hint: chmod +x)`, "err");
  const text = n.content || "";
  if (text.startsWith("#!sugreev-builtin")) return execute(fs.basename(path) + " " + args.join(" "), ctx);
  if (fs.isBinary(text)) return ctx.print(`bash: ${path}: cannot execute binary file: Exec format error`, "err");
  const env = { ...ctx.env };
  args.forEach((a, i) => (env[String(i + 1)] = a));
  env["0"] = path;
  const sub = { ...ctx, env };
  for (const raw of text.split("\n")) {
    const l = raw.trim();
    if (!l || l.startsWith("#")) continue;
    await execute(l, sub);
  }
  Object.keys(sub.env).forEach((k) => /^\d$/.test(k) || (ctx.env[k] = sub.env[k]));
}

async function dispatch(words: string[], ctx: ShellCtx, out: Out, stdin: string[] | undefined): Promise<boolean> {
  let failed = false;
  const wrap: ShellCtx = {
    ...ctx,
    stdin,
    print: (t, k) => {
      if (k === "err") failed = true;
      out.print(t, k);
    },
    segs: (s) => out.segs(s),
  };
  let [name, ...args] = words;
  if (!name) return true;
  if (ALIASES[name]) {
    const t = tokenize(ALIASES[name], ctx.env).map((x) => x.v);
    [name, ...args] = [...t, ...args];
  }
  if (/^[A-Za-z_]\w*=/.test(name) && !args.length) {
    const i = name.indexOf("=");
    ctx.env[name.slice(0, i)] = name.slice(i + 1);
    return true;
  }
  if (name === "sudo") {
    const rest = args.filter((a, i) => !(a.startsWith("-") && i < 2 && ["-i", "-s", "-E", "-n"].includes(a)));
    const interactive = args.includes("-i") || args.includes("-s") || rest[0] === "su" || !rest.length;
    if (interactive) {
      wrap.print("[sudo] password for vaibhav: ********", "dim");
      ctx.setUser("root");
      ctx.setCwd("/root");
      return true;
    }
    return dispatch(rest, { ...ctx, root: true, user: "root" }, out, stdin);
  }
  if (name === "su") {
    wrap.print("Password: ********", "dim");
    ctx.setUser("root");
    ctx.setCwd("/root");
    return true;
  }
  if (name === "bash" || name === "sh" || name === "source") {
    if (!args[0]) return true;
    await runScript(fs.resolvePath(args[0], ctx.cwd), args.slice(1), wrap, false);
    return !failed;
  }
  if (name.startsWith("./") || name.startsWith("/") || name.startsWith("../")) {
    await runScript(fs.resolvePath(name, ctx.cwd), args, wrap, true);
    return !failed;
  }
  const cmd = COMMANDS[name];
  if (!cmd) {
    wrap.print(`sgsh: ${name}: command not found. Type 'help' to list commands.`, "err");
    return false;
  }
  await cmd.run(args, wrap);
  return !failed;
}

export async function execute(line: string, ctx: ShellCtx): Promise<boolean> {
  const toks = tokenize(line, ctx.env);
  if (!toks.length) return true;
  // split into groups by ; and &&
  const groups: { toks: Tok[]; sep: string }[] = [];
  let cur: Tok[] = [];
  let sep = ";";
  for (const t of toks) {
    if (t.op === ";" || t.op === "&&") {
      groups.push({ toks: cur, sep });
      cur = [];
      sep = t.op;
    } else cur.push(t);
  }
  groups.push({ toks: cur, sep });
  let ok = true;
  for (const g of groups) {
    if (g.sep === "&&" && !ok) break;
    if (!g.toks.length) continue;
    // pipeline
    const stages: Tok[][] = [[]];
    for (const t of g.toks) t.op === "|" ? stages.push([]) : stages[stages.length - 1].push(t);
    let stdin: string[] | undefined;
    for (let si = 0; si < stages.length; si++) {
      const stage = stages[si];
      const last = si === stages.length - 1;
      let redirect: { file: string; append: boolean } | null = null;
      const wordToks: Tok[] = [];
      for (let i = 0; i < stage.length; i++) {
        if (stage[i].op === ">" || stage[i].op === ">>") {
          redirect = { file: stage[i + 1]?.v ?? "", append: stage[i].op === ">>" };
          i++;
        } else wordToks.push(stage[i]);
      }
      const words = wordToks.flatMap((t, i) => (t.glob && i > 0 ? expandGlob(t.v, ctx.cwd) : [t.v]));
      const capture = !last || !!redirect;
      const buf: string[] = [];
      const out: Out = capture
        ? { print: (t) => void buf.push(...t.split("\n")), segs: (s) => void buf.push(s.map((x) => x.t).join("")) }
        : { print: ctx.print, segs: ctx.segs };
      ok = await dispatch(words, ctx, out, stdin);
      if (redirect) {
        const path = fs.resolvePath(redirect.file, ctx.cwd);
        if (!redirect.file) ctx.print("sgsh: syntax error near unexpected token `newline'", "err");
        else if (!canWrite({ ...ctx }, path)) ctx.print(`sgsh: ${redirect.file}: Permission denied`, "err");
        else {
          const prev = redirect.append ? fs.readFile(path) ?? "" : "";
          fs.writeFile(path, prev + buf.join("\n") + (buf.length ? "\n" : ""));
        }
        stdin = [];
      } else stdin = capture ? buf : undefined;
    }
  }
  return ok;
}

export function complete(word: string, isFirst: boolean, cwd: string): string[] {
  if (isFirst && !word.includes("/")) {
    return [...new Set([...Object.keys(COMMANDS), ...Object.keys(ALIASES)])].filter((n) => n.startsWith(word)).sort();
  }
  const idx = word.lastIndexOf("/");
  const dirPart = idx >= 0 ? word.slice(0, idx + 1) : "";
  const name = word.slice(idx + 1);
  const list = fs.listDir(fs.resolvePath(dirPart || ".", cwd));
  if (!list) return [];
  return list.filter((e) => e.name.startsWith(name) && (name.startsWith(".") || !e.name.startsWith("."))).map((e) => dirPart + e.name + (e.node.type === "dir" ? "/" : ""));
}
