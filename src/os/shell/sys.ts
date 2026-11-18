import * as fs from "../vfs";
import { getSnapshot, killProc, injectEvent, threatLabel, CPU_INFO } from "../kernel";
import { md5, sha, b64enc, b64dec, type ShaAlgo } from "../hash";
import { parseFlags, pad, lpad, fmtLsDate, syslogDate, globToRegex, type Cmd, type ShellCtx, type Seg } from "./types";
import type { AppId } from "../context";

const P = (c: ShellCtx, p: string) => fs.resolvePath(p, c.cwd);
const isDeny = (c: ShellCtx, path: string) => !c.root && (path === "/root" || path.startsWith("/root/") || path === "/etc/shadow");
export function canWrite(c: ShellCtx, path: string) {
  if (c.root) return true;
  const parent = fs.getNode(fs.dirname(path));
  if (!parent) return false;
  return parent.owner === "vaibhav" || parent.mode[8] === "w";
}
function errPerm(c: ShellCtx, cmd: string, p: string) {
  c.print(`${cmd}: cannot access '${p}': Permission denied`, "err");
}
function inputText(files: string[], c: ShellCtx, cmd: string): string[] | null {
  if (!files.length) return c.stdin ?? [];
  const out: string[] = [];
  for (const f of files) {
    const path = P(c, f);
    if (isDeny(c, path)) {
      c.print(`${cmd}: ${f}: Permission denied`, "err");
      return null;
    }
    const t = fs.readFile(path);
    if (t === null) {
      c.print(`${cmd}: ${f}: ${fs.exists(path) ? "Is a directory" : "No such file or directory"}`, "err");
      return null;
    }
    if (fs.isBinary(t)) {
      c.print(`${cmd}: ${f}: binary file matches`, "warn");
      return null;
    }
    out.push(...t.replace(/\n$/, "").split("\n"));
  }
  return out;
}
const kindOf = (n: fs.FSNode): Seg["k"] => (n.type === "dir" ? "accent" : n.mode.includes("x") && n.mode[3] === "x" ? "ok" : "out");

const dateStr = () => new Date().toString().replace(/ GMT.*/, "");

const LOGO = [
  "      ▄████████████▄      ",
  "    ▄██▀▀▀▀▀▀▀▀▀▀▀▀██▄    ",
  "   ███   ▄▄▄▄▄▄▄▄▄   ███  ",
  "   ███  █▀▀     ▀▀█  ███  ",
  "   ███  █▄▄▄▄▄▄▄▄    ███  ",
  "   ███       ▀▀▀▀█▄  ███  ",
  "   ███  ▄▄      ▄█▀  ███  ",
  "   ███   ▀▀▀▀▀▀▀▀    ███  ",
  "    ▀██▄            ▄██▀  ",
  "      ▀██▄        ▄██▀    ",
  "        ▀██▄    ▄██▀      ",
  "          ▀██████▀        ",
];

const APPS: Record<string, AppId> = {
  terminal: "terminal", term: "terminal", files: "files", fm: "files", browser: "browser", web: "browser", siem: "siem", threats: "threats", threat: "threats", vapt: "vapt", monitor: "monitor", sysmon: "monitor", editor: "editor", crypto: "crypto", settings: "settings", about: "about",
};

const SERVICES: [string, string, string][] = [
  ["sgv-siemd", "Sugreev SIEM Correlation Daemon", "412"],
  ["sgv-ids", "Sugreev IDS/IPS Engine", "418"],
  ["sgv-firewalld", "Sugreev Firewall Daemon", "421"],
  ["ssh", "OpenBSD Secure Shell server", "455"],
  ["nginx", "A high performance web server", "1204"],
  ["postgresql", "PostgreSQL RDBMS", "1230"],
  ["fail2ban", "Fail2Ban Service", "1301"],
  ["clamav-daemon", "Clam AntiVirus userspace daemon", "1480"],
  ["auditd", "Security Auditing Service", "1402"],
  ["cron", "Regular background program processing daemon", "1305"],
];

const FORTUNES = [
  "The only truly secure system is one that is powered off. — Gene Spafford",
  "Amateurs hack systems, professionals hack people. — Bruce Schneier",
  "Security is a process, not a product. — Bruce Schneier",
  "There are only two types of companies: those that have been hacked, and those that will be.",
  "Passwords are like underwear: change them often and don't share them.",
  "Trust, but verify. Then verify again, then log it.",
  "If you think technology can solve your security problems, you don't understand the problems. — Bruce Schneier",
  "Sugreev: the vanara king who guarded Kishkindha. Your SIEM guards your kingdom.",
];

export const SYS: Record<string, Cmd> = {
  ls: {
    cat: "Files", desc: "List directory contents", usage: "ls [-lah] [path...]",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const targets = rest.length ? rest : ["."];
      targets.forEach((t, ti) => {
        const path = P(c, t);
        const node = fs.getNode(path);
        if (!node) return c.print(`ls: cannot access '${t}': No such file or directory`, "err");
        if (isDeny(c, path)) return errPerm(c, "ls", t);
        if (targets.length > 1) c.print((ti ? "\n" : "") + t + ":", "dim");
        let entries = node.type === "dir" ? fs.listDir(path)! : [{ name: fs.basename(path), node }];
        if (!flags.has("a")) entries = entries.filter((e) => !e.name.startsWith("."));
        else if (node.type === "dir") entries = [{ name: ".", node }, { name: "..", node }, ...entries];
        if (flags.has("l")) {
          c.print(`total ${entries.length * 4}`, "dim");
          entries.forEach((e) => {
            const size = fs.sizeOf(e.node);
            const sz = flags.has("h") ? fs.fmtSize(size).replace(" ", "") : String(size);
            c.segs([{ t: `${e.node.mode} ${lpad(e.node.type === "dir" ? 2 : 1, 2)} ${pad(e.node.owner, 8)} ${pad(e.node.owner, 8)} ${lpad(sz, 6)} ${fmtLsDate(e.node.mtime)} `, k: "dim" }, { t: e.name, k: kindOf(e.node) }]);
          });
        } else if (entries.length) {
          const s: Seg[] = [];
          entries.forEach((e) => {
            s.push({ t: e.name, k: kindOf(e.node) });
            s.push({ t: "  " });
          });
          c.segs(s);
        }
      });
    },
  },
  cd: {
    cat: "Files", desc: "Change directory", usage: "cd [dir]",
    run(args, c) {
      const t = args[0] ?? "~";
      const path = P(c, t === "-" ? c.env.OLDPWD || "~" : t);
      const n = fs.getNode(path);
      if (!n) return c.print(`bash: cd: ${t}: No such file or directory`, "err");
      if (n.type !== "dir") return c.print(`bash: cd: ${t}: Not a directory`, "err");
      if (isDeny(c, path)) return c.print(`bash: cd: ${t}: Permission denied`, "err");
      c.env.OLDPWD = c.cwd;
      c.setCwd(path);
    },
  },
  pwd: { cat: "Files", desc: "Print working directory", run: (_a, c) => c.print(c.cwd) },
  cat: {
    cat: "Files", desc: "Print file contents", usage: "cat [-n] file...",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const lines = inputText(rest, c, "cat");
      if (!lines) return;
      lines.forEach((l, i) => c.print(flags.has("n") ? `${lpad(i + 1, 6)}  ${l}` : l));
    },
  },
  mkdir: {
    cat: "Files", desc: "Create directories", usage: "mkdir [-p] dir...",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      if (!rest.length) return c.print("mkdir: missing operand", "err");
      rest.forEach((d) => {
        const p = P(c, d);
        if (fs.exists(p) && !flags.has("p")) return c.print(`mkdir: cannot create directory '${d}': File exists`, "err");
        if (!canWrite(c, p) && !flags.has("p")) return c.print(`mkdir: cannot create directory '${d}': Permission denied`, "err");
        if (!fs.mkdir(p, flags.has("p"))) c.print(`mkdir: cannot create directory '${d}': No such file or directory`, "err");
      });
    },
  },
  rmdir: {
    cat: "Files", desc: "Remove empty directories", run(args, c) {
      args.forEach((d) => {
        const p = P(c, d);
        const n = fs.getNode(p);
        if (!n) return c.print(`rmdir: failed to remove '${d}': No such file or directory`, "err");
        if (n.type !== "dir") return c.print(`rmdir: failed to remove '${d}': Not a directory`, "err");
        if (Object.keys(n.children || {}).length) return c.print(`rmdir: failed to remove '${d}': Directory not empty`, "err");
        if (!canWrite(c, p)) return c.print(`rmdir: failed to remove '${d}': Permission denied`, "err");
        fs.remove(p);
      });
    },
  },
  touch: {
    cat: "Files", desc: "Create empty file / update timestamp", usage: "touch file...",
    run(args, c) {
      args.forEach((f) => {
        const p = P(c, f);
        if (!canWrite(c, p)) return c.print(`touch: cannot touch '${f}': Permission denied`, "err");
        if (!fs.touch(p)) c.print(`touch: cannot touch '${f}': No such file or directory`, "err");
      });
    },
  },
  rm: {
    cat: "Files", desc: "Remove files or directories", usage: "rm [-rf] path...",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      if (!rest.length) return c.print("rm: missing operand", "err");
      rest.forEach((f) => {
        const p = P(c, f);
        if (p === "/" || p === "/home" || p === fs.HOME) return c.print(`rm: it is dangerous to operate recursively on '${f}'\nrm: use --no-preserve-root to override this failsafe`, "err");
        const n = fs.getNode(p);
        if (!n) return flags.has("f") || c.print(`rm: cannot remove '${f}': No such file or directory`, "err");
        if (n.type === "dir" && !flags.has("r") && !flags.has("R")) return c.print(`rm: cannot remove '${f}': Is a directory`, "err");
        if (!canWrite(c, p) || (n.owner === "root" && !c.root)) return c.print(`rm: cannot remove '${f}': Permission denied`, "err");
        fs.remove(p);
      });
    },
  },
  cp: {
    cat: "Files", desc: "Copy files", usage: "cp [-r] src dest",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      if (rest.length < 2) return c.print("cp: missing destination file operand", "err");
      const dest = P(c, rest[rest.length - 1]);
      rest.slice(0, -1).forEach((s) => {
        const sp = P(c, s);
        const n = fs.getNode(sp);
        if (!n) return c.print(`cp: cannot stat '${s}': No such file or directory`, "err");
        if (isDeny(c, sp)) return c.print(`cp: cannot open '${s}' for reading: Permission denied`, "err");
        if (n.type === "dir" && !flags.has("r") && !flags.has("R")) return c.print(`cp: -r not specified; omitting directory '${s}'`, "err");
        if (!canWrite(c, fs.isDir(dest) ? dest + "/x" : dest)) return c.print(`cp: cannot create regular file '${rest[rest.length - 1]}': Permission denied`, "err");
        if (!fs.copy(sp, dest)) c.print(`cp: cannot create '${rest[rest.length - 1]}'`, "err");
      });
    },
  },
  mv: {
    cat: "Files", desc: "Move / rename files", usage: "mv src dest",
    run(args, c) {
      if (args.length < 2) return c.print("mv: missing destination file operand", "err");
      const dest = P(c, args[args.length - 1]);
      args.slice(0, -1).forEach((s) => {
        const sp = P(c, s);
        const n = fs.getNode(sp);
        if (!n) return c.print(`mv: cannot stat '${s}': No such file or directory`, "err");
        if (n.owner === "root" && !c.root) return c.print(`mv: cannot move '${s}': Permission denied`, "err");
        if (!fs.rename(sp, dest)) c.print(`mv: cannot move '${s}' to '${args[args.length - 1]}'`, "err");
      });
    },
  },
  echo: {
    cat: "Files", desc: "Print text", usage: "echo [-n] text...",
    run(args, c) {
      const { flags, rest } = parseFlags(args.filter((a) => a !== "-e"));
      c.print(rest.join(" ").replace(/\\n/g, "\n").replace(/\\t/g, "\t") + (flags.has("n") ? "" : ""));
    },
  },
  head: {
    cat: "Text", desc: "Output first lines", usage: "head [-n N] file",
    run(args, c) {
      const { rest, values } = parseFlags(args.map((a) => (/^-\d+$/.test(a) ? "-n" + a.slice(1) : a)), ["n"]);
      const num = parseInt(values.n ?? args.find((a) => /^-n\d+$/.test(a))?.slice(2) ?? "10");
      const l = inputText(rest, c, "head");
      l?.slice(0, num).forEach((x) => c.print(x));
    },
  },
  tail: {
    cat: "Text", desc: "Output last lines", usage: "tail [-n N] file",
    run(args, c) {
      const { rest, values } = parseFlags(args.map((a) => (/^-\d+$/.test(a) ? "-n" + a.slice(1) : a)), ["n"]);
      const num = parseInt(values.n ?? "10");
      const l = inputText(rest.filter((r) => r !== String(num)), c, "tail");
      l?.slice(-num).forEach((x) => c.print(x));
    },
  },
  wc: {
    cat: "Text", desc: "Count lines, words, bytes", usage: "wc [-lwc] file",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const l = inputText(rest, c, "wc");
      if (!l) return;
      const text = l.join("\n") + "\n";
      const parts: number[] = [];
      const all = !flags.has("l") && !flags.has("w") && !flags.has("c");
      if (all || flags.has("l")) parts.push(l.length);
      if (all || flags.has("w")) parts.push(text.split(/\s+/).filter(Boolean).length);
      if (all || flags.has("c")) parts.push(text.length);
      c.print(parts.join(" ") + (rest[0] ? " " + rest[0] : ""));
    },
  },
  sort: {
    cat: "Text", desc: "Sort lines", usage: "sort [-rnu] file",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      let l = inputText(rest, c, "sort");
      if (!l) return;
      l = [...l].sort(flags.has("n") ? (a, b) => parseFloat(a) - parseFloat(b) : (a, b) => a.localeCompare(b));
      if (flags.has("r")) l.reverse();
      if (flags.has("u")) l = l.filter((x, i) => l![i - 1] !== x);
      l.forEach((x) => c.print(x));
    },
  },
  uniq: {
    cat: "Text", desc: "Report or omit repeated lines", usage: "uniq [-c] file",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const l = inputText(rest, c, "uniq");
      if (!l) return;
      const out: [string, number][] = [];
      l.forEach((x) => (out.length && out[out.length - 1][0] === x ? out[out.length - 1][1]++ : out.push([x, 1])));
      out.forEach(([x, n]) => c.print(flags.has("c") ? `${lpad(n, 7)} ${x}` : x));
    },
  },
  cut: {
    cat: "Text", desc: "Cut fields from lines", usage: "cut -d: -f1 file",
    run(args, c) {
      const { values, rest } = parseFlags(args.flatMap((a) => (a.startsWith("-d") && a.length > 2 ? ["-d", a.slice(2)] : a.startsWith("-f") && a.length > 2 ? ["-f", a.slice(2)] : [a])), ["d", "f"]);
      const d = values.d ?? "\t";
      const fl = (values.f ?? "1").split(",").map((x) => parseInt(x) - 1);
      inputText(rest, c, "cut")?.forEach((l) => c.print(fl.map((i) => l.split(d)[i] ?? "").join(d)));
    },
  },
  grep: {
    cat: "Text", desc: "Search text with a pattern", usage: "grep [-inrvc] pattern [file...]",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const pat = rest.shift();
      if (!pat) return c.print("Usage: grep [OPTION]... PATTERNS [FILE]...", "err");
      let re: RegExp;
      try {
        re = new RegExp(pat, flags.has("i") ? "i" : "");
      } catch {
        re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), flags.has("i") ? "i" : "");
      }
      const emit = (label: string | null, lines: string[]) => {
        let n = 0;
        lines.forEach((l, i) => {
          const m = re.test(l);
          if (m !== flags.has("v")) {
            n++;
            if (flags.has("c")) return;
            const prefix = (label ? label + ":" : "") + (flags.has("n") ? i + 1 + ":" : "");
            const mm = l.match(re);
            if (mm && mm.index !== undefined && !flags.has("v") && mm[0]) c.segs([{ t: prefix, k: "info" }, { t: l.slice(0, mm.index) }, { t: mm[0], k: "crit" }, { t: l.slice(mm.index + mm[0].length) }]);
            else c.print(prefix + l);
          }
        });
        if (flags.has("c")) c.print((label ? label + ":" : "") + n);
      };
      if (!rest.length) return emit(null, c.stdin ?? []);
      const files: string[] = [];
      rest.forEach((f) => {
        const p = P(c, f);
        if (flags.has("r") || flags.has("R")) fs.walk(p, (pp, n) => n.type === "file" && files.push(pp));
        else files.push(p);
      });
      files.forEach((p) => {
        if (isDeny(c, p)) return c.print(`grep: ${p}: Permission denied`, "err");
        const t = fs.readFile(p);
        if (t === null) return c.print(`grep: ${p}: No such file or directory`, "err");
        if (fs.isBinary(t)) return;
        emit(files.length > 1 ? p : null, t.replace(/\n$/, "").split("\n"));
      });
    },
  },
  find: {
    cat: "Files", desc: "Search for files", usage: "find [path] -name pattern [-type f|d]",
    run(args, c) {
      const start = args[0] && !args[0].startsWith("-") ? args[0] : ".";
      const { values } = parseFlags(args.slice(start === args[0] ? 1 : 0), ["name", "type", "iname"]);
      const nm = args.indexOf("-name") >= 0 ? args[args.indexOf("-name") + 1] : args.indexOf("-iname") >= 0 ? args[args.indexOf("-iname") + 1] : null;
      const ty = args.indexOf("-type") >= 0 ? args[args.indexOf("-type") + 1] : values.type;
      const re = nm ? globToRegex(nm) : null;
      const base = P(c, start);
      if (!fs.exists(base)) return c.print(`find: '${start}': No such file or directory`, "err");
      fs.walk(base, (p, n) => {
        if (isDeny(c, p)) return;
        if (ty === "f" && n.type !== "file") return;
        if (ty === "d" && n.type !== "dir") return;
        if (re && !re.test(fs.basename(p))) return;
        c.print(start === "." ? "." + p.slice(base.length) || "." : p);
      });
    },
  },
  tree: {
    cat: "Files", desc: "Show directory tree", usage: "tree [path]",
    run(args, c) {
      const base = P(c, args.find((a) => !a.startsWith("-")) ?? ".");
      if (!fs.isDir(base)) return c.print(`${args[0]} [error opening dir]`, "err");
      c.print(base === c.cwd ? "." : base, "accent");
      let dirs = 0,
        files = 0;
      const rec = (p: string, prefix: string, depth: number) => {
        if (depth > 3) return;
        const list = (fs.listDir(p) || []).filter((e) => !e.name.startsWith("."));
        list.forEach((e, i) => {
          const last = i === list.length - 1;
          c.segs([{ t: prefix + (last ? "└── " : "├── "), k: "dim" }, { t: e.name, k: kindOf(e.node) }]);
          if (e.node.type === "dir") {
            dirs++;
            if (!isDeny(c, p + "/" + e.name)) rec((p === "/" ? "" : p) + "/" + e.name, prefix + (last ? "    " : "│   "), depth + 1);
          } else files++;
        });
      };
      rec(base, "", 1);
      c.print(`\n${dirs} directories, ${files} files`, "dim");
    },
  },
  du: {
    cat: "Files", desc: "Disk usage", usage: "du [-sh] path",
    run(args, c) {
      const { rest } = parseFlags(args);
      const p = P(c, rest[0] ?? ".");
      let total = 0;
      fs.walk(p, (_pp, n) => (total += fs.sizeOf(n)));
      c.print(`${fs.fmtSize(total).replace(" ", "")}\t${rest[0] ?? "."}`);
    },
  },
  stat: {
    cat: "Files", desc: "Display file status", usage: "stat file",
    run(args, c) {
      args.forEach((f) => {
        const p = P(c, f);
        const n = fs.getNode(p);
        if (!n) return c.print(`stat: cannot statx '${f}': No such file or directory`, "err");
        c.print(`  File: ${f}\n  Size: ${fs.sizeOf(n)}\tBlocks: 8\tIO Block: 4096  ${n.type === "dir" ? "directory" : "regular file"}\nAccess: (${n.mode})  Uid: (${n.owner})   Gid: (${n.owner})\nModify: ${new Date(n.mtime).toISOString()}`);
      });
    },
  },
  file: {
    cat: "Files", desc: "Determine file type", run(args, c) {
      args.forEach((f) => {
        const n = fs.getNode(P(c, f));
        if (!n) return c.print(`${f}: cannot open (No such file or directory)`, "err");
        const t = n.content || "";
        c.print(`${f}: ${n.type === "dir" ? "directory" : fs.isBinary(t) ? "ELF 64-bit LSB pie executable, x86-64" : t.startsWith("#!") ? "Bourne-Again shell script, ASCII text executable" : t.startsWith("#") ? "UTF-8 Unicode text (Markdown)" : "ASCII text"}`);
      });
    },
  },
  xxd: {
    cat: "Text", desc: "Hex dump a file", usage: "xxd file",
    run(args, c) {
      const t = args[0] ? fs.readFile(P(c, args[0])) : (c.stdin ?? []).join("\n");
      if (t === null) return c.print(`xxd: ${args[0]}: No such file or directory`, "err");
      const bytes = [...new TextEncoder().encode(t)];
      for (let i = 0; i < bytes.length; i += 16) {
        const row = bytes.slice(i, i + 16);
        const hex = row.map((b) => b.toString(16).padStart(2, "0")).reduce((a, h, j) => a + h + (j % 2 ? " " : ""), "");
        c.segs([{ t: i.toString(16).padStart(8, "0") + ": ", k: "info" }, { t: pad(hex, 40) }, { t: row.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join(""), k: "dim" }]);
      }
    },
  },
  chmod: {
    cat: "Files", desc: "Change file mode", usage: "chmod 755 file | chmod +x file",
    run(args, c) {
      if (args.length < 2) return c.print("chmod: missing operand", "err");
      const [m, ...files] = args;
      files.forEach((f) => {
        const p = P(c, f);
        const n = fs.getNode(p);
        if (!n) return c.print(`chmod: cannot access '${f}': No such file or directory`, "err");
        if (n.owner === "root" && !c.root) return c.print(`chmod: changing permissions of '${f}': Operation not permitted`, "err");
        let mode = n.mode;
        if (/^[0-7]{3,4}$/.test(m)) {
          const d = m.slice(-3).split("").map(Number);
          mode = (n.type === "dir" ? "d" : "-") + d.map((x) => (x & 4 ? "r" : "-") + (x & 2 ? "w" : "-") + (x & 1 ? "x" : "-")).join("");
        } else if (m === "+x") mode = mode.split("").map((ch, i) => (i === 3 || i === 6 || i === 9 ? "x" : ch)).join("");
        else if (m === "-x") mode = mode.split("").map((ch, i) => (i === 3 || i === 6 || i === 9 ? "-" : ch)).join("");
        fs.chmod(p, mode);
      });
    },
  },
  chown: {
    cat: "Files", desc: "Change file owner", usage: "sudo chown user file",
    run(args, c) {
      if (!c.root) return c.print("chown: changing ownership: Operation not permitted (use sudo)", "err");
      const [u, ...files] = args;
      files.forEach((f) => {
        const n = fs.getNode(P(c, f));
        if (n) n.owner = u.split(":")[0];
        else c.print(`chown: cannot access '${f}': No such file or directory`, "err");
      });
    },
  },
  which: { cat: "Files", desc: "Locate a command", run: (a, c) => a.forEach((x) => c.print(`/usr/bin/${x}`)) },
  basename: { cat: "Files", desc: "Strip directory from path", run: (a, c) => c.print(fs.basename(a[0] || "")) },
  tar: { cat: "Files", desc: "Archive utility (simulated)", run: (a, c) => c.print(`tar: ${a.join(" ")} — archive operation simulated`, "dim") },
  wget: {
    cat: "Network", desc: "Download a file (simulated)", usage: "wget <url>",
    async run(args, c) {
      const url = args.find((a) => !a.startsWith("-"));
      if (!url) return c.print("wget: missing URL", "err");
      const name = fs.basename(url.split("?")[0]) || "index.html";
      c.print(`--${new Date().toISOString()}--  ${url}`, "dim");
      c.print(`Resolving ${url.replace(/^https?:\/\//, "").split("/")[0]}... connected.\nHTTP request sent, awaiting response... 200 OK`);
      await c.sleep(500);
      const path = P(c, name);
      fs.writeFile(path, `Simulated download from ${url}\nSugreev OS never touches the real network.\n`);
      c.print(`Saving to: '${name}'\n\n${name}   100%[===================>]   1.2K  --.-KB/s    in 0s\n`, "ok");
    },
  },
  clear: { cat: "System", desc: "Clear the screen", run: (_a, c) => c.clear() },
  history: { cat: "System", desc: "Command history", run: (_a, c) => c.history.forEach((h, i) => c.print(`${lpad(i + 1, 5)}  ${h}`)) },
  export: {
    cat: "System", desc: "Set environment variable", usage: "export VAR=value",
    run(args, c) {
      args.forEach((a) => {
        const i = a.indexOf("=");
        if (i > 0) c.env[a.slice(0, i)] = a.slice(i + 1);
      });
    },
  },
  env: { cat: "System", desc: "Print environment", run: (_a, c) => Object.entries(c.env).forEach(([k, v]) => c.print(`${k}=${v}`)) },
  printenv: { cat: "System", desc: "Print environment variable", run: (a, c) => (a.length ? a.forEach((k) => c.env[k] !== undefined && c.print(c.env[k])) : Object.entries(c.env).forEach(([k, v]) => c.print(`${k}=${v}`))) },
  whoami: { cat: "System", desc: "Current user", run: (_a, c) => c.print(c.user) },
  id: { cat: "System", desc: "User identity", run: (_a, c) => c.print(c.user === "root" ? "uid=0(root) gid=0(root) groups=0(root)" : "uid=1000(vaibhav) gid=1000(vaibhav) groups=1000(vaibhav),27(sudo),2000(siem)") },
  groups: { cat: "System", desc: "User groups", run: (_a, c) => c.print(c.user === "root" ? "root" : "vaibhav sudo siem") },
  hostname: { cat: "System", desc: "Show hostname", run: (_a, c) => c.print("sgv-node-01") },
  hostnamectl: {
    cat: "System", desc: "Host information",
    run: (_a, c) => c.print(` Static hostname: sgv-node-01\n       Icon name: computer-desktop\n      Machine ID: 5367756772656576f5ec4a1bd0d5c001\n    Operating System: Sugreev OS 1.0 (Kishkindha)\n          Kernel: Sugreev 6.8.0-sgv\n    Architecture: x86-64\n Hardware Vendor: Vaibhav Thakur Labs\n  Hardware Model: Sugreev Cyber Workstation SG-1`),
  },
  uname: {
    cat: "System", desc: "System information", usage: "uname [-a]",
    run(args, c) {
      c.print(args.includes("-a") ? "Sugreev sgv-node-01 6.8.0-sgv #1 SMP PREEMPT_DYNAMIC Kishkindha x86_64 GNU/Linux" : "Sugreev");
    },
  },
  lsb_release: { cat: "System", desc: "Distribution info", run: (_a, c) => c.print("Distributor ID:\tSugreev\nDescription:\tSugreev OS 1.0 Kishkindha\nRelease:\t1.0\nCodename:\tkishkindha") },
  date: { cat: "System", desc: "Current date and time", run: (_a, c) => c.print(dateStr() + " IST") },
  cal: {
    cat: "System", desc: "Show calendar",
    run(_a, c) {
      const now = new Date();
      const first = new Date(now.getFullYear(), now.getMonth(), 1).getDay();
      const days = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
      const title = now.toLocaleString("en-US", { month: "long", year: "numeric" });
      c.print(title.padStart(10 + title.length / 2), "accent");
      c.print("Su Mo Tu We Th Fr Sa", "info");
      let row = "   ".repeat(first);
      for (let d = 1; d <= days; d++) {
        row += String(d).padStart(2) + " ";
        if ((first + d) % 7 === 0) {
          c.print(row);
          row = "";
        }
      }
      if (row) c.print(row);
    },
  },
  uptime: {
    cat: "System", desc: "System uptime",
    run(_a, c) {
      const k = getSnapshot();
      const s = Math.floor((Date.now() - k.bootTime) / 1000);
      c.print(` ${new Date().toLocaleTimeString("en-GB")} up ${Math.floor(s / 60)} min,  1 user,  load average: ${k.load.map((x) => x.toFixed(2)).join(", ")}`);
    },
  },
  who: { cat: "System", desc: "Logged-in users", run: (_a, c) => c.print(`vaibhav  tty1   ${new Date().toISOString().slice(0, 16).replace("T", " ")}\nvaibhav  pts/0  ${new Date().toISOString().slice(0, 16).replace("T", " ")} (10.0.0.21)`) },
  w: { cat: "System", desc: "Who is logged in and what they do", run: (_a, c) => c.print(` ${new Date().toLocaleTimeString("en-GB")} up  1 user\nUSER     TTY      FROM             LOGIN@   IDLE WHAT\nvaibhav  tty1     -                08:00    0.00s sugreev-shell\nvaibhav  pts/0    10.0.0.21        08:02    0.00s sgv-terminal`) },
  last: { cat: "System", desc: "Last logins", run: (_a, c) => c.print("vaibhav  tty1         Sat Mar 14 08:00   still logged in\nvaibhav  pts/0        Fri Mar 13 22:14 - 23:40  (01:26)\nanalyst  pts/1        Fri Mar 13 14:02 - 17:30  (03:28)\nreboot   system boot  6.8.0-sgv        Fri Mar 13 08:00   still running") },
  free: {
    cat: "System", desc: "Memory usage", usage: "free [-h|-m]",
    run(args, c) {
      const k = getSnapshot();
      const h = args.includes("-h");
      const f = (mb: number) => (h ? (mb / 1024).toFixed(1) + "Gi" : String(Math.round(mb)));
      c.print(`               total        used        free      shared  buff/cache   available`);
      c.print(`Mem:    ${lpad(f(k.memTotal), 11)} ${lpad(f(k.memUsed), 11)} ${lpad(f(k.memTotal - k.memUsed - k.memCached), 11)} ${lpad(f(212), 11)} ${lpad(f(k.memCached), 11)} ${lpad(f(k.memTotal - k.memUsed), 11)}`);
      c.print(`Swap:   ${lpad(f(k.swapTotal), 11)} ${lpad(f(k.swapUsed), 11)} ${lpad(f(k.swapTotal - k.swapUsed), 11)}`);
    },
  },
  df: {
    cat: "System", desc: "Disk free space", usage: "df [-h]",
    run: (_a, c) => c.print("Filesystem      Size  Used Avail Use% Mounted on\ntmpfs           1.6G  2.1M  1.6G   1% /run\n/dev/nvme0n1p2  468G  214G  231G  49% /\ntmpfs           7.8G     0  7.8G   0% /dev/shm\n/dev/nvme0n1p1  512M  6.1M  506M   2% /boot/efi\n/dev/sda1       1.8T  612G  1.1T  36% /mnt/evidence"),
  },
  lsblk: {
    cat: "System", desc: "List block devices",
    run: (_a, c) => c.print("NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\nnvme0n1     259:0    0 476.9G  0 disk\n├─nvme0n1p1 259:1    0   512M  0 part /boot/efi\n└─nvme0n1p2 259:2    0 476.4G  0 part /\nsda           8:0    0   1.8T  0 disk\n└─sda1        8:1    0   1.8T  0 part /mnt/evidence"),
  },
  lscpu: {
    cat: "System", desc: "CPU architecture information",
    run(_a, c) {
      const L = CPU_INFO;
      const rows: [string, string][] = [
        ["Architecture", L.arch], ["CPU op-mode(s)", "32-bit, 64-bit"], ["Address sizes", "48 bits physical, 48 bits virtual"], ["Byte Order", "Little Endian"], ["CPU(s)", String(L.threads)], ["On-line CPU(s) list", "0-15"], ["Vendor ID", L.vendor], ["Model name", L.model], ["CPU family", "25"], ["Model", "97"], ["Thread(s) per core", "2"], ["Core(s) per socket", String(L.cores)], ["Socket(s)", "1"], ["Stepping", "2"], ["CPU max MHz", "5000.0000"], ["CPU min MHz", "800.0000"], ["BogoMIPS", "7600.00"], ["Virtualization", "SVM"], ["L1d cache", L.l1d], ["L1i cache", L.l1i], ["L2 cache", L.l2], ["L3 cache", L.l3], ["TDP", L.tdp],
      ];
      rows.forEach(([k, v]) => c.segs([{ t: pad(k + ":", 24), k: "info" }, { t: v }]));
      c.segs([{ t: pad("Flags:", 24), k: "info" }, { t: L.flags.slice(0, 200) + " ...", k: "dim" }]);
      c.print("Vulnerabilities:", "info");
      L.vulnMitigations.forEach(([k, v]) => c.print(`  ${pad(k + ":", 14)} ${v}`));
    },
  },
  lspci: { cat: "System", desc: "List PCI devices", run: (_a, c) => c.print("00:00.0 Host bridge: Sugreev Silicon Root Complex\n00:02.0 VGA compatible controller: Sugreev Vector G7 [8GB]\n00:14.0 USB controller: Sugreev xHCI Host Controller\n01:00.0 Non-Volatile memory controller: Sugreev NVMe SSD SN850\n02:00.0 Ethernet controller: Realtek RTL8125 2.5GbE\n03:00.0 Network controller: Sugreev AX210 Wi-Fi 6E") },
  lsusb: { cat: "System", desc: "List USB devices", run: (_a, c) => c.print("Bus 001 Device 002: ID 1d6b:0002 Linux Foundation 2.0 root hub\nBus 001 Device 003: ID 046d:c52b Logitech Unifying Receiver\nBus 002 Device 002: ID 0bda:8153 Realtek USB 3.0 Ethernet\nBus 001 Device 004: ID 1050:0407 Yubico YubiKey OTP+FIDO+CCID") },
  lsmod: { cat: "System", desc: "Loaded kernel modules", run: (_a, c) => c.print("Module                  Size  Used by\nsgv_netfilter         163840  4\nsgv_audit              81920  2\nnf_conntrack          172032  2 sgv_netfilter\nnvme                   57344  3\napparmor              159744  1\nsgv_ids_tap            49152  1") },
  dmesg: {
    cat: "System", desc: "Kernel ring buffer",
    run: (_a, c) => c.print("[    0.000000] Linux version 6.8.0-sgv (vaibhav@build) #1 SMP PREEMPT_DYNAMIC Kishkindha\n[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-6.8.0-sgv root=/dev/nvme0n1p2 quiet splash lockdown=integrity\n[    0.412311] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'\n[    0.880112] sgv_audit: initializing audit subsystem (sgv-audit v1.0)\n[    1.204551] apparmor: AppArmor initialized\n[    1.911002] nvme nvme0: 16/0/0 default/read/poll queues\n[    2.600114] sgv_netfilter: connection tracking enabled, 262144 buckets\n[    3.110002] sgv_ids_tap: promiscuous tap attached to eth0\n[    3.911210] Sugreev: Secure boot enabled, lockdown mode = integrity"),
  },
  ip: {
    cat: "Network", desc: "Show network interfaces", usage: "ip a | ip route",
    run(args, c) {
      if (args[0] === "route" || args[0] === "r") return c.print("default via 10.0.0.1 dev eth0 proto dhcp metric 100\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100");
      c.print("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    link/ether 52:54:00:5e:a1:07 brd ff:ff:ff:ff:ff:ff\n    inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic eth0\n    inet6 fe80::5054:ff:fe5e:a107/64 scope link\n3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN\n    link/ether 9c:b6:d0:11:22:33 brd ff:ff:ff:ff:ff:ff");
    },
  },
  ifconfig: {
    cat: "Network", desc: "Configure network interface",
    run(_a, c) {
      const k = getSnapshot();
      c.print(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n        inet6 fe80::5054:ff:fe5e:a107  prefixlen 64  scopeid 0x20<link>\n        ether 52:54:00:5e:a1:07  txqueuelen 1000  (Ethernet)\n        RX packets ${k.tick * 811 + 482113}  bytes ${(k.tick * 811 + 482113) * 640}\n        TX packets ${k.tick * 402 + 201332}  bytes ${(k.tick * 402 + 201332) * 410}\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)`);
    },
  },
  netstat: {
    cat: "Network", desc: "Network connections", usage: "netstat -tulnp",
    run(_a, c) {
      const k = getSnapshot();
      c.print("Active Internet connections (servers and established)", "dim");
      c.print("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name", "info");
      k.conns.forEach((x) => c.print(`${pad(x.proto, 6)}${pad(0, 7)}${pad(0, 7)}${pad(x.local, 24)}${pad(x.remote, 24)}${pad(x.state, 12)}${x.pid}/${x.proc}`));
    },
  },
  ss: {
    cat: "Network", desc: "Socket statistics", usage: "ss -tulpn",
    run(_a, c) {
      const k = getSnapshot();
      c.print("Netid State      Recv-Q Send-Q  Local Address:Port    Peer Address:Port  Process", "info");
      k.conns.forEach((x) => c.print(`${pad(x.proto, 6)} ${pad(x.state, 10)} ${pad(0, 6)} ${pad(0, 7)} ${pad(x.local, 21)} ${pad(x.remote, 18)} users:(("${x.proc}",pid=${x.pid}))`));
    },
  },
  ps: {
    cat: "Process", desc: "Process status", usage: "ps [aux]",
    run(_a, c) {
      const k = getSnapshot();
      c.print("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND", "info");
      k.procs.slice().sort((a, b) => a.pid - b.pid).forEach((p) => c.print(`${pad(p.user, 10)} ${lpad(p.pid, 5)} ${lpad((p.cpu / k.cores).toFixed(1), 4)} ${lpad(((p.mem / k.memTotal) * 100).toFixed(1), 4)} ${lpad(p.mem * 1024 * 2, 7)} ${lpad(p.mem * 1024, 6)} ?        ${pad(p.state + "s", 4)} 08:00   0:${String(p.pid % 60).padStart(2, "0")} ${p.cmd.slice(0, 60)}`));
    },
  },
  top: {
    cat: "Process", desc: "Process activity snapshot", usage: "top",
    run(_a, c) {
      const k = getSnapshot();
      c.print(`top - ${new Date().toLocaleTimeString("en-GB")} up ${Math.floor((Date.now() - k.bootTime) / 60000)} min,  2 users,  load average: ${k.load.map((x) => x.toFixed(2)).join(", ")}`, "accent");
      c.print(`Tasks: ${k.procs.length} total,   2 running, ${k.procs.length - 2} sleeping,   0 stopped,   0 zombie`);
      c.print(`%Cpu(s): ${k.cpuTotal.toFixed(1)} us,  ${(k.cpuTotal * 0.2).toFixed(1)} sy,  0.0 ni, ${(100 - k.cpuTotal * 1.2).toFixed(1)} id,  0.1 wa`);
      c.print(`MiB Mem : ${k.memTotal.toFixed(1)} total, ${(k.memTotal - k.memUsed - k.memCached).toFixed(1)} free, ${k.memUsed.toFixed(1)} used, ${k.memCached.toFixed(1)} buff/cache`);
      c.print(`MiB Swap: ${k.swapTotal.toFixed(1)} total, ${(k.swapTotal - k.swapUsed).toFixed(1)} free, ${k.swapUsed.toFixed(1)} used\n`);
      c.print("  PID USER      PR  NI    VIRT    RES  %CPU  %MEM COMMAND", "info");
      k.procs.slice(0, 12).forEach((p) => c.print(`${lpad(p.pid, 5)} ${pad(p.user, 9)} 20   0 ${lpad(p.mem * 2048, 7)} ${lpad(p.mem * 1024, 6)} ${lpad(p.cpu.toFixed(1), 5)} ${lpad(((p.mem / k.memTotal) * 100).toFixed(1), 5)} ${p.name}`));
    },
  },
  kill: {
    cat: "Process", desc: "Terminate a process", usage: "kill [-9] <pid>",
    run(args, c) {
      const { rest } = parseFlags(args);
      if (!rest.length) return c.print("kill: usage: kill [-s sigspec | -n signum | -sigspec] pid", "err");
      rest.forEach((x) => {
        const pid = parseInt(x);
        const p = getSnapshot().procs.find((q) => q.pid === pid);
        const r = killProc(pid);
        if (r === "none") c.print(`bash: kill: (${pid}) - No such process`, "err");
        else if (r === "denied" || (p && p.user === "root" && !c.root)) c.print(`bash: kill: (${pid}) - Operation not permitted`, "err");
        else injectEvent({ sev: "medium", source: "endpoint", msg: `process ${p?.name}[${pid}] terminated by ${c.user} (SIGKILL)`, rule: "Security Service Stopped", mitre: "T1562.001" });
      });
    },
  },
  systemctl: {
    cat: "System", desc: "Control services", usage: "systemctl status|start|stop|restart <svc> | list-units",
    run(args, c) {
      const [sub, svc] = args;
      if (sub === "list-units" || sub === "list-unit-files" || !sub) {
        c.print("UNIT                  LOAD   ACTIVE SUB     DESCRIPTION", "info");
        SERVICES.forEach(([n, d]) => c.segs([{ t: pad(n + ".service", 22) }, { t: pad("loaded", 7) }, { t: pad("active", 7), k: "ok" }, { t: pad("running", 8), k: "ok" }, { t: d, k: "dim" }]));
        return;
      }
      const s = SERVICES.find((x) => x[0] === svc || x[0] + ".service" === svc);
      if (!s) return c.print(`Unit ${svc}.service could not be found.`, "err");
      if (sub === "status") {
        c.segs([{ t: "● ", k: "ok" }, { t: `${s[0]}.service - ${s[1]}` }]);
        c.print(`     Loaded: loaded (/lib/systemd/system/${s[0]}.service; enabled; preset: enabled)`);
        c.segs([{ t: "     Active: " }, { t: "active (running)", k: "ok" }, { t: " since Sat 08:00:02 IST; " + Math.floor((Date.now() - getSnapshot().bootTime) / 60000) + "min ago" }]);
        c.print(`   Main PID: ${s[2]} (${s[0]})\n      Tasks: 4 (limit: 18934)\n     Memory: 48.2M\n     CGroup: /system.slice/${s[0]}.service`);
        return;
      }
      if (!c.root) return c.print("==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====\nFailed to " + sub + " " + s[0] + ".service: Interactive authentication required. (use sudo)", "err");
      injectEvent({ sev: sub === "stop" ? "high" : "info", source: "endpoint", msg: `systemd: ${sub} ${s[0]}.service by ${c.user}`, rule: sub === "stop" ? "Security Service Stopped" : undefined, mitre: sub === "stop" ? "T1562.001" : undefined });
      c.print(`${sub} ${s[0]}.service ... done`, "ok");
    },
  },
  journalctl: {
    cat: "System", desc: "Query the system journal", usage: "journalctl [-n N]",
    run(args, c) {
      const { values } = parseFlags(args, ["n"]);
      const n = parseInt(values.n ?? "15");
      getSnapshot().events.slice(0, n).reverse().forEach((e) => c.print(`${syslogDate(e.ts)} ${e.host} ${e.msg}`));
    },
  },
  apt: {
    cat: "System", desc: "Package manager (simulated)", usage: "sudo apt update|upgrade|install <pkg>",
    async run(args, c) {
      const sub = args[0];
      if (!c.root) {
        c.print("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?", "err");
        return;
      }
      if (sub === "update") {
        for (const l of ["Hit:1 http://repo.sugreev.os kishkindha InRelease", "Get:2 http://repo.sugreev.os kishkindha-security InRelease [110 kB]", "Get:3 http://repo.sugreev.os kishkindha/main amd64 Packages [1,214 kB]", "Fetched 1,324 kB in 1s (1,812 kB/s)"]) {
          c.print(l);
          await c.sleep(350);
        }
        c.print("Reading package lists... Done\nBuilding dependency tree... Done\n3 packages can be upgraded. Run 'apt list --upgradable' to see them.", "ok");
      } else if (sub === "upgrade") {
        c.print("Reading package lists... Done\nCalculating upgrade... Done");
        for (const p of ["openssl", "sgv-siem", "linux-image-6.8.0-sgv"]) {
          await c.sleep(450);
          c.print(`Setting up ${p} ...`);
        }
        c.print("Upgrade complete.", "ok");
      } else if (sub === "install" && args[1]) {
        c.print(`Reading package lists... Done\nThe following NEW packages will be installed:\n  ${args.slice(1).join(" ")}`);
        await c.sleep(500);
        c.print(`Get:1 http://repo.sugreev.os kishkindha/main amd64 ${args[1]} [412 kB]`);
        await c.sleep(600);
        c.print(`Selecting previously unselected package ${args[1]}.\nSetting up ${args[1]} ...`, "dim");
        c.print(`Done. ${args[1]} installed (simulated).`, "ok");
      } else c.print("Usage: apt update | upgrade | install <package>", "warn");
    },
  },
  reboot: { cat: "Power", desc: "Restart the system", run: (_a, c) => c.os.power("restart") },
  shutdown: { cat: "Power", desc: "Power off the system", run: (_a, c) => c.os.power("shutdown") },
  poweroff: { cat: "Power", desc: "Power off the system", run: (_a, c) => c.os.power("shutdown") },
  logout: { cat: "Power", desc: "Log out of the session", run: (_a, c) => c.os.power("logout") },
  lock: { cat: "Power", desc: "Lock the screen", run: (_a, c) => c.os.power("lock") },
  exit: {
    cat: "System", desc: "Exit shell / drop root",
    run(_a, c) {
      if (c.user === "root") {
        c.setUser("vaibhav");
        c.setCwd(fs.HOME);
        c.print("logout", "dim");
      } else c.closeSelf();
    },
  },
  open: {
    cat: "Desktop", desc: "Open a desktop app", usage: "open <terminal|files|browser|siem|threats|vapt|monitor|editor|crypto|settings|about>",
    run(args, c) {
      const id = APPS[(args[0] || "").toLowerCase()];
      if (!id) return c.print(`open: unknown app '${args[0] ?? ""}'. Try: ${[...new Set(Object.values(APPS))].join(", ")}`, "err");
      c.os.openApp(id);
      c.print(`Launching ${id}...`, "dim");
    },
  },
  files: { cat: "Desktop", desc: "Open file manager at path", run: (a, c) => c.os.openApp("files", { path: P(c, a[0] ?? ".") }) },
  edit: {
    cat: "Desktop", desc: "Edit a file in the text editor", usage: "edit <file>",
    run(args, c) {
      if (!args[0]) return c.os.openApp("editor");
      const p = P(c, args[0]);
      if (isDeny(c, p)) return c.print(`edit: ${args[0]}: Permission denied`, "err");
      if (!fs.exists(p)) {
        if (!canWrite(c, p)) return c.print(`edit: ${args[0]}: Permission denied`, "err");
        fs.writeFile(p, "");
      }
      c.os.openFile(p);
    },
  },
  browse: { cat: "Desktop", desc: "Open the browser at a URL", usage: "browse <url>", run: (a, c) => c.os.openApp("browser", { url: a[0] ?? "sugreev://home" }) },
  neofetch: {
    cat: "System", desc: "System information banner",
    run(_a, c) {
      const k = getSnapshot();
      const t = threatLabel(k.threatLevel);
      const up = Math.floor((Date.now() - k.bootTime) / 1000);
      const info: Seg[][] = [
        [{ t: `${c.user}@sgv-node-01`, k: "accent" }],
        [{ t: "-".repeat(20), k: "dim" }],
        [{ t: "OS: ", k: "accent" }, { t: "Sugreev OS 1.0 Kishkindha x86_64" }],
        [{ t: "Host: ", k: "accent" }, { t: "Sugreev Cyber Workstation SG-1" }],
        [{ t: "Kernel: ", k: "accent" }, { t: "6.8.0-sgv" }],
        [{ t: "Uptime: ", k: "accent" }, { t: `${Math.floor(up / 60)} mins, ${up % 60} secs` }],
        [{ t: "Packages: ", k: "accent" }, { t: "1842 (dpkg), 64 (sgv-tools)" }],
        [{ t: "Shell: ", k: "accent" }, { t: "sgsh 5.2" }],
        [{ t: "DE: ", k: "accent" }, { t: "Sugreev Shell (Glass/Cyber-Dark)" }],
        [{ t: "WM: ", k: "accent" }, { t: "sgv-compositor" }],
        [{ t: "CPU: ", k: "accent" }, { t: `${CPU_INFO.model} (16) @ ${CPU_INFO.boostGhz.toFixed(1)}GHz` }],
        [{ t: "GPU: ", k: "accent" }, { t: "Sugreev Vector G7 8GB" }],
        [{ t: "Memory: ", k: "accent" }, { t: `${Math.round(k.memUsed)}MiB / ${k.memTotal}MiB` }],
        [{ t: "Threat Level: ", k: "accent" }, { t: `${t.label} (${k.threatLevel}/100)`, k: k.threatLevel < 35 ? "ok" : k.threatLevel < 60 ? "warn" : "crit" }],
        [{ t: "Open Alerts: ", k: "accent" }, { t: String(k.alerts.filter((a) => a.status === "open").length) }],
      ];
      LOGO.forEach((l, i) => c.segs([{ t: l, k: "accent" }, ...(info[i] ?? [])]));
      for (let i = LOGO.length; i < info.length; i++) c.segs([{ t: " ".repeat(26) }, ...info[i]]);
      c.segs([{ t: " ".repeat(26) }, { t: "███", k: "crit" }, { t: "███", k: "warn" }, { t: "███", k: "ok" }, { t: "███", k: "info" }, { t: "███", k: "accent" }, { t: "███", k: "dim" }]);
    },
  },
  cowsay: {
    cat: "Fun", desc: "A talking cow", run(args, c) {
      const msg = args.join(" ") || "Moo. Patch your servers.";
      c.print(` ${"_".repeat(msg.length + 2)}\n< ${msg} >\n ${"-".repeat(msg.length + 2)}\n        \\   ^__^\n         \\  (oo)\\_______\n            (__)\\       )\\/\\\n                ||----w |\n                ||     ||`, "ok");
    },
  },
  fortune: { cat: "Fun", desc: "Security wisdom", run: (_a, c) => c.print(FORTUNES[Math.floor(Math.random() * FORTUNES.length)], "info") },
  matrix: {
    cat: "Fun", desc: "Enter the matrix", usage: "matrix  (Ctrl+C to stop)",
    async run(_a, c) {
      const chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾅﾆﾇﾈﾉ0123456789ABCDEF";
      for (let i = 0; i < 30; i++) {
        c.print(Array.from({ length: 64 }, () => (Math.random() < 0.55 ? " " : chars[Math.floor(Math.random() * chars.length)])).join(""), "ok");
        await c.sleep(90);
      }
      c.print("Wake up, Vaibhav...", "accent");
    },
  },
  hack: {
    cat: "Fun", desc: "Hollywood hacking simulation", usage: "hack",
    async run(_a, c) {
      const steps = ["[*] Initializing exploit framework...", "[*] Scanning 10.13.37.0/24 ... 12 hosts alive", "[+] Found vulnerable service: vsftpd 2.3.4", "[*] Sending crafted payload...", "[*] Bypassing IDS (just kidding, this is a sim)", "[+] Shell opened: root@target:/#", "[*] Dumping /etc/shadow ...", "[+] ACCESS GRANTED — (this is a simulation, nothing happened)"];
      for (const s of steps) {
        c.print(s, s.startsWith("[+]") ? "ok" : "info");
        await c.sleep(450);
      }
    },
  },
  calc: {
    cat: "Fun", desc: "Calculator", usage: "calc 2*(3+4)",
    run(args, c) {
      const ex = args.join(" ");
      if (!/^[0-9+\-*/().%\s^]+$/.test(ex)) return c.print("calc: only numbers and + - * / % ( ) allowed", "err");
      try {
        c.print(String(Function(`"use strict";return (${ex.replace(/\^/g, "**")})`)()));
      } catch {
        c.print("calc: syntax error", "err");
      }
    },
  },
  sleep: { cat: "System", desc: "Delay for N seconds", run: async (a, c) => c.sleep((parseFloat(a[0]) || 1) * 1000) },
  base64: {
    cat: "Crypto", desc: "Base64 encode/decode", usage: "base64 [-d] <file|text>",
    run(args, c) {
      const { flags, rest } = parseFlags(args);
      const src = rest.length ? fs.readFile(P(c, rest[0])) ?? rest.join(" ") : (c.stdin ?? []).join("\n");
      try {
        c.print(flags.has("d") ? b64dec(src) : b64enc(src));
      } catch {
        c.print("base64: invalid input", "err");
      }
    },
  },
  md5sum: {
    cat: "Crypto", desc: "Compute MD5 hash of a file", usage: "md5sum <file>",
    run(args, c) {
      args.forEach((f) => {
        const t = fs.readFile(P(c, f));
        if (t === null) return c.print(`md5sum: ${f}: No such file or directory`, "err");
        c.print(`${md5(t)}  ${f}`);
      });
    },
  },
};

(["sha1sum:SHA-1", "sha256sum:SHA-256", "sha512sum:SHA-512"] as const).forEach((x) => {
  const [name, algo] = x.split(":");
  SYS[name] = {
    cat: "Crypto", desc: `Compute ${algo} hash of a file`, usage: `${name} <file>`,
    async run(args, c) {
      for (const f of args) {
        const t = fs.readFile(P(c, f));
        if (t === null) c.print(`${name}: ${f}: No such file or directory`, "err");
        else c.print(`${await sha(algo as ShaAlgo, t)}  ${f}`);
      }
    },
  };
});

