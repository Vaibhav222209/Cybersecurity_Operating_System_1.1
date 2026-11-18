/**
 * Sugreev OS — shell smoke test.
 * Bundles the terminal engine with esbuild and runs a batch of commands headlessly.
 *
 *   npx esbuild tests/shell.smoke.ts --bundle --platform=node --format=esm --outfile=.tmp/shell.smoke.mjs && node .tmp/shell.smoke.mjs
 */
import { execute } from "../src/os/shell/engine";
import { COMMANDS } from "../src/os/shell/engine";
import type { ShellCtx } from "../src/os/shell/types";
import * as fs from "../src/os/vfs";

let out: string[] = [];
const state = { cwd: fs.HOME, user: "vaibhav" };
const ctx: ShellCtx = {
  print: (t) => void out.push(...t.split("\n")),
  segs: (s) => void out.push(s.map((x) => x.t).join("")),
  clear: () => void (out = []),
  cwd: state.cwd,
  setCwd: (p) => {
    ctx.cwd = p;
  },
  user: "vaibhav",
  setUser: (u) => {
    ctx.user = u;
    ctx.root = u === "root";
  },
  root: false,
  sleep: async () => undefined,
  os: {
    openApp: (id) => void out.push(`<openApp ${id}>`),
    openFile: (p) => void out.push(`<openFile ${p}>`),
    closeWindow: () => undefined,
    notify: () => undefined,
    power: (a) => void out.push(`<power ${a}>`),
    settings: { accent: "#00e5ff", wallpaper: "matrix", scanlines: true, animations: true, notifications: true },
    setSettings: () => undefined,
    notifications: [],
    clearNotifications: () => undefined,
  },
  history: [],
  env: { HOME: fs.HOME, USER: "vaibhav", PATH: "/usr/bin" },
  closeSelf: () => undefined,
  run: async () => undefined,
};

const CASES: { cmd: string; expect?: RegExp; forbid?: RegExp }[] = [
  { cmd: "help", expect: /commands available/ },
  { cmd: "neofetch", expect: /Sugreev OS 1\.0/ },
  { cmd: "ls -la", expect: /Documents/ },
  { cmd: "cd Documents && pwd", expect: /\/home\/vaibhav\/Documents/ },
  { cmd: "cd ~ && cat notes.txt | grep TODO", expect: /TODO/ },
  { cmd: "echo hello > /tmp/x.txt && cat /tmp/x.txt", expect: /hello/ },
  { cmd: "mkdir -p ~/lab/a/b && ls ~/lab", expect: /a/ },
  { cmd: "cat /etc/shadow", expect: /Permission denied/ },
  { cmd: "sudo cat /etc/shadow", expect: /REDACTED/ },
  { cmd: "rm -rf /", expect: /dangerous/ },
  { cmd: "foobar", expect: /command not found/ },
  { cmd: "nmap -sV 192.168.56.101", expect: /Nmap scan report/ },
  { cmd: "vapt scan 192.168.56.101", expect: /Risk score/ },
  { cmd: "vapt web 192.168.56.101", expect: /PASS|FAIL/ },
  { cmd: "vapt report", expect: /Report written/ },
  { cmd: "ls ~/Reports", expect: /vapt-192\.168\.56\.101/ },
  { cmd: "vapt scan localhost", expect: /8443/ },
  { cmd: "siem status", expect: /RUNNING/ },
  { cmd: "siem alerts 3", expect: /MITRE/ },
  { cmd: "siem stats", expect: /severity/ },
  { cmd: "siem top", expect: /SOURCE IP/ },
  { cmd: "threats", expect: /THREAT LEVEL/ },
  { cmd: "sudo siem block 8.8.4.4", expect: /blocklist/ },
  { cmd: "iptables -L", expect: /8\.8\.4\.4/ },
  { cmd: "searchsploit apache", expect: /apache_normalize_path_rce/ },
  { cmd: "cve log4j", expect: /CVE-2021-44228/ },
  { cmd: "ps aux | head -3", expect: /PID/ },
  { cmd: "top", expect: /Tasks:/ },
  { cmd: "lscpu", expect: /Model name/ },
  { cmd: "free -h", expect: /Mem:/ },
  { cmd: "df -h", expect: /nvme0n1p2/ },
  { cmd: "ip a", expect: /eth0/ },
  { cmd: "netstat -tulnp", expect: /LISTEN/ },
  { cmd: "md5sum README.md", expect: /^[0-9a-f]{32}\s/ },
  { cmd: "sha256sum README.md", expect: /^[0-9a-f]{64}\s/ },
  { cmd: "echo -n abc | base64", expect: /YWJj/ },
  { cmd: "find / -name '*.log'", expect: /auth\.log/ },
  { cmd: "tree ~/Documents", expect: /directories/ },
  { cmd: "grep -r vsftpd ~", expect: /vsftpd/ },
  { cmd: "apt update", expect: /Permission denied/ },
  { cmd: "sudo apt install nmap", expect: /installed/ },
  { cmd: "systemctl status sgv-siemd", expect: /active \(running\)/ },
  { cmd: "journalctl -n 3" },
  { cmd: "whois example.com", expect: /Domain Name/ },
  { cmd: "dig example.com", expect: /ANSWER/ },
  { cmd: "curl -I example.com", expect: /HTTP\/1\.1 200/ },
  { cmd: "hashid 5f4dcc3b5aa765d61d8327deb882cf99", expect: /MD5/ },
  { cmd: "xxd README.md | head -2", expect: /00000000/ },
  { cmd: "chmod +x ~/Tools/ioc-list.txt && ls -l ~/Tools", expect: /ioc-list/ },
  { cmd: "bash ~/Tools/portscan.sh 10.10.10.5", expect: /Nmap scan report/ },
  { cmd: "open siem", expect: /openApp siem/ },
  { cmd: "edit ~/notes.txt", expect: /openFile/ },
  { cmd: "nikto -h testphp.lab", expect: /Nikto/ },
  { cmd: "ping -c 2 sugreev.local", expect: /2 packets transmitted/ },
  { cmd: "traceroute example.com", expect: /hops max/ },
  { cmd: "sudo reboot", expect: /power restart/ },
];

let failed = 0;
console.log(`Registered commands: ${Object.keys(COMMANDS).length}`);
for (const c of CASES) {
  out = [];
  try {
    await execute(c.cmd, ctx);
  } catch (e) {
    out.push("EXCEPTION " + (e as Error).message);
  }
  const text = out.join("\n");
  const ok = (!c.expect || c.expect.test(text)) && !/EXCEPTION|undefined|NaN|\[object/.test(text);
  if (!ok) {
    failed++;
    console.log(`✘ ${c.cmd}\n${text.split("\n").slice(0, 8).join("\n")}\n`);
  } else console.log(`✔ ${c.cmd}`);
}
console.log(failed ? `\n${failed} FAILED` : "\nAll shell smoke tests passed");
process.exit(failed ? 1 : 0);
