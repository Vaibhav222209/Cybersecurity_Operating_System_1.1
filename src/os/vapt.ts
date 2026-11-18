// Sugreev OS — VAPT engine (100% SIMULATED, deterministic per target).
// No packets are ever sent. Results are generated from a seeded RNG + a database of real, public CVEs.

export type RiskLevel = "critical" | "high" | "medium" | "low";

export interface Vuln {
  cve: string;
  cvss: number;
  title: string;
  desc: string;
  fix: string;
}
interface Variant {
  v: string;
  vulns: Vuln[];
}
interface SvcDef {
  port: number;
  proto: "tcp" | "udp";
  name: string;
  product: string;
  p: number; // probability of being open
  variants: Variant[];
  os?: "windows" | "linux";
}

export const sevOf = (cvss: number): RiskLevel => (cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low");

const V = (cve: string, cvss: number, title: string, desc: string, fix: string): Vuln => ({ cve, cvss, title, desc, fix });

const SERVICES: SvcDef[] = [
  { port: 21, proto: "tcp", name: "ftp", product: "vsftpd", p: 0.45, variants: [{ v: "2.3.4", vulns: [V("CVE-2011-2523", 9.8, "vsftpd 2.3.4 Backdoor Command Execution", "A malicious backdoor in the vsftpd 2.3.4 source opens a root shell on port 6200 when a username ending in ':)' is sent.", "Upgrade to vsftpd >= 3.0.5 from a trusted source; verify package signatures.")] }, { v: "3.0.5", vulns: [] }] },
  { port: 22, proto: "tcp", name: "ssh", product: "OpenSSH", p: 0.95, variants: [{ v: "7.2p2 Ubuntu", vulns: [V("CVE-2016-6210", 5.9, "OpenSSH User Enumeration via Timing", "Response-time difference for valid vs invalid users allows username enumeration.", "Upgrade OpenSSH >= 9.x and enforce key-based auth."), V("CVE-2018-15473", 5.3, "OpenSSH Username Enumeration", "Malformed packet auth responses reveal valid usernames.", "Upgrade OpenSSH >= 7.8.")] }, { v: "9.6p1 Ubuntu", vulns: [] }] },
  { port: 23, proto: "tcp", name: "telnet", product: "Linux telnetd", p: 0.22, variants: [{ v: "", vulns: [V("CWE-319", 7.5, "Cleartext Telnet Service Exposed", "Telnet transmits credentials and sessions unencrypted and is trivially sniffed or hijacked.", "Disable telnet; use SSH with key authentication.")] }] },
  { port: 25, proto: "tcp", name: "smtp", product: "Exim smtpd", p: 0.3, variants: [{ v: "4.87", vulns: [V("CVE-2019-10149", 9.8, "Exim 'Return of the WIZard' RCE", "Improper validation of recipient address in deliver_message() allows remote command execution as root.", "Upgrade Exim >= 4.92 and restrict SMTP exposure.")] }, { v: "4.96", vulns: [] }] },
  { port: 53, proto: "tcp", name: "domain", product: "ISC BIND", p: 0.28, variants: [{ v: "9.11.3", vulns: [V("CVE-2020-8617", 7.5, "BIND TSIG Assertion Failure DoS", "A crafted TSIG-signed message can trigger an assertion failure and crash named.", "Upgrade BIND to 9.16.3+ / 9.18.")] }, { v: "9.18.24", vulns: [] }] },
  { port: 80, proto: "tcp", name: "http", product: "Apache httpd", p: 0.85, variants: [{ v: "2.4.49", vulns: [V("CVE-2021-41773", 7.5, "Apache 2.4.49 Path Traversal", "Flaw in path normalization allows reading files outside document root.", "Upgrade Apache >= 2.4.51."), V("CVE-2021-42013", 9.8, "Apache 2.4.50 Path Traversal / RCE", "Incomplete fix allows traversal and remote code execution when mod_cgi is enabled.", "Upgrade Apache >= 2.4.51; disable mod_cgi if not needed.")] }, { v: "2.2.22 (CGI enabled)", vulns: [V("CVE-2014-6271", 10.0, "Shellshock (Bash Env Injection)", "Bash executes trailing commands in crafted environment variables passed through CGI.", "Patch bash; remove legacy CGI scripts.")] }, { v: "2.4.58", vulns: [] }] },
  { port: 80, proto: "tcp", name: "http", product: "nginx", p: 0, variants: [{ v: "1.24.0", vulns: [] }] },
  { port: 111, proto: "tcp", name: "rpcbind", product: "rpcbind", p: 0.18, variants: [{ v: "2-4", vulns: [V("CWE-200", 4.3, "RPC Portmapper Exposed", "rpcbind reveals running RPC services and can be abused for DDoS amplification.", "Firewall port 111 from untrusted networks.")] }] },
  { port: 139, proto: "tcp", name: "netbios-ssn", product: "Samba smbd", p: 0.3, variants: [{ v: "3.5.0", vulns: [V("CVE-2017-7494", 9.8, "SambaCry Remote Code Execution", "A writable share lets an attacker upload a shared library and make smbd load it, leading to RCE.", "Upgrade Samba >= 4.6.4; set 'nt pipe support = no'.")] }, { v: "4.19.5", vulns: [] }], os: "linux" },
  { port: 443, proto: "tcp", name: "https", product: "OpenSSL / Apache", p: 0.7, variants: [{ v: "OpenSSL 1.0.1f", vulns: [V("CVE-2014-0160", 7.5, "Heartbleed", "Missing bounds check in TLS heartbeat extension leaks up to 64KB of server memory (keys, sessions).", "Upgrade OpenSSL >= 1.0.1g, revoke and reissue certificates.")] }, { v: "OpenSSL 3.0.13", vulns: [] }] },
  { port: 445, proto: "tcp", name: "microsoft-ds", product: "Windows SMBv1", p: 0.2, variants: [{ v: "Windows 7 SP1", vulns: [V("CVE-2017-0144", 8.1, "EternalBlue SMBv1 RCE (MS17-010)", "A flaw in SMBv1 allows unauthenticated remote code execution via crafted packets.", "Apply MS17-010; disable SMBv1.")] }], os: "windows" },
  { port: 1433, proto: "tcp", name: "ms-sql-s", product: "Microsoft SQL Server", p: 0.1, variants: [{ v: "2014 12.0.2000", vulns: [V("CWE-521", 7.2, "Weak 'sa' Credentials Likely", "MSSQL exposed to the network with default sa account policy.", "Restrict by firewall, enforce strong auth, disable sa.")] }], os: "windows" },
  { port: 2375, proto: "tcp", name: "docker", product: "Docker Engine API", p: 0.08, variants: [{ v: "24.0 (unauthenticated)", vulns: [V("CWE-306", 10.0, "Unauthenticated Docker Remote API", "Exposed Docker daemon socket allows launching privileged containers = host takeover.", "Bind to unix socket or enable TLS client auth; firewall port 2375.")] }] },
  { port: 3306, proto: "tcp", name: "mysql", product: "MySQL", p: 0.4, variants: [{ v: "5.5.23", vulns: [V("CVE-2012-2122", 8.1, "MySQL Authentication Bypass", "Memcmp timing issue lets attackers log in with a wrong password after repeated attempts.", "Upgrade MySQL >= 5.5.24; bind to localhost.")] }, { v: "8.0.36", vulns: [] }] },
  { port: 3389, proto: "tcp", name: "ms-wbt-server", product: "Microsoft Terminal Services", p: 0.22, variants: [{ v: "6.1 (Windows 7)", vulns: [V("CVE-2019-0708", 9.8, "BlueKeep RDP RCE", "Pre-auth use-after-free in RDP allows wormable remote code execution.", "Apply KB4499175; enable NLA; put RDP behind VPN.")] }, { v: "10.0 (NLA enforced)", vulns: [] }], os: "windows" },
  { port: 5432, proto: "tcp", name: "postgresql", product: "PostgreSQL DB", p: 0.3, variants: [{ v: "11.2", vulns: [V("CVE-2019-10164", 8.8, "PostgreSQL SCRAM Stack Overflow", "Authenticated user can trigger stack buffer overflow via crafted SCRAM password change.", "Upgrade PostgreSQL >= 11.3.")] }, { v: "16.2", vulns: [] }] },
  { port: 5900, proto: "tcp", name: "vnc", product: "VNC (protocol 3.8)", p: 0.15, variants: [{ v: "no authentication", vulns: [V("CWE-306", 9.8, "VNC Server Without Authentication", "Desktop is accessible with no password - full remote control.", "Require strong password / tunnel over SSH.")] }] },
  { port: 6379, proto: "tcp", name: "redis", product: "Redis key-value store", p: 0.25, variants: [{ v: "5.0.7", vulns: [V("CVE-2022-0543", 10.0, "Redis Lua Sandbox Escape (Debian/Ubuntu)", "Lua sandbox escape lets unauthenticated users run arbitrary commands on the host.", "Upgrade package; set requirepass; bind 127.0.0.1; protected-mode yes.")] }, { v: "7.2.4", vulns: [] }] },
  { port: 8080, proto: "tcp", name: "http-proxy", product: "Apache Tomcat", p: 0.35, variants: [{ v: "9.0.30", vulns: [V("CVE-2020-1938", 9.8, "Ghostcat AJP File Read/Inclusion", "Default AJP connector on 8009 allows reading webapp files and potential RCE.", "Upgrade Tomcat >= 9.0.31; disable AJP or require secret.")] }, { v: "Struts 2.3.31", vulns: [V("CVE-2017-5638", 10.0, "Apache Struts2 Jakarta Multipart RCE", "Crafted Content-Type header leads to OGNL injection and RCE.", "Upgrade Struts >= 2.3.32 / 2.5.10.1.")] }, { v: "10.1.19", vulns: [] }] },
  { port: 9200, proto: "tcp", name: "elasticsearch", product: "Elasticsearch REST API", p: 0.15, variants: [{ v: "1.4.2", vulns: [V("CVE-2015-1427", 9.8, "Elasticsearch Groovy Sandbox Bypass RCE", "Dynamic scripting allows remote attackers to execute arbitrary Java/Groovy code.", "Upgrade >= 1.4.3; disable dynamic scripting; secure with auth.")] }, { v: "8.12.2", vulns: [] }] },
  { port: 27017, proto: "tcp", name: "mongodb", product: "MongoDB", p: 0.15, variants: [{ v: "3.4 (auth disabled)", vulns: [V("CWE-306", 9.1, "MongoDB Without Authentication", "Database accepts unauthenticated connections - full read/write/dump possible.", "Enable --auth, bind to private IP, firewall 27017.")] }, { v: "7.0.5", vulns: [] }] },
];

/* ---------- seeded rng ---------- */
function hash(str: string) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function mulberry(seed: number) {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface PortResult {
  port: number;
  proto: string;
  state: "open" | "filtered" | "closed";
  service: string;
  product: string;
  version: string;
  vulns: Vuln[];
}
export interface WebCheck {
  id: string;
  name: string;
  pass: boolean;
  sev: RiskLevel;
  detail: string;
  fix: string;
}
export interface ScanResult {
  target: string;
  ip: string;
  hostname: string;
  os: string;
  latency: number;
  mac: string;
  profile: string;
  startedAt: number;
  ports: PortResult[];
  filtered: number;
  closed: number;
  web: WebCheck[];
  risk: number;
  counts: Record<RiskLevel, number>;
  hardened: boolean;
}

const WEB_DEFS: { id: string; name: string; sev: RiskLevel; pFail: number; detail: string; fix: string }[] = [
  { id: "hsts", name: "HTTP Strict-Transport-Security header", sev: "medium", pFail: 0.6, detail: "Strict-Transport-Security header is missing; downgrade attacks possible.", fix: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'." },
  { id: "csp", name: "Content-Security-Policy header", sev: "medium", pFail: 0.7, detail: "No CSP detected; XSS impact is not mitigated by the browser.", fix: "Define a strict CSP, avoid 'unsafe-inline'." },
  { id: "xfo", name: "Clickjacking protection (X-Frame-Options)", sev: "low", pFail: 0.5, detail: "Page can be framed by any origin.", fix: "Send 'X-Frame-Options: DENY' or CSP frame-ancestors." },
  { id: "xcto", name: "X-Content-Type-Options: nosniff", sev: "low", pFail: 0.4, detail: "MIME sniffing is not disabled.", fix: "Add 'X-Content-Type-Options: nosniff'." },
  { id: "server", name: "Server banner disclosure", sev: "low", pFail: 0.65, detail: "Server header reveals exact software version.", fix: "Set ServerTokens Prod / server_tokens off." },
  { id: "cookie", name: "Cookie flags (Secure, HttpOnly, SameSite)", sev: "medium", pFail: 0.5, detail: "Session cookie lacks HttpOnly/Secure flags.", fix: "Set Secure; HttpOnly; SameSite=Lax on session cookies." },
  { id: "sqli", name: "SQL Injection (error-based) on /products?id=", sev: "critical", pFail: 0.25, detail: "Parameter 'id' returned a database error when a single quote was injected.", fix: "Use parameterised queries / prepared statements; add WAF rule." },
  { id: "xss", name: "Reflected XSS on /search?q=", sev: "high", pFail: 0.3, detail: "Input reflected without output encoding.", fix: "Context-aware output encoding; deploy CSP." },
  { id: "dirlist", name: "Directory listing disabled", sev: "medium", pFail: 0.25, detail: "Directory indexing is enabled on /uploads/.", fix: "Disable autoindex / Options -Indexes." },
  { id: "git", name: "Exposed repository metadata (/.git/)", sev: "high", pFail: 0.15, detail: "/.git/config is publicly reachable; source code may be recoverable.", fix: "Block dotfiles at the web server; remove .git from deployments." },
  { id: "cors", name: "CORS policy", sev: "medium", pFail: 0.2, detail: "Access-Control-Allow-Origin reflects arbitrary origin with credentials.", fix: "Use an explicit allowlist; never combine * with credentials." },
  { id: "tls", name: "TLS configuration (no TLS 1.0/1.1)", sev: "medium", pFail: 0.3, detail: "Server still negotiates TLS 1.0 and weak ciphers.", fix: "Enable TLS 1.2+ only with modern ciphers." },
  { id: "robots", name: "robots.txt sensitive paths", sev: "low", pFail: 0.35, detail: "robots.txt lists /admin and /backup, aiding recon.", fix: "Do not rely on robots.txt for secrecy; require authentication." },
  { id: "admin", name: "Admin panel exposed (/admin)", sev: "high", pFail: 0.2, detail: "Administrative login reachable from the internet without IP restriction or MFA.", fix: "Restrict by VPN/IP allowlist and enforce MFA." },
];

export function generateScan(rawTarget: string, profile = "full"): ScanResult {
  const target = rawTarget.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "192.168.56.101";
  const lower = target.toLowerCase();
  const rng = mulberry(hash(lower));
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
  const hardened = ["localhost", "127.0.0.1", "sugreev.local", "sgv-node-01"].includes(lower);
  const ip = hardened ? "127.0.0.1" : isIp ? target : `${rng() < 0.5 ? 192 : 10}.${Math.floor(rng() * 255)}.${Math.floor(rng() * 255)}.${1 + Math.floor(rng() * 253)}`;
  const hostname = isIp ? `host-${ip.replace(/\./g, "-")}.lab` : target;
  const latency = Math.round((0.3 + rng() * 14) * 100) / 100;
  const mac = Array.from({ length: 6 }, () => Math.floor(rng() * 256).toString(16).padStart(2, "0")).join(":").toUpperCase();

  let ports: PortResult[] = [];
  let os = "Linux 5.x (Ubuntu)";
  if (hardened) {
    ports = [
      { port: 22, proto: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: "9.6p1 Ubuntu (key-only)", vulns: [] },
      { port: 8443, proto: "tcp", state: "open", service: "https-alt", product: "sgv-siem-ui", version: "1.0 (mTLS)", vulns: [] },
    ];
    os = "Sugreev OS 1.0 (Kishkindha) - kernel 6.8.0-sgv";
  } else {
    const vulnBias = profile === "quick" ? 0.45 : 0.62;
    let windows = 0;
    const seenPorts = new Set<number>();
    for (const s of SERVICES) {
      if (s.p === 0 || seenPorts.has(s.port)) continue;
      if (rng() > s.p) continue;
      seenPorts.add(s.port);
      const vulnerable = s.variants.filter((x) => x.vulns.length > 0);
      const safe = s.variants.filter((x) => x.vulns.length === 0);
      const useVuln = vulnerable.length > 0 && (safe.length === 0 || rng() < vulnBias);
      const arr = useVuln ? vulnerable : safe;
      const variant = arr[Math.floor(rng() * arr.length)];
      let product = s.product;
      if (s.port === 80 && variant.v === "" && !variant.vulns.length) product = "nginx";
      if (s.port === 80 && !useVuln && variant.v === "2.4.58") product = "Apache httpd";
      ports.push({ port: s.port, proto: s.proto, state: "open", service: s.name, product, version: variant.v, vulns: variant.vulns });
      if (s.os === "windows") windows++;
    }
    if (ports.length < 3) {
      const ssh = SERVICES[1];
      ports.push({ port: 22, proto: "tcp", state: "open", service: "ssh", product: "OpenSSH", version: ssh.variants[0].v, vulns: ssh.variants[0].vulns });
    }
    ports = ports.filter((p, i, a) => a.findIndex((q) => q.port === p.port) === i).sort((a, b) => a.port - b.port);
    if (windows > 0) os = rng() < 0.5 ? "Microsoft Windows 7 SP1 / Server 2008 R2" : "Microsoft Windows Server 2012";
    else os = rng() < 0.5 ? "Linux 3.2 - 4.9 (Ubuntu 16.04)" : "Linux 5.4 (Ubuntu 20.04)";
  }

  const web: WebCheck[] = WEB_DEFS.map((w) => {
    const hasWeb = ports.some((p) => [80, 443, 8080, 8443].includes(p.port));
    const fail = hardened ? false : hasWeb && rng() < w.pFail;
    return { id: w.id, name: w.name, pass: !fail, sev: w.sev, detail: fail ? w.detail : "No issue detected.", fix: fail ? w.fix : "-" };
  });

  const counts: Record<RiskLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  ports.forEach((p) => p.vulns.forEach((v) => counts[sevOf(v.cvss)]++));
  web.filter((w) => !w.pass).forEach((w) => counts[w.sev]++);
  const risk = Math.min(100, counts.critical * 22 + counts.high * 10 + counts.medium * 4 + counts.low * 1);
  const filtered = hardened ? 996 : Math.floor(rng() * 30);
  const closed = hardened ? 0 : 1000 - ports.length - filtered;
  return { target, ip, hostname, os, latency, mac, profile, startedAt: Date.now(), ports, filtered, closed, web, risk, counts, hardened };
}

export function riskLabel(risk: number): { label: string; color: string } {
  if (risk >= 70) return { label: "CRITICAL", color: "#ff3b5c" };
  if (risk >= 45) return { label: "HIGH", color: "#ff7a3c" };
  if (risk >= 20) return { label: "MEDIUM", color: "#ffb020" };
  if (risk > 0) return { label: "LOW", color: "#38bdf8" };
  return { label: "MINIMAL", color: "#00ffa3" };
}

/* ---------- last scan store (shared between terminal + VAPT app) ---------- */
let lastScan: ScanResult | null = null;
const subs = new Set<() => void>();
export const getLastScan = () => lastScan;
export function setLastScan(s: ScanResult) {
  lastScan = s;
  subs.forEach((f) => f());
}
export function subscribeScan(cb: () => void) {
  subs.add(cb);
  return () => {
    subs.delete(cb);
  };
}

/* ---------- exploit database (Metasploit module paths; simulated, no payloads) ---------- */
export interface ExploitEntry {
  module: string;
  title: string;
  cve: string;
  type: "remote" | "local" | "webapp" | "auxiliary";
  platform: string;
  rank: "excellent" | "great" | "good" | "normal";
}
export const EXPLOITS: ExploitEntry[] = [
  { module: "exploit/unix/ftp/vsftpd_234_backdoor", title: "VSFTPD v2.3.4 Backdoor Command Execution", cve: "CVE-2011-2523", type: "remote", platform: "Unix", rank: "excellent" },
  { module: "exploit/linux/samba/is_known_pipename", title: "Samba is_known_pipename() Arbitrary Module Load (SambaCry)", cve: "CVE-2017-7494", type: "remote", platform: "Linux", rank: "excellent" },
  { module: "exploit/windows/smb/ms17_010_eternalblue", title: "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption", cve: "CVE-2017-0144", type: "remote", platform: "Windows", rank: "good" },
  { module: "auxiliary/scanner/ssl/openssl_heartbleed", title: "OpenSSL Heartbeat (Heartbleed) Information Leak", cve: "CVE-2014-0160", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "exploit/multi/http/apache_normalize_path_rce", title: "Apache 2.4.49/2.4.50 Traversal RCE", cve: "CVE-2021-41773", type: "webapp", platform: "Multi", rank: "excellent" },
  { module: "exploit/multi/http/struts2_content_type_ognl", title: "Apache Struts Jakarta Multipart Parser OGNL Injection", cve: "CVE-2017-5638", type: "webapp", platform: "Multi", rank: "excellent" },
  { module: "auxiliary/admin/http/tomcat_ghostcat", title: "Apache Tomcat AJP File Read (Ghostcat)", cve: "CVE-2020-1938", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "exploit/multi/http/log4shell_header_injection", title: "Log4Shell HTTP Header Injection", cve: "CVE-2021-44228", type: "webapp", platform: "Multi", rank: "excellent" },
  { module: "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", title: "CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free", cve: "CVE-2019-0708", type: "remote", platform: "Windows", rank: "good" },
  { module: "exploit/multi/redis/redis_debian_sandbox_escape", title: "Redis Lua Sandbox Escape", cve: "CVE-2022-0543", type: "remote", platform: "Linux", rank: "excellent" },
  { module: "exploit/multi/http/apache_mod_cgi_bash_env_exec", title: "Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)", cve: "CVE-2014-6271", type: "webapp", platform: "Linux", rank: "excellent" },
  { module: "exploit/unix/smtp/exim4_deliver_message_priv_esc", title: "Exim 4 deliver_message() Privilege Escalation", cve: "CVE-2019-10149", type: "remote", platform: "Unix", rank: "excellent" },
  { module: "exploit/multi/elasticsearch/search_groovy_script", title: "ElasticSearch Search Groovy Sandbox Bypass", cve: "CVE-2015-1427", type: "remote", platform: "Multi", rank: "excellent" },
  { module: "auxiliary/scanner/ssh/ssh_enumusers", title: "SSH Username Enumeration", cve: "CVE-2018-15473", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "auxiliary/scanner/mysql/mysql_authbypass_hashdump", title: "MySQL Authentication Bypass Password Dump", cve: "CVE-2012-2122", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "auxiliary/scanner/vnc/vnc_none_auth", title: "VNC Authentication None Detection", cve: "CWE-306", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "exploit/linux/http/docker_daemon_tcp", title: "Unprotected TCP Docker Daemon Remote Code Execution", cve: "CWE-306", type: "remote", platform: "Linux", rank: "excellent" },
  { module: "auxiliary/scanner/mongodb/mongodb_login", title: "MongoDB Login Utility", cve: "CWE-306", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "auxiliary/scanner/telnet/telnet_login", title: "Telnet Login Check Scanner", cve: "CWE-319", type: "auxiliary", platform: "Multi", rank: "normal" },
  { module: "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec", title: "Local Privilege Escalation in polkit's pkexec (PwnKit)", cve: "CVE-2021-4034", type: "local", platform: "Linux", rank: "excellent" },
  { module: "exploit/linux/local/dirty_pipe", title: "Dirty Pipe Local Privilege Escalation", cve: "CVE-2022-0847", type: "local", platform: "Linux", rank: "excellent" },
];

export function exploitFor(cve: string) {
  return EXPLOITS.find((e) => e.cve === cve);
}

/* ---------- CVE reference (for sugreev://cve browser page & terminal) ---------- */
export function cveDatabase(): (Vuln & { product: string })[] {
  const out: (Vuln & { product: string })[] = [];
  const seen = new Set<string>();
  for (const s of SERVICES)
    for (const v of s.variants)
      for (const x of v.vulns)
        if (!seen.has(x.cve + s.product)) {
          seen.add(x.cve + s.product);
          out.push({ ...x, product: `${s.product} ${v.v}`.trim() });
        }
  out.push({ cve: "CVE-2021-44228", cvss: 10.0, title: "Apache Log4j2 JNDI RCE (Log4Shell)", desc: "JNDI features do not protect against attacker-controlled LDAP endpoints, enabling RCE via log messages.", fix: "Upgrade Log4j >= 2.17.1; set log4j2.formatMsgNoLookups.", product: "Apache Log4j 2.0-2.14.1" });
  out.push({ cve: "CVE-2021-4034", cvss: 7.8, title: "polkit pkexec Local Privilege Escalation (PwnKit)", desc: "Out-of-bounds read/write in pkexec argument handling gives local users root.", fix: "Update polkit; chmod 0755 /usr/bin/pkexec as a stopgap.", product: "polkit < 0.120" });
  out.push({ cve: "CVE-2022-0847", cvss: 7.8, title: "Linux Kernel Dirty Pipe", desc: "Uninitialised pipe buffer flags allow overwriting data in read-only files.", fix: "Upgrade kernel >= 5.16.11 / 5.15.25 / 5.10.102.", product: "Linux Kernel 5.8 - 5.16" });
  out.push({ cve: "CVE-2023-4863", cvss: 8.8, title: "libwebp Heap Buffer Overflow", desc: "Crafted WebP image triggers heap overflow in browsers and apps embedding libwebp.", fix: "Update libwebp >= 1.3.2 and browsers.", product: "libwebp < 1.3.2" });
  out.push({ cve: "CVE-2024-3094", cvss: 10.0, title: "XZ Utils Backdoor", desc: "Malicious code in xz/liblzma 5.6.0-5.6.1 tampers with sshd authentication via systemd linkage.", fix: "Downgrade to xz 5.4.x; rebuild affected systems.", product: "xz-utils 5.6.0-5.6.1" });
  return out.sort((a, b) => b.cvss - a.cvss);
}

/* ---------- report ---------- */
export function buildReport(s: ScanResult, author = "Vaibhav Thakur"): string {
  const rl = riskLabel(s.risk);
  const date = new Date(s.startedAt).toISOString();
  const L: string[] = [];
  L.push(`# Vulnerability Assessment & Penetration Test Report`);
  L.push(``);
  L.push(`> Generated by **Sugreev OS VAPT Engine** (simulated lab data) - for education only.`);
  L.push(``);
  L.push(`| Field | Value |`);
  L.push(`|---|---|`);
  L.push(`| Target | ${s.target} (${s.ip}) |`);
  L.push(`| Hostname | ${s.hostname} |`);
  L.push(`| OS Guess | ${s.os} |`);
  L.push(`| Scan Profile | ${s.profile} |`);
  L.push(`| Date | ${date} |`);
  L.push(`| Tester | ${author} |`);
  L.push(`| Overall Risk | **${rl.label}** (${s.risk}/100) |`);
  L.push(``);
  L.push(`## 1. Executive Summary`);
  L.push(``);
  L.push(`The assessment identified **${s.counts.critical} critical**, **${s.counts.high} high**, **${s.counts.medium} medium** and **${s.counts.low} low** severity findings across ${s.ports.length} open ports and web application checks.`);
  L.push(``);
  L.push(`## 2. Open Ports & Services`);
  L.push(``);
  L.push(`| Port | Service | Product | Version |`);
  L.push(`|---|---|---|---|`);
  s.ports.forEach((p) => L.push(`| ${p.port}/${p.proto} | ${p.service} | ${p.product} | ${p.version || "-"} |`));
  L.push(``);
  L.push(`## 3. Vulnerability Findings`);
  L.push(``);
  let n = 1;
  const all = s.ports.flatMap((p) => p.vulns.map((v) => ({ p, v }))).sort((a, b) => b.v.cvss - a.v.cvss);
  if (!all.length) L.push(`No service-level vulnerabilities detected.`);
  all.forEach(({ p, v }) => {
    const ex = exploitFor(v.cve);
    L.push(`### 3.${n++} ${v.title}`);
    L.push(`- **ID:** ${v.cve}   **CVSS:** ${v.cvss.toFixed(1)} (${sevOf(v.cvss).toUpperCase()})`);
    L.push(`- **Affected:** ${p.product} ${p.version} on ${p.port}/${p.proto}`);
    L.push(`- **Description:** ${v.desc}`);
    if (ex) L.push(`- **Reference module:** \`${ex.module}\``);
    L.push(`- **Remediation:** ${v.fix}`);
    L.push(``);
  });
  L.push(`## 4. Web Application Audit`);
  L.push(``);
  L.push(`| Check | Result | Severity |`);
  L.push(`|---|---|---|`);
  s.web.forEach((w) => L.push(`| ${w.name} | ${w.pass ? "PASS" : "FAIL"} | ${w.pass ? "-" : w.sev} |`));
  L.push(``);
  const fails = s.web.filter((w) => !w.pass);
  if (fails.length) {
    L.push(`### Web Remediation`);
    fails.forEach((w) => L.push(`- **${w.name}:** ${w.fix}`));
    L.push(``);
  }
  L.push(`## 5. Recommendations`);
  L.push(``);
  L.push(`1. Patch all critical/high findings within 72 hours.`);
  L.push(`2. Restrict management and database ports with firewall rules.`);
  L.push(`3. Enforce MFA and key-based authentication.`);
  L.push(`4. Forward logs to the Sugreev SIEM and enable alerting for the observed attack patterns.`);
  L.push(`5. Re-test after remediation.`);
  L.push(``);
  L.push(`---`);
  L.push(`Report by ${author} - Sugreev OS - https://github.com/Vaibhav222209`);
  return L.join("\n");
}
