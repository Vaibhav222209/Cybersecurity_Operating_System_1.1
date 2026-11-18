// Sugreev OS — in-memory virtual file system (persisted to localStorage).
import { useSyncExternalStore } from "react";

export interface FSNode {
  type: "file" | "dir";
  content?: string;
  children?: Record<string, FSNode>;
  mtime: number;
  mode: string;
  owner: string;
}

export const HOME = "/home/vaibhav";
const KEY = "sugreev.fs.v2";

const T0 = Date.now() - 1000 * 60 * 60 * 24 * 12;
const f = (content: string, owner = "vaibhav", mode = "-rw-r--r--"): FSNode => ({ type: "file", content, mtime: T0 + Math.floor(Math.random() * 1e9), mode, owner });
const d = (children: Record<string, FSNode> = {}, owner = "vaibhav", mode = "drwxr-xr-x"): FSNode => ({ type: "dir", children, mtime: T0 + Math.floor(Math.random() * 1e9), mode, owner });

function authLog() {
  const ips = ["185.220.101.4", "91.240.118.22", "112.85.42.17", "45.155.205.9", "177.54.19.200", "78.128.113.7"];
  const out: string[] = [];
  for (let i = 0; i < 38; i++) {
    const ip = ips[i % ips.length];
    const m = String(10 + Math.floor(i / 6)).padStart(2, "0");
    const s = String((i * 7) % 60).padStart(2, "0");
    if (i % 9 === 8) out.push(`Mar 14 ${m}:${s}:11 sgv-node-01 sshd[2211]: Accepted publickey for vaibhav from 10.0.0.21 port 51822 ssh2: ED25519 SHA256:q8...Zk`);
    else if (i % 5 === 4) out.push(`Mar 14 ${m}:${s}:02 sgv-node-01 sudo: vaibhav : TTY=pts/0 ; PWD=/home/vaibhav ; USER=root ; COMMAND=/usr/bin/apt update`);
    else out.push(`Mar 14 ${m}:${s}:42 sgv-node-01 sshd[${2100 + i}]: Failed password for ${i % 2 ? "root" : "invalid user admin"} from ${ip} port ${40000 + i * 37} ssh2`);
  }
  return out.join("\n") + "\n";
}

function sysLog() {
  return [
    "Mar 14 08:00:01 sgv-node-01 systemd[1]: Started Sugreev SIEM Daemon.",
    "Mar 14 08:00:02 sgv-node-01 sgv-siemd[412]: loaded 128 detection rules (MITRE ATT&CK mapped)",
    "Mar 14 08:00:03 sgv-node-01 sgv-ids[418]: engine started, 42,118 signatures loaded",
    "Mar 14 08:00:04 sgv-node-01 sgv-firewalld[421]: default policy: deny incoming, allow outgoing",
    "Mar 14 08:00:09 sgv-node-01 NetworkManager[502]: <info> device (eth0): state change: activated",
    "Mar 14 08:01:15 sgv-node-01 fail2ban.actions[1301]: NOTICE [sshd] Ban 185.220.101.4",
    "Mar 14 08:05:44 sgv-node-01 sgv-threatintel[1533]: feed sync complete (+312 IOCs)",
    "Mar 14 08:12:08 sgv-node-01 CRON[3921]: (root) CMD (/opt/sugreev/bin/log-rotate)",
    "Mar 14 08:30:31 sgv-node-01 kernel: [ 1830.2] audit: type=1400 apparmor=\"STATUS\" operation=\"profile_load\"",
    "Mar 14 09:02:10 sgv-node-01 clamd[1480]: SelfCheck: Database status OK.",
  ].join("\n") + "\n";
}

function buildDefault(): FSNode {
  const readme = `# Sugreev OS 1.0 "Kishkindha"

Welcome, Vaibhav. This is your home directory on Sugreev OS —
a Linux-style cybersecurity operating system running in your browser.

Quick start
-----------
  terminal     -> type 'help' for 110+ commands
  siem         -> open the SIEM console with live logs & alerts
  threats      -> live threat map and IDS/IPS
  vapt         -> simulated vulnerability assessment lab

Everything here is simulated for education. No packets leave your browser.

Author : Vaibhav Thakur  (github.com/Vaibhav222209)
`;
  return d(
    {
      bin: d({ ls: f("#!sugreev-builtin"), cat: f("#!sugreev-builtin"), nmap: f("#!sugreev-builtin"), vapt: f("#!sugreev-builtin"), siem: f("#!sugreev-builtin") }, "root"),
      boot: d({ "vmlinuz-6.8.0-sgv": f("\u0000BINARY\u0000", "root"), "initrd.img-6.8.0-sgv": f("\u0000BINARY\u0000", "root"), grub: d({ "grub.cfg": f('set default=0\nset timeout=3\nmenuentry "Sugreev OS 1.0 (Kishkindha)" {\n  linux /boot/vmlinuz-6.8.0-sgv root=/dev/nvme0n1p2 quiet splash lockdown=integrity\n  initrd /boot/initrd.img-6.8.0-sgv\n}\n', "root")}, "root") }, "root"),
      dev: d({ null: f("", "root", "crw-rw-rw-"), tty: f("", "root", "crw-rw-rw-"), random: f("", "root", "crw-rw-rw-") }, "root"),
      etc: d(
        {
          hostname: f("sgv-node-01\n", "root"),
          hosts: f("127.0.0.1\tlocalhost\n127.0.1.1\tsgv-node-01 sugreev.local\n10.0.0.5\tsgv-node-01\n::1\tlocalhost ip6-localhost\n", "root"),
          "os-release": f('NAME="Sugreev OS"\nVERSION="1.0 (Kishkindha)"\nID=sugreev\nID_LIKE=debian\nPRETTY_NAME="Sugreev OS 1.0 Kishkindha"\nVERSION_ID="1.0"\nHOME_URL="https://github.com/Vaibhav222209/Sugreev-OS"\nSUPPORT_URL="https://github.com/Vaibhav222209/Sugreev-OS/issues"\n', "root"),
          passwd: f("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:114:120:PostgreSQL:/var/lib/postgresql:/bin/bash\nclamav:x:116:122::/var/lib/clamav:/bin/false\nvaibhav:x:1000:1000:Vaibhav Thakur:/home/vaibhav:/bin/bash\nanalyst:x:1001:1001:SOC Analyst:/home/analyst:/bin/bash\n", "root"),
          shadow: f("root:$6$sgv$Hq0v...REDACTED:19800:0:99999:7:::\nvaibhav:$6$sgv$k9Zt...REDACTED:19800:0:99999:7:::\n", "root", "-rw-r-----"),
          group: f("root:x:0:\nsudo:x:27:vaibhav\nvaibhav:x:1000:\nsiem:x:2000:vaibhav,analyst\n", "root"),
          issue: f("Sugreev OS 1.0 \\n \\l\n", "root"),
          motd: f("Welcome to Sugreev OS - authorised access only. All activity is monitored by SIEM.\n", "root"),
          sugreev: d(
            {
              "siem.conf": f("# Sugreev SIEM configuration\n[core]\nnode_name   = sgv-node-01\nretention   = 90d\nbatch_size  = 512\n\n[ingest]\nsyslog      = udp://0.0.0.0:514\nbeats       = tcp://0.0.0.0:5044\nfilebeat    = /var/log/*.log\n\n[detection]\nrules_dir   = /etc/sugreev/rules.d\nmitre_map   = true\nauto_block  = false\n\n[notify]\nsmtp        = alerts@sugreev.local\nwebhook     = https://hooks.sugreev.local/soc\n", "root"),
              "ids.yaml": f("# Sugreev IDS/IPS\nvars:\n  HOME_NET: \"[10.0.0.0/24]\"\n  EXTERNAL_NET: \"!$HOME_NET\"\nmode: ips\ninterfaces:\n  - eth0\nrule-files:\n  - emerging-exploit.rules\n  - emerging-scan.rules\n  - sugreev-custom.rules\n", "root"),
              "rules.d": d({ "10-ssh-bruteforce.rule": f("name: SSH Brute Force\nmitre: T1110.001\nmatch: source=auth AND msg~'Failed password'\nthreshold: 5 in 60s per src_ip\nseverity: medium\naction: alert\n", "root"), "20-sqli.rule": f("name: SQL Injection\nmitre: T1190\nmatch: source=web AND msg~'(UNION SELECT|OR 1=1|--)'\nseverity: high\naction: alert,block\n", "root"), "30-reverse-shell.rule": f("name: Reverse Shell Spawned\nmitre: T1059.004\nmatch: source=endpoint AND msg~'/dev/tcp/'\nseverity: critical\naction: alert,isolate\n", "root") }, "root"),
            },
            "root",
          ),
          ssh: d({ sshd_config: f("Port 22\nProtocol 2\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\nMaxAuthTries 3\nClientAliveInterval 300\nAllowUsers vaibhav analyst\nX11Forwarding no\n", "root") }, "root"),
          ufw: d({ "ufw.conf": f("ENABLED=yes\nLOGLEVEL=medium\n", "root") }, "root"),
        },
        "root",
      ),
      home: d({
        vaibhav: d({
          ".bashrc": f('# ~/.bashrc - Sugreev OS\nexport PS1="\\u@\\h:\\w\\$ "\nalias ll="ls -la"\nalias scan="vapt scan"\nalias alerts="siem alerts"\nexport PATH="$PATH:/opt/sugreev/bin"\n'),
          ".bash_history": f("ls -la\nsiem status\nvapt scan 192.168.56.101\nsudo apt update\n"),
          ".ssh": d({ authorized_keys: f("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEx... vaibhav@sugreev\n", "vaibhav", "-rw-------") }, "vaibhav", "drwx------"),
          "README.md": f(readme),
          "notes.txt": f("TODO\n----\n[x] Deploy SIEM node\n[x] Enable IDS in IPS mode\n[ ] Run weekly VAPT against lab network 192.168.56.0/24\n[ ] Write incident-response runbook for ransomware\n[ ] Rotate SSH keys\n\nIdeas\n-----\n- Add YARA rules to endpoint sensor\n- Map detections to MITRE ATT&CK coverage matrix\n"),
          Desktop: d({ "welcome.txt": f("Welcome to Sugreev OS!\nDouble-click the dock icons on the left to launch apps.\n") }),
          Documents: d({
            "security-policy.md": f("# Security Policy\n\n1. All access via SSH keys only.\n2. Principle of least privilege.\n3. Logs retained for 90 days.\n4. Critical alerts must be triaged within 15 minutes.\n"),
            "incident-response-playbook.md": f("# Incident Response Playbook\n\n## 1. Preparation\n- Maintain asset inventory & contact tree\n\n## 2. Identification\n- Triage SIEM alert, validate true/false positive\n\n## 3. Containment\n- Block attacker IP (SIEM > Alerts > Block)\n- Isolate affected host\n\n## 4. Eradication\n- Remove persistence (cron, SUID, SSH keys)\n\n## 5. Recovery\n- Restore from clean backup, monitor for 72h\n\n## 6. Lessons Learned\n- Post-incident review within 5 days\n"),
            "network-diagram.txt": f("            [Internet]\n                |\n          [Firewall/IPS]\n                |\n   +------------+------------+\n   |            |            |\n [DMZ]        [LAN]       [SIEM]\n web-01      10.0.0.0/24  sgv-node-01\n"),
            "mitre-coverage.csv": f("tactic,technique,covered\nInitial Access,T1190,yes\nExecution,T1059,yes\nPersistence,T1053,yes\nPrivilege Escalation,T1548,yes\nCredential Access,T1110,yes\nDiscovery,T1046,yes\nExfiltration,T1041,partial\nImpact,T1486,no\n"),
          }),
          Downloads: d({ "wordlist-sample.txt": f("password\n123456\nadmin\nletmein\nqwerty\nwelcome1\nsugreev\n") }),
          Pictures: d({ "wallpaper-notes.txt": f("Wallpapers are rendered live: matrix rain, neon grid, aurora.\nChange them in Settings > Appearance.\n") }),
          Reports: d({ "sample-pentest-report.md": f("# Sample Penetration Test Report\n\n**Target:** 192.168.56.101 (lab)\n**Tester:** Vaibhav Thakur\n\n## Summary\n3 critical, 2 high, 4 medium findings.\n\n## Top Finding\nvsftpd 2.3.4 backdoor (CVE-2011-2523) - CVSS 9.8\n\n## Remediation\nUpgrade vsftpd >= 3.0.5, restrict FTP at firewall.\n") }),
          Tools: d({
            "portscan.sh": f('#!/bin/bash\n# Simple wrapper for the Sugreev VAPT engine\nTARGET=${1:-192.168.56.101}\necho "[*] scanning $TARGET"\nnmap -sV $TARGET\n', "vaibhav", "-rwxr-xr-x"),
            "backup.sh": f("#!/bin/bash\ntar czf /tmp/backup-$(date +%F).tgz ~/Documents ~/Reports\necho 'backup complete'\n", "vaibhav", "-rwxr-xr-x"),
            "ioc-list.txt": f("# Indicators of Compromise\n185.220.101.4\n91.240.118.22\nupdate-sec.xyz\ncdn-static-live.top\n44d88612fea8a8f36de82e1278abb02f\n"),
          }),
        }),
        analyst: d({ "shift-handover.txt": f("Shift handover: 2 open incidents, 1 pending VAPT retest.\n", "analyst") }, "analyst"),
      }),
      lib: d({}, "root"),
      mnt: d({}, "root"),
      opt: d({ sugreev: d({ bin: d({ "log-rotate": f("#!sugreev-builtin", "root", "-rwxr-xr-x") }, "root"), siem: d({ siemd: f("\u0000BINARY\u0000", "root", "-rwxr-xr-x") }, "root"), ids: d({}, "root"), vapt: d({ "engine": f("\u0000BINARY\u0000", "root", "-rwxr-xr-x") }, "root") }, "root") }, "root"),
      proc: d(
        {
          cpuinfo: f("processor\t: 0\nvendor_id\t: SugreevSilicon\ncpu family\t: 25\nmodel name\t: Sugreev SG-8700X Cyber-Core Processor\ncpu MHz\t\t: 3800.000\ncache size\t: 32768 KB\ncpu cores\t: 8\nsiblings\t: 16\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sse sse2 aes avx avx2 bmi2 sha_ni\nbogomips\t: 7600.00\n", "root"),
          meminfo: f("MemTotal:       16777216 kB\nMemFree:         6291456 kB\nMemAvailable:   10485760 kB\nBuffers:          262144 kB\nCached:          4194304 kB\nSwapTotal:       4194304 kB\nSwapFree:        4063232 kB\n", "root"),
          version: f("Sugreev version 6.8.0-sgv (vaibhav@build) (gcc 13.2.0) #1 SMP PREEMPT_DYNAMIC Kishkindha\n", "root"),
        },
        "root",
      ),
      root: d({ "flag.txt": f("SGV{y0u_n33d_r00t_f0r_th1s}\n", "root", "-rw-------") }, "root", "drwx------"),
      srv: d({}, "root"),
      tmp: d({}, "root", "drwxrwxrwt"),
      usr: d({ bin: d({}, "root"), share: d({}, "root"), local: d({}, "root") }, "root"),
      var: d(
        {
          log: d(
            {
              "auth.log": f(authLog(), "root", "-rw-r-----"),
              syslog: f(sysLog(), "root", "-rw-r-----"),
              "ufw.log": f("Mar 14 08:03:12 sgv-node-01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.4 DST=10.0.0.5 PROTO=TCP DPT=22\nMar 14 08:03:13 sgv-node-01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.4 DST=10.0.0.5 PROTO=TCP DPT=23\nMar 14 08:06:40 sgv-node-01 kernel: [UFW BLOCK] IN=eth0 SRC=91.240.118.22 DST=10.0.0.5 PROTO=TCP DPT=3389\n", "root", "-rw-r-----"),
              "sugreev-siem.log": f("[2026-03-14T08:00:02Z] INFO  siemd: rules loaded=128 mitre_mapped=119\n[2026-03-14T08:02:51Z] WARN  siemd: alert #501 'SSH Brute Force' src=185.220.101.4\n[2026-03-14T08:10:12Z] CRIT  siemd: alert #507 'Log4Shell RCE Attempt' src=45.155.205.9\n[2026-03-14T08:10:13Z] INFO  siemd: response executed: block 45.155.205.9\n", "root", "-rw-r-----"),
              nginx: d({ "access.log": f('185.220.101.4 - - [14/Mar/2026:08:10:11 +0000] "GET /products.php?id=1\' OR \'1\'=\'1\'-- HTTP/1.1" 500 612 "-" "sqlmap/1.7"\n91.240.118.22 - - [14/Mar/2026:08:11:42 +0000] "GET /.env HTTP/1.1" 404 146 "-" "Mozilla/5.0"\n10.0.0.21 - - [14/Mar/2026:08:12:00 +0000] "GET / HTTP/1.1" 200 2048 "-" "Mozilla/5.0"\n', "www-data", "-rw-r-----") }, "www-data"),
            },
            "root",
          ),
          lib: d({}, "root"),
          www: d({ html: d({ "index.html": f("<h1>Sugreev OS web node</h1>\n", "www-data") }, "www-data") }, "root"),
        },
        "root",
      ),
    },
    "root",
  );
}

/* ---------- store ---------- */
let root: FSNode = load();
let version = 0;
const listeners = new Set<() => void>();
let saveTimer: ReturnType<typeof setTimeout> | null = null;

function load(): FSNode {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    /* ignore */
  }
  return buildDefault();
}
function bump() {
  version++;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(root));
    } catch {
      /* quota */
    }
  }, 400);
  listeners.forEach((l) => l());
}
export function useFsVersion() {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    },
    () => version,
    () => version,
  );
}
export function resetFs() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  root = buildDefault();
  bump();
}

/* ---------- path helpers ---------- */
export function resolvePath(p: string, cwd = HOME): string {
  if (!p) return cwd;
  if (p === "~") p = HOME;
  else if (p.startsWith("~/")) p = HOME + p.slice(1);
  const parts = (p.startsWith("/") ? p : cwd + "/" + p).split("/");
  const out: string[] = [];
  for (const s of parts) {
    if (!s || s === ".") continue;
    if (s === "..") out.pop();
    else out.push(s);
  }
  return "/" + out.join("/");
}
export function dirname(p: string) {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}
export function basename(p: string) {
  return p === "/" ? "/" : p.slice(p.lastIndexOf("/") + 1);
}
export function prettyPath(p: string) {
  if (p === HOME) return "~";
  if (p.startsWith(HOME + "/")) return "~" + p.slice(HOME.length);
  return p;
}
export function getNode(path: string): FSNode | null {
  if (path === "/") return root;
  let cur = root;
  for (const s of path.split("/").filter(Boolean)) {
    if (cur.type !== "dir" || !cur.children || !cur.children[s]) return null;
    cur = cur.children[s];
  }
  return cur;
}
export const exists = (p: string) => !!getNode(p);
export const isDir = (p: string) => getNode(p)?.type === "dir";
export function sizeOf(n: FSNode): number {
  if (n.type === "file") return (n.content || "").length;
  return 4096;
}
export function listDir(path: string): { name: string; node: FSNode }[] | null {
  const n = getNode(path);
  if (!n || n.type !== "dir" || !n.children) return null;
  return Object.entries(n.children)
    .map(([name, node]) => ({ name, node }))
    .sort((a, b) => (a.node.type === b.node.type ? a.name.localeCompare(b.name) : a.node.type === "dir" ? -1 : 1));
}
export function readFile(path: string): string | null {
  const n = getNode(path);
  return n && n.type === "file" ? n.content ?? "" : null;
}
export function writeFile(path: string, content: string, owner = "vaibhav"): boolean {
  const parent = getNode(dirname(path));
  if (!parent || parent.type !== "dir" || !parent.children) return false;
  const name = basename(path);
  const ex = parent.children[name];
  if (ex && ex.type === "dir") return false;
  parent.children[name] = ex ? { ...ex, content, mtime: Date.now() } : { type: "file", content, mtime: Date.now(), mode: "-rw-r--r--", owner };
  bump();
  return true;
}
export function mkdir(path: string, parents = false): boolean {
  if (exists(path)) return parents;
  const parent = dirname(path);
  if (!exists(parent)) {
    if (!parents || !mkdir(parent, true)) return false;
  }
  const pn = getNode(parent);
  if (!pn || pn.type !== "dir" || !pn.children) return false;
  pn.children[basename(path)] = d({}, "vaibhav");
  pn.children[basename(path)].mtime = Date.now();
  bump();
  return true;
}
export function remove(path: string): boolean {
  if (path === "/") return false;
  const parent = getNode(dirname(path));
  if (!parent || !parent.children) return false;
  const name = basename(path);
  if (!parent.children[name]) return false;
  delete parent.children[name];
  bump();
  return true;
}
export function rename(from: string, to: string): boolean {
  const n = getNode(from);
  if (!n) return false;
  let dest = to;
  if (isDir(to)) dest = to + "/" + basename(from);
  const dp = getNode(dirname(dest));
  if (!dp || dp.type !== "dir" || !dp.children) return false;
  if (dest.startsWith(from + "/")) return false;
  dp.children[basename(dest)] = n;
  const sp = getNode(dirname(from));
  if (sp && sp.children && !(dirname(from) === dirname(dest) && basename(from) === basename(dest))) delete sp.children[basename(from)];
  n.mtime = Date.now();
  bump();
  return true;
}
export function copy(from: string, to: string): boolean {
  const n = getNode(from);
  if (!n) return false;
  let dest = to;
  if (isDir(to)) dest = to + "/" + basename(from);
  const dp = getNode(dirname(dest));
  if (!dp || dp.type !== "dir" || !dp.children) return false;
  dp.children[basename(dest)] = JSON.parse(JSON.stringify(n));
  dp.children[basename(dest)].mtime = Date.now();
  bump();
  return true;
}
export function chmod(path: string, mode: string): boolean {
  const n = getNode(path);
  if (!n) return false;
  n.mode = mode;
  bump();
  return true;
}
export function touch(path: string): boolean {
  const n = getNode(path);
  if (n) {
    n.mtime = Date.now();
    bump();
    return true;
  }
  return writeFile(path, "");
}
export function walk(path: string, cb: (p: string, n: FSNode) => void) {
  const n = getNode(path);
  if (!n) return;
  cb(path, n);
  if (n.type === "dir" && n.children) {
    for (const k of Object.keys(n.children).sort()) walk((path === "/" ? "" : path) + "/" + k, cb);
  }
}
export function uniqueName(dirPath: string, base: string): string {
  let name = base;
  let i = 1;
  while (exists(dirPath + "/" + name)) name = `${base} ${i++}`;
  return name;
}
export function isBinary(content: string | null | undefined) {
  return !!content && (content.startsWith("\u0000BINARY") || content.startsWith("#!sugreev-builtin"));
}
export function fmtSize(n: number) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
