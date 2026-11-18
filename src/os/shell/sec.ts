import * as fs from "../vfs";
import { getSnapshot, blockIp, unblockIp, threatLabel, setAlertStatus, type Severity, type LogEvent } from "../kernel";
import { generateScan, setLastScan, getLastScan, buildReport, sevOf, riskLabel, exploitFor, EXPLOITS, cveDatabase, type ScanResult } from "../vapt";
import { pad, lpad, syslogDate, parseFlags, type Cmd, type ShellCtx, type Kind, type Seg } from "./types";

const sevKind: Record<string, Kind> = { info: "dim", low: "info", medium: "warn", high: "warn", critical: "crit" };
const cvssKind = (n: number): Kind => (n >= 9 ? "crit" : n >= 7 ? "warn" : n >= 4 ? "info" : "dim");

function evLine(e: LogEvent): Seg[] {
  return [{ t: syslogDate(e.ts) + " ", k: "dim" }, { t: pad(e.sev.toUpperCase(), 9), k: sevKind[e.sev] }, { t: pad(`[${e.source}]`, 11), k: "info" }, { t: e.msg }];
}
function ensureScan(target: string): ScanResult {
  const last = getLastScan();
  if (last && last.target === target.replace(/^https?:\/\//, "").replace(/\/.*$/, "")) return last;
  const s = generateScan(target);
  setLastScan(s);
  return s;
}
const SIM = "[simulated lab output — no packets were sent]";

function parsePorts(spec: string | undefined): ((n: number) => boolean) | null {
  if (!spec) return null;
  if (spec === "-") return () => true;
  const parts = spec.split(",").map((s) => s.trim());
  return (n) => parts.some((p) => (p.includes("-") ? n >= parseInt(p.split("-")[0]) && n <= parseInt(p.split("-")[1] || "65535") : parseInt(p) === n));
}

export const SEC: Record<string, Cmd> = {
  nmap: {
    cat: "Security", desc: "Network mapper (simulated)", usage: "nmap [-sV] [-A] [-O] [-p ports] [--script vuln] <target>",
    async run(args, c) {
      let target = "";
      let portSpec: string | undefined;
      const fl = new Set<string>();
      let script = false;
      for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === "-p") portSpec = args[++i];
        else if (a.startsWith("-p") && a.length > 2) portSpec = a.slice(2);
        else if (a.startsWith("--script")) {
          script = true;
          if (!a.includes("=")) i++;
        } else if (a.startsWith("-")) fl.add(a.slice(1));
        else target = a;
      }
      if (!target) return c.print("Nmap 7.94SVN ( https://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}", "warn");
      const s = ensureScan(target);
      const A = fl.has("A");
      c.print(`Starting Nmap 7.94SVN ( https://nmap.org ) at ${new Date().toISOString().slice(0, 16).replace("T", " ")} IST`);
      await c.sleep(700);
      c.print(`Nmap scan report for ${s.hostname}${s.hostname !== s.ip ? ` (${s.ip})` : ""}`);
      c.print(`Host is up (${(s.latency / 1000).toFixed(4)}s latency).`);
      await c.sleep(500);
      const flt = parsePorts(portSpec);
      const list = s.ports.filter((p) => !flt || flt(p.port));
      c.print(`Not shown: ${s.closed + (flt ? 0 : s.filtered)} closed tcp ports (reset)`, "dim");
      const sv = fl.has("sV") || A;
      c.print(`${pad("PORT", 10)}${pad("STATE", 7)}${pad("SERVICE", 15)}${sv ? "VERSION" : ""}`, "info");
      for (const p of list) {
        await c.sleep(140);
        c.segs([{ t: pad(`${p.port}/${p.proto}`, 10) }, { t: pad(p.state, 7), k: "ok" }, { t: pad(p.service, 15), k: "accent" }, { t: sv ? `${p.product} ${p.version}`.trim() : "" }]);
        if ((script || A) && p.vulns.length) {
          p.vulns.forEach((v) => c.segs([{ t: "|   ", k: "dim" }, { t: pad(v.cve, 16), k: "warn" }, { t: pad(v.cvss.toFixed(1), 6), k: cvssKind(v.cvss) }, { t: v.title, k: "dim" }]));
          c.print("|_  (vulners / vuln script)", "dim");
        }
      }
      if (!list.length) c.print("(no open ports in the requested range)", "dim");
      if (fl.has("O") || A) {
        c.print(`MAC Address: ${s.mac} (Virtual NIC)`, "dim");
        c.print(`OS details: ${s.os}`);
      }
      c.print(`\nService detection performed. Nmap done: 1 IP address (1 host up) scanned in ${(1.8 + s.ports.length * 0.17).toFixed(2)} seconds`);
      c.print(SIM, "dim");
    },
  },
  vapt: {
    cat: "Security", desc: "Sugreev VAPT engine", usage: "vapt scan <target> [--profile quick|full|stealth] | web <target> | report [target] | exploits <term> | summary | open",
    async run(args, c) {
      const { values, rest } = parseFlags(args, ["profile"]);
      const sub = rest[0];
      if (!sub || sub === "help") {
        c.print("Sugreev VAPT Engine v1.0 — Vulnerability Assessment & Penetration Testing (simulation sandbox)", "accent");
        c.print("  vapt scan <target> [--profile quick|full|stealth]   run full assessment\n  vapt web <target>                                   web application audit\n  vapt report [target]                                save markdown report to ~/Reports\n  vapt exploits <term>                                search exploit modules\n  vapt summary                                        show last scan summary\n  vapt open                                           open the VAPT GUI\n\nTry:  vapt scan 192.168.56.101   |   vapt scan localhost (hardened)");
        return;
      }
      if (sub === "open") return c.os.openApp("vapt");
      if (sub === "scan") {
        const target = rest[1];
        if (!target) return c.print("vapt: scan requires a target (IP or hostname)", "err");
        const prof = values.profile || "full";
        c.print(`[*] Sugreev VAPT Engine — profile=${prof}`, "accent");
        c.print(`[*] Target: ${target}`);
        const s = generateScan(target, prof);
        const phases: [string, string][] = [
          ["Phase 1/5  Host discovery", `host is up (${s.latency}ms) ip=${s.ip}`],
          ["Phase 2/5  Port scan (top 1000 TCP)", `${s.ports.length} open, ${s.filtered} filtered`],
          ["Phase 3/5  Service & version fingerprinting", `${s.ports.length} services identified, OS: ${s.os}`],
          ["Phase 4/5  CVE correlation", `${Object.values(s.counts).reduce((a, b) => a + b, 0) - s.web.filter((w) => !w.pass).length} service vulnerabilities matched`],
          ["Phase 5/5  Web application audit", `${s.web.filter((w) => !w.pass).length} of ${s.web.length} checks failed`],
        ];
        for (const [a, b] of phases) {
          c.segs([{ t: "[*] ", k: "info" }, { t: a + " ... " }]);
          await c.sleep(prof === "quick" ? 350 : prof === "stealth" ? 1100 : 700);
          c.segs([{ t: "[+] ", k: "ok" }, { t: b, k: "dim" }]);
        }
        setLastScan(s);
        c.print("");
        printSummary(c, s);
        c.print("\nNext: 'vapt report' to export, 'searchsploit <cve>' for modules.", "dim");
        c.print(SIM, "dim");
        return;
      }
      if (sub === "summary") {
        const s = getLastScan();
        if (!s) return c.print("vapt: no scan yet. Run: vapt scan <target>", "warn");
        return printSummary(c, s);
      }
      if (sub === "web") {
        const t = rest[1] || getLastScan()?.target;
        if (!t) return c.print("vapt web: need a target", "err");
        const s = ensureScan(t);
        c.print(`[*] Web audit of ${s.target}`, "accent");
        for (const w of s.web) {
          await c.sleep(90);
          c.segs([{ t: w.pass ? "[ PASS ] " : "[ FAIL ] ", k: w.pass ? "ok" : "crit" }, { t: pad(w.sev.toUpperCase(), 9), k: w.pass ? "dim" : sevKind[w.sev] }, { t: w.name }]);
          if (!w.pass) c.print(`          ↳ ${w.fix}`, "dim");
        }
        return;
      }
      if (sub === "exploits") return exploitSearch(rest.slice(1).join(" "), c);
      if (sub === "report") {
        const s = rest[1] ? ensureScan(rest[1]) : getLastScan();
        if (!s) return c.print("vapt: nothing to report. Run a scan first.", "warn");
        if (!fs.exists(fs.HOME + "/Reports")) fs.mkdir(fs.HOME + "/Reports");
        const name = `vapt-${s.target.replace(/[^a-z0-9.-]/gi, "_")}-${new Date().toISOString().slice(0, 10)}.md`;
        fs.writeFile(`${fs.HOME}/Reports/${name}`, buildReport(s));
        c.print(`[+] Report written to ~/Reports/${name}`, "ok");
        c.print("    Open with: edit ~/Reports/" + name, "dim");
        return;
      }
      c.print(`vapt: unknown subcommand '${sub}'. Try 'vapt help'.`, "err");
    },
  },
  nikto: {
    cat: "Security", desc: "Web server scanner (simulated)", usage: "nikto -h <host>",
    async run(args, c) {
      const i = args.indexOf("-h");
      const t = i >= 0 ? args[i + 1] : args[0];
      if (!t) return c.print("nikto: -h <host> required", "err");
      const s = ensureScan(t);
      c.print(`- Nikto v2.5.0\n---------------------------------------------------------------------------\n+ Target IP:          ${s.ip}\n+ Target Hostname:    ${s.hostname}\n+ Target Port:        ${s.ports.find((p) => p.port === 80 || p.port === 8080)?.port ?? 80}\n+ Start Time:         ${new Date().toISOString()}\n---------------------------------------------------------------------------`);
      const web = s.ports.find((p) => [80, 8080].includes(p.port));
      if (web) c.print(`+ Server: ${web.product} ${web.version}`);
      for (const w of s.web.filter((x) => !x.pass)) {
        await c.sleep(300);
        c.print(`+ ${w.detail}`, w.sev === "critical" || w.sev === "high" ? "crit" : "warn");
      }
      c.print(`+ ${s.web.filter((x) => !x.pass).length} item(s) reported on remote host`);
      c.print(SIM, "dim");
    },
  },
  searchsploit: {
    cat: "Security", desc: "Search exploit modules", usage: "searchsploit <term>",
    run: (args, c) => exploitSearch(args.join(" "), c),
  },
  cve: {
    cat: "Security", desc: "Look up CVE details", usage: "cve <CVE-ID | keyword>",
    run(args, c) {
      const q = args.join(" ").toLowerCase();
      if (!q) return c.print("Usage: cve <CVE-ID | keyword>", "warn");
      const r = cveDatabase().filter((v) => (v.cve + v.title + v.product + v.desc).toLowerCase().includes(q));
      if (!r.length) return c.print(`No CVE records matching '${q}' in the local database.`, "warn");
      r.slice(0, 6).forEach((v) => {
        c.segs([{ t: v.cve, k: "accent" }, { t: `  CVSS ${v.cvss.toFixed(1)} `, k: cvssKind(v.cvss) }, { t: `[${sevOf(v.cvss).toUpperCase()}]  `, k: cvssKind(v.cvss) }, { t: v.title }]);
        c.print(`    Affected : ${v.product}\n    Details  : ${v.desc}\n    Fix      : ${v.fix}\n`, "dim");
      });
    },
  },
  siem: {
    cat: "Security", desc: "Sugreev SIEM control", usage: "siem status|alerts|tail [-f]|stats|top|block <ip>|unblock <ip>|ack <id>|open",
    async run(args, c) {
      const { flags, rest } = parseFlags(args);
      const sub = rest[0] || "status";
      const k = getSnapshot();
      if (sub === "open") return c.os.openApp("siem");
      if (sub === "status") {
        const t = threatLabel(k.threatLevel);
        c.print("Sugreev SIEM v1.0 — node sgv-node-01", "accent");
        c.segs([{ t: "  engine        : " }, { t: "RUNNING", k: "ok" }]);
        c.print(`  events total  : ${k.totalEvents.toLocaleString()}\n  ingest rate   : ${k.epsHist.slice(-10).reduce((a, b) => a + b, 0) / 10} eps (10s avg)\n  rules loaded  : 128 (MITRE mapped: 119)\n  open alerts   : ${k.alerts.filter((a) => a.status === "open").length} (critical: ${k.alerts.filter((a) => a.status === "open" && a.sev === "critical").length})\n  blocked IPs   : ${k.blockedIps.length}\n  auto-response : ${k.autoBlock ? "ENABLED" : "disabled"}`);
        c.segs([{ t: "  threat level  : " }, { t: `${t.label} (${k.threatLevel}/100)`, k: k.threatLevel < 35 ? "ok" : k.threatLevel < 60 ? "warn" : "crit" }]);
        return;
      }
      if (sub === "alerts") {
        const n = parseInt(rest[1] ?? "10");
        c.print(`${pad("ID", 6)}${pad("SEV", 10)}${pad("STATUS", 15)}${pad("SOURCE IP", 17)}${pad("MITRE", 11)}TITLE`, "info");
        k.alerts.slice(0, n).forEach((a) => c.segs([{ t: pad(a.id, 6), k: "dim" }, { t: pad(a.sev.toUpperCase(), 10), k: sevKind[a.sev] }, { t: pad(a.status, 15) }, { t: pad(a.srcIp, 17) }, { t: pad(a.mitre, 11), k: "accent" }, { t: a.title }]));
        return;
      }
      if (sub === "tail") {
        const n = parseInt(rest[1] ?? "12") || 12;
        k.events.slice(0, n).reverse().forEach((e) => c.segs(evLine(e)));
        if (flags.has("f")) {
          c.print("-- following (Ctrl+C to stop) --", "dim");
          let last = k.events[0]?.id ?? 0;
          for (;;) {
            await c.sleep(1000);
            const fresh = getSnapshot().events.filter((e) => e.id > last);
            fresh.reverse().forEach((e) => c.segs(evLine(e)));
            if (fresh.length) last = Math.max(...fresh.map((e) => e.id));
          }
        }
        return;
      }
      if (sub === "stats") {
        c.print("Events by severity", "accent");
        (Object.keys(k.sevCounts) as Severity[]).forEach((s) => c.segs([{ t: "  " + pad(s, 10), k: sevKind[s] }, { t: lpad(k.sevCounts[s], 5) + "  " }, { t: "█".repeat(Math.ceil(k.sevCounts[s] / 6)), k: sevKind[s] }]));
        c.print("\nEvents by source", "accent");
        Object.entries(k.srcCounts).forEach(([s, n]) => c.segs([{ t: "  " + pad(s, 10), k: "info" }, { t: lpad(n, 5) + "  " }, { t: "█".repeat(Math.ceil(n / 6)), k: "info" }]));
        return;
      }
      if (sub === "top") {
        c.print(`${pad("SOURCE IP", 18)}${pad("COUNTRY", 16)}${pad("EVENTS", 8)}STATE`, "info");
        k.attackers.forEach((a) => c.segs([{ t: pad(a.ip, 18) }, { t: pad(a.country.name, 16) }, { t: pad(a.count, 8) }, { t: a.blocked ? "BLOCKED" : "active", k: a.blocked ? "ok" : "crit" }]));
        return;
      }
      if (sub === "block" || sub === "unblock") {
        const ip = rest[1];
        if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return c.print(`Usage: siem ${sub} <ip>`, "err");
        if (!c.root) return c.print("siem: firewall changes require root (use sudo)", "err");
        sub === "block" ? blockIp(ip) : unblockIp(ip);
        return c.print(`[+] ${ip} ${sub === "block" ? "added to" : "removed from"} the firewall blocklist`, "ok");
      }
      if (sub === "ack" || sub === "resolve") {
        const id = parseInt(rest[1]);
        if (!k.alerts.find((a) => a.id === id)) return c.print(`siem: alert #${rest[1]} not found`, "err");
        setAlertStatus(id, sub === "ack" ? "investigating" : "resolved");
        return c.print(`[+] alert #${id} marked ${sub === "ack" ? "investigating" : "resolved"}`, "ok");
      }
      c.print(`siem: unknown subcommand '${sub}'`, "err");
    },
  },
  threats: {
    cat: "Security", desc: "Threat summary (or 'threats map')", usage: "threats [map]",
    run(args, c) {
      if (args[0] === "map" || args[0] === "open") return c.os.openApp("threats");
      const k = getSnapshot();
      const t = threatLabel(k.threatLevel);
      c.segs([{ t: "THREAT LEVEL  ", k: "accent" }, { t: `${t.label} `, k: k.threatLevel < 35 ? "ok" : k.threatLevel < 60 ? "warn" : "crit" }, { t: `[${"█".repeat(Math.round(k.threatLevel / 5))}${"░".repeat(20 - Math.round(k.threatLevel / 5))}] ${k.threatLevel}/100` }]);
      c.print(`Active attackers: ${k.attackers.filter((a) => !a.blocked).length}   Blocked: ${k.blockedIps.length}   Surge: ${k.surge ? "YES" : "no"}\n`);
      c.print("Top hostile sources:", "info");
      k.attackers.slice(0, 6).forEach((a) => c.segs([{ t: "  " + pad(a.ip, 17) }, { t: pad(a.country.name, 14), k: "dim" }, { t: lpad(a.count, 3) + " events  " }, { t: a.blocked ? "blocked" : "ACTIVE", k: a.blocked ? "ok" : "crit" }]));
      c.print("\nType 'threats map' to open the live threat map.", "dim");
    },
  },
  ping: {
    cat: "Network", desc: "Send ICMP echo (simulated)", usage: "ping [-c N] <host>",
    async run(args, c) {
      const { values, rest } = parseFlags(args, ["c"]);
      const t = rest[0];
      if (!t) return c.print("ping: usage error: Destination address required", "err");
      const s = generateScan(t);
      const n = parseInt(values.c ?? "4");
      c.print(`PING ${t} (${s.ip}) 56(84) bytes of data.`);
      const times: number[] = [];
      for (let i = 1; i <= n; i++) {
        await c.sleep(650);
        const ms = s.latency + Math.random() * 2;
        times.push(ms);
        c.print(`64 bytes from ${s.ip}: icmp_seq=${i} ttl=${s.os.startsWith("Micro") ? 128 : 64} time=${ms.toFixed(1)} ms`);
      }
      const avg = times.reduce((a, b) => a + b, 0) / n;
      c.print(`\n--- ${t} ping statistics ---\n${n} packets transmitted, ${n} received, 0% packet loss, time ${n * 650}ms\nrtt min/avg/max/mdev = ${Math.min(...times).toFixed(3)}/${avg.toFixed(3)}/${Math.max(...times).toFixed(3)}/0.412 ms`);
    },
  },
  traceroute: {
    cat: "Network", desc: "Trace route to host (simulated)", usage: "traceroute <host>",
    async run(args, c) {
      if (!args[0]) return c.print("traceroute: missing host", "err");
      const s = generateScan(args[0]);
      c.print(`traceroute to ${args[0]} (${s.ip}), 30 hops max, 60 byte packets`);
      const hops = ["_gateway (10.0.0.1)", "isp-edge-01.net (100.64.0.1)", "core-rtr.isp.net (172.16.4.9)", "ae-4.bb.transit.net (80.231.1.4)", "ix-2.peering.net (195.66.224.12)", `edge.${s.hostname.replace(/^host-/, "")} (${s.ip})`];
      for (let i = 0; i < hops.length; i++) {
        await c.sleep(380);
        c.print(`${lpad(i + 1, 2)}  ${hops[i]}  ${(1 + i * 3.2 + Math.random()).toFixed(3)} ms  ${(1 + i * 3.1 + Math.random()).toFixed(3)} ms  ${(1 + i * 3.4 + Math.random()).toFixed(3)} ms`);
      }
    },
  },
  whois: {
    cat: "Network", desc: "Domain registration lookup (simulated)", usage: "whois <domain>",
    run(args, c) {
      const d = args[0];
      if (!d) return c.print("whois: missing domain", "err");
      const s = generateScan(d);
      c.print(`Domain Name: ${d.toUpperCase()}\nRegistry Domain ID: D${s.mac.replace(/:/g, "").slice(0, 8)}-SGV\nRegistrar: Sugreev Registrar Simulation, Inc.\nCreation Date: 2016-0${(s.latency % 9 | 0) + 1}-14T08:00:00Z\nRegistry Expiry Date: 2027-03-14T08:00:00Z\nRegistrant Organization: REDACTED FOR PRIVACY\nName Server: NS1.${d.toUpperCase()}\nName Server: NS2.${d.toUpperCase()}\nDNSSEC: unsigned\n${SIM}`);
    },
  },
  dig: {
    cat: "Network", desc: "DNS lookup (simulated)", usage: "dig <domain>",
    run(args, c) {
      const d = args.find((a) => !a.startsWith("-") && !a.startsWith("@"));
      if (!d) return c.print("dig: missing domain", "err");
      const s = generateScan(d);
      c.print(`; <<>> Sugreev dig 9.18 <<>> ${d}\n;; ANSWER SECTION:\n${pad(d + ".", 28)}300 IN A  ${s.ip}\n\n;; Query time: ${Math.round(s.latency)} msec\n;; SERVER: 127.0.0.53#53(127.0.0.53)\n${SIM}`);
    },
  },
  nslookup: { cat: "Network", desc: "Query DNS (simulated)", run: (a, c) => (a[0] ? c.print(`Server:  127.0.0.53\nAddress: 127.0.0.53#53\n\nName:    ${a[0]}\nAddress: ${generateScan(a[0]).ip}`) : c.print("nslookup: missing host", "err")) },
  curl: {
    cat: "Network", desc: "Transfer a URL (simulated)", usage: "curl [-I] <url>",
    async run(args, c) {
      const { flags, rest } = parseFlags(args);
      const u = rest[0];
      if (!u) return c.print("curl: try 'curl --help' for more information", "err");
      const s = generateScan(u);
      const web = s.ports.find((p) => [80, 443, 8080].includes(p.port));
      await c.sleep(350);
      if (flags.has("I") || flags.has("i")) {
        c.print(`HTTP/1.1 200 OK\nServer: ${s.hardened ? "sugreev-httpd" : web ? `${web.product}/${web.version}`.trim() : "unknown"}\nDate: ${new Date().toUTCString()}\nContent-Type: text/html; charset=UTF-8\n${s.web.find((w) => w.id === "hsts")?.pass ? "Strict-Transport-Security: max-age=31536000\n" : ""}${s.web.find((w) => w.id === "csp")?.pass ? "Content-Security-Policy: default-src 'self'\n" : ""}Connection: keep-alive`);
      } else c.print(`<!doctype html><html><head><title>${s.hostname}</title></head><body><h1>It works!</h1><!-- ${SIM} --></body></html>`);
    },
  },
  hashid: {
    cat: "Crypto", desc: "Identify hash type", usage: "hashid <hash>",
    run(args, c) {
      const h = args[0];
      if (!h) return c.print("Usage: hashid <hash>", "warn");
      const L = h.length;
      const hex = /^[0-9a-f]+$/i.test(h);
      const r: string[] = [];
      if (h.startsWith("$2")) r.push("bcrypt");
      else if (h.startsWith("$6$")) r.push("SHA-512 Crypt (Unix)");
      else if (h.startsWith("$5$")) r.push("SHA-256 Crypt (Unix)");
      else if (h.startsWith("$1$")) r.push("MD5 Crypt (Unix)");
      else if (hex && L === 32) r.push("MD5", "NTLM", "MD4");
      else if (hex && L === 40) r.push("SHA-1", "RIPEMD-160");
      else if (hex && L === 64) r.push("SHA-256", "SHA3-256");
      else if (hex && L === 96) r.push("SHA-384");
      else if (hex && L === 128) r.push("SHA-512", "Whirlpool");
      if (!r.length) return c.print("Unknown hash format", "warn");
      r.forEach((x) => c.print(`[+] ${x}`, "ok"));
    },
  },
  iptables: {
    cat: "Firewall", desc: "Firewall rules", usage: "iptables -L",
    run(_a, c) {
      const k = getSnapshot();
      c.print("Chain INPUT (policy DROP)", "accent");
      c.print("target     prot opt source               destination", "info");
      k.blockedIps.forEach((ip) => c.print(`DROP       all  --  ${pad(ip, 20)} anywhere`));
      c.print("ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED\nACCEPT     tcp  --  10.0.0.0/24          anywhere             tcp dpt:ssh\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:https\nACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http");
      c.print("\nChain FORWARD (policy DROP)\n\nChain OUTPUT (policy ACCEPT)", "accent");
    },
  },
  ufw: {
    cat: "Firewall", desc: "Uncomplicated firewall", usage: "ufw status",
    run(_a, c) {
      const k = getSnapshot();
      c.segs([{ t: "Status: " }, { t: "active", k: "ok" }]);
      c.print("\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       10.0.0.0/24\n80/tcp                     ALLOW       Anywhere\n443/tcp                    ALLOW       Anywhere");
      k.blockedIps.forEach((ip) => c.segs([{ t: pad("Anywhere", 27) }, { t: pad("DENY", 12), k: "crit" }, { t: ip }]));
    },
  },
  "fail2ban-client": {
    cat: "Firewall", desc: "Fail2ban status", usage: "fail2ban-client status [sshd]",
    run(_a, c) {
      const k = getSnapshot();
      const f = k.events.filter((e) => e.rule === "SSH Brute Force").length;
      c.print(`Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t${Math.min(f, 9)}\n|  |- Total failed:\t${f * 14}\n|  \`- File list:\t/var/log/auth.log\n\`- Actions\n   |- Currently banned:\t${k.blockedIps.length}\n   |- Total banned:\t${k.blockedIps.length + 37}\n   \`- Banned IP list:\t${k.blockedIps.join(" ") || "(none)"}`);
    },
  },
};

function exploitSearch(q: string, c: ShellCtx) {
  const t = q.toLowerCase();
  if (!t) return c.print("Usage: searchsploit <term>   e.g. searchsploit apache", "warn");
  const r = EXPLOITS.filter((e) => (e.title + e.module + e.cve + e.platform).toLowerCase().includes(t));
  if (!r.length) return c.print("Exploits: No Results", "warn");
  c.print(`${pad("Exploit Title", 70)}| Module Path`, "info");
  c.print("-".repeat(70) + "-+-" + "-".repeat(50), "dim");
  r.forEach((e) => c.segs([{ t: pad(e.title.slice(0, 68), 70) }, { t: "| " }, { t: e.module, k: "accent" }]));
  c.print(`\n${r.length} module(s) found. (reference only — Sugreev ships no payloads)`, "dim");
}

function printSummary(c: ShellCtx, s: ScanResult) {
  const rl = riskLabel(s.risk);
  c.print(`═══ Scan Summary: ${s.target} (${s.ip}) ═══`, "accent");
  c.print(`OS guess : ${s.os}`);
  c.print(`${pad("PORT", 11)}${pad("SERVICE", 15)}${pad("VERSION", 34)}VULNS`, "info");
  s.ports.forEach((p) => c.segs([{ t: pad(`${p.port}/${p.proto}`, 11) }, { t: pad(p.service, 15), k: "accent" }, { t: pad(`${p.product} ${p.version}`.trim().slice(0, 32), 34) }, { t: p.vulns.length ? String(p.vulns.length) : "-", k: p.vulns.length ? "crit" : "ok" }]));
  const all = s.ports.flatMap((p) => p.vulns.map((v) => ({ p, v }))).sort((a, b) => b.v.cvss - a.v.cvss);
  if (all.length) {
    c.print("\nTop findings:", "info");
    all.slice(0, 8).forEach(({ p, v }) => {
      c.segs([{ t: pad(v.cve, 16), k: "warn" }, { t: pad(v.cvss.toFixed(1), 6), k: cvssKind(v.cvss) }, { t: pad(`${p.port}/${p.proto}`, 10), k: "dim" }, { t: v.title }]);
      const ex = exploitFor(v.cve);
      if (ex) c.print(`                                      ↳ module: ${ex.module}`, "dim");
    });
  }
  c.segs([{ t: "\nRisk score: " }, { t: `${s.risk}/100 ${rl.label}`, k: s.risk >= 45 ? "crit" : s.risk >= 20 ? "warn" : "ok" }, { t: `   (critical ${s.counts.critical}, high ${s.counts.high}, medium ${s.counts.medium}, low ${s.counts.low})`, k: "dim" }]);
}
