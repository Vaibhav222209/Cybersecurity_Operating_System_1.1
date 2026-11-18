import { useMemo, useState } from "react";
import { Activity, AlertTriangle, Ban, CheckCircle2, Database, Eye, LayoutDashboard, ListFilter, Pause, Play, ScrollText, Search, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import { useKernel, blockIp, setAlertStatus, resolveAllAlerts, SEV_COLOR, type Alert, type Severity, type LogEvent, type LogSource } from "../os/kernel";
import { useOS } from "../os/context";
import { Card, Sparkline, Stat, Tabs, SevBadge, Bar, Toggle, fmtTime, fmtNum } from "../components/ui";

type Tab = "dash" | "logs" | "alerts" | "rules";
const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const SOURCES: LogSource[] = ["auth", "firewall", "ids", "web", "endpoint", "dns", "kernel"];

const TACTICS: [string, string[]][] = [
  ["Reconnaissance", ["T1595", "T1595.002"]],
  ["Initial Access", ["T1190", "T1078"]],
  ["Execution", ["T1059", "T1059.004", "T1059.007", "T1203"]],
  ["Persistence", ["T1053", "T1053.003"]],
  ["Priv. Escalation", ["T1548", "T1548.001"]],
  ["Defense Evasion", ["T1562", "T1562.001"]],
  ["Credential Access", ["T1110", "T1110.001", "T1110.004"]],
  ["Discovery", ["T1046", "T1083"]],
  ["Command & Control", ["T1071", "T1071.004", "T1568.002"]],
  ["Exfiltration", ["T1041"]],
];

const RULES = [
  { name: "SSH Brute Force", mitre: "T1110.001", sev: "medium", src: "auth" },
  { name: "Credential Stuffing", mitre: "T1110.004", sev: "high", src: "auth" },
  { name: "Successful Login After Brute Force", mitre: "T1078", sev: "critical", src: "auth" },
  { name: "Port Scan Detected", mitre: "T1046", sev: "low", src: "firewall" },
  { name: "Recon Tool Fingerprint", mitre: "T1595.002", sev: "medium", src: "ids" },
  { name: "Log4Shell RCE Attempt", mitre: "T1190", sev: "critical", src: "ids" },
  { name: "Exploit Kit / Shellcode", mitre: "T1203", sev: "high", src: "ids" },
  { name: "SQL Injection", mitre: "T1190", sev: "high", src: "web" },
  { name: "Directory Traversal", mitre: "T1083", sev: "medium", src: "web" },
  { name: "Reflected XSS", mitre: "T1059.007", sev: "medium", src: "web" },
  { name: "Sensitive File Probe", mitre: "T1083", sev: "low", src: "web" },
  { name: "Reverse Shell Spawned", mitre: "T1059.004", sev: "critical", src: "endpoint" },
  { name: "Suspicious SUID Binary", mitre: "T1548.001", sev: "high", src: "endpoint" },
  { name: "Persistence via Cron", mitre: "T1053.003", sev: "medium", src: "endpoint" },
  { name: "C2 Beaconing (DNS)", mitre: "T1071.004", sev: "high", src: "dns" },
  { name: "DGA-like Domain", mitre: "T1568.002", sev: "low", src: "dns" },
  { name: "Outbound Data Exfil", mitre: "T1041", sev: "medium", src: "firewall" },
  { name: "Security Service Stopped", mitre: "T1562.001", sev: "high", src: "endpoint" },
];

const PLAYBOOK: Record<string, string[]> = {
  "SSH Brute Force": ["Confirm repeated failures in /var/log/auth.log", "Block source IP at the firewall", "Verify PasswordAuthentication is disabled", "Check fail2ban jail status"],
  "Log4Shell RCE Attempt": ["Identify exposed Java services (Elasticsearch, Tomcat, Struts)", "Upgrade Log4j >= 2.17.1", "Block outbound LDAP/RMI at egress", "Hunt for JNDI strings in web logs"],
  "Reverse Shell Spawned": ["Isolate the host from the network immediately", "Capture process tree and memory", "Kill suspicious PID, rotate credentials", "Review web shell / dropper in /var/www"],
  "SQL Injection": ["Review WAF logs for successful 200 responses", "Patch with parameterised queries", "Rotate DB credentials if data exposure suspected"],
  "Successful Login After Brute Force": ["Treat account as compromised — force logout", "Reset credentials and revoke SSH keys", "Search for persistence (cron, authorized_keys, SUID)", "Escalate to incident commander"],
  "C2 Beaconing (DNS)": ["Sinkhole the domain at DNS", "Identify the internal host making the queries", "Run EDR triage and memory scan"],
};
const DEFAULT_PLAY = ["Validate alert (true / false positive)", "Enrich source IP with threat intelligence", "Contain: block IP / isolate host if confirmed", "Document findings and close alert"];

function statusColor(s: string) {
  return s === "open" ? "#ff3b5c" : s === "investigating" ? "#ffb020" : s === "blocked" ? "#38bdf8" : "#00ffa3";
}

function Dashboard({ go }: { go: (t: Tab) => void }) {
  const k = useKernel();
  const open = k.alerts.filter((a) => a.status === "open");
  const techniques = useMemo(() => {
    const m: Record<string, number> = {};
    k.events.forEach((e) => e.mitre && (m[e.mitre] = (m[e.mitre] || 0) + 1));
    return m;
  }, [k.events]);
  const maxT = Math.max(1, ...TACTICS.map(([, ids]) => ids.reduce((s, i) => s + (techniques[i] || 0), 0)));
  const maxSev = Math.max(1, ...Object.values(k.sevCounts));
  const maxSrc = Math.max(1, ...Object.values(k.srcCounts));

  return (
    <div className="space-y-3 p-3">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Events / sec" value={k.eps} sub={`avg ${(k.epsHist.reduce((a, b) => a + b, 0) / k.epsHist.length).toFixed(1)} · 60s`} icon={<Zap size={13} />} color="var(--accent)" />
        <Stat label="Events indexed" value={fmtNum(k.totalEvents)} sub="since boot + archive" icon={<Database size={13} />} />
        <Stat label="Open alerts" value={open.length} sub={`${k.alerts.length} total tracked`} icon={<AlertTriangle size={13} />} color="#ffb020" />
        <Stat label="Critical open" value={open.filter((a) => a.sev === "critical").length} sub="needs triage < 15 min" icon={<ShieldAlert size={13} />} color="#ff3b5c" />
        <Stat label="Blocked IPs" value={k.blockedIps.length} sub={k.autoBlock ? "auto-response ON" : "manual response"} icon={<Ban size={13} />} color="#38bdf8" />
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="Ingest rate (EPS)" icon={<Activity size={13} />} className="lg:col-span-2">
          <Sparkline data={k.epsHist} height={110} />
          <div className="mt-2 flex justify-between font-mono text-[10px] text-slate-500">
            <span>-60s</span>
            <span>-30s</span>
            <span>now</span>
          </div>
        </Card>
        <Card title="Severity" icon={<ListFilter size={13} />}>
          <div className="space-y-2">
            {SEVS.map((s) => (
              <div key={s} className="flex items-center gap-2 text-xs">
                <span className="w-14 font-mono uppercase" style={{ color: SEV_COLOR[s] }}>{s}</span>
                <div className="flex-1"><Bar value={k.sevCounts[s]} max={maxSev} color={SEV_COLOR[s]} /></div>
                <span className="w-8 text-right font-mono text-slate-400">{k.sevCounts[s]}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>
      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="MITRE ATT&CK coverage" icon={<ShieldCheck size={13} />}>
          <div className="space-y-1.5">
            {TACTICS.map(([n, ids]) => {
              const v = ids.reduce((s, i) => s + (techniques[i] || 0), 0);
              return (
                <div key={n} className="flex items-center gap-2 text-[11px]">
                  <span className="w-28 truncate text-slate-400">{n}</span>
                  <div className="h-3 flex-1 overflow-hidden rounded-sm bg-[#0e1c2b]">
                    <div className="h-full rounded-sm" style={{ width: `${(v / maxT) * 100}%`, background: `linear-gradient(90deg, #0e7490, ${v / maxT > 0.6 ? "#ff3b5c" : "var(--accent)"})` }} />
                  </div>
                  <span className="w-6 text-right font-mono text-slate-500">{v}</span>
                </div>
              );
            })}
          </div>
        </Card>
        <Card title="Top sources (log type)" icon={<ScrollText size={13} />}>
          <div className="space-y-2">
            {SOURCES.map((s) => (
              <div key={s} className="flex items-center gap-2 text-xs">
                <span className="w-16 font-mono text-slate-400">{s}</span>
                <div className="flex-1"><Bar value={k.srcCounts[s]} max={maxSrc} /></div>
                <span className="w-8 text-right font-mono text-slate-500">{k.srcCounts[s]}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Top attackers" icon={<ShieldAlert size={13} />} right={<button className="text-[10px] text-accent hover:underline" onClick={() => go("alerts")}>alerts →</button>} bodyClass="p-0 overflow-auto max-h-64">
          <table className="tbl w-full">
            <tbody>
              {k.attackers.slice(0, 8).map((a) => (
                <tr key={a.ip}>
                  <td className="font-mono text-slate-200">{a.ip}</td>
                  <td className="text-slate-500">{a.country.code}</td>
                  <td className="font-mono text-slate-400">{a.count}</td>
                  <td className="text-right">
                    {a.blocked ? <span className="text-[10px] text-info">BLOCKED</span> : <button className="text-[10px] text-crit hover:underline" onClick={() => blockIp(a.ip)}>block</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
      <Card title="Latest alerts" icon={<AlertTriangle size={13} />} bodyClass="p-0">
        <table className="tbl w-full">
          <tbody>
            {k.alerts.slice(0, 5).map((a) => (
              <tr key={a.id}>
                <td className="w-16"><SevBadge sev={a.sev} /></td>
                <td className="text-slate-200">{a.title}</td>
                <td className="font-mono text-slate-500">{a.srcIp}</td>
                <td className="font-mono text-accent">{a.mitre}</td>
                <td className="text-right font-mono text-[10px]" style={{ color: statusColor(a.status) }}>{a.status.toUpperCase()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function Logs() {
  const k = useKernel();
  const [sev, setSev] = useState<"all" | Severity>("all");
  const [src, setSrc] = useState<"all" | LogSource>("all");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<LogEvent[]>([]);
  const [selId, setSelId] = useState<number | null>(null);
  const base = paused ? frozen : k.events;
  const rows = base.filter((e) => (sev === "all" || e.sev === sev) && (src === "all" || e.source === src) && (!q || (e.msg + e.srcIp).toLowerCase().includes(q.toLowerCase()))).slice(0, 200);
  const sel = base.find((e) => e.id === selId);
  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel/50 p-2">
        <button className={`btn ${paused ? "btn-primary" : ""}`} onClick={() => (setFrozen(k.events), setPaused(!paused))}>{paused ? <Play size={12} /> : <Pause size={12} />}{paused ? "Resume" : "Pause"}</button>
        <select className="inp" value={sev} onChange={(e) => setSev(e.target.value as Severity)}>
          <option value="all">All severities</option>
          {SEVS.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="inp" value={src} onChange={(e) => setSrc(e.target.value as LogSource)}>
          <option value="all">All sources</option>
          {SOURCES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <div className="relative flex-1">
          <Search size={12} className="absolute left-2 top-2 text-slate-500" />
          <input className="inp !w-full !pl-7" placeholder="Search message or IP…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <span className="font-mono text-[10px] text-slate-500">{rows.length} shown {!paused && <span className="ml-1 text-neon">● live</span>}</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="tbl w-full font-mono">
          <thead>
            <tr><th>Time</th><th>Sev</th><th>Source</th><th>Src IP</th><th>Message</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} onClick={() => setSelId(e.id)} className={`cursor-pointer ${selId === e.id ? "!bg-accent/10" : ""}`}>
                <td className="whitespace-nowrap text-slate-500">{fmtTime(e.ts)}</td>
                <td><SevBadge sev={e.sev} /></td>
                <td className="text-info">{e.source}</td>
                <td className="whitespace-nowrap text-slate-400">{e.srcIp}</td>
                <td className="max-w-[520px] truncate text-slate-300" title={e.msg}>{e.msg}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sel && (
        <div className="selectable border-t border-accent/40 bg-ink/90 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
          <div className="mb-1 flex items-center justify-between text-accent">
            <span>EVENT #{sel.id}</span>
            <button className="text-slate-500 hover:text-white" onClick={() => setSelId(null)}>close ✕</button>
          </div>
          <div><span className="text-slate-500">timestamp</span> {new Date(sel.ts).toISOString()} <span className="text-slate-500 ml-3">host</span> {sel.host}</div>
          <div><span className="text-slate-500">src</span> {sel.srcIp} {sel.country && `(${sel.country})`} <span className="text-slate-500 ml-3">dst</span> {sel.dstIp} {sel.rule && <><span className="text-slate-500 ml-3">rule</span> {sel.rule}</>} {sel.mitre && <><span className="text-slate-500 ml-3">mitre</span> <span className="text-accent">{sel.mitre}</span></>}</div>
          <div className="mt-1 break-all text-white">{sel.msg}</div>
        </div>
      )}
    </div>
  );
}

function Alerts() {
  const k = useKernel();
  const os = useOS();
  const [filter, setFilter] = useState<"all" | Alert["status"]>("all");
  const [selId, setSelId] = useState<number | null>(null);
  const rows = k.alerts.filter((a) => filter === "all" || a.status === filter);
  const sel = k.alerts.find((a) => a.id === selId) ?? null;
  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-line bg-panel/50 p-2">
          {(["all", "open", "investigating", "blocked", "resolved"] as const).map((f) => (
            <button key={f} onClick={() => setFilter(f)} className={`btn ${filter === f ? "btn-primary" : ""} capitalize`}>
              {f} <span className="font-mono text-[10px] opacity-70">{f === "all" ? k.alerts.length : k.alerts.filter((a) => a.status === f).length}</span>
            </button>
          ))}
          <button className="btn ml-auto" onClick={resolveAllAlerts}><CheckCircle2 size={12} />Resolve all</button>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="tbl w-full">
            <thead><tr><th>ID</th><th>Sev</th><th>Alert</th><th>Source</th><th>MITRE</th><th>Time</th><th>Status</th></tr></thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} onClick={() => setSelId(a.id)} className={`cursor-pointer ${selId === a.id ? "!bg-accent/10" : ""}`}>
                  <td className="font-mono text-slate-500">#{a.id}</td>
                  <td><SevBadge sev={a.sev} /></td>
                  <td className="text-slate-200">{a.title}</td>
                  <td className="font-mono text-slate-400">{a.srcIp} <span className="text-slate-600">{a.country}</span></td>
                  <td className="font-mono text-accent">{a.mitre}</td>
                  <td className="font-mono text-slate-500">{fmtTime(a.ts)}</td>
                  <td className="font-mono text-[10px]" style={{ color: statusColor(a.status) }}>{a.status.toUpperCase()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="p-10 text-center text-sm text-slate-500">No alerts in this view.</div>}
        </div>
      </div>
      {sel && (
        <div className="anim-slide hidden w-72 shrink-0 overflow-y-auto border-l border-line bg-panel/80 p-3 md:block">
          <div className="flex items-center justify-between">
            <SevBadge sev={sel.sev} />
            <button className="text-xs text-slate-500 hover:text-white" onClick={() => setSelId(null)}>✕</button>
          </div>
          <h3 className="mt-2 text-sm font-semibold text-white">{sel.title}</h3>
          <div className="mt-1 font-mono text-[11px] text-slate-500">Alert #{sel.id} · {new Date(sel.ts).toLocaleString()}</div>
          <div className="selectable mt-3 rounded-md border border-line bg-ink p-2 font-mono text-[11px] leading-relaxed text-slate-300">{sel.msg}</div>
          <div className="mt-3 grid grid-cols-2 gap-2 text-[11px]">
            <div><div className="text-slate-500">Source</div><div className="font-mono text-slate-200">{sel.srcIp}</div></div>
            <div><div className="text-slate-500">Country</div><div className="text-slate-200">{sel.country}</div></div>
            <div><div className="text-slate-500">MITRE</div><button className="font-mono text-accent hover:underline" onClick={() => os.openApp("browser", { url: `https://attack.mitre.org/techniques/${sel.mitre.replace(".", "/")}/` })}>{sel.mitre} ↗</button></div>
            <div><div className="text-slate-500">Status</div><div className="font-mono" style={{ color: statusColor(sel.status) }}>{sel.status}</div></div>
          </div>
          <div className="mt-4 font-mono text-[10px] uppercase tracking-widest text-slate-500">Response playbook</div>
          <ol className="mt-1 space-y-1.5 text-xs text-slate-300">
            {(PLAYBOOK[sel.rule] ?? DEFAULT_PLAY).map((s, i) => (
              <li key={i} className="flex gap-2"><span className="font-mono text-accent">{i + 1}.</span>{s}</li>
            ))}
          </ol>
          <div className="mt-4 flex flex-wrap gap-2">
            <button className="btn" onClick={() => setAlertStatus(sel.id, "investigating")}><Eye size={12} />Investigate</button>
            <button className="btn btn-danger" onClick={() => blockIp(sel.srcIp)} disabled={sel.country === "--"}><Ban size={12} />Block IP</button>
            <button className="btn btn-primary" onClick={() => setAlertStatus(sel.id, "resolved")}><CheckCircle2 size={12} />Resolve</button>
          </div>
        </div>
      )}
    </div>
  );
}

function Rules() {
  const k = useKernel();
  const [on, setOn] = useState<Record<string, boolean>>({});
  return (
    <div className="h-full overflow-auto">
      <table className="tbl w-full">
        <thead><tr><th>Rule</th><th>MITRE</th><th>Severity</th><th>Source</th><th>Hits (buffer)</th><th>Enabled</th></tr></thead>
        <tbody>
          {RULES.map((r) => (
            <tr key={r.name}>
              <td className="text-slate-200">{r.name}</td>
              <td className="font-mono text-accent">{r.mitre}</td>
              <td><SevBadge sev={r.sev} /></td>
              <td className="font-mono text-info">{r.src}</td>
              <td className="font-mono text-slate-400">{k.events.filter((e) => e.rule === r.name).length}</td>
              <td><Toggle on={on[r.name] ?? true} onChange={(v) => setOn({ ...on, [r.name]: v })} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="p-3 font-mono text-[10px] text-slate-500">Rules are loaded from /etc/sugreev/rules.d — 128 total, {RULES.length} shown in the community pack.</div>
    </div>
  );
}

export default function Siem() {
  const k = useKernel();
  const [tab, setTab] = useState<Tab>("dash");
  const openCount = k.alerts.filter((a) => a.status === "open").length;
  return (
    <div className="flex h-full flex-col bg-base/80">
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "dash", label: "Dashboard", icon: <LayoutDashboard size={13} /> },
          { id: "logs", label: "Live Logs", icon: <ScrollText size={13} /> },
          { id: "alerts", label: "Alerts", icon: <AlertTriangle size={13} />, badge: openCount > 0 ? <span className="rounded bg-crit/20 px-1 font-mono text-[10px] text-crit">{openCount}</span> : null },
          { id: "rules", label: "Detection Rules", icon: <ShieldCheck size={13} /> },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-auto">{tab === "dash" ? <Dashboard go={setTab} /> : tab === "logs" ? <Logs /> : tab === "alerts" ? <Alerts /> : <Rules />}</div>
    </div>
  );
}
