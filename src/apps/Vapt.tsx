import { Fragment, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Bug, ChevronDown, ChevronRight, Download, FileText, Globe, Play, Radar, Save, ShieldAlert, ShieldCheck, Target, TriangleAlert, Copy } from "lucide-react";
import { useOS } from "../os/context";
import * as fs from "../os/vfs";
import { generateScan, getLastScan, subscribeScan, setLastScan, buildReport, riskLabel, sevOf, exploitFor, EXPLOITS } from "../os/vapt";
import { Card, Ring, Tabs, Stat } from "../components/ui";

type Tab = "scan" | "web" | "exploits" | "report";
const SEV_C: Record<string, string> = { critical: "#ff3b5c", high: "#ff7a3c", medium: "#ffb020", low: "#38bdf8" };

function Cvss({ v }: { v: number }) {
  const c = SEV_C[sevOf(v)];
  return (
    <span className="inline-block min-w-[38px] rounded px-1.5 py-0.5 text-center font-mono text-[11px] font-bold" style={{ color: c, background: c + "1f", border: `1px solid ${c}55` }}>
      {v.toFixed(1)}
    </span>
  );
}

function useLastScan() {
  return useSyncExternalStore(subscribeScan, getLastScan, getLastScan);
}

function ScanTab() {
  const scan = useLastScan();
  const [target, setTarget] = useState(scan?.target ?? "192.168.56.101");
  const [profile, setProfile] = useState("full");
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [prog, setProg] = useState(0);
  const [open, setOpen] = useState<number | null>(null);
  const alive = useRef(true);
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => () => void (alive.current = false), []);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const start = async () => {
    if (running || !target.trim()) return;
    setRunning(true);
    setProg(0);
    setLog([`[*] Sugreev VAPT Engine — profile=${profile}`, `[*] Target: ${target}`]);
    const s = generateScan(target, profile);
    const wait = profile === "quick" ? 350 : profile === "stealth" ? 1000 : 650;
    const steps: [string, string][] = [
      ["Resolving & host discovery", `[+] host up — ip ${s.ip}, latency ${s.latency}ms, MAC ${s.mac}`],
      ["Port scan (top 1000 TCP + common UDP)", `[+] ${s.ports.length} open ports, ${s.filtered} filtered, ${s.closed} closed`],
      ["Service & version fingerprinting", `[+] ${s.ports.map((p) => p.service).join(", ")}`],
      ["OS detection", `[+] OS guess: ${s.os}`],
      ["CVE correlation & CVSS scoring", `[+] ${s.counts.critical} critical · ${s.counts.high} high · ${s.counts.medium} medium · ${s.counts.low} low`],
      ["Web application audit", `[+] ${s.web.filter((w) => !w.pass).length}/${s.web.length} web checks failed`],
    ];
    for (let i = 0; i < steps.length; i++) {
      if (!alive.current) return;
      setLog((l) => [...l, `[*] ${steps[i][0]} ...`]);
      await new Promise((r) => setTimeout(r, wait));
      setLog((l) => [...l, steps[i][1]]);
      setProg(Math.round(((i + 1) / steps.length) * 100));
    }
    if (!alive.current) return;
    setLog((l) => [...l, `[✔] Scan complete. Risk score ${s.risk}/100`]);
    setLastScan(s);
    setRunning(false);
    setOpen(null);
  };

  const rl = scan ? riskLabel(scan.risk) : null;
  const flat = scan ? scan.ports.flatMap((p) => p.vulns.map((v) => ({ p, v }))).sort((a, b) => b.v.cvss - a.v.cvss) : [];

  return (
    <div className="space-y-3 p-3">
      <div className="flex items-start gap-2 rounded-lg border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-warn">
        <TriangleAlert size={14} className="mt-0.5 shrink-0" />
        <span>
          <b>Simulation sandbox.</b> Results are generated from a seeded engine and a database of public CVEs. No packets are sent. Same target ⇒ same results. Try <span className="font-mono">sugreev.local</span> for a hardened host.
        </span>
      </div>
      <Card title="Target" icon={<Target size={13} />}>
        <div className="flex flex-wrap items-center gap-2">
          <input className="inp min-w-[180px] flex-1 font-mono" value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && start()} placeholder="IP address or hostname" />
          <select className="inp" value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="quick">Quick scan</option>
            <option value="full">Full scan</option>
            <option value="stealth">Stealth scan</option>
          </select>
          <button className="btn btn-primary" onClick={start} disabled={running}>
            <Play size={13} />
            {running ? "Scanning…" : "Start scan"}
          </button>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5 text-[10px]">
          <span className="text-slate-500">Presets:</span>
          {["192.168.56.101", "10.10.10.5", "testphp.lab", "metasploitable.lab", "sugreev.local"].map((t) => (
            <button key={t} className="rounded border border-line px-1.5 py-0.5 font-mono text-slate-400 hover:border-accent hover:text-accent" onClick={() => setTarget(t)}>{t}</button>
          ))}
        </div>
      </Card>

      {(running || log.length > 0) && (
        <Card title="Engine output" icon={<Radar size={13} />} right={<span className="font-mono text-[10px] text-accent">{prog}%</span>} bodyClass="p-0">
          <div className="h-1 w-full bg-line"><div className="h-full bg-accent transition-all duration-500" style={{ width: prog + "%" }} /></div>
          <div ref={logRef} className="selectable term-out max-h-40 overflow-auto bg-ink/70 p-3 text-[12px]">
            {log.map((l, i) => (
              <div key={i} className={l.startsWith("[+]") ? "text-emerald-400" : l.startsWith("[✔]") ? "font-bold text-accent" : "text-slate-400"}>{l}</div>
            ))}
          </div>
        </Card>
      )}

      {scan && rl && !running && (
        <>
          <div className="grid gap-3 lg:grid-cols-[auto_1fr]">
            <Card title="Risk score" icon={<ShieldAlert size={13} />}>
              <div className="flex items-center gap-4">
                <Ring value={scan.risk} size={100} stroke={10} color={rl.color} label={String(scan.risk)} sub="/ 100" />
                <div>
                  <div className="font-display text-lg font-bold" style={{ color: rl.color }}>{rl.label}</div>
                  <div className="font-mono text-[11px] text-slate-400">{scan.target}</div>
                  <div className="font-mono text-[11px] text-slate-500">{scan.ip}</div>
                </div>
              </div>
            </Card>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Critical" value={scan.counts.critical} color="#ff3b5c" />
              <Stat label="High" value={scan.counts.high} color="#ff7a3c" />
              <Stat label="Medium" value={scan.counts.medium} color="#ffb020" />
              <Stat label="Low" value={scan.counts.low} color="#38bdf8" />
              <div className="col-span-2 rounded-lg border border-line bg-panel/80 px-3 py-2 sm:col-span-4">
                <div className="text-[10px] uppercase tracking-[0.14em] text-slate-500">Host fingerprint</div>
                <div className="font-mono text-xs text-slate-300">{scan.os}</div>
                <div className="font-mono text-[11px] text-slate-500">hostname {scan.hostname} · latency {scan.latency}ms · MAC {scan.mac}</div>
              </div>
            </div>
          </div>

          <Card title={`Open ports & services (${scan.ports.length})`} icon={<Globe size={13} />} bodyClass="p-0 overflow-auto">
            <table className="tbl w-full">
              <thead><tr><th /><th>Port</th><th>State</th><th>Service</th><th>Product / Version</th><th>Findings</th></tr></thead>
              <tbody>
                {scan.ports.map((p, i) => (
                  <Fragment key={p.port}>
                    <tr className="cursor-pointer" onClick={() => setOpen(open === i ? null : i)}>
                      <td className="w-6 text-slate-500">{p.vulns.length ? open === i ? <ChevronDown size={13} /> : <ChevronRight size={13} /> : null}</td>
                      <td className="font-mono text-accent">{p.port}/{p.proto}</td>
                      <td className="font-mono text-neon">{p.state}</td>
                      <td className="font-mono text-slate-300">{p.service}</td>
                      <td className="text-slate-300">{p.product} <span className="text-slate-500">{p.version}</span></td>
                      <td>{p.vulns.length ? <span className="font-mono text-xs font-bold" style={{ color: SEV_C[sevOf(Math.max(...p.vulns.map((v) => v.cvss)))] }}>{p.vulns.length} vuln · max {Math.max(...p.vulns.map((v) => v.cvss)).toFixed(1)}</span> : <span className="text-[11px] text-slate-500">clean</span>}</td>
                    </tr>
                    {open === i && p.vulns.map((v) => {
                      const ex = exploitFor(v.cve);
                      return (
                        <tr key={p.port + v.cve} className="bg-ink/60">
                          <td />
                          <td colSpan={5}>
                            <div className="selectable space-y-1 py-1.5 text-[11px]">
                              <div className="flex items-center gap-2"><Cvss v={v.cvss} /><span className="font-mono text-accent">{v.cve}</span><span className="text-sm text-slate-200">{v.title}</span></div>
                              <div className="text-slate-400">{v.desc}</div>
                              <div className="text-emerald-400/90"><b>Fix:</b> {v.fix}</div>
                              {ex && <div className="font-mono text-slate-500">module: <span className="text-violet">{ex.module}</span></div>}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </Card>

          {flat.length > 0 && (
            <Card title="Prioritised remediation" icon={<ShieldCheck size={13} />}>
              <ol className="space-y-1.5 text-xs">
                {flat.slice(0, 6).map(({ p, v }, i) => (
                  <li key={v.cve + p.port} className="flex items-start gap-2">
                    <span className="font-mono text-slate-500">{i + 1}.</span>
                    <Cvss v={v.cvss} />
                    <span className="text-slate-300"><b className="text-slate-100">{p.service}:{p.port}</b> — {v.fix}</span>
                  </li>
                ))}
              </ol>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function WebTab() {
  const scan = useLastScan();
  if (!scan) return <Empty text="Run a scan first — the web audit uses the latest target." />;
  const fails = scan.web.filter((w) => !w.pass).length;
  return (
    <div className="space-y-3 p-3">
      <div className="flex items-center gap-3 text-xs text-slate-400">
        <span className="font-mono text-slate-200">{scan.target}</span>
        <span className={fails ? "text-crit" : "text-neon"}>{fails} failed</span>
        <span>· {scan.web.length - fails} passed</span>
      </div>
      <div className="space-y-1.5">
        {scan.web.map((w) => (
          <div key={w.id} className="flex items-start gap-3 rounded-lg border border-line bg-panel/70 px-3 py-2">
            <span className={`mt-0.5 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${w.pass ? "bg-neon/15 text-neon" : "bg-crit/15 text-crit"}`}>{w.pass ? "PASS" : "FAIL"}</span>
            <div className="min-w-0 flex-1">
              <div className="text-sm text-slate-200">{w.name}</div>
              {!w.pass && (
                <>
                  <div className="text-xs text-slate-400">{w.detail}</div>
                  <div className="text-xs text-emerald-400/90">Fix: {w.fix}</div>
                </>
              )}
            </div>
            {!w.pass && <span className="font-mono text-[10px] font-bold uppercase" style={{ color: SEV_C[w.sev] }}>{w.sev}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex h-full min-h-[240px] flex-col items-center justify-center gap-2 text-center text-sm text-slate-500">
      <Bug size={36} className="text-slate-600" />
      {text}
    </div>
  );
}

function ExploitTab() {
  const scan = useLastScan();
  const [q, setQ] = useState("");
  const relevant = new Set(scan?.ports.flatMap((p) => p.vulns.map((v) => v.cve)) ?? []);
  const rows = EXPLOITS.filter((e) => (e.title + e.module + e.cve + e.platform).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-line bg-panel/50 p-2">
        <input className="inp flex-1" placeholder="Search modules, CVE, platform…  (searchsploit style)" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="font-mono text-[10px] text-slate-500">{rows.length} modules</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="tbl w-full">
          <thead><tr><th>Module</th><th>Description</th><th>CVE</th><th>Type</th><th>Platform</th><th>Rank</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.module}>
                <td className="font-mono text-[11px] text-violet">{e.module}{relevant.has(e.cve) && <span className="ml-2 rounded bg-crit/15 px-1 text-[9px] font-bold text-crit">MATCHES SCAN</span>}</td>
                <td className="text-slate-300">{e.title}</td>
                <td className="font-mono text-accent">{e.cve}</td>
                <td className="text-slate-400">{e.type}</td>
                <td className="text-slate-400">{e.platform}</td>
                <td className="text-slate-500">{e.rank}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="border-t border-line bg-panel/60 px-3 py-1.5 font-mono text-[10px] text-slate-500">Reference catalogue only — Sugreev OS ships no payloads and executes no exploits.</div>
    </div>
  );
}

function ReportTab() {
  const scan = useLastScan();
  const os = useOS();
  const [msg, setMsg] = useState("");
  if (!scan) return <Empty text="No scan data yet. Run a scan to generate a report." />;
  const md = buildReport(scan);
  const name = `vapt-${scan.target.replace(/[^a-z0-9.-]/gi, "_")}-${new Date().toISOString().slice(0, 10)}.md`;
  const save = (openIt: boolean) => {
    if (!fs.exists(fs.HOME + "/Reports")) fs.mkdir(fs.HOME + "/Reports");
    const p = `${fs.HOME}/Reports/${name}`;
    fs.writeFile(p, md);
    setMsg(`Saved to ~/Reports/${name}`);
    if (openIt) os.openFile(p);
  };
  const dl = () => {
    const url = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-panel/50 p-2">
        <button className="btn btn-primary" onClick={() => save(true)}><Save size={13} />Save & open in editor</button>
        <button className="btn" onClick={() => save(false)}><FileText size={13} />Save to Reports</button>
        <button className="btn" onClick={dl}><Download size={13} />Download .md</button>
        <button className="btn" onClick={() => navigator.clipboard?.writeText(md).then(() => setMsg("Copied to clipboard"))}><Copy size={13} />Copy</button>
        <span className="font-mono text-[11px] text-neon">{msg}</span>
      </div>
      <pre className="selectable min-h-0 flex-1 overflow-auto whitespace-pre-wrap p-4 font-mono text-[12px] leading-relaxed text-slate-300">{md}</pre>
    </div>
  );
}

export default function Vapt() {
  const [tab, setTab] = useState<Tab>("scan");
  return (
    <div className="flex h-full flex-col bg-base/80">
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "scan", label: "Scanner", icon: <Radar size={13} /> },
          { id: "web", label: "Web Audit", icon: <Globe size={13} /> },
          { id: "exploits", label: "Exploit DB", icon: <Bug size={13} /> },
          { id: "report", label: "Report", icon: <FileText size={13} /> },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-auto">{tab === "scan" ? <ScanTab /> : tab === "web" ? <WebTab /> : tab === "exploits" ? <ExploitTab /> : <ReportTab />}</div>
    </div>
  );
}
