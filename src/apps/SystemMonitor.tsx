import { useState } from "react";
import { Activity, ArrowDown, ArrowUp, Cpu, HardDrive, MemoryStick, Network, Skull, Thermometer, ListTree, Wrench, Search } from "lucide-react";
import { useKernel, killProc, CPU_INFO, injectEvent } from "../os/kernel";
import { Card, Sparkline, Bar, Tabs, Stat, fmtRate, fmtUptime } from "../components/ui";

type Tab = "perf" | "procs" | "hw";
type SortKey = "cpu" | "mem" | "pid" | "name";

const coreColor = (v: number) => (v > 80 ? "#ff3b5c" : v > 55 ? "#ffb020" : "var(--accent)");

function Perf() {
  const k = useKernel();
  const memPct = (k.memUsed / k.memTotal) * 100;
  const tempColor = k.temp > 75 ? "#ff3b5c" : k.temp > 62 ? "#ffb020" : "#00ffa3";
  return (
    <div className="space-y-3 p-3">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="CPU" value={k.cpuTotal.toFixed(0) + "%"} sub={`${(k.freq.reduce((a, b) => a + b, 0) / k.freq.length).toFixed(2)} GHz avg`} icon={<Cpu size={13} />} color="var(--accent)" />
        <Stat label="Memory" value={memPct.toFixed(0) + "%"} sub={`${(k.memUsed / 1024).toFixed(1)} / ${(k.memTotal / 1024).toFixed(0)} GiB`} icon={<MemoryStick size={13} />} color="#a78bfa" />
        <Stat label="Temperature" value={k.temp.toFixed(0) + "°C"} sub="package sensor" icon={<Thermometer size={13} />} color={tempColor} />
        <Stat label="Uptime" value={fmtUptime(k.now - k.bootTime)} sub={`load ${k.load.map((x) => x.toFixed(2)).join(" ")}`} icon={<Activity size={13} />} />
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="CPU utilisation · 60s" icon={<Cpu size={13} />} className="lg:col-span-2">
          <Sparkline data={k.cpuHist} height={100} max={100} />
          <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-4">
            {k.cpu.map((c, i) => (
              <div key={i}>
                <div className="flex justify-between font-mono text-[10px] text-slate-400">
                  <span>CORE {i}</span>
                  <span style={{ color: coreColor(c) }}>{c.toFixed(0)}%</span>
                </div>
                <Bar value={c} color={coreColor(c)} height={5} />
                <div className="mt-0.5 font-mono text-[9px] text-slate-600">{k.freq[i].toFixed(2)} GHz</div>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Processor" icon={<Cpu size={13} />}>
          <div className="space-y-1.5 text-[11px]">
            {[
              ["Model", CPU_INFO.model],
              ["Vendor", CPU_INFO.vendor],
              ["Architecture", CPU_INFO.arch],
              ["Cores / Threads", `${CPU_INFO.cores} / ${CPU_INFO.threads}`],
              ["Base / Boost", `${CPU_INFO.baseGhz.toFixed(1)} / ${CPU_INFO.boostGhz.toFixed(1)} GHz`],
              ["L1 cache", CPU_INFO.l1d],
              ["L2 cache", CPU_INFO.l2],
              ["L3 cache", CPU_INFO.l3],
              ["TDP", CPU_INFO.tdp],
              ["Processes", String(k.procs.length)],
            ].map(([a, b]) => (
              <div key={a} className="flex justify-between gap-3 border-b border-line/60 pb-1">
                <span className="text-slate-500">{a}</span>
                <span className="text-right font-mono text-slate-200">{b}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="Memory" icon={<MemoryStick size={13} />}>
          <Sparkline data={k.memHist} height={60} min={4000} max={8000} color="#a78bfa" />
          <div className="mt-2 flex h-3 overflow-hidden rounded bg-[#0e1c2b]">
            <div style={{ width: `${(k.memUsed / k.memTotal) * 100}%`, background: "#a78bfa" }} />
            <div style={{ width: `${(k.memCached / k.memTotal) * 100}%`, background: "#38bdf8", opacity: 0.6 }} />
          </div>
          <div className="mt-2 grid grid-cols-3 gap-2 font-mono text-[10px] text-slate-400">
            <div><i className="mr-1 inline-block h-2 w-2 rounded-sm bg-violet" />used {Math.round(k.memUsed)}M</div>
            <div><i className="mr-1 inline-block h-2 w-2 rounded-sm bg-info" />cache {Math.round(k.memCached)}M</div>
            <div>free {Math.round(k.memTotal - k.memUsed - k.memCached)}M</div>
          </div>
          <div className="mt-2 text-[10px] text-slate-500">Swap {Math.round(k.swapUsed)} / {k.swapTotal} MiB</div>
        </Card>
        <Card title="Network · eth0" icon={<Network size={13} />}>
          <div className="space-y-2">
            <div>
              <div className="flex justify-between font-mono text-[11px]"><span className="flex items-center gap-1 text-neon"><ArrowDown size={11} />RX</span><span>{fmtRate(k.rx)}</span></div>
              <Sparkline data={k.rxHist} height={34} color="#00ffa3" />
            </div>
            <div>
              <div className="flex justify-between font-mono text-[11px]"><span className="flex items-center gap-1 text-warn"><ArrowUp size={11} />TX</span><span>{fmtRate(k.tx)}</span></div>
              <Sparkline data={k.txHist} height={34} color="#ffb020" />
            </div>
          </div>
          <div className="mt-2 font-mono text-[10px] text-slate-500">10.0.0.5/24 · 1000 Mbps · {k.surge ? <span className="text-crit">traffic surge</span> : "normal"}</div>
        </Card>
        <Card title="Storage" icon={<HardDrive size={13} />}>
          <div className="space-y-3 text-[11px]">
            {[["/ (nvme0n1p2)", 49, "214 / 468 GB"], ["/boot/efi", 2, "6 / 512 MB"], ["/mnt/evidence (sda1)", 36, "612 GB / 1.8 TB"]].map(([n, p, d]) => (
              <div key={n as string}>
                <div className="mb-1 flex justify-between"><span className="text-slate-300">{n}</span><span className="font-mono text-slate-500">{d}</span></div>
                <Bar value={p as number} color={(p as number) > 80 ? "#ff3b5c" : "var(--accent)"} />
              </div>
            ))}
            <div className="flex justify-between font-mono text-[10px] text-slate-500">
              <span>read {k.diskR.toFixed(0)} MB/s</span>
              <span>write {k.diskW.toFixed(0)} MB/s</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

function Procs() {
  const k = useKernel();
  const [sort, setSort] = useState<SortKey>("cpu");
  const [q, setQ] = useState("");
  const [msg, setMsg] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const rows = k.procs
    .filter((p) => !q || (p.name + p.user + p.pid).toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => (sort === "name" ? a.name.localeCompare(b.name) : sort === "pid" ? a.pid - b.pid : (b[sort] as number) - (a[sort] as number)));
  const kill = () => {
    if (sel === null) return;
    const p = k.procs.find((x) => x.pid === sel);
    if (!p) return;
    if (p.user === "root" || p.protected) return setMsg(`Operation not permitted: ${p.name} (${p.pid}) is owned by ${p.user}. Use sudo in the terminal.`);
    const r = killProc(sel);
    if (r === "ok") {
      injectEvent({ sev: "medium", source: "endpoint", msg: `process ${p.name}[${p.pid}] terminated by vaibhav (SIGKILL)`, rule: "Security Service Stopped", mitre: "T1562.001" });
      setMsg(`Killed ${p.name} (${p.pid})`);
      setSel(null);
    }
  };
  const Th = ({ k: key, children }: { k: SortKey; children: React.ReactNode }) => (
    <th className="cursor-pointer select-none hover:text-accent" onClick={() => setSort(key)}>
      {children} {sort === key && "▾"}
    </th>
  );
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-line bg-panel/50 p-2">
        <div className="relative flex-1">
          <Search size={12} className="absolute left-2 top-2 text-slate-500" />
          <input className="inp !w-full !pl-7" placeholder="Filter processes…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <button className="btn btn-danger" disabled={sel === null} onClick={kill}><Skull size={12} />Kill process</button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="tbl w-full font-mono">
          <thead><tr><Th k="pid">PID</Th><Th k="name">Name</Th><th>User</th><th>State</th><th>Thr</th><Th k="cpu">CPU %</Th><Th k="mem">Mem MB</Th></tr></thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.pid} onClick={() => setSel(p.pid)} className={`cursor-pointer ${sel === p.pid ? "!bg-accent/10" : ""}`} title={p.cmd}>
                <td className="text-slate-500">{p.pid}</td>
                <td className="text-slate-200">{p.name}</td>
                <td className={p.user === "root" ? "text-crit/80" : "text-slate-400"}>{p.user}</td>
                <td className="text-slate-500">{p.state}</td>
                <td className="text-slate-500">{p.threads}</td>
                <td style={{ color: p.cpu > 60 ? "#ff7a3c" : p.cpu > 25 ? "#ffb020" : "#cfe3f1" }}>{p.cpu.toFixed(1)}</td>
                <td className="text-slate-300">{p.mem}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex justify-between border-t border-line bg-panel/60 px-3 py-1 font-mono text-[10px] text-slate-500">
        <span>{rows.length} processes · CPU {k.cpuTotal.toFixed(1)}% · MEM {Math.round(k.memUsed)} MB</span>
        <span className="text-warn">{msg}</span>
      </div>
    </div>
  );
}

function Hardware() {
  return (
    <div className="space-y-3 p-3">
      <Card title="CPU" icon={<Cpu size={13} />}>
        <div className="font-display text-lg font-bold neon-text">{CPU_INFO.model}</div>
        <div className="mb-3 font-mono text-[11px] text-slate-500">{CPU_INFO.vendor} · {CPU_INFO.arch} · family 25 model 97 stepping 2</div>
        <div className="mb-3 flex flex-wrap gap-1">
          {CPU_INFO.flags.split(" ").slice(0, 60).map((f) => (
            <span key={f} className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[9px] text-slate-400">{f}</span>
          ))}
          <span className="px-1 text-[9px] text-slate-600">+{CPU_INFO.flags.split(" ").length - 60} more</span>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Security mitigations</div>
            {CPU_INFO.vulnMitigations.map(([a, b]) => (
              <div key={a} className="flex justify-between border-b border-line/50 py-1 text-[11px]">
                <span className="text-slate-300">{a}</span>
                <span className={b.startsWith("Not") ? "text-neon" : "text-info"}>{b}</span>
              </div>
            ))}
          </div>
          <div>
            <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-500">Cache hierarchy</div>
            {[["L1d", CPU_INFO.l1d], ["L1i", CPU_INFO.l1i], ["L2", CPU_INFO.l2], ["L3", CPU_INFO.l3]].map(([a, b]) => (
              <div key={a} className="flex justify-between border-b border-line/50 py-1 text-[11px]">
                <span className="text-slate-300">{a}</span>
                <span className="font-mono text-slate-400">{b}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>
      <div className="grid gap-3 sm:grid-cols-2">
        <Card title="System devices" icon={<Wrench size={13} />}>
          <div className="space-y-1.5 text-[11px]">
            {[["Board", "Sugreev Cyber Workstation SG-1"], ["GPU", "Sugreev Vector G7 · 8 GB GDDR6"], ["Memory", "16 GiB DDR5-5600 (2×8)"], ["Storage", "NVMe SN850 512GB · SATA 2TB"], ["Network", "RTL8125 2.5GbE · AX210 Wi-Fi 6E"], ["Security", "TPM 2.0 · Secure Boot · YubiKey"], ["Kernel", "6.8.0-sgv (PREEMPT_DYNAMIC)"], ["Firmware", "SGV-BIOS 2.14 (UEFI)"]].map(([a, b]) => (
              <div key={a} className="flex justify-between gap-3 border-b border-line/50 pb-1"><span className="text-slate-500">{a}</span><span className="text-right text-slate-200">{b}</span></div>
            ))}
          </div>
        </Card>
        <Card title="Kernel modules" icon={<ListTree size={13} />}>
          <div className="space-y-1 font-mono text-[11px] text-slate-300">
            {["sgv_netfilter", "sgv_audit", "nf_conntrack", "nvme", "apparmor", "sgv_ids_tap"].map((m) => (
              <div key={m} className="flex justify-between border-b border-line/50 pb-1"><span>{m}</span><span className="text-neon">loaded</span></div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

export default function SystemMonitor() {
  const [tab, setTab] = useState<Tab>("perf");
  return (
    <div className="flex h-full flex-col bg-base/80">
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "perf", label: "Performance", icon: <Activity size={13} /> },
          { id: "procs", label: "Processes", icon: <ListTree size={13} /> },
          { id: "hw", label: "Hardware", icon: <Cpu size={13} /> },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-auto">{tab === "perf" ? <Perf /> : tab === "procs" ? <Procs /> : <Hardware />}</div>
    </div>
  );
}
