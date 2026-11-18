import { useMemo } from "react";
import { Ban, Crosshair, Globe2, Radar, ShieldAlert, ShieldCheck, Siren, Unlock, Cpu } from "lucide-react";
import { useKernel, blockIp, unblockIp, setAutoBlock, threatLabel, COUNTRIES, HOME_NODE, SEV_COLOR } from "../os/kernel";
import { useOS } from "../os/context";
import { Card, Ring, SevBadge, Stat, Toggle, fmtTime } from "../components/ui";

// coarse continent outlines [lon, lat]
const LAND: [number, number][][] = [
  [[-168, 66], [-156, 71], [-125, 70], [-95, 69], [-82, 68], [-62, 58], [-56, 50], [-66, 44], [-76, 36], [-81, 30], [-80, 25], [-90, 29], [-97, 26], [-97, 20], [-87, 21], [-83, 15], [-78, 8], [-85, 10], [-92, 15], [-105, 20], [-110, 24], [-115, 30], [-122, 37], [-124, 48], [-135, 58], [-150, 60], [-165, 60]],
  [[-55, 60], [-45, 60], [-20, 70], [-20, 82], [-60, 82], [-70, 76]],
  [[-78, 8], [-62, 11], [-50, 0], [-35, -6], [-40, -22], [-48, -28], [-58, -38], [-65, -42], [-68, -52], [-72, -50], [-74, -40], [-71, -20], [-81, -5]],
  [[-10, 36], [-9, 43], [-2, 48], [4, 52], [8, 56], [12, 56], [20, 60], [28, 70], [40, 68], [40, 55], [30, 45], [26, 40], [20, 38], [12, 38], [5, 43], [-5, 36]],
  [[-17, 21], [-10, 30], [-5, 36], [10, 37], [32, 31], [35, 25], [43, 12], [51, 12], [40, -5], [40, -15], [33, -26], [20, -35], [15, -28], [12, -12], [9, 4], [-8, 4], [-17, 14]],
  [[28, 41], [36, 37], [35, 30], [43, 13], [53, 16], [58, 23], [57, 26], [67, 25], [73, 18], [77, 8], [80, 15], [88, 22], [92, 20], [98, 15], [100, 3], [105, 10], [109, 20], [120, 25], [122, 32], [122, 40], [130, 43], [140, 52], [160, 60], [180, 66], [170, 70], [140, 73], [110, 77], [70, 73], [60, 68], [40, 68], [40, 55], [30, 45]],
  [[114, -22], [122, -18], [130, -12], [137, -12], [142, -11], [146, -19], [153, -26], [150, -37], [140, -38], [130, -32], [115, -34]],
  [[130, 32], [135, 35], [141, 40], [143, 44], [140, 36]],
  [[-10, 50], [-5, 58], [1, 52], [-5, 50]],
  [[95, 5], [105, -6], [120, -8], [140, -6], [130, -1], [110, 2]],
];

const px = (lon: number, lat: number): [number, number] => [lon + 180, 90 - lat];
const poly = (pts: [number, number][]) => pts.map((p) => px(p[0], p[1]).join(",")).join(" ");

const IOCS = [
  ["IP", "185.220.101.4", "Tor exit / brute-force"],
  ["IP", "91.240.118.22", "Scanner (Masscan)"],
  ["DOMAIN", "update-sec.xyz", "C2 beaconing"],
  ["DOMAIN", "cdn-static-live.top", "Phishing kit"],
  ["HASH", "44d88612fea8a8f36de82e1278abb02f", "Mirai variant (MD5)"],
  ["URL", "hxxp://dl-assets[.]ru/payload.sh", "Dropper"],
];

export default function ThreatMonitor() {
  const k = useKernel();
  const os = useOS();
  const t = threatLabel(k.threatLevel);
  const recent = useMemo(() => k.events.filter((e) => e.country && e.sev !== "info").slice(0, 14), [k.events]);
  const byCountry = useMemo(() => {
    const m: Record<string, number> = {};
    k.events.forEach((e) => e.country && e.sev !== "info" && (m[e.country] = (m[e.country] || 0) + 1));
    return m;
  }, [k.events]);
  const [hx, hy] = px(HOME_NODE.lon, HOME_NODE.lat);
  const activeThreats = k.alerts.filter((a) => (a.sev === "critical" || a.sev === "high") && (a.status === "open" || a.status === "investigating")).slice(0, 7);
  const topCountries = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxC = Math.max(1, ...Object.values(byCountry));

  return (
    <div className="h-full overflow-auto bg-base/80 p-3">
      {k.surge && (
        <div className="anim-pop mb-3 flex items-center gap-2 rounded-lg border border-crit/50 bg-crit/10 px-3 py-2 text-xs text-crit">
          <Siren size={14} className="animate-pulse" /> <b>ATTACK SURGE DETECTED</b> — inbound hostile traffic is above baseline. IDS is in prevention mode.
        </div>
      )}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card title="Global threat map · live" icon={<Globe2 size={13} />} className="lg:col-span-2" right={<span className="font-mono text-[10px] text-neon">● {recent.length} active vectors</span>} bodyClass="p-0 relative">
          <div className="relative overflow-hidden rounded-b-lg bg-[#050c14]">
            <svg viewBox="0 0 360 180" className="block w-full" style={{ aspectRatio: "2 / 1" }}>
              <defs>
                <pattern id="dots" width="3" height="3" patternUnits="userSpaceOnUse">
                  <circle cx="1.5" cy="1.5" r="0.65" fill="var(--accent)" fillOpacity="0.5" />
                </pattern>
                <radialGradient id="glow" cx="50%" cy="50%" r="60%">
                  <stop offset="0" stopColor="#0b2236" />
                  <stop offset="1" stopColor="#050c14" />
                </radialGradient>
                <filter id="blur"><feGaussianBlur stdDeviation="1.2" /></filter>
              </defs>
              <rect width="360" height="180" fill="url(#glow)" />
              {[...Array(7)].map((_, i) => <line key={"h" + i} x1="0" x2="360" y1={(i + 1) * 22.5} y2={(i + 1) * 22.5} stroke="#12304a" strokeWidth="0.3" />)}
              {[...Array(11)].map((_, i) => <line key={"v" + i} y1="0" y2="180" x1={(i + 1) * 30} x2={(i + 1) * 30} stroke="#12304a" strokeWidth="0.3" />)}
              {LAND.map((p, i) => <polygon key={i} points={poly(p)} fill="url(#dots)" stroke="var(--accent)" strokeOpacity="0.25" strokeWidth="0.4" strokeLinejoin="round" />)}
              {recent.map((e) => {
                const c = COUNTRIES.find((x) => x.code === e.country)!;
                const [x, y] = px(c.lon, c.lat);
                const dist = Math.hypot(hx - x, hy - y);
                const cx = (x + hx) / 2;
                const cy = Math.min(y, hy) - dist * 0.28;
                const col = SEV_COLOR[e.sev];
                return (
                  <g key={e.id}>
                    <path d={`M${x},${y} Q${cx},${cy} ${hx},${hy}`} fill="none" stroke={col} strokeWidth="0.7" strokeLinecap="round" strokeDasharray="120" style={{ animation: "arc 1.8s ease-out forwards", filter: `drop-shadow(0 0 1.5px ${col})` }} />
                  </g>
                );
              })}
              {COUNTRIES.map((c) => {
                const n = byCountry[c.code] || 0;
                if (!n) return null;
                const [x, y] = px(c.lon, c.lat);
                return (
                  <g key={c.code}>
                    <circle cx={x} cy={y} r={1.5 + Math.min(4, n / 5)} fill="#ff3b5c" fillOpacity="0.25" style={{ transformBox: "fill-box", transformOrigin: "center", animation: "ping-ring 2s infinite" }} />
                    <circle cx={x} cy={y} r="1.4" fill="#ff3b5c" />
                    <text x={x + 3} y={y - 2} fontSize="4" fill="#ffb4c0" fontFamily="JetBrains Mono, monospace">{c.code} {n}</text>
                  </g>
                );
              })}
              <circle cx={hx} cy={hy} r="3" fill="none" stroke="#00ffa3" strokeWidth="0.6" style={{ transformBox: "fill-box", transformOrigin: "center", animation: "ping-ring 2.2s infinite" }} />
              <circle cx={hx} cy={hy} r="1.8" fill="#00ffa3" />
              <text x={hx + 3} y={hy + 5} fontSize="4" fill="#00ffa3" fontFamily="JetBrains Mono, monospace">{HOME_NODE.name}</text>
            </svg>
            <div className="pointer-events-none absolute bottom-2 left-3 flex gap-3 font-mono text-[9px] text-slate-400">
              {(["critical", "high", "medium", "low"] as const).map((s) => (
                <span key={s} className="flex items-center gap-1"><i className="inline-block h-1.5 w-3 rounded" style={{ background: SEV_COLOR[s] }} />{s}</span>
              ))}
            </div>
          </div>
        </Card>

        <div className="space-y-3">
          <Card title="Threat level" icon={<Radar size={13} />}>
            <div className="flex items-center gap-4">
              <Ring value={k.threatLevel} size={96} stroke={9} color={t.color} label={String(k.threatLevel)} sub="/ 100" />
              <div>
                <div className="font-display text-xl font-bold" style={{ color: t.color, textShadow: `0 0 14px ${t.color}88` }}>{t.label}</div>
                <div className="mt-1 text-[11px] text-slate-500">Weighted by open critical/high alerts and live attack surge.</div>
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between rounded-md border border-line bg-ink/60 px-3 py-2 text-xs">
              <div>
                <div className="text-slate-200">Auto-response</div>
                <div className="text-[10px] text-slate-500">Block IPs behind critical events</div>
              </div>
              <Toggle on={k.autoBlock} onChange={setAutoBlock} />
            </div>
          </Card>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Hostile IPs" value={k.attackers.filter((a) => !a.blocked).length} color="#ff3b5c" icon={<Crosshair size={12} />} />
            <Stat label="Blocked" value={k.blockedIps.length} color="#38bdf8" icon={<Ban size={12} />} />
          </div>
          <Card title="Attack origins" icon={<Globe2 size={13} />}>
            <div className="space-y-1.5">
              {topCountries.map(([c, n]) => (
                <div key={c} className="flex items-center gap-2 text-[11px]">
                  <span className="w-24 truncate text-slate-300">{COUNTRIES.find((x) => x.code === c)?.name}</span>
                  <div className="h-1.5 flex-1 rounded bg-[#10212f]"><div className="h-full rounded bg-crit" style={{ width: `${(n / maxC) * 100}%` }} /></div>
                  <span className="w-5 text-right font-mono text-slate-500">{n}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-3">
        <Card title="Active threats" icon={<ShieldAlert size={13} />} bodyClass="p-0" right={<button className="text-[10px] text-accent hover:underline" onClick={() => os.openApp("siem")}>open SIEM →</button>}>
          <div className="max-h-64 divide-y divide-line overflow-auto">
            {activeThreats.map((a) => (
              <div key={a.id} className="flex items-center gap-2 px-3 py-2">
                <SevBadge sev={a.sev} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-xs text-slate-200">{a.title}</div>
                  <div className="font-mono text-[10px] text-slate-500">{a.srcIp} · {a.country} · {fmtTime(a.ts)}</div>
                </div>
                <button className="btn btn-danger !px-2 !py-1" onClick={() => blockIp(a.srcIp)} disabled={a.country === "--"}><Ban size={11} /></button>
              </div>
            ))}
            {!activeThreats.length && <div className="p-6 text-center text-xs text-neon">✔ No active high-severity threats</div>}
          </div>
        </Card>
        <Card title="Firewall blocklist" icon={<Ban size={13} />} bodyClass="p-0">
          <div className="max-h-64 divide-y divide-line overflow-auto">
            {k.blockedIps.map((ip) => (
              <div key={ip} className="flex items-center justify-between px-3 py-2">
                <span className="font-mono text-xs text-slate-200">{ip}</span>
                <button className="btn !px-2 !py-1" onClick={() => unblockIp(ip)}><Unlock size={11} />Unblock</button>
              </div>
            ))}
            {!k.blockedIps.length && <div className="p-6 text-center text-xs text-slate-500">Blocklist is empty. Block hostile IPs from alerts.</div>}
          </div>
          <div className="border-t border-line p-2">
            <button className="btn w-full justify-center" onClick={() => k.attackers.filter((a) => !a.blocked).slice(0, 3).forEach((a) => blockIp(a.ip))}>
              <Ban size={12} /> Block top 3 attackers
            </button>
          </div>
        </Card>
        <div className="space-y-3">
          <Card title="Defence engines" icon={<ShieldCheck size={13} />}>
            <div className="space-y-2 text-xs">
              {[["sgv-ids", "IDS/IPS · 42,118 signatures", true], ["sgv-firewalld", "Firewall · default deny", true], ["fail2ban", "Brute-force jail", true], ["clamd", "Antivirus · DB v27412", true], ["sgv-threatintel", "TI feed · 312 IOCs", true]].map(([n, d]) => (
                <div key={n as string} className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-neon shadow-[0_0_8px_#00ffa3]" />
                  <span className="font-mono text-slate-200">{n}</span>
                  <span className="ml-auto text-[10px] text-slate-500">{d}</span>
                </div>
              ))}
            </div>
          </Card>
          <Card title="Threat intel · IOC feed" icon={<Cpu size={13} />} bodyClass="p-0">
            <div className="max-h-40 divide-y divide-line overflow-auto">
              {IOCS.map(([ty, v, d]) => (
                <div key={v} className="px-3 py-1.5">
                  <div className="flex items-center gap-2"><span className="rounded bg-crit/15 px-1 font-mono text-[9px] text-crit">{ty}</span><span className="truncate font-mono text-[11px] text-slate-200">{v}</span></div>
                  <div className="text-[10px] text-slate-500">{d}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
