import { useState } from "react";
import { Check, Cpu, Info, Lock, Palette, RotateCcw, ExternalLink, GitBranch, Heart } from "lucide-react";
import { ACCENTS, useOS, type Wallpaper } from "../os/context";
import { useKernel, setAutoBlock, CPU_INFO } from "../os/kernel";
import { resetFs } from "../os/vfs";
import { Tabs, Toggle, Card, SugreevLogo, fmtUptime } from "../components/ui";

type Tab = "look" | "security" | "system";

const WALLS: { id: Wallpaper; name: string; css: string }[] = [
  { id: "matrix", name: "Matrix Rain", css: "linear-gradient(180deg,#010a05,#02160b)" },
  { id: "grid", name: "Neon Grid", css: "linear-gradient(180deg,#07031a,#150633)" },
  { id: "aurora", name: "Aurora", css: "linear-gradient(135deg,#06222e,#14073a,#042a1f)" },
];

function Row({ title, desc, children }: { title: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line/60 py-2.5">
      <div>
        <div className="text-sm text-slate-200">{title}</div>
        {desc && <div className="text-[11px] text-slate-500">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

export default function Settings() {
  const os = useOS();
  const k = useKernel();
  const [tab, setTab] = useState<Tab>("look");
  const s = os.settings;
  return (
    <div className="flex h-full flex-col bg-base/80">
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "look", label: "Appearance", icon: <Palette size={13} /> },
          { id: "security", label: "Security", icon: <Lock size={13} /> },
          { id: "system", label: "System", icon: <Cpu size={13} /> },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {tab === "look" && (
          <div className="mx-auto max-w-xl space-y-4">
            <Card title="Accent colour">
              <div className="grid grid-cols-3 gap-2">
                {ACCENTS.map((a) => (
                  <button key={a.value} onClick={() => os.setSettings({ accent: a.value })} className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs transition ${s.accent === a.value ? "border-white/40 bg-white/5" : "border-line hover:border-white/20"}`}>
                    <span className="flex h-5 w-5 items-center justify-center rounded-full" style={{ background: a.value, boxShadow: `0 0 12px ${a.value}` }}>{s.accent === a.value && <Check size={12} className="text-black" />}</span>
                    <span className="text-slate-300">{a.name}</span>
                  </button>
                ))}
              </div>
            </Card>
            <Card title="Wallpaper">
              <div className="grid grid-cols-3 gap-3">
                {WALLS.map((w) => (
                  <button key={w.id} onClick={() => os.setSettings({ wallpaper: w.id })} className={`overflow-hidden rounded-lg border text-left transition ${s.wallpaper === w.id ? "border-accent neon-border" : "border-line hover:border-white/20"}`}>
                    <div className="h-16" style={{ background: w.css }} />
                    <div className="px-2 py-1.5 text-xs text-slate-300">{w.name}</div>
                  </button>
                ))}
              </div>
            </Card>
            <Card title="Effects">
              <Row title="CRT scanlines" desc="Subtle retro overlay"><Toggle on={s.scanlines} onChange={(v) => os.setSettings({ scanlines: v })} /></Row>
              <Row title="Animations" desc="Window transitions & background motion"><Toggle on={s.animations} onChange={(v) => os.setSettings({ animations: v })} /></Row>
              <Row title="Desktop notifications" desc="Toast alerts for critical SIEM events"><Toggle on={s.notifications} onChange={(v) => os.setSettings({ notifications: v })} /></Row>
            </Card>
          </div>
        )}
        {tab === "security" && (
          <div className="mx-auto max-w-xl space-y-4">
            <Card title="Active response">
              <Row title="Auto-block critical attackers" desc="SIEM adds firewall rules for IPs behind critical events"><Toggle on={k.autoBlock} onChange={setAutoBlock} /></Row>
              <Row title="Firewall (sgv-firewalld)" desc="Default policy: deny incoming"><span className="font-mono text-xs text-neon">ACTIVE</span></Row>
              <Row title="IDS / IPS mode" desc="sgv-ids on eth0"><span className="font-mono text-xs text-neon">IPS</span></Row>
              <Row title="SSH password authentication" desc="/etc/ssh/sshd_config"><span className="font-mono text-xs text-slate-400">disabled</span></Row>
              <Row title="Secure boot & TPM 2.0" desc="Kernel lockdown = integrity"><span className="font-mono text-xs text-neon">ENABLED</span></Row>
            </Card>
            <Card title="Login">
              <Row title="User" desc="vaibhav · uid 1000 · groups sudo, siem"><span className="font-mono text-xs text-slate-400">Vaibhav Thakur</span></Row>
              <Row title="Default password" desc="Educational build — change in production"><span className="font-mono text-xs text-warn">sugreev</span></Row>
            </Card>
          </div>
        )}
        {tab === "system" && (
          <div className="mx-auto max-w-xl space-y-4">
            <Card title="About this system">
              <div className="flex items-center gap-4">
                <SugreevLogo size={56} />
                <div className="text-xs text-slate-300">
                  <div className="font-display text-base font-bold neon-text">Sugreev OS 1.0</div>
                  <div className="text-slate-500">Kishkindha · kernel 6.8.0-sgv · x86_64</div>
                  <div className="mt-1">{CPU_INFO.model}</div>
                  <div className="text-slate-500">16 GiB RAM · uptime {fmtUptime(k.now - k.bootTime)}</div>
                </div>
              </div>
            </Card>
            <Card title="Maintenance">
              <Row title="Reset virtual file system" desc="Restore default files (deletes your changes)">
                <button className="btn btn-danger" onClick={() => confirm("Reset the file system to factory defaults?") && resetFs()}><RotateCcw size={12} />Reset</button>
              </Row>
              <Row title="About Sugreev OS" desc="Credits, license & links">
                <button className="btn" onClick={() => os.openApp("about")}><Info size={12} />Open</button>
              </Row>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

export function About() {
  const os = useOS();
  return (
    <div className="h-full overflow-auto bg-base/80">
      <div className="relative overflow-hidden border-b border-line px-6 py-8 text-center">
        <div className="grid-bg absolute inset-0 opacity-60" />
        <div className="relative">
          <SugreevLogo size={84} className="mx-auto drop-shadow-[0_0_24px_var(--accent)]" />
          <h1 className="glitch mt-3 font-display text-3xl font-black tracking-[0.35em] neon-text">SUGREEV</h1>
          <div className="mt-1 font-mono text-[11px] uppercase tracking-[0.35em] text-slate-400">Cybersecurity Operating System</div>
          <div className="mt-3 inline-flex gap-2 font-mono text-[10px]">
            <span className="rounded border border-accent/40 px-2 py-0.5 text-accent">v1.0 “Kishkindha”</span>
            <span className="rounded border border-neon/40 px-2 py-0.5 text-neon">SIEM</span>
            <span className="rounded border border-crit/40 px-2 py-0.5 text-crit">VAPT</span>
          </div>
        </div>
      </div>
      <div className="mx-auto max-w-xl space-y-4 p-5 text-sm text-slate-300">
        <p className="leading-relaxed">
          Sugreev OS is a browser-based, Linux-style operating system built for learning <b className="text-white">Security Information & Event Management (SIEM)</b> and <b className="text-white">Vulnerability Assessment & Penetration Testing (VAPT)</b>. It ships a hardened-looking desktop, a real shell with 110+ commands, a virtual file system, a live threat map and a simulated attack lab.
        </p>
        <div className="grid grid-cols-2 gap-3 text-xs">
          {[["Author", "Vaibhav Thakur"], ["GitHub", "@Vaibhav222209"], ["License", "MIT"], ["Stack", "React · Vite · Tailwind"]].map(([a, b]) => (
            <div key={a} className="rounded-lg border border-line bg-panel/70 p-3"><div className="text-[10px] uppercase tracking-widest text-slate-500">{a}</div><div className="font-mono text-slate-100">{b}</div></div>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn btn-primary" onClick={() => os.openApp("browser", { url: "https://github.com/Vaibhav222209" })}><GitBranch size={13} />GitHub profile</button>
          <a className="btn" href="https://github.com/Vaibhav222209" target="_blank" rel="noreferrer"><ExternalLink size={13} />Open in new tab</a>
        </div>
        <div className="rounded-lg border border-warn/30 bg-warn/5 p-3 text-[11px] leading-relaxed text-warn/90">
          <b>Ethical use:</b> all scanning, exploitation and attack data inside Sugreev OS is simulated. Never test systems you do not own or lack written permission to assess.
        </div>
        <div className="flex items-center justify-center gap-1 pt-2 text-[11px] text-slate-500">Made with <Heart size={11} className="text-crit" fill="currentColor" /> by Vaibhav Thakur</div>
      </div>
    </div>
  );
}
