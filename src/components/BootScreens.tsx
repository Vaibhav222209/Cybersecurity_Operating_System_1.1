import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, Lock, LogIn, Power, RotateCw, ShieldCheck } from "lucide-react";
import { SugreevLogo } from "./ui";
import { Wallpaper } from "./Wallpaper";
import type { PowerAction, Settings } from "../os/context";

const BOOT_LINES: [string, string][] = [
  ["", "SugreevBIOS v2.14  (C) 2026 Vaibhav Thakur Labs"],
  ["", "CPU: Sugreev SG-8700X Cyber-Core Processor @ 3.80GHz  [8C/16T]"],
  ["", "Memory test: 16384 MB OK"],
  ["", "Detecting storage: nvme0n1 (512 GB)  sda (2 TB)"],
  ["", "Secure Boot: ENABLED   TPM 2.0: present   Lockdown: integrity"],
  ["", "GRUB 2.12 — booting 'Sugreev OS 1.0 (Kishkindha)'"],
  ["", "Loading Linux 6.8.0-sgv ..."],
  ["", "Loading initial ramdisk ..."],
  ["OK", "Reached target Local File Systems"],
  ["OK", "Started Sugreev Journal Service"],
  ["OK", "Mounted /mnt/evidence (read-only forensics volume)"],
  ["OK", "Started AppArmor mandatory access control"],
  ["OK", "Started Network Manager — eth0 up 10.0.0.5/24"],
  ["OK", "Started Sugreev Firewall Daemon (sgv-firewalld)"],
  ["OK", "Started Sugreev IDS/IPS Engine (sgv-ids) — 42,118 signatures"],
  ["OK", "Started Sugreev SIEM Correlation Daemon (sgv-siemd)"],
  ["OK", "Started Threat Intelligence Feed Sync (sgv-threatintel)"],
  ["OK", "Started Fail2Ban Service"],
  ["OK", "Started Security Auditing Service (auditd)"],
  ["OK", "Started OpenBSD Secure Shell server"],
  ["OK", "Started VAPT Sandbox Engine"],
  ["OK", "Reached target Sugreev Graphical Interface"],
];

export function BootScreen({ onDone }: { onDone: () => void }) {
  const [n, setN] = useState(0);
  const [splash, setSplash] = useState(false);
  const done = useRef(false);
  useEffect(() => {
    if (n < BOOT_LINES.length) {
      const t = setTimeout(() => setN(n + 1), n < 8 ? 160 : 85);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setSplash(true), 350);
    return () => clearTimeout(t);
  }, [n]);
  useEffect(() => {
    if (!splash) return;
    const t = setTimeout(finish, 1500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [splash]);
  const finish = () => {
    if (done.current) return;
    done.current = true;
    onDone();
  };
  useEffect(() => {
    const k = () => finish();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className="fixed inset-0 z-[9000] bg-black font-mono" onClick={finish}>
      {!splash ? (
        <div className="h-full overflow-hidden p-6 text-[12px] leading-relaxed sm:p-10 sm:text-[13px]">
          {BOOT_LINES.slice(0, n).map(([t, l], i) => (
            <div key={i} className="text-slate-300">
              {t ? (
                <>
                  <span className="text-slate-500">[</span>
                  <span className="text-emerald-400"> OK </span>
                  <span className="text-slate-500">] </span>
                </>
              ) : null}
              {l}
            </div>
          ))}
          <span className="term-cursor" />
          <div className="fixed bottom-4 right-6 text-[10px] text-slate-600">press any key or click to skip</div>
        </div>
      ) : (
        <div className="anim-fade flex h-full flex-col items-center justify-center gap-5">
          <SugreevLogo size={96} className="drop-shadow-[0_0_30px_var(--accent)]" />
          <div className="font-display text-3xl font-black tracking-[0.5em] neon-text">SUGREEV</div>
          <div className="h-1 w-64 overflow-hidden rounded-full bg-[#10202e]">
            <div className="h-full rounded-full bg-gradient-to-r from-neon to-accent" style={{ animation: "bootbar 1.4s ease-out forwards" }} />
          </div>
          <div className="text-[10px] uppercase tracking-[0.4em] text-slate-500">starting secure session</div>
          <style>{`@keyframes bootbar{from{width:0}to{width:100%}}`}</style>
        </div>
      )}
    </div>
  );
}

export function LoginScreen({ settings, locked, onLogin, onPower }: { settings: Settings; locked: boolean; onLogin: () => void; onPower: (a: PowerAction) => void }) {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [err, setErr] = useState(false);
  const [now, setNow] = useState(new Date());
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (pw.trim().toLowerCase() === "sugreev") {
      setBusy(true);
      setTimeout(onLogin, 650);
    } else {
      setErr(true);
      setPw("");
      setTimeout(() => setErr(false), 600);
    }
  };
  return (
    <div className="anim-fade fixed inset-0 z-[8000] overflow-hidden">
      <Wallpaper kind={settings.wallpaper} animate={settings.animations} accent={settings.accent} />
      <div className="absolute inset-0 bg-black/55 backdrop-blur-md" />
      <div className="absolute inset-x-0 top-10 text-center">
        <div className="font-display text-6xl font-bold tracking-wider text-white drop-shadow-[0_0_24px_var(--accent)]">{now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}</div>
        <div className="mt-1 font-mono text-xs uppercase tracking-[0.3em] text-slate-400">{now.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}</div>
      </div>
      <div className="absolute inset-0 flex items-center justify-center px-4">
        <form onSubmit={submit} className={`glass-strong anim-pop w-[360px] rounded-2xl p-7 text-center neon-border ${err ? "anim-shake" : ""}`}>
          <div className="relative mx-auto mb-4 flex h-24 w-24 items-center justify-center rounded-full bg-gradient-to-br from-neon to-accent font-display text-3xl font-black text-black shadow-[0_0_40px_-4px_var(--accent)]">
            VT
            <span className="absolute -bottom-1 -right-1 flex h-7 w-7 items-center justify-center rounded-full border-2 border-ink bg-ink text-neon">{locked ? <Lock size={14} /> : <ShieldCheck size={15} />}</span>
          </div>
          <div className="text-lg font-semibold text-white">Vaibhav Thakur</div>
          <div className="mb-5 font-mono text-[11px] text-slate-500">vaibhav@sgv-node-01 · {locked ? "session locked" : "administrator"}</div>
          <div className="relative">
            <input autoFocus type={show ? "text" : "password"} value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Password" className={`inp !w-full !py-2.5 !pr-10 !text-sm ${err ? "!border-crit" : ""}`} />
            <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-3 text-slate-500 hover:text-accent">{show ? <EyeOff size={15} /> : <Eye size={15} />}</button>
          </div>
          <div className="mt-2 h-4 font-mono text-[11px]">{err ? <span className="text-crit">Authentication failure — try again</span> : <span className="text-slate-500">hint: default password is <span className="text-warn">sugreev</span></span>}</div>
          <button type="submit" disabled={busy} className="btn btn-primary mt-3 w-full justify-center !py-2.5 !text-sm font-semibold">
            <LogIn size={15} />
            {busy ? "Authenticating…" : locked ? "Unlock" : "Log in"}
          </button>
        </form>
      </div>
      <div className="absolute bottom-5 left-6 font-mono text-[11px] text-slate-500">Sugreev OS 1.0 “Kishkindha” · by Vaibhav Thakur</div>
      <div className="absolute bottom-4 right-5 flex gap-2">
        <button onClick={() => onPower("restart")} title="Restart" className="rounded-full border border-line bg-black/40 p-2.5 text-warn transition hover:bg-white/10"><RotateCw size={16} /></button>
        <button onClick={() => onPower("shutdown")} title="Shut down" className="rounded-full border border-line bg-black/40 p-2.5 text-crit transition hover:bg-white/10"><Power size={16} /></button>
      </div>
    </div>
  );
}

const MSG: Record<string, string[]> = {
  logout: ["Closing user session…", "Stopping user services", "Saving window state", "Session closed"],
  restart: ["Stopping sgv-siemd", "Stopping sgv-ids", "Flushing logs to disk", "Unmounting /mnt/evidence", "Reached target Reboot", "Rebooting…"],
  shutdown: ["Stopping sgv-siemd", "Stopping sgv-ids", "Flushing logs to disk", "Unmounting /mnt/evidence", "Reached target Power-Off", "Powering off…"],
};

export function PowerTransition({ kind }: { kind: PowerAction }) {
  const [i, setI] = useState(0);
  const msgs = MSG[kind] ?? MSG.logout;
  useEffect(() => {
    const t = setInterval(() => setI((x) => Math.min(msgs.length, x + 1)), 380);
    return () => clearInterval(t);
  }, [msgs.length]);
  const color = kind === "shutdown" ? "#ff3b5c" : kind === "restart" ? "#ffb020" : "#00e5ff";
  return (
    <div className="anim-fade fixed inset-0 z-[9000] flex flex-col items-center justify-center bg-black">
      <div className="relative mb-6 h-16 w-16">
        <div className="absolute inset-0 animate-spin rounded-full border-2 border-transparent" style={{ borderTopColor: color, borderRightColor: color + "55" }} />
        <div className="absolute inset-3 flex items-center justify-center"><SugreevLogo size={34} /></div>
      </div>
      <div className="font-display text-xl font-bold tracking-[0.35em]" style={{ color }}>{kind === "logout" ? "LOGGING OUT" : kind === "restart" ? "RESTARTING" : "SHUTTING DOWN"}</div>
      <div className="mt-5 w-80 space-y-1 font-mono text-[11px] text-slate-400">
        {msgs.slice(0, i).map((m, k) => (
          <div key={k}>
            <span className="text-emerald-400">[ OK ]</span> {m}
          </div>
        ))}
      </div>
    </div>
  );
}

export function OffScreen({ onPowerOn }: { onPowerOn: () => void }) {
  return (
    <div className="fixed inset-0 z-[9000] flex flex-col items-center justify-center bg-black">
      <button onClick={onPowerOn} className="group flex h-24 w-24 items-center justify-center rounded-full border border-line text-slate-600 transition hover:border-neon hover:text-neon hover:shadow-[0_0_50px_-5px_#00ffa3]" title="Power on">
        <Power size={40} />
      </button>
      <div className="mt-6 font-mono text-[11px] uppercase tracking-[0.4em] text-slate-700">System halted — press to power on</div>
      <div className="mt-2 font-mono text-[10px] text-slate-800">Sugreev OS · Vaibhav Thakur</div>
    </div>
  );
}
