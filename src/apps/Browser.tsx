import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, BookOpen, Bug, ExternalLink, Globe, Home, Lock, Plus, RotateCw, Search, Shield, X, Radar, Activity, FileSearch, GitBranch, Crosshair, Database, Skull } from "lucide-react";
import { useOS, useWin, type AppId } from "../os/context";
import { cveDatabase, sevOf } from "../os/vapt";
import { SugreevLogo, SevBadge } from "../components/ui";

interface Tab {
  id: number;
  hist: string[];
  idx: number;
}
let tabId = 1;

const QUICK = [
  { name: "OWASP Top 10", url: "https://owasp.org/www-project-top-ten/", icon: <Shield size={20} /> },
  { name: "MITRE ATT&CK", url: "https://attack.mitre.org/", icon: <Crosshair size={20} /> },
  { name: "NVD (NIST)", url: "https://nvd.nist.gov/", icon: <Database size={20} /> },
  { name: "Exploit-DB", url: "https://www.exploit-db.com/", icon: <Bug size={20} /> },
  { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", icon: <Skull size={20} /> },
  { name: "HackTricks", url: "https://book.hacktricks.xyz/", icon: <BookOpen size={20} /> },
  { name: "Vaibhav222209", url: "https://github.com/Vaibhav222209", icon: <GitBranch size={20} /> },
  { name: "Wikipedia", url: "https://en.wikipedia.org/", icon: <Globe size={20} /> },
];

const LOCAL: { name: string; app: AppId; icon: React.ReactNode; desc: string }[] = [
  { name: "SIEM Console", app: "siem", icon: <Activity size={18} />, desc: "Live logs & alerts" },
  { name: "Threat Monitor", app: "threats", icon: <Radar size={18} />, desc: "Global attack map" },
  { name: "VAPT Lab", app: "vapt", icon: <Bug size={18} />, desc: "Scan & report" },
  { name: "Crypto Toolkit", app: "crypto", icon: <FileSearch size={18} />, desc: "Hash & encode" },
];

function normalize(raw: string): string {
  const v = raw.trim();
  if (!v) return "sugreev://home";
  if (v.startsWith("sugreev://")) return v;
  if (/^https?:\/\//i.test(v)) return v;
  if (/^[\w-]+(\.[\w-]+)+(:\d+)?(\/.*)?$/.test(v) && !v.includes(" ")) return "https://" + v;
  return "sugreev://search?q=" + encodeURIComponent(v);
}

function titleOf(url: string) {
  if (url.startsWith("sugreev://")) {
    const h = url.slice(10).split("?")[0];
    return { home: "New Tab", cve: "CVE Database", docs: "Sugreev Docs", search: "Search", about: "About" }[h] || h;
  }
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function HomePage({ go }: { go: (u: string) => void }) {
  const os = useOS();
  const [q, setQ] = useState("");
  return (
    <div className="mx-auto flex max-w-3xl flex-col items-center px-6 py-10">
      <SugreevLogo size={70} />
      <h1 className="mt-3 font-display text-3xl font-black tracking-[0.3em] neon-text">SUGREEV</h1>
      <p className="mb-6 mt-1 font-mono text-[11px] uppercase tracking-[0.3em] text-slate-500">secure browser · sandboxed</p>
      <form
        className="relative w-full"
        onSubmit={(e) => {
          e.preventDefault();
          go(q);
        }}
      >
        <Search size={16} className="absolute left-4 top-3.5 text-slate-500" />
        <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search CVEs, tools, or enter a URL…" className="inp !w-full !rounded-full !py-3 !pl-11 !text-sm" />
      </form>
      <div className="mt-8 grid w-full grid-cols-4 gap-3 sm:grid-cols-4">
        {QUICK.map((t) => (
          <button key={t.name} onClick={() => go(t.url)} className="group flex flex-col items-center gap-2 rounded-xl border border-line bg-panel/60 p-3 text-center transition hover:border-accent/60 hover:bg-accent/5">
            <span className="text-accent transition group-hover:scale-110">{t.icon}</span>
            <span className="text-[11px] text-slate-300">{t.name}</span>
          </button>
        ))}
      </div>
      <div className="mt-8 w-full">
        <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-slate-500">Local services</div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {LOCAL.map((l) => (
            <button key={l.name} onClick={() => os.openApp(l.app)} className="flex items-center gap-3 rounded-lg border border-line bg-raised/50 p-3 text-left hover:border-accent/60">
              <span className="text-neon">{l.icon}</span>
              <span>
                <div className="text-xs text-slate-200">{l.name}</div>
                <div className="text-[10px] text-slate-500">{l.desc}</div>
              </span>
            </button>
          ))}
        </div>
        <div className="mt-4 flex gap-2 text-xs">
          <button className="btn" onClick={() => go("sugreev://cve")}>CVE Database</button>
          <button className="btn" onClick={() => go("sugreev://docs")}>Documentation</button>
          <button className="btn" onClick={() => go("sugreev://about")}>About</button>
        </div>
      </div>
      <div className="mt-8 w-full rounded-lg border border-line bg-panel/60 p-4">
        <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-accent">Daily security tip</div>
        <p className="text-sm text-slate-300">Enable MFA everywhere, prefer hardware keys (FIDO2) for admin accounts, and treat any unexpected login prompt as hostile until proven otherwise.</p>
      </div>
    </div>
  );
}

function CvePage({ initial = "", go }: { initial?: string; go: (u: string) => void }) {
  const [q, setQ] = useState(initial);
  const [open, setOpen] = useState<string | null>(null);
  const all = useMemo(() => cveDatabase(), []);
  const list = all.filter((v) => (v.cve + v.title + v.product + v.desc).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="mx-auto max-w-4xl p-6">
      <h1 className="font-display text-xl font-bold text-accent">CVE Database</h1>
      <p className="mb-4 text-xs text-slate-500">Local reference of {all.length} vulnerabilities used by the Sugreev VAPT engine.</p>
      <input className="inp mb-4 !w-full !py-2" placeholder="Filter by CVE, product or keyword…" value={q} onChange={(e) => setQ(e.target.value)} />
      <div className="space-y-2">
        {list.map((v) => (
          <div key={v.cve + v.product} className="rounded-lg border border-line bg-panel/70">
            <button className="flex w-full items-center gap-3 px-3 py-2 text-left" onClick={() => setOpen(open === v.cve + v.product ? null : v.cve + v.product)}>
              <span className="w-12 rounded bg-raised py-0.5 text-center font-mono text-xs font-bold" style={{ color: v.cvss >= 9 ? "#ff3b5c" : v.cvss >= 7 ? "#ff7a3c" : "#ffb020" }}>{v.cvss.toFixed(1)}</span>
              <span className="font-mono text-xs text-accent">{v.cve}</span>
              <span className="flex-1 text-sm text-slate-200">{v.title}</span>
              <SevBadge sev={sevOf(v.cvss) === "low" ? "low" : (sevOf(v.cvss) as string)} />
            </button>
            {open === v.cve + v.product && (
              <div className="selectable space-y-1 border-t border-line px-3 py-2 text-xs text-slate-400">
                <div><b className="text-slate-300">Affected:</b> {v.product}</div>
                <div><b className="text-slate-300">Description:</b> {v.desc}</div>
                <div><b className="text-slate-300">Remediation:</b> {v.fix}</div>
                {v.cve.startsWith("CVE") && <button className="btn mt-1" onClick={() => go(`https://nvd.nist.gov/vuln/detail/${v.cve}`)}><ExternalLink size={12} />NVD entry</button>}
              </div>
            )}
          </div>
        ))}
        {!list.length && <div className="py-10 text-center text-sm text-slate-500">No matches.</div>}
      </div>
    </div>
  );
}

function DocsPage() {
  const sections: [string, string][] = [
    ["Apps", "Terminal · Files · Browser · SIEM Console · Threat Monitor · VAPT Lab · System Monitor · Crypto Toolkit · Editor · Settings"],
    ["Terminal", "110+ commands. Try: help, neofetch, siem status, siem tail -f, threats, vapt scan 192.168.56.101, nmap -sV -A host, searchsploit apache, cve log4j. Pipes, redirects and globbing work."],
    ["Privileges", "Use sudo / sudo -i for root-only actions such as `siem block <ip>`, apt, systemctl restart and reading /root."],
    ["Shortcuts", "Ctrl+C abort · Ctrl+L clear · Tab autocomplete · ↑↓ history · Ctrl+S save in editor · Delete / F2 in Files."],
    ["Power", "Use the top-right power menu: Lock, Log out, Restart or Shut down. Or run lock / logout / reboot / shutdown in the terminal."],
    ["Safety", "Every scan, exploit reference and log in Sugreev OS is simulated for education. No packets are sent. Only test systems you own or are authorised to test."],
  ];
  return (
    <div className="mx-auto max-w-3xl p-6">
      <h1 className="font-display text-xl font-bold text-accent">Sugreev OS Documentation</h1>
      <div className="mt-4 space-y-4">
        {sections.map(([t, d]) => (
          <div key={t} className="rounded-lg border border-line bg-panel/70 p-4">
            <div className="mb-1 font-mono text-xs uppercase tracking-widest text-neon">{t}</div>
            <p className="text-sm leading-relaxed text-slate-300">{d}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function AboutPage() {
  return (
    <div className="mx-auto flex max-w-xl flex-col items-center p-10 text-center">
      <SugreevLogo size={80} />
      <h1 className="mt-4 font-display text-2xl font-black tracking-widest neon-text">SUGREEV OS</h1>
      <p className="mt-2 text-sm text-slate-400">A Linux-style cybersecurity operating system for SIEM and VAPT learning, built by <b className="text-white">Vaibhav Thakur</b>.</p>
      <a href="https://github.com/Vaibhav222209" target="_blank" rel="noreferrer" className="btn btn-primary mt-4"><GitBranch size={14} />github.com/Vaibhav222209</a>
    </div>
  );
}

function SearchPage({ q, go }: { q: string; go: (u: string) => void }) {
  const hits = cveDatabase().filter((v) => (v.cve + v.title + v.product + v.desc).toLowerCase().includes(q.toLowerCase())).slice(0, 5);
  const engines = [
    ["DuckDuckGo", `https://duckduckgo.com/?q=${encodeURIComponent(q)}`],
    ["Google", `https://www.google.com/search?q=${encodeURIComponent(q)}`],
    ["Bing", `https://www.bing.com/search?q=${encodeURIComponent(q)}`],
    ["GitHub", `https://github.com/search?q=${encodeURIComponent(q)}`],
  ];
  return (
    <div className="mx-auto max-w-3xl p-6">
      <h1 className="text-lg text-slate-200">Results for “<span className="text-accent">{q}</span>”</h1>
      <div className="mt-4 font-mono text-[10px] uppercase tracking-widest text-slate-500">Local CVE database</div>
      <div className="mt-2 space-y-2">
        {hits.map((v) => (
          <button key={v.cve + v.product} onClick={() => go("sugreev://cve?q=" + v.cve)} className="block w-full rounded-lg border border-line bg-panel/70 p-3 text-left hover:border-accent/60">
            <div className="font-mono text-xs text-accent">{v.cve} · CVSS {v.cvss.toFixed(1)}</div>
            <div className="text-sm text-slate-200">{v.title}</div>
            <div className="text-xs text-slate-500">{v.desc}</div>
          </button>
        ))}
        {!hits.length && <div className="text-sm text-slate-500">No local matches.</div>}
      </div>
      <div className="mt-6 font-mono text-[10px] uppercase tracking-widest text-slate-500">Search the web (opens a real browser tab)</div>
      <div className="mt-2 flex flex-wrap gap-2">
        {engines.map(([n, u]) => (
          <a key={n} href={u} target="_blank" rel="noreferrer" className="btn"><ExternalLink size={12} />{n}</a>
        ))}
      </div>
    </div>
  );
}

export default function Browser() {
  const { props } = useWin();
  const start = normalize((props.url as string) || "sugreev://home");
  const [tabs, setTabs] = useState<Tab[]>([{ id: tabId++, hist: [start], idx: 0 }]);
  const [active, setActive] = useState(tabs[0].id);
  const [addr, setAddr] = useState(start);
  const [loading, setLoading] = useState(false);
  const [nonce, setNonce] = useState(0);
  const tab = tabs.find((t) => t.id === active) ?? tabs[0];
  const url = tab.hist[tab.idx];

  useEffect(() => {
    setAddr(url);
    setLoading(true);
    const t = setTimeout(() => setLoading(false), 450);
    return () => clearTimeout(t);
  }, [url, active, nonce]);

  const upd = (fn: (t: Tab) => Tab) => setTabs((ts) => ts.map((t) => (t.id === tab.id ? fn(t) : t)));
  const go = (raw: string) => {
    const u = normalize(raw);
    upd((t) => ({ ...t, hist: [...t.hist.slice(0, t.idx + 1), u], idx: t.idx + 1 }));
  };
  const newTab = () => {
    const t = { id: tabId++, hist: ["sugreev://home"], idx: 0 };
    setTabs([...tabs, t]);
    setActive(t.id);
  };
  const closeTab = (id: number) => {
    if (tabs.length === 1) return;
    const rest = tabs.filter((t) => t.id !== id);
    setTabs(rest);
    if (active === id) setActive(rest[rest.length - 1].id);
  };

  const internal = url.startsWith("sugreev://");
  const [host, query] = internal ? url.slice(10).split("?") : ["", ""];
  const qs = new URLSearchParams(query || "");

  return (
    <div className="flex h-full flex-col bg-base/90">
      <div className="flex items-end gap-1 border-b border-line bg-ink/80 px-2 pt-1.5">
        {tabs.map((t) => (
          <div key={t.id} onClick={() => setActive(t.id)} className={`group flex max-w-[160px] cursor-default items-center gap-2 rounded-t-md border border-b-0 px-3 py-1.5 text-xs ${t.id === active ? "border-line bg-panel text-accent" : "border-transparent text-slate-500 hover:text-slate-300"}`}>
            <Globe size={11} />
            <span className="truncate">{titleOf(t.hist[t.idx])}</span>
            {tabs.length > 1 && <X size={11} className="opacity-0 hover:text-crit group-hover:opacity-100" onClick={(e) => (e.stopPropagation(), closeTab(t.id))} />}
          </div>
        ))}
        <button className="mb-1 rounded p-1 text-slate-500 hover:bg-white/10 hover:text-accent" onClick={newTab}><Plus size={14} /></button>
      </div>
      <div className="flex items-center gap-1.5 border-b border-line bg-panel/70 px-2 py-1.5">
        <button className="btn !px-1.5" disabled={tab.idx === 0} onClick={() => upd((t) => ({ ...t, idx: t.idx - 1 }))}><ArrowLeft size={14} /></button>
        <button className="btn !px-1.5" disabled={tab.idx >= tab.hist.length - 1} onClick={() => upd((t) => ({ ...t, idx: t.idx + 1 }))}><ArrowRight size={14} /></button>
        <button className="btn !px-1.5" onClick={() => setNonce(nonce + 1)}><RotateCw size={14} className={loading ? "animate-spin" : ""} /></button>
        <button className="btn !px-1.5" onClick={() => go("sugreev://home")}><Home size={14} /></button>
        <form className="relative flex-1" onSubmit={(e) => (e.preventDefault(), go(addr))}>
          <Lock size={12} className={`absolute left-3 top-2 ${internal || url.startsWith("https") ? "text-neon" : "text-warn"}`} />
          <input value={addr} onChange={(e) => setAddr(e.target.value)} onFocus={(e) => e.target.select()} className="inp !w-full !rounded-full !py-1.5 !pl-8 font-mono" spellCheck={false} />
        </form>
        {!internal && <a href={url} target="_blank" rel="noreferrer" className="btn !px-1.5" title="Open in real tab"><ExternalLink size={14} /></a>}
      </div>
      <div className="h-0.5 w-full bg-transparent">{loading && <div className="h-full w-1/2 animate-pulse bg-accent" />}</div>
      <div className="min-h-0 flex-1 overflow-auto">
        {internal ? (
          host === "home" ? <HomePage go={go} /> : host === "cve" ? <CvePage key={url} initial={qs.get("q") ?? ""} go={go} /> : host === "docs" ? <DocsPage /> : host === "about" ? <AboutPage /> : host === "search" ? <SearchPage q={qs.get("q") ?? ""} go={go} /> : <div className="p-10 text-center text-slate-500">sugreev://{host} — page not found</div>
        ) : (
          <div className="flex h-full flex-col">
            <div className="flex items-center gap-2 border-b border-line bg-warn/10 px-3 py-1 text-[11px] text-warn">
              <Shield size={12} /> Sandboxed frame. Many sites forbid embedding (X-Frame-Options). If the page stays blank,
              <a href={url} target="_blank" rel="noreferrer" className="underline">open it in a real tab ↗</a>
            </div>
            <iframe key={url + nonce} src={url} title="page" sandbox="allow-scripts allow-forms allow-same-origin allow-popups" className="min-h-0 flex-1 bg-white" referrerPolicy="no-referrer" />
          </div>
        )}
      </div>
    </div>
  );
}
