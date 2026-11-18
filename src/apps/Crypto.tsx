import { useEffect, useState } from "react";
import { Binary, Copy, Hash, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { b64dec, b64enc, fromHex, genPassword, humanTime, md5, passwordStats, rot13, sha, toBinary, toHex, type ShaAlgo } from "../os/hash";
import { Card, Tabs, Bar } from "../components/ui";

type Tab = "transform" | "hash" | "password" | "jwt";

const OPS: { id: string; label: string; fn: (s: string) => string | Promise<string> }[] = [
  { id: "b64e", label: "Base64 encode", fn: b64enc },
  { id: "b64d", label: "Base64 decode", fn: b64dec },
  { id: "hexe", label: "Hex encode", fn: toHex },
  { id: "hexd", label: "Hex decode", fn: fromHex },
  { id: "urle", label: "URL encode", fn: encodeURIComponent },
  { id: "urld", label: "URL decode", fn: decodeURIComponent },
  { id: "rot", label: "ROT13", fn: rot13 },
  { id: "bin", label: "To binary", fn: toBinary },
  { id: "rev", label: "Reverse", fn: (s) => [...s].reverse().join("") },
  { id: "up", label: "UPPERCASE", fn: (s) => s.toUpperCase() },
];

function copy(t: string) {
  navigator.clipboard?.writeText(t);
}

function Transform() {
  const [input, setInput] = useState("Sugreev OS — by Vaibhav Thakur");
  const [out, setOut] = useState("");
  const [op, setOp] = useState("b64e");
  const [err, setErr] = useState("");
  useEffect(() => {
    const o = OPS.find((x) => x.id === op)!;
    Promise.resolve()
      .then(() => o.fn(input))
      .then((r) => (setOut(r), setErr("")))
      .catch(() => (setOut(""), setErr("Invalid input for this operation")));
  }, [input, op]);
  return (
    <div className="grid gap-3 p-3 lg:grid-cols-[1fr_200px]">
      <div className="space-y-3">
        <Card title="Input">
          <textarea className="inp selectable h-28 w-full resize-none font-mono" value={input} onChange={(e) => setInput(e.target.value)} />
        </Card>
        <Card title="Output" right={<button className="btn !py-0.5" onClick={() => copy(out)}><Copy size={11} />Copy</button>}>
          <pre className="selectable min-h-[96px] whitespace-pre-wrap break-all font-mono text-xs text-emerald-300">{err ? <span className="text-crit">{err}</span> : out}</pre>
        </Card>
      </div>
      <Card title="Operation" bodyClass="p-2">
        <div className="flex flex-col gap-1">
          {OPS.map((o) => (
            <button key={o.id} onClick={() => setOp(o.id)} className={`rounded px-2 py-1.5 text-left text-xs ${op === o.id ? "bg-accent/15 text-accent" : "text-slate-300 hover:bg-white/5"}`}>{o.label}</button>
          ))}
        </div>
      </Card>
    </div>
  );
}

function Hashes() {
  const [input, setInput] = useState("sugreev");
  const [h, setH] = useState<Record<string, string>>({});
  useEffect(() => {
    let alive = true;
    (async () => {
      const r: Record<string, string> = { MD5: md5(input) };
      for (const a of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] as ShaAlgo[]) r[a] = await sha(a, input);
      if (alive) setH(r);
    })();
    return () => {
      alive = false;
    };
  }, [input]);
  return (
    <div className="space-y-3 p-3">
      <Card title="Text to hash">
        <input className="inp selectable w-full font-mono" value={input} onChange={(e) => setInput(e.target.value)} />
      </Card>
      {Object.entries(h).map(([k, v]) => (
        <div key={k} className="rounded-lg border border-line bg-panel/70 p-3">
          <div className="mb-1 flex items-center justify-between">
            <span className="font-mono text-[11px] font-bold text-accent">{k}</span>
            <button className="text-slate-500 hover:text-accent" onClick={() => copy(v)}><Copy size={12} /></button>
          </div>
          <div className="selectable break-all font-mono text-[11px] text-slate-300">{v}</div>
        </div>
      ))}
      <div className="text-[10px] text-slate-500">MD5 and SHA-1 are broken for security use — shown for forensics and CTF work only.</div>
    </div>
  );
}

function Password() {
  const [pw, setPw] = useState("Sugreev@2026!");
  const [len, setLen] = useState(20);
  const st = passwordStats(pw);
  const score = Math.min(100, (st.entropy / 100) * 100);
  const col = st.entropy < 40 ? "#ff3b5c" : st.entropy < 60 ? "#ffb020" : st.entropy < 80 ? "#38bdf8" : "#00ffa3";
  const label = st.entropy < 28 ? "Very weak" : st.entropy < 40 ? "Weak" : st.entropy < 60 ? "Fair" : st.entropy < 80 ? "Strong" : "Excellent";
  const checks: [string, boolean][] = [["12+ characters", pw.length >= 12], ["Lowercase", /[a-z]/.test(pw)], ["Uppercase", /[A-Z]/.test(pw)], ["Digits", /\d/.test(pw)], ["Symbols", /[^a-zA-Z0-9]/.test(pw)], ["Not a common password", !st.isCommon]];
  return (
    <div className="space-y-3 p-3">
      <Card title="Password auditor" icon={<ShieldCheck size={13} />}>
        <input className="inp selectable w-full font-mono !text-sm" value={pw} onChange={(e) => setPw(e.target.value)} />
        <div className="mt-3">
          <div className="mb-1 flex justify-between text-xs">
            <span className="font-bold" style={{ color: col }}>{label}</span>
            <span className="font-mono text-slate-400">{st.entropy.toFixed(1)} bits entropy</span>
          </div>
          <Bar value={score} color={col} height={8} />
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
          {checks.map(([n, ok]) => (
            <div key={n} className={`flex items-center gap-2 ${ok ? "text-neon" : "text-slate-500"}`}>{ok ? "✔" : "✘"} {n}</div>
          ))}
        </div>
        <div className="mt-3 rounded-md border border-line bg-ink/60 p-2 font-mono text-[11px] text-slate-400">
          Offline crack time (10 B guesses/s, fast hash): <span className="text-white">{pw ? humanTime(st.secs) : "—"}</span>
        </div>
      </Card>
      <Card title="Generator" icon={<KeyRound size={13} />}>
        <div className="flex items-center gap-3 text-xs text-slate-400">
          Length <input type="range" min={8} max={48} value={len} onChange={(e) => setLen(+e.target.value)} className="flex-1 accent-[var(--accent)]" /> <span className="w-6 font-mono text-white">{len}</span>
          <button className="btn btn-primary" onClick={() => setPw(genPassword(len))}><RefreshCw size={12} />Generate</button>
        </div>
      </Card>
    </div>
  );
}

function Jwt() {
  const [t, setT] = useState("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YWliaGF2Iiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzQwMDAwMDAwLCJpc3MiOiJzdWdyZWV2Lm9zIn0.c2lnbmF0dXJl");
  const parts = t.trim().split(".");
  let header = "",
    payload = "",
    bad = false;
  try {
    const dec = (s: string) => b64dec(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
    header = JSON.stringify(JSON.parse(dec(parts[0])), null, 2);
    payload = JSON.stringify(JSON.parse(dec(parts[1])), null, 2);
  } catch {
    bad = true;
  }
  const alg = (() => {
    try {
      return JSON.parse(header).alg;
    } catch {
      return "";
    }
  })();
  return (
    <div className="space-y-3 p-3">
      <Card title="JWT token">
        <textarea className="inp selectable h-20 w-full resize-none break-all font-mono" value={t} onChange={(e) => setT(e.target.value)} />
      </Card>
      {bad ? (
        <div className="rounded-lg border border-crit/40 bg-crit/10 p-3 text-xs text-crit">Not a valid JWT (expected header.payload.signature, base64url JSON).</div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <Card title="Header"><pre className="selectable font-mono text-xs text-sky-300">{header}</pre></Card>
          <Card title="Payload"><pre className="selectable font-mono text-xs text-emerald-300">{payload}</pre></Card>
          <div className="text-xs sm:col-span-2">
            {alg === "none" || alg === "None" ? <span className="text-crit">⚠ alg=none — signature not verified. Classic JWT attack vector.</span> : <span className="text-slate-500">Algorithm: <b className="text-slate-300">{alg}</b>. Signature is not verified here (no secret).</span>}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Crypto() {
  const [tab, setTab] = useState<Tab>("transform");
  return (
    <div className="flex h-full flex-col bg-base/80">
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "transform", label: "Encode / Decode", icon: <Binary size={13} /> },
          { id: "hash", label: "Hashes", icon: <Hash size={13} /> },
          { id: "password", label: "Passwords", icon: <KeyRound size={13} /> },
          { id: "jwt", label: "JWT", icon: <ShieldCheck size={13} /> },
        ]}
      />
      <div className="min-h-0 flex-1 overflow-auto">{tab === "transform" ? <Transform /> : tab === "hash" ? <Hashes /> : tab === "password" ? <Password /> : <Jwt />}</div>
    </div>
  );
}
