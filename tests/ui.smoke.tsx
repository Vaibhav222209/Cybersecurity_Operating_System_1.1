/**
 * Sugreev OS — UI smoke test (jsdom).
 * Boots the real <App/>, logs in, opens every application, exercises power menu & lock screen.
 *
 *   npx esbuild tests/ui.smoke.tsx --bundle --platform=node --format=esm --jsx=automatic --loader:.css=empty \
 *     --external:jsdom --outfile=.tmp/ui.smoke.mjs && node .tmp/ui.smoke.mjs
 */
import { JSDOM } from "jsdom";

const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', { url: "http://localhost/", pretendToBeVisual: true });
const w = dom.window as unknown as Record<string, unknown>;
const g = globalThis as unknown as Record<string, unknown>;
for (const k of Object.getOwnPropertyNames(dom.window)) {
  if (k in g && !["document", "window", "navigator", "localStorage"].includes(k)) continue;
  try {
    Object.defineProperty(g, k, { value: w[k], configurable: true, writable: true });
  } catch {
    /* ignore read-only */
  }
}
g.window = dom.window;
g.document = dom.window.document;
g.IS_REACT_ACT_ENVIRONMENT = false;
(dom.window as unknown as { HTMLCanvasElement: { prototype: { getContext: () => null } } }).HTMLCanvasElement.prototype.getContext = () => null;
dom.window.localStorage.setItem("sugreev.settings.v1", JSON.stringify({ wallpaper: "grid", animations: false, scanlines: false, accent: "#00ff9c", notifications: true }));

const errors: string[] = [];
const origErr = console.error;
console.error = (...a: unknown[]) => {
  const msg = a.map(String).join(" ");
  if (/not implemented|Not implemented/.test(msg)) return;
  errors.push(msg.slice(0, 400));
  origErr(...a);
};
process.on("uncaughtException", (e) => errors.push("uncaught: " + e.message));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const doc = dom.window.document;
const $$ = (sel: string) => [...doc.querySelectorAll<HTMLElement>(sel)];
const findBtn = (text: string, scope: ParentNode = doc) => [...scope.querySelectorAll<HTMLElement>("button")].find((b) => (b.textContent || "").includes(text));
const typeInto = (el: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!;
  setter.call(el, value);
  el.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
};
let step = 0;
const check = (name: string, ok: boolean) => {
  step++;
  console.log(`${ok ? "✔" : "✘"} ${name}`);
  if (!ok) errors.push("FAILED: " + name);
};

const { createRoot } = await import("react-dom/client");
const { default: App } = await import("../src/App");
const { createElement } = await import("react");
createRoot(doc.getElementById("root")!).render(createElement(App));

await sleep(200);
check("boot screen renders", /SugreevBIOS/.test(doc.body.textContent || ""));
doc.defaultView!.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Enter" }));
await sleep(300);
check("login screen renders", /Vaibhav Thakur/.test(doc.body.textContent || "") && !!doc.querySelector('input[type="password"]'));

// wrong password
typeInto(doc.querySelector('input[type="password"]') as HTMLInputElement, "wrong");
doc.querySelector('input[type="password"]')!.closest("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(100);
check("wrong password rejected", /Authentication failure/.test(doc.body.textContent || ""));

typeInto(doc.querySelector('input[type="password"]') as HTMLInputElement, "sugreev");
doc.querySelector('input[type="password"]')!.closest("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(1200);
check("desktop renders with top bar", /SUGREEV/.test(doc.body.textContent || "") && /Terminal/.test(doc.body.textContent || ""));
check("terminal window opened at login", /Sugreev OS 1\.0/.test(doc.body.textContent || ""));

// open every app through the dock
const apps = ["Files", "Browser", "SIEM Console", "Threat Monitor", "VAPT Lab", "System Monitor", "Crypto Toolkit", "Settings"];
for (const a of apps) {
  const dock = doc.querySelector(".fixed.left-0.top-10") as HTMLElement;
  const btn = [...dock.querySelectorAll<HTMLElement>("button")].find((b) => (b.textContent || "").trim() === a);
  btn?.click();
  await sleep(250);
  check(`open ${a}`, !!btn && $$(".glass-strong.absolute").length > 0);
}
await sleep(1500); // let the kernel tick
check("window count", $$(".glass-strong.absolute").length >= 9);

// drive each tabbed app's tabs
for (const label of ["Live Logs", "Alerts", "Detection Rules", "Dashboard", "Web Audit", "Exploit DB", "Report", "Processes", "Hardware", "Hashes", "Passwords", "JWT", "Encode / Decode", "Scanner"]) {
  const tabs = $$("button").filter((b) => (b.textContent || "").trim().startsWith(label));
  tabs.forEach((t) => t.click());
  await sleep(60);
}
check("tabs render without crashing", errors.length === 0);

// run a VAPT scan from the GUI
const startBtn = findBtn("Start scan");
startBtn?.click();
await sleep(5200);
check("VAPT GUI scan completes", /Risk score/.test(doc.body.textContent || ""));

// terminal interaction
const termInput = doc.querySelector<HTMLInputElement>("input.term-out");
if (termInput) {
  typeInto(termInput, "siem status");
  termInput.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  await sleep(300);
  check("terminal runs `siem status`", /ingest rate/.test(doc.body.textContent || ""));
}

// launcher + power menu
(doc.querySelector('button[title="All applications"]') as HTMLElement | null)?.click();
await sleep(100);
check("launcher opens", /Applications/.test(doc.body.textContent || ""));
doc.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Escape" }));
(doc.querySelector(".fixed.inset-0.z-\\[5400\\]") as HTMLElement | null)?.click();
await sleep(100);

const powerBtn = $$(".glass-strong.fixed button").find((b) => b.querySelector("svg.lucide-power") && b.textContent === "VT" ) ?? $$("button").find((b) => b.querySelector(".lucide-power") && /VT/.test(b.textContent || ""));
powerBtn?.click();
await sleep(100);
check("power menu lists Lock / Log out / Restart / Shut down", ["Lock screen", "Log out", "Restart", "Shut down"].every((t) => (doc.body.textContent || "").includes(t)));
findBtn("Lock screen")?.click();
await sleep(100);
check("confirm dialog for lock", /LOCK SCREEN/.test(doc.body.textContent || ""));
const lockConfirm = $$("button").find((b) => (b.textContent || "").trim() === "Lock");
lockConfirm?.click();
await sleep(200);
check("lock screen shows Unlock", /Unlock/.test(doc.body.textContent || ""));
typeInto(doc.querySelector('input[type="password"]') as HTMLInputElement, "sugreev");
doc.querySelector('input[type="password"]')!.closest("form")!.dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
await sleep(1000);
check("unlock returns to desktop", !/Unlock/.test(doc.body.textContent || "") && $$(".glass-strong.absolute").length > 5);

// shutdown flow
(doc.querySelector("body") as HTMLElement).dispatchEvent(new dom.window.Event("click"));
const power2 = $$("button").find((b) => b.querySelector(".lucide-power") && /VT/.test(b.textContent || ""));
power2?.click();
await sleep(100);
findBtn("Shut down")?.click();
await sleep(100);
$$("button").find((b) => (b.textContent || "").trim() === "Shut down" && b.className.includes("flex-1"))?.click();
await sleep(500);
check("shutdown animation", /SHUTTING DOWN/.test(doc.body.textContent || ""));
await sleep(3300);
check("system halted screen with power-on", /System halted/.test(doc.body.textContent || ""));
$$("button").find((b) => b.title === "Power on")?.click();
await sleep(300);
check("power-on boots again", /SugreevBIOS/.test(doc.body.textContent || ""));

console.log(errors.length ? `\n${errors.length} problem(s):\n${errors.join("\n")}` : `\nAll ${step} UI smoke checks passed`);
process.exit(errors.length ? 1 : 0);
