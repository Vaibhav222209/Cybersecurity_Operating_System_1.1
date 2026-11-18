import { useCallback, useEffect, useState } from "react";
import { DEFAULT_SETTINGS, type PowerAction, type Settings } from "./os/context";
import { startKernel, stopKernel } from "./os/kernel";
import Desktop from "./components/Desktop";
import { BootScreen, LoginScreen, OffScreen, PowerTransition } from "./components/BootScreens";

type Phase = "boot" | "login" | "desktop" | "locked" | "transition" | "off";
const KEY = "sugreev.settings.v1";

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    /* ignore */
  }
  return DEFAULT_SETTINGS;
}

export default function App() {
  const [phase, setPhase] = useState<Phase>("boot");
  const [trans, setTrans] = useState<PowerAction>("logout");
  const [settings, setSettingsState] = useState<Settings>(loadSettings);

  const setSettings = useCallback((p: Partial<Settings>) => {
    setSettingsState((s) => {
      const n = { ...s, ...p };
      try {
        localStorage.setItem(KEY, JSON.stringify(n));
      } catch {
        /* ignore */
      }
      return n;
    });
  }, []);

  useEffect(() => {
    document.documentElement.style.setProperty("--accent", settings.accent);
  }, [settings.accent]);

  useEffect(() => {
    if (phase === "login") startKernel();
  }, [phase]);

  const onPower = useCallback((a: PowerAction) => {
    if (a === "lock") return setPhase("locked");
    setTrans(a);
    setPhase("transition");
  }, []);

  useEffect(() => {
    if (phase !== "transition") return;
    const t = setTimeout(() => {
      if (trans === "logout") setPhase("login");
      else {
        stopKernel();
        setPhase(trans === "restart" ? "boot" : "off");
      }
    }, trans === "logout" ? 1900 : 2900);
    return () => clearTimeout(t);
  }, [phase, trans]);

  return (
    <div className={`fixed inset-0 overflow-hidden bg-black ${settings.scanlines ? "scanlines" : ""} ${settings.animations ? "" : "reduce-motion"}`}>
      {(phase === "desktop" || phase === "locked") && <Desktop settings={settings} setSettings={setSettings} onPower={onPower} />}
      {phase === "locked" && <LoginScreen settings={settings} locked onLogin={() => setPhase("desktop")} onPower={onPower} />}
      {phase === "login" && <LoginScreen settings={settings} locked={false} onLogin={() => setPhase("desktop")} onPower={onPower} />}
      {phase === "boot" && <BootScreen onDone={() => setPhase("login")} />}
      {phase === "transition" && <PowerTransition kind={trans} />}
      {phase === "off" && <OffScreen onPowerOn={() => setPhase("boot")} />}
    </div>
  );
}
