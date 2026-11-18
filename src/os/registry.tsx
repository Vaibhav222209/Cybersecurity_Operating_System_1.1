import { memo, type ComponentType } from "react";
import { Activity, Crosshair, FolderOpen, Gauge, Globe2, Info, KeyRound, Radar, Settings as SettingsIcon, SquareTerminal, FileText, type LucideIcon } from "lucide-react";
import type { AppId } from "./context";
import Terminal from "../apps/Terminal";
import Files from "../apps/Files";
import Browser from "../apps/Browser";
import Siem from "../apps/Siem";
import ThreatMonitor from "../apps/ThreatMonitor";
import Vapt from "../apps/Vapt";
import SystemMonitor from "../apps/SystemMonitor";
import Editor from "../apps/Editor";
import Crypto from "../apps/Crypto";
import Settings, { About } from "../apps/Settings";

export interface AppDef {
  id: AppId;
  title: string;
  desc: string;
  icon: LucideIcon;
  color: string;
  w: number;
  h: number;
  multi?: boolean;
  pinned?: boolean;
  Comp: ComponentType;
}

export const APPS: AppDef[] = [
  { id: "terminal", title: "Terminal", desc: "sgsh shell · 110+ commands", icon: SquareTerminal, color: "#00ff9c", w: 760, h: 480, multi: true, pinned: true, Comp: memo(Terminal) },
  { id: "files", title: "Files", desc: "Virtual file system", icon: FolderOpen, color: "#ffb020", w: 780, h: 500, multi: true, pinned: true, Comp: memo(Files) },
  { id: "browser", title: "Browser", desc: "Sandboxed secure browser", icon: Globe2, color: "#38bdf8", w: 940, h: 580, multi: true, pinned: true, Comp: memo(Browser) },
  { id: "siem", title: "SIEM Console", desc: "Logs, alerts & MITRE ATT&CK", icon: Activity, color: "#00e5ff", w: 1020, h: 620, pinned: true, Comp: memo(Siem) },
  { id: "threats", title: "Threat Monitor", desc: "Live attack map & IDS", icon: Radar, color: "#ff3b5c", w: 1000, h: 620, pinned: true, Comp: memo(ThreatMonitor) },
  { id: "vapt", title: "VAPT Lab", desc: "Scanner, web audit & reports", icon: Crosshair, color: "#ff7a3c", w: 960, h: 620, pinned: true, Comp: memo(Vapt) },
  { id: "monitor", title: "System Monitor", desc: "CPU, memory & processes", icon: Gauge, color: "#a78bfa", w: 920, h: 580, pinned: true, Comp: memo(SystemMonitor) },
  { id: "crypto", title: "Crypto Toolkit", desc: "Hashes, encoders & passwords", icon: KeyRound, color: "#f472b6", w: 820, h: 540, pinned: true, Comp: memo(Crypto) },
  { id: "editor", title: "Text Editor", desc: "Edit files & preview Markdown", icon: FileText, color: "#94a3b8", w: 700, h: 480, multi: true, pinned: false, Comp: memo(Editor) },
  { id: "settings", title: "Settings", desc: "Appearance & security", icon: SettingsIcon, color: "#cbd5e1", w: 640, h: 540, pinned: true, Comp: memo(Settings) },
  { id: "about", title: "About Sugreev", desc: "Credits & license", icon: Info, color: "#00e5ff", w: 560, h: 560, pinned: false, Comp: memo(About) },
];

export const appById = (id: AppId) => APPS.find((a) => a.id === id)!;
