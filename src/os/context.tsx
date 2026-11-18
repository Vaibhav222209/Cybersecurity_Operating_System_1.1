import { createContext, useContext } from "react";
import type { Severity } from "./kernel";

export type AppId =
  | "terminal"
  | "files"
  | "browser"
  | "siem"
  | "threats"
  | "vapt"
  | "monitor"
  | "editor"
  | "crypto"
  | "settings"
  | "about";

export type Wallpaper = "matrix" | "grid" | "aurora";

export interface Settings {
  accent: string;
  wallpaper: Wallpaper;
  scanlines: boolean;
  animations: boolean;
  notifications: boolean;
}

export type PowerAction = "logout" | "restart" | "shutdown" | "lock";

export interface Notification {
  id: number;
  ts: number;
  title: string;
  body: string;
  sev: Severity;
  app?: AppId;
}

export interface OSApi {
  openApp: (id: AppId, props?: Record<string, unknown>) => void;
  openFile: (path: string) => void;
  closeWindow: (winId: string) => void;
  notify: (n: { title: string; body: string; sev?: Severity; app?: AppId }) => void;
  power: (a: PowerAction) => void;
  settings: Settings;
  setSettings: (p: Partial<Settings>) => void;
  notifications: Notification[];
  clearNotifications: () => void;
}

export const OSContext = createContext<OSApi | null>(null);
export function useOS(): OSApi {
  const c = useContext(OSContext);
  if (!c) throw new Error("OSContext missing");
  return c;
}

export const WinContext = createContext<{ winId: string; props: Record<string, unknown> }>({ winId: "", props: {} });
export const useWin = () => useContext(WinContext);

export const ACCENTS = [
  { name: "Cyber Cyan", value: "#00e5ff" },
  { name: "Matrix Green", value: "#00ff9c" },
  { name: "Neon Magenta", value: "#ff2bd6" },
  { name: "Amber Alert", value: "#ffb020" },
  { name: "Ultra Violet", value: "#a78bfa" },
  { name: "Blood Red", value: "#ff3b5c" },
];

export const DEFAULT_SETTINGS: Settings = {
  accent: "#00e5ff",
  wallpaper: "matrix",
  scanlines: true,
  animations: true,
  notifications: true,
};
