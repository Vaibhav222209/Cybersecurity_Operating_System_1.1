# 📖 Sugreev OS — User Guide

## 1. Opening Sugreev OS

| Method | Steps |
|---|---|
| **Online** | Visit `https://vaibhav222209.github.io/Sugreev-OS/` |
| **Local dev** | `git clone …` → `npm install` → `npm run dev` → open `http://localhost:5173` |
| **Portable file** | `npm run build` → open `dist/index.html` (or download the `.html` from a GitHub Release) |

**Login:** user **Vaibhav Thakur** · password **`sugreev`**

## 2. Desktop tour

```
┌────────────────────────────────────────────────────────────────────────────┐
│ ◈ SUGREEV │ [Terminal] [SIEM] …       12:04:33          CPU MEM NET  ⚠ Bell ⏻│  ← top bar (taskbar)
├────┬───────────────────────────────────────────────────────────────────────┤
│ ▦  │  desktop icons          ┌────────── window ──────────┐   ┌──────────┐ │
│ ⌨  │  Home  README  Reports  │ title            _  ▢  ✕  │   │ clock +  │ │
│ 📁 │                         │                            │   │ threat   │ │
│ 🌐 │                         │                            │   │ widget   │ │
│ 📊 │                         └────────────────────────────┘   └──────────┘ │
│ 🛰 │                                                                        │
│ 🎯 │   ← dock on the left (running apps have a glowing marker)             │
└────┴───────────────────────────────────────────────────────────────────────┘
```

- **Top bar** — launcher button, open-window tabs, clock, live CPU/MEM/NET, threat-level chip, notifications, user/power menu
- **Dock (left)** — click to launch; click again to minimise; right-click the desktop for a context menu
- **Windows** — drag the title bar, resize from any edge/corner, double-click title to maximise

## 3. Power options

Top-right avatar menu (or launcher footer, or terminal):

| Action | Terminal | Result |
|---|---|---|
| Lock screen | `lock` | Apps keep running; enter the password to resume |
| Log out | `logout` | Closes all windows → login screen |
| Restart | `reboot` | Shutdown animation → boot sequence → login |
| Shut down | `shutdown` | Shutdown animation → black screen with a **power-on** button |

## 4. Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` + `Alt` + `T` | Open a new terminal |
| `Esc` | Close launcher / dialogs |
| `Ctrl+C` / `Ctrl+L` / `Tab` / `↑↓` | Terminal: abort · clear · autocomplete · history |
| `Ctrl+S` | Editor: save |
| `Del` / `F2` | Files: delete / rename |

## 5. Guided labs

### Lab 1 — Investigate a brute-force attack

1. `siem tail -f` — watch for `Failed password … ssh2`
2. `Ctrl+C`, then `siem alerts 10` and find **SSH Brute Force**
3. `siem top` — list the noisiest source IPs
4. `sudo siem block <ip>` and verify with `iptables -L`
5. Open **SIEM Console → Alerts**, review the **response playbook** and mark the alert *resolved*

### Lab 2 — Vulnerability assessment

1. `nmap -sV 192.168.56.101` — discover services
2. `vapt scan 192.168.56.101` — full 5-phase assessment
3. `cve vsftpd` and `searchsploit vsftpd` — research the finding
4. `vapt web 192.168.56.101` — web hygiene checks
5. `vapt report` → `edit ~/Reports/<file>.md` → click **Preview**
6. Re-scan the hardened host: `vapt scan sugreev.local`

### Lab 3 — Log forensics with pipes

```bash
cat /var/log/auth.log | grep "Failed password" | cut -d' ' -f11 | sort | uniq -c | sort -nr | head
grep -r "CVE" ~ | wc -l
find / -name "*.log"
```

### Lab 4 — Automate the response

1. **Threat Monitor → Auto-response ON** (or Settings → Security)
2. Wait for a critical event — the attacker is blocked automatically and a toast appears
3. Check `siem status` and the **Firewall blocklist**

### Lab 5 — Crypto toolkit

1. `echo -n "sugreev" | base64`
2. `md5sum README.md`, `sha256sum README.md`
3. Open **Crypto Toolkit → Passwords** and audit a few passwords
4. Decode a JWT and spot an `alg: none` token

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| Blank page when opening a website in the Browser | The site blocks embedding (X-Frame-Options). Use **Open in real tab ↗** |
| Lost files or settings | Settings → System → **Reset virtual file system**, or clear site data |
| Fonts look different offline | Expected — Google Fonts are optional; system monospace is used |
| Wrong password | Default password is `sugreev` |
