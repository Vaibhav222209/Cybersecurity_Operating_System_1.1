/**
 * Generates docs/COMMANDS.md from the live command registry.
 *
 *   npx esbuild scripts/gen-commands.ts --bundle --platform=node --format=esm --outfile=.tmp/gen-commands.mjs
 *   node .tmp/gen-commands.mjs
 */
import { writeFileSync } from "node:fs";
import { COMMANDS } from "../src/os/shell/engine";

const ORDER = ["Security", "Firewall", "Network", "Crypto", "Files", "Text", "System", "Process", "Desktop", "Power", "Fun"];
const ICON: Record<string, string> = { Security: "🛡️", Firewall: "🔥", Network: "🌐", Crypto: "🔐", Files: "📂", Text: "📝", System: "⚙️", Process: "📊", Desktop: "🖥️", Power: "⏻", Fun: "🎮" };

const names = Object.keys(COMMANDS).sort();
const lines: string[] = [];
lines.push("# ⌨️ Sugreev OS — Command Reference", "");
lines.push(`> Auto-generated from the live command registry — **${names.length} commands**. Run \`help\` or \`man <command>\` inside the terminal for the same information.`, "");
lines.push("## Shell features", "");
lines.push("| Feature | Example |", "|---|---|");
lines.push("| Pipes | `cat /var/log/auth.log \\| grep Failed \\| wc -l` |");
lines.push("| Redirects | `siem alerts 20 > ~/alerts.txt` , `echo hi >> notes.txt` |");
lines.push("| Chaining | `cd ~/Documents && ls` , `mkdir a; cd a` |");
lines.push("| Globbing | `ls /var/log/*.log` |");
lines.push("| Variables | `export TARGET=10.10.10.5` then `nmap $TARGET` |");
lines.push("| Scripts | `bash ~/Tools/portscan.sh 10.10.10.5` or `chmod +x x.sh && ./x.sh` |");
lines.push("| Privilege | `sudo <cmd>` , `sudo -i` , `su` , `exit` |");
lines.push("| Keys | `Tab` complete · `↑/↓` history · `Ctrl+C` abort · `Ctrl+L` clear · `Ctrl+U` clear line |", "");

for (const cat of ORDER) {
  const list = names.filter((n) => COMMANDS[n].cat === cat);
  if (!list.length) continue;
  lines.push(`## ${ICON[cat] ?? ""} ${cat}`, "", "| Command | Usage | Description |", "|---|---|---|");
  for (const n of list) {
    const c = COMMANDS[n];
    lines.push(`| \`${n}\` | \`${(c.usage ?? n).replace(/\|/g, "\\|")}\` | ${c.desc} |`);
  }
  lines.push("");
}
lines.push("## Aliases", "", "`ll` → `ls -la` · `la` → `ls -A` · `cls` → `clear` · `..` → `cd ..` · `scan` → `vapt scan` · `alerts` → `siem alerts` · `restart` → `reboot` · `halt` → `shutdown`", "");
writeFileSync("docs/COMMANDS.md", lines.join("\n"));
console.log(`Wrote docs/COMMANDS.md (${names.length} commands)`);
