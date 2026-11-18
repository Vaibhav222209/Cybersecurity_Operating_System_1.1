# ⌨️ Sugreev OS — Command Reference

> Auto-generated from the live command registry — **113 commands**. Run `help` or `man <command>` inside the terminal for the same information.

## Shell features

| Feature | Example |
|---|---|
| Pipes | `cat /var/log/auth.log \| grep Failed \| wc -l` |
| Redirects | `siem alerts 20 > ~/alerts.txt` , `echo hi >> notes.txt` |
| Chaining | `cd ~/Documents && ls` , `mkdir a; cd a` |
| Globbing | `ls /var/log/*.log` |
| Variables | `export TARGET=10.10.10.5` then `nmap $TARGET` |
| Scripts | `bash ~/Tools/portscan.sh 10.10.10.5` or `chmod +x x.sh && ./x.sh` |
| Privilege | `sudo <cmd>` , `sudo -i` , `su` , `exit` |
| Keys | `Tab` complete · `↑/↓` history · `Ctrl+C` abort · `Ctrl+L` clear · `Ctrl+U` clear line |

## 🛡️ Security

| Command | Usage | Description |
|---|---|---|
| `cve` | `cve <CVE-ID \| keyword>` | Look up CVE details |
| `nikto` | `nikto -h <host>` | Web server scanner (simulated) |
| `nmap` | `nmap [-sV] [-A] [-O] [-p ports] [--script vuln] <target>` | Network mapper (simulated) |
| `searchsploit` | `searchsploit <term>` | Search exploit modules |
| `siem` | `siem status\|alerts\|tail [-f]\|stats\|top\|block <ip>\|unblock <ip>\|ack <id>\|open` | Sugreev SIEM control |
| `threats` | `threats [map]` | Threat summary (or 'threats map') |
| `vapt` | `vapt scan <target> [--profile quick\|full\|stealth] \| web <target> \| report [target] \| exploits <term> \| summary \| open` | Sugreev VAPT engine |

## 🔥 Firewall

| Command | Usage | Description |
|---|---|---|
| `fail2ban-client` | `fail2ban-client status [sshd]` | Fail2ban status |
| `iptables` | `iptables -L` | Firewall rules |
| `ufw` | `ufw status` | Uncomplicated firewall |

## 🌐 Network

| Command | Usage | Description |
|---|---|---|
| `curl` | `curl [-I] <url>` | Transfer a URL (simulated) |
| `dig` | `dig <domain>` | DNS lookup (simulated) |
| `ifconfig` | `ifconfig` | Configure network interface |
| `ip` | `ip a \| ip route` | Show network interfaces |
| `netstat` | `netstat -tulnp` | Network connections |
| `nslookup` | `nslookup` | Query DNS (simulated) |
| `ping` | `ping [-c N] <host>` | Send ICMP echo (simulated) |
| `ss` | `ss -tulpn` | Socket statistics |
| `traceroute` | `traceroute <host>` | Trace route to host (simulated) |
| `wget` | `wget <url>` | Download a file (simulated) |
| `whois` | `whois <domain>` | Domain registration lookup (simulated) |

## 🔐 Crypto

| Command | Usage | Description |
|---|---|---|
| `base64` | `base64 [-d] <file\|text>` | Base64 encode/decode |
| `hashid` | `hashid <hash>` | Identify hash type |
| `md5sum` | `md5sum <file>` | Compute MD5 hash of a file |
| `sha1sum` | `sha1sum <file>` | Compute SHA-1 hash of a file |
| `sha256sum` | `sha256sum <file>` | Compute SHA-256 hash of a file |
| `sha512sum` | `sha512sum <file>` | Compute SHA-512 hash of a file |

## 📂 Files

| Command | Usage | Description |
|---|---|---|
| `basename` | `basename` | Strip directory from path |
| `cat` | `cat [-n] file...` | Print file contents |
| `cd` | `cd [dir]` | Change directory |
| `chmod` | `chmod 755 file \| chmod +x file` | Change file mode |
| `chown` | `sudo chown user file` | Change file owner |
| `cp` | `cp [-r] src dest` | Copy files |
| `du` | `du [-sh] path` | Disk usage |
| `echo` | `echo [-n] text...` | Print text |
| `file` | `file` | Determine file type |
| `find` | `find [path] -name pattern [-type f\|d]` | Search for files |
| `ls` | `ls [-lah] [path...]` | List directory contents |
| `mkdir` | `mkdir [-p] dir...` | Create directories |
| `mv` | `mv src dest` | Move / rename files |
| `pwd` | `pwd` | Print working directory |
| `rm` | `rm [-rf] path...` | Remove files or directories |
| `rmdir` | `rmdir` | Remove empty directories |
| `stat` | `stat file` | Display file status |
| `tar` | `tar` | Archive utility (simulated) |
| `touch` | `touch file...` | Create empty file / update timestamp |
| `tree` | `tree [path]` | Show directory tree |
| `which` | `which` | Locate a command |

## 📝 Text

| Command | Usage | Description |
|---|---|---|
| `cut` | `cut -d: -f1 file` | Cut fields from lines |
| `grep` | `grep [-inrvc] pattern [file...]` | Search text with a pattern |
| `head` | `head [-n N] file` | Output first lines |
| `sort` | `sort [-rnu] file` | Sort lines |
| `tail` | `tail [-n N] file` | Output last lines |
| `uniq` | `uniq [-c] file` | Report or omit repeated lines |
| `wc` | `wc [-lwc] file` | Count lines, words, bytes |
| `xxd` | `xxd file` | Hex dump a file |

## ⚙️ System

| Command | Usage | Description |
|---|---|---|
| `alias` | `alias` | Show command aliases |
| `apt` | `sudo apt update\|upgrade\|install <pkg>` | Package manager (simulated) |
| `bash` | `bash <script>` | Run a shell script |
| `cal` | `cal` | Show calendar |
| `clear` | `clear` | Clear the screen |
| `date` | `date` | Current date and time |
| `df` | `df [-h]` | Disk free space |
| `dmesg` | `dmesg` | Kernel ring buffer |
| `env` | `env` | Print environment |
| `exit` | `exit` | Exit shell / drop root |
| `export` | `export VAR=value` | Set environment variable |
| `free` | `free [-h\|-m]` | Memory usage |
| `groups` | `groups` | User groups |
| `help` | `help [command]` | List commands or show help for one |
| `history` | `history` | Command history |
| `hostname` | `hostname` | Show hostname |
| `hostnamectl` | `hostnamectl` | Host information |
| `id` | `id` | User identity |
| `journalctl` | `journalctl [-n N]` | Query the system journal |
| `last` | `last` | Last logins |
| `lsb_release` | `lsb_release` | Distribution info |
| `lsblk` | `lsblk` | List block devices |
| `lscpu` | `lscpu` | CPU architecture information |
| `lsmod` | `lsmod` | Loaded kernel modules |
| `lspci` | `lspci` | List PCI devices |
| `lsusb` | `lsusb` | List USB devices |
| `man` | `man <command>` | Manual page for a command |
| `neofetch` | `neofetch` | System information banner |
| `printenv` | `printenv` | Print environment variable |
| `sh` | `sh <script>` | Run a shell script |
| `sleep` | `sleep` | Delay for N seconds |
| `source` | `source` | Run a script in current shell |
| `su` | `su` | Switch to root user |
| `sudo` | `sudo <command> \| sudo -i` | Run a command as root |
| `systemctl` | `systemctl status\|start\|stop\|restart <svc> \| list-units` | Control services |
| `uname` | `uname [-a]` | System information |
| `uptime` | `uptime` | System uptime |
| `w` | `w` | Who is logged in and what they do |
| `who` | `who` | Logged-in users |
| `whoami` | `whoami` | Current user |

## 📊 Process

| Command | Usage | Description |
|---|---|---|
| `kill` | `kill [-9] <pid>` | Terminate a process |
| `ps` | `ps [aux]` | Process status |
| `top` | `top` | Process activity snapshot |

## 🖥️ Desktop

| Command | Usage | Description |
|---|---|---|
| `browse` | `browse <url>` | Open the browser at a URL |
| `edit` | `edit <file>` | Edit a file in the text editor |
| `files` | `files` | Open file manager at path |
| `open` | `open <terminal\|files\|browser\|siem\|threats\|vapt\|monitor\|editor\|crypto\|settings\|about>` | Open a desktop app |

## ⏻ Power

| Command | Usage | Description |
|---|---|---|
| `lock` | `lock` | Lock the screen |
| `logout` | `logout` | Log out of the session |
| `poweroff` | `poweroff` | Power off the system |
| `reboot` | `reboot` | Restart the system |
| `shutdown` | `shutdown` | Power off the system |

## 🎮 Fun

| Command | Usage | Description |
|---|---|---|
| `calc` | `calc 2*(3+4)` | Calculator |
| `cowsay` | `cowsay` | A talking cow |
| `fortune` | `fortune` | Security wisdom |
| `hack` | `hack` | Hollywood hacking simulation |
| `matrix` | `matrix  (Ctrl+C to stop)` | Enter the matrix |

## Aliases

`ll` → `ls -la` · `la` → `ls -A` · `cls` → `clear` · `..` → `cd ..` · `scan` → `vapt scan` · `alerts` → `siem alerts` · `restart` → `reboot` · `halt` → `shutdown`
