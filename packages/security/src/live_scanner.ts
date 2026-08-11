/**
 * Live Network Scanner
 * Real port scanning, service enumeration, banner grabbing.
 * Uses: masscan, nmap, nc, smbclient, snmpwalk, openssl (via execFile)
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as net from 'node:net'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'

const execFileP = promisify(execFile)

function rand() { return crypto.randomBytes(4).toString('hex') }

export interface ServiceInfo {
  host: string
  port: number
  protocol: 'tcp' | 'udp'
  state: 'open' | 'closed' | 'filtered'
  service?: string
  version?: string
  banner?: string
}

export interface ScanResult {
  host: string
  openPorts: ServiceInfo[]
  scanDurationMs: number
  tool: string
}

export class LiveNetworkScanner {
  async tcpConnect(host: string, port: number, timeoutMs: number = 3000): Promise<boolean> {
    return new Promise((resolve) => {
      const sock = new net.Socket()
      sock.setTimeout(timeoutMs)
      sock.on('connect', () => { sock.destroy(); resolve(true) })
      sock.on('error', () => { sock.destroy(); resolve(false) })
      sock.on('timeout', () => { sock.destroy(); resolve(false) })
      sock.connect(port, host)
    })
  }

  async grabBanner(host: string, port: number, timeoutMs: number = 3000): Promise<string> {
    return new Promise((resolve) => {
      const sock = new net.Socket()
      let banner = ''
      sock.setTimeout(timeoutMs)
      sock.on('connect', () => { /* wait for banner */ })
      sock.on('data', (d) => { banner += d.toString('utf-8', 0, 512); sock.destroy() })
      sock.on('timeout', () => { sock.destroy(); resolve(banner) })
      sock.on('error', () => { sock.destroy(); resolve(banner) })
      sock.on('close', () => resolve(banner))
      sock.connect(port, host)
    })
  }

  async scanPortsMasscan(host: string, portRange: string = '1-65535', rate: number = 1000): Promise<ServiceInfo[]> {
    const outFile = `/tmp/masscan_${rand()}.json`
    try {
      await execFileP('masscan', [
        host, '-p', portRange,
        '--rate', String(rate),
        '-oJ', outFile,
        '--wait', '2',
      ], { timeout: 120000 })
      const raw = fs.readFileSync(outFile, 'utf-8')
      const services: ServiceInfo[] = []
      const matches = raw.matchAll(/"port"\s*:\s*(\d+).*?"proto"\s*:\s*"(\w+)"/gs)
      for (const m of matches) {
        if (m[1] && m[2]) {
          services.push({ host, port: parseInt(m[1]), protocol: m[2] as 'tcp' | 'udp', state: 'open' })
        }
      }
      return services
    } catch {
      return this.scanPortsNmap(host, portRange)
    } finally {
      try { fs.unlinkSync(outFile) } catch { /* ignore */ }
    }
  }

  async scanPortsNmap(host: string, portRange: string = '1-1024'): Promise<ServiceInfo[]> {
    const outFile = `/tmp/nmap_${rand()}.xml`
    try {
      await execFileP('nmap', [
        '-sV', '-sT', '-p', portRange,
        '-T4', '--open',
        '-oX', outFile,
        host,
      ], { timeout: 120000 }).catch(() => {})
      const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf-8') : ''
      const services: ServiceInfo[] = []
      const portMatches = raw.matchAll(/<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?<\/port>/gs)
      for (const m of portMatches) {
        if (m[3] === 'open' && m[1] && m[2]) {
          const svc: ServiceInfo = { host, port: parseInt(m[2]), protocol: m[1] as 'tcp' | 'udp', state: 'open' }
          const svcMatch = raw.match(new RegExp(`portid="${m[2]}".*?<service name="([^"]+)"[^>]*version="([^"]*)"`, 's'))
          if (svcMatch) { svc.service = svcMatch[1]; svc.version = svcMatch[2] }
          services.push(svc)
        }
      }
      return services
    } catch {
      const commonPorts = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
      const services: ServiceInfo[] = []
      await Promise.all(commonPorts.map(async (port) => {
        const open = await this.tcpConnect(host, port, 2000)
        if (open) {
          const banner = await this.grabBanner(host, port, 2000)
          services.push({ host, port, protocol: 'tcp', state: 'open', banner: banner.slice(0, 200) })
        }
      }))
      return services
    } finally {
      try { fs.unlinkSync(outFile) } catch { /* ignore */ }
    }
  }

  async smbEnumerate(host: string): Promise<{ shares: string[]; users: string[]; os?: string }> {
    const shares: string[] = []
    const users: string[] = []
    let os: string | undefined
    try {
      const result = await execFileP('smbclient', ['-L', `\\\\${host}`, '-N', '--no-pass'], { timeout: 15000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      const shareMatches = out.matchAll(/^\s+(\S+)\s+(?:Disk|IPC|Printer)/gm)
      for (const m of shareMatches) { if (m[1]) shares.push(m[1].trim()) }
      const osMatch = out.match(/OS=\[([^\]]+)\]/)
      if (osMatch && osMatch[1]) os = osMatch[1]
    } catch { /* ignore */ }
    return { shares, users, os }
  }

  async checkFtpAnonymous(host: string, port: number = 21): Promise<{ allowed: boolean; listing?: string }> {
    try {
      const result = await execFileP('ftp', ['-n', '-v', host, String(port)], { timeout: 15000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '', stderr: (e as {stderr?: string}).stderr || '' }))
      const out = result.stdout + result.stderr
      if (out.includes('230') || out.toLowerCase().includes('anonymous login')) {
        return { allowed: true, listing: out.slice(0, 500) }
      }
    } catch { /* ignore */ }
    const banner = await this.grabBanner(host, port, 5000)
    if (banner.includes('220')) {
      return { allowed: false }
    }
    return { allowed: false }
  }

  async snmpWalk(host: string, community: string = 'public'): Promise<string> {
    try {
      const result = await execFileP('snmpwalk', ['-v2c', '-c', community, host, '1.3.6.1.2.1.1'], { timeout: 20000 })
      return result.stdout.slice(0, 2000)
    } catch (e) {
      return String((e as Error).message || e).slice(0, 200)
    }
  }

  async fullScan(host: string): Promise<ScanResult> {
    const start = Date.now()
    const openPorts = await this.scanPortsNmap(host, '1-10000')
    await Promise.all(openPorts.map(async (svc) => {
      if (!svc.banner) {
        svc.banner = (await this.grabBanner(svc.host, svc.port, 2000)).slice(0, 200)
      }
    }))
    return { host, openPorts, scanDurationMs: Date.now() - start, tool: 'nmap+tcp-connect' }
  }
}
