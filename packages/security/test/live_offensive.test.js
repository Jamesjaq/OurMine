import { test, describe } from 'node:test'
import assert from 'node:assert'
import {
  LiveWebExploitEngine,
  LiveCredAttacks,
  LivePrivescChecker,
  LiveNetworkScanner,
  LivePostExEngine,
  LiveAdEngine,
  LiveReconEngine,
  MetasploitClient,
  ToolBroker,
} from '../src/index.ts'

describe('Live Offensive Capability Suite', () => {

  test('ToolBroker — allows expanded security tools', () => {
    const broker = new ToolBroker()
    const tools = ['sqlmap', 'hydra', 'john', 'hashcat', 'masscan', 'nuclei', 'smbclient', 'searchsploit', 'msfvenom', 'python3']
    for (const t of tools) {
      const v = broker.validateCommand(`${t} --help`)
      assert.strictEqual(v.valid, true, `Tool '${t}' should be allowed`)
    }
  })

  test('LiveWebExploitEngine — parameter detection and traversal check', async () => {
    const engine = new LiveWebExploitEngine(3000)
    // Run against local benchmark target or test parameters
    const params = await engine.detectParameters({ url: 'http://127.0.0.1:8080/admin?id=1&search=test' })
    assert.ok(Array.isArray(params))
    assert.ok(params.includes('id') || params.includes('search'))
  })

  test('LivePrivescChecker — executes real system SUID and sudo checks', async () => {
    const checker = new LivePrivescChecker()
    const suid = await checker.findSuidBinaries()
    assert.ok(Array.isArray(suid))

    const sudo = await checker.checkSudoRules()
    assert.ok(Array.isArray(sudo))

    const groups = await checker.checkGroupMembership()
    assert.ok(Array.isArray(groups))

    const kernel = await checker.checkKernelVersion()
    assert.ok(Array.isArray(kernel))
  })

  test('LiveNetworkScanner — TCP connect probe on localhost', async () => {
    const scanner = new LiveNetworkScanner()
    // Test localhost:8080 or port 22
    const is8080Open = await scanner.tcpConnect('127.0.0.1', 8080, 1000)
    assert.strictEqual(typeof is8080Open, 'boolean')
  })

  test('LivePostExEngine — local enumeration and credential harvesting', async () => {
    const postEx = new LivePostExEngine()
    const sys = await postEx.enumerateSystem()
    assert.ok(sys.length > 0)
    assert.ok(sys.some(f => f.name === 'Current user' || f.name === 'Identity'))

    const creds = await postEx.harvestCredentials()
    assert.ok(Array.isArray(creds))
  })

  test('LiveReconEngine — crt.sh query handle errors gracefully', async () => {
    const recon = new LiveReconEngine()
    const subs = await recon.queryCrtSh('example.com')
    assert.ok(Array.isArray(subs))
  })

  test('MetasploitClient — MSF tool availability check', async () => {
    const client = new MetasploitClient()
    const search = await client.searchModules('log4j')
    assert.ok(Array.isArray(search))
  })

  test('LiveAdEngine — handles disconnected DC gracefully', async () => {
    const ad = new LiveAdEngine()
    const findings = await ad.kerberoast({ domainController: '127.0.0.99', domain: 'test.local' })
    assert.ok(Array.isArray(findings))
  })

  test('LiveCredAttacks — default creds format check', async () => {
    const creds = new LiveCredAttacks()
    assert.ok(typeof creds.testDefaultCredentials === 'function')
  })

})
