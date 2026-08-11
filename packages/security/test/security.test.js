import test from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Core Infrastructure Tests ────────────────────────────────────────────────

test('Tool detection utility', async () => {
  const { isToolAvailable, checkTools, toolSummary } = await import('../src/tool_detection.ts');
  assert.strictEqual(isToolAvailable('node'), true, 'node should be available');
  assert.strictEqual(isToolAvailable('nonexistent_tool_xyz'), false, 'fake tool should not exist');
  const results = checkTools('node', 'nonexistent_tool_xyz');
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[0].available, true);
  assert.strictEqual(results[1].available, false);
  const summary = toolSummary();
  assert.ok(summary.includes('Available:'));
});

test('LLM client module loads', async () => {
  const { hasLLMKey, listProviders } = await import('../src/llm_client.ts');
  const hasKey = hasLLMKey();
  assert.strictEqual(typeof hasKey, 'boolean');
  const providers = listProviders();
  assert.ok(Array.isArray(providers));
});

// ─── Container Tests ─────────────────────────────────────────────────────────

test('Container audit (dry-run)', async () => {
  const { auditContainer } = await import('../src/container.ts');
  const audit = auditContainer({ live: false });
  assert.ok(audit);
  assert.strictEqual(audit.dryRun, true);
});

test('Container K8s audit (dry-run)', async () => {
  const { auditCluster } = await import('../src/container_k8s.ts');
  const result = await auditCluster({ dryRun: true });
  assert.ok(result);
  assert.ok(result.findings);
  assert.ok(result.findings.length > 0);
});

// ─── Recon Tests ─────────────────────────────────────────────────────────────

test('AI Recon (dry-run)', async () => {
  const { runRecon } = await import('../src/ai_recon.ts');
  const result = await runRecon({ domain: 'example.com' }, { dryRun: true });
  assert.ok(result);
  assert.ok(result.employees.length > 0);
  assert.ok(result.subdomains.length > 0);
  assert.ok(result.emailPatterns.length > 0);
  assert.strictEqual(result.dryRun, true);
});

// ─── Supply Chain Tests ──────────────────────────────────────────────────────

test('Supply chain typosquat detection', async () => {
  const { auditPackage } = await import('../src/supply_chain.ts');
  const result = await auditPackage('reqeusts', 'npm', { dryRun: true });
  assert.ok(result);
  assert.strictEqual(result.isTyposquat, true);
});

// ─── Identity & AD Tests ─────────────────────────────────────────────────────

test('Credential dumping (dry-run)', async () => {
  const { CredentialDumpingEngine } = await import('../src/cred_dump.ts');
  const engine = new CredentialDumpingEngine();
  const result = await engine.dump({ dryRun: true });
  assert.ok(result);
  assert.ok(result.artifacts);
});

test('Identity kerberoast (dry-run)', async () => {
  const { kerberoast } = await import('../src/identity.ts');
  const res = await kerberoast({ live: false });
  assert.ok(res.length > 0);
});

// ─── Anti-Analysis Tests ─────────────────────────────────────────────────────

test('Anti-Analysis profiling (dry-run)', async () => {
  const { profileEnvironment } = await import('../src/anti_analysis.ts');
  const profile = profileEnvironment({ live: false });
  assert.strictEqual(typeof profile.score, 'number');
});

// ─── Financial Tests ─────────────────────────────────────────────────────────

test('Financial MT103 parsing (dry-run)', async () => {
  const { parseMT103 } = await import('../src/financial.ts');
  const result = parseMT103(':20:1234567890\n:32A:240101USD10000,00\n:50K:/123456789\nTest User\n:59:/987654321\nBeneficiary User');
  assert.ok(result);
  assert.ok(result.amount);
  assert.ok(result.currency);
});

test('Financial fraud scoring (dry-run)', async () => {
  const { evaluateFraudRisk } = await import('../src/financial_fraud.ts');
  const result = evaluateFraudRisk('192.168.1.1', 'Mozilla/5.0', true);
  assert.ok(result);
  assert.strictEqual(typeof result.fraudScore, 'number');
});

// ─── C2 Tests ────────────────────────────────────────────────────────────────

test('C2 ProxyRotator', async () => {
  const { ProxyRotator } = await import('../src/c2.ts');
  const rotator = new ProxyRotator([
    { host: 'proxy1.example.com', port: 8080, type: 'http' },
    { host: 'proxy2.example.com', port: 8080, type: 'http' },
  ]);
  assert.strictEqual(rotator.count, 2);
  const first = rotator.next();
  assert.ok(first.host);
});

// ─── Skills Tests ────────────────────────────────────────────────────────────

test('Skills list (dry-run)', async () => {
  const { detectAllTools } = await import('../src/skills.ts');
  const tools = await detectAllTools(undefined, true);
  assert.ok(tools.length > 0);
  assert.ok(tools[0].tool);
});

// ─── Identity Theft Tests ────────────────────────────────────────────────────

test('Identity theft PII detection (dry-run)', async () => {
  const { detectPII } = await import('../src/identity_theft.ts');
  const result = detectPII('My SSN is 123-45-6789 and email is test@example.com', true);
  assert.ok(result);
  assert.ok(result.matches.length > 0);
});

// ─── Physical Security Tests ─────────────────────────────────────────────────

test('Ducky Script parser (dry-run)', async () => {
  const { compileDuckyScript } = await import('../src/physical.ts');
  const result = compileDuckyScript('REM Test script\nSTRING Hello World\nENTER', true);
  assert.ok(result);
  assert.ok(result.hidReports);
});

// ─── Multi-language Payloads ─────────────────────────────────────────────────

test('Multi-language payload generation (dry-run)', async () => {
  const { generateAllPayloads } = await import('../src/multi_lang.ts');
  const result = generateAllPayloads('127.0.0.1', 4444, 'linux');
  assert.ok(result);
  assert.ok(result.reverseShells.python);
  assert.ok(result.reverseShells.bash);
  assert.ok(result.reverseShells.powershell);
});

// ─── OAuth Tests ─────────────────────────────────────────────────────────────

test('OAuth chain audit (dry-run)', async () => {
  const { auditOAuthChain } = await import('../src/oauth_chain.ts');
  const result = auditOAuthChain({ targetUrl: 'https://example.com/callback', dryRun: true });
  assert.ok(result);
  assert.ok(result.vulnerabilities);
});

// ─── Meterpreter Tests ───────────────────────────────────────────────────────

test('Meterpreter TLV framing', async () => {
  const { buildTlvPacket, parseTlvPackets } = await import('../src/meterpreter.ts');
  const packet = buildTlvPacket(1, Buffer.from('test'));
  assert.ok(packet);
  const parsed = parseTlvPackets(packet);
  assert.ok(parsed.length > 0);
});

// ─── Insider Threat Tests ────────────────────────────────────────────────────

test('Insider risk evaluation (dry-run)', async () => {
  const { evaluateInsiderRisk } = await import('../src/insider.ts');
  const result = evaluateInsiderRisk([], { dryRun: true });
  assert.ok(result);
  assert.strictEqual(typeof result.riskScore, 'number');
});

// ─── Atlas Arsenal Tests ─────────────────────────────────────────────────────

test('Atlas arsenal jailbreak prompts (dry-run)', async () => {
  const { generateJailbreakPrompts } = await import('../src/atlas_arsenal.ts');
  const prompts = await generateJailbreakPrompts(undefined, true);
  assert.ok(Array.isArray(prompts));
  assert.ok(prompts.length > 0);
});

// ─── Counter Intel Tests ─────────────────────────────────────────────────────

test('Counter-intel audit (dry-run)', async () => {
  const { auditDefenses } = await import('../src/counter_intel.ts');
  const result = auditDefenses({ dryRun: true });
  assert.ok(result);
  assert.ok(typeof result.blueTeamMonitoring === 'boolean');
});

// ─── eBPF Audit Tests ────────────────────────────────────────────────────────

test('eBPF audit (dry-run)', async () => {
  const { auditEBPFAndPersistence } = await import('../src/ebpf_audit.ts');
  const result = auditEBPFAndPersistence({ dryRun: true });
  assert.ok(result);
  assert.ok(result.findings);
});

// ─── LOLBins Audit Tests ─────────────────────────────────────────────────────

test('LOLBins audit (dry-run)', async () => {
  const { auditLOLBins } = await import('../src/lolbins_audit.ts');
  const result = auditLOLBins({ dryRun: true });
  assert.ok(result);
  assert.ok(result.discoveredLOLBins);
});

// ─── Master Export Index Test ─────────────────────────────────────────────────

test('Master security export index covers all module namespaces', async () => {
  const security = await import('../src/index.ts');
  const srcDir = path.resolve(__dirname, '../src');
  const expected = fs.readdirSync(srcDir)
    .filter((f) => f.endsWith('.ts') && f !== 'index.ts' && f !== 'mcp_server.ts')
    .map((f) => f.replace(/\.ts$/, ''));
  for (const mod of expected) {
    assert.ok(security[mod] !== undefined, `Missing namespace: ${mod}`);
  }
  assert.ok(Object.keys(security).length >= 75);
});
