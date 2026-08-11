import test from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(__dirname, '../src');

test('index import does not start MCP server', async () => {
  const stderrChunks = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...args) => {
    stderrChunks.push(String(chunk));
    return origWrite(chunk, ...args);
  };
  try {
    await import('../src/index.ts');
    const stderr = stderrChunks.join('');
    assert.ok(!stderr.includes('[ourmine-ares MCP] started'), 'MCP should not auto-start on index import');
  } finally {
    process.stderr.write = origWrite;
  }
});

test('namespace exports cover all src modules except index and mcp_server', async () => {
  const security = await import('../src/index.ts');
  const files = fs.readdirSync(srcDir)
    .filter((f) => f.endsWith('.ts') && f !== 'index.ts' && f !== 'mcp_server.ts')
    .map((f) => f.replace(/\.ts$/, ''))
    .sort();

  for (const mod of files) {
    assert.ok(
      security[mod] !== undefined,
      `Missing namespace export: security.${mod}`,
    );
  }
  assert.ok(files.length >= 114);
});

test('CLI/MCP critical wiring functions exist', async () => {
  const security = await import('../src/index.ts');

  assert.strictEqual(typeof security.ai_recon.runRecon, 'function');
  assert.strictEqual(typeof security.bountyhunter.recon, 'function');
  assert.strictEqual(typeof security.yara.scanText, 'function');
  assert.strictEqual(typeof security.skills.listSkills, 'function');
  assert.strictEqual(typeof security.counter_intel.detect, 'function');
  assert.strictEqual(typeof security.container.escape, 'function');
  assert.strictEqual(typeof security.supply_chain.analyze, 'function');
  assert.strictEqual(typeof security.identity.execute, 'function');
  assert.strictEqual(typeof security.agent_resilience.resilienceEngine, 'object');
});

test('ai_recon honors live flag', async () => {
  const { runRecon } = await import('../src/ai_recon.ts');
  const dry = await runRecon({ domain: 'example.com' }, { live: false });
  assert.strictEqual(dry.dryRun, true);
  const live = await runRecon({ domain: 'example.com' }, { live: true });
  assert.strictEqual(live.dryRun, false);
});

test('mcp_server exports startMcpServer without auto-start on import', async () => {
  const stderrChunks = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...args) => {
    stderrChunks.push(String(chunk));
    return origWrite(chunk, ...args);
  };
  try {
    const mcp = await import('../src/mcp_server.ts');
    assert.strictEqual(typeof mcp.startMcpServer, 'function');
    assert.ok(!stderrChunks.join('').includes('[ourmine-ares MCP] started'));
  } finally {
    process.stderr.write = origWrite;
  }
});
