import test from 'node:test';
import assert from 'node:assert';
import * as security from '../src/index.ts';

test('Container & K8s security auditing', async () => {
  const audit = security.container.auditContainer({ live: false });
  assert.strictEqual(audit.dryRun, true);
  assert.strictEqual(typeof audit.isContainer, 'boolean');
});

test('AI Recon & Prompt injection analysis', async () => {
  const prompts = security.atlas_arsenal.generateJailbreakPrompts();
  assert.ok(prompts.length > 0);
  assert.strictEqual(prompts[0].dryRun, true);
});

test('CI/CD Supply chain auditing', async () => {
  const audit = security.supply_chain.auditPackage('reqeusts');
  assert.strictEqual(audit.isTyposquat, true);
});

test('Credential dumping & Identity attacks', async () => {
  const res = await security.identity.kerberoast({ live: false });
  assert.ok(res.length > 0);
  assert.strictEqual(res[0].hashType, 'krb5tgs');
});

test('Anti-Forensics & Anti-Analysis', async () => {
  const profile = security.anti_analysis.profileEnvironment({ live: false });
  assert.strictEqual(typeof profile.score, 'number');
});

test('Master security export index covers all 75 modules', async () => {
  const modules = Object.keys(security);
  assert.ok(modules.length >= 75, `Expected >= 75 modules exported, found ${modules.length}`);
});
