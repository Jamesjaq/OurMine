import test from 'node:test';
import assert from 'node:assert';
import {
  K8sSecurityAuditor,
  AiSecurityAnalyzer,
  CicdSupplyChainAuditor,
  CredentialDumpingEngine,
  AntiForensicsEngine
} from '../src/index.ts';

test('K8sSecurityAuditor audits cluster risks', async () => {
  const auditor = new K8sSecurityAuditor();
  const res = await auditor.auditCluster({ targetCluster: 'k8s.corp.local', dryRun: true });
  assert.strictEqual(res.cluster, 'k8s.corp.local');
  assert.ok(res.rbacIssues.length > 0);
  assert.strictEqual(res.simulated, true);
});

test('AiSecurityAnalyzer tests prompt injection vulnerability', async () => {
  const analyzer = new AiSecurityAnalyzer();
  const res = await analyzer.analyzePromptSecurity({ modelEndpoint: 'https://api.ai.local/v1' });
  assert.strictEqual(res.promptInjectionVulnerable, true);
  assert.strictEqual(res.jailbreakRisk, 'high');
});

test('CicdSupplyChainAuditor checks pipeline security', async () => {
  const auditor = new CicdSupplyChainAuditor();
  const res = await auditor.auditPipeline({ repoUrl: 'https://github.com/corp/app' });
  assert.strictEqual(res.untrustedRunnerRisk, true);
  assert.ok(res.dependencyConfusionVulnerabilities.length > 0);
});

test('CredentialDumpingEngine dumps simulated hashes', async () => {
  const engine = new CredentialDumpingEngine();
  const res = await engine.dumpCredentials({ targetSystem: 'DC01.corp.local', method: 'lsass' });
  assert.strictEqual(res.extractedHashes, 4);
  assert.ok(res.sampleArtifacts[0].includes('Administrator:500'));
});

test('AntiForensicsEngine checks log wiping posture', async () => {
  const engine = new AntiForensicsEngine();
  const res = await engine.reviewAntiForensics({ targetOS: 'linux' });
  assert.strictEqual(res.clearedArtifacts.length, 3);
});
