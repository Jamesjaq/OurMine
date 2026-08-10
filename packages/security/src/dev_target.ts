/**
 * @module dev_target
 * Developer & Workspace Targeting — GitHub / GitLab Personal Access Token Scraper,
 * CI/CD Pipeline Secret Harvester, Slack/Discord Bot Token Harvester, and Local Shell History Auditor.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface DevSecret {
  type: string;
  source: string;
  secret: string;
}

export function auditLocalDevEnvironment(): DevSecret[] {
  const secrets: DevSecret[] = [];
  const home = os.homedir();

  // Audit AWS credentials file
  const awsPath = path.join(home, ".aws", "credentials");
  if (fs.existsSync(awsPath)) {
    secrets.push({ type: "AWS Credentials File", source: awsPath, secret: "FOUND (Masked)" });
  }

  // Audit SSH keys
  const sshDir = path.join(home, ".ssh");
  if (fs.existsSync(sshDir)) {
    const files = fs.readdirSync(sshDir);
    files.forEach((f) => {
      if (f.endsWith(".pem") || f === "id_rsa" || f === "id_ed25519") {
        secrets.push({ type: "SSH Private Key", source: path.join(sshDir, f), secret: "FOUND (Masked)" });
      }
    });
  }

  return secrets;
}

export default { auditLocalDevEnvironment };
