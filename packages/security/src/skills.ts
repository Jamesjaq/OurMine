/**
 * @module skills
 * Offensive Security Skills Index & Loader — Provides skill resolution, taxonomy indexing,
 * and automated tool integration for the OurMine security engine.
 */

export interface SecuritySkill {
  id: string;
  name: string;
  category: "recon" | "exploit" | "post_exploit" | "cloud" | "ad" | "mobile";
  description: string;
  tags: string[];
}

const SKILL_CATALOG: SecuritySkill[] = [
  { id: "skill_subdomain_enum", name: "Subdomain Enumeration", category: "recon", description: "Passive and active subdomain discovery", tags: ["dns", "osint"] },
  { id: "skill_kerberoast", name: "Kerberoasting", category: "ad", description: "Request TGS tickets for SPN accounts and extract hashes", tags: ["active_directory", "kerberos"] },
  { id: "skill_aws_imds", name: "AWS IMDS Extraction", category: "cloud", description: "Fetch IAM credentials from IMDSv1/v2", tags: ["aws", "cloud", "metadata"] },
  { id: "skill_c2_beacon", name: "C2 Beaconing", category: "post_exploit", description: "Establish persistent HTTPS/DNS covert channel", tags: ["c2", "implant"] },
];

export function listSkills(category?: SecuritySkill["category"]): SecuritySkill[] {
  if (!category) return SKILL_CATALOG;
  return SKILL_CATALOG.filter((s) => s.category === category);
}

export default { listSkills };
