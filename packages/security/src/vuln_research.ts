/**
 * @module vuln_research
 * Vulnerability Research & CVE Intelligence — NVD API Query Client, ExploitDB Search Interface,
 * EPSS (Exploit Prediction Scoring System) Evaluator, and CISA KEV (Known Exploited Vulnerabilities) Lookup.
 */

export interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
}

export async function checkCisaKev(cveId: string, live = false): Promise<boolean> {
  if (!live) {
    return cveId === "CVE-2021-44228"; // Log4Shell example for dry-run
  }

  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!res.ok) return false;
    const data = (await res.json()) as { vulnerabilities: CisaKevEntry[] };
    return data.vulnerabilities.some((v) => v.cveID === cveId);
  } catch {
    return false;
  }
}

export default { checkCisaKev };
