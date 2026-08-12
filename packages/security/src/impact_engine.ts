/**
 * @module security/impact_engine
 * ImpactDemonstrationEngine — HTTP canaries + ICS semantic process proofs.
 */
import type { VulnNode } from "./attack_surface.ts"
import { proveIcsImpact, icsImpactToEngineProof, type IcsImpactProof } from "./ics_impact_proof.ts"

export interface ImpactProof {
  vulnId: string
  level: "L3_VALIDATION" | "L4_CONTROLLED_IMPACT"
  proofType:
    | "CANARY_OBJECT_ACCESS"
    | "PRIVILEGE_BOUNDARY_CROSS"
    | "AUTHENTICATED_ENDPOINT_REACHED"
    | "HEADER_INDICATOR_REPRODUCED"
    | "ICS_REGISTER_READ"
    | "ICS_SEMANTIC_PROCESS"
  evidenceSnippet: string
  timestamp: string
  safeProofMarker: string
}

export class ImpactDemonstrationEngine {
  /** HTTP / text-body impact proof (existing). */
  public static demonstrateImpact(vuln: VulnNode, targetUrl: string, responseBody: string): ImpactProof | null {
    if (responseBody.includes("CONFIDENTIAL_DB_KEYS") || responseBody.includes("Superuser Access Granted")) {
      return {
        vulnId: vuln.id,
        level: "L4_CONTROLLED_IMPACT",
        proofType: "CANARY_OBJECT_ACCESS",
        evidenceSnippet: responseBody.slice(0, 100),
        timestamp: new Date().toISOString(),
        safeProofMarker: "PROOF_CANARY_READ_SUCCESS",
      }
    }

    if (responseBody.includes("Log4j/2.14.1")) {
      return {
        vulnId: vuln.id,
        level: "L3_VALIDATION",
        proofType: "HEADER_INDICATOR_REPRODUCED",
        evidenceSnippet: "X-Powered-By: Log4j/2.14.1",
        timestamp: new Date().toISOString(),
        safeProofMarker: "PROOF_INDICATOR_MATCH",
      }
    }

    return null
  }

  /** ICS Modbus / semantic process impact (unified path). */
  public static async demonstrateIcsImpact(
    vuln: VulnNode,
    host: string,
    opts: { port?: number; live?: boolean } = {},
  ): Promise<{ proof: ImpactProof | null; ics: IcsImpactProof }> {
    const ics = await proveIcsImpact({
      host,
      port: opts.port ?? 502,
      live: opts.live,
      vulnId: vuln.id,
    })
    const proof = icsImpactToEngineProof(vuln.id, ics)
    if (proof && ics.semantic) {
      proof.proofType = ics.proofType === "SEMANTIC_PROCESS_IMPACT"
        ? "ICS_SEMANTIC_PROCESS"
        : "ICS_REGISTER_READ"
    }
    return { proof, ics }
  }
}

export default { ImpactDemonstrationEngine }
