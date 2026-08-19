/**
 * @module lateral_movement
 * Autonomous Lateral Movement Engine — finds multi-hop paths using the CredentialGraph.
 */
import { CredentialGraph, CredentialNode } from "../credential_graph.ts"

export interface MovementPath {
  hops: Array<{
    from: string
    to: string
    method: string
    credentialId: string
  }>
  targetReached: boolean
}

export class LateralMovementEngine {
  constructor(private credGraph: CredentialGraph) {}

  /**
   * Find a multi-hop path from a source host to a target host using available credentials.
   * Uses a simple Breadth-First Search (BFS) over known hosts and credentials.
   */
  findPath(sourceHost: string, targetHost: string): MovementPath | null {
    const queue: Array<{ host: string; path: MovementPath["hops"] }> = [
      { host: sourceHost, path: [] }
    ]
    const visited = new Set<string>([sourceHost])
    const allCreds = this.credGraph.listCredentials()

    while (queue.length > 0) {
      const { host, path } = queue.shift()!

      if (host === targetHost) {
        return { hops: path, targetReached: true }
      }

      // Find credentials that can be used from this host or for this host
      for (const cred of allCreds) {
        // If we have a credential for a new host, that's a potential hop
        if (cred.host && !visited.has(cred.host)) {
          const newPath = [...path, {
            from: host,
            to: cred.host,
            method: this.determineMethod(cred),
            credentialId: cred.id
          }]
          
          if (cred.host === targetHost) {
            return { hops: newPath, targetReached: true }
          }

          visited.add(cred.host)
          queue.push({ host: cred.host, path: newPath })
        }
      }
    }

    return null
  }

  private determineMethod(cred: CredentialNode): string {
    switch (cred.type) {
      case "nthash": return "pth" // Pass-the-Hash
      case "ticket": return "ptt" // Pass-the-Ticket
      case "token": return "token_impersonation"
      case "password": return "smb_exec"
      default: return "generic_auth"
    }
  }

  /** Suggest the best next hop towards a high-value target (e.g., Domain Controller). */
  suggestNextHop(currentHost: string, highValueTargets: string[]): MovementPath["hops"][0] | null {
    for (const target of highValueTargets) {
      const path = this.findPath(currentHost, target)
      if (path && path.hops.length > 0) {
        return path.hops[0]
      }
    }
    return null
  }
}

export default LateralMovementEngine
